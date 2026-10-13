use anyhow::{Context, Result};
use ethers_signers::{LocalWallet, Signer};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub enum EngineAuth {
    Bearer(String),
    ApiKey { header: String, key: String },
    None,
}

impl EngineAuth {
    pub fn apply(&self, builder: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        match self {
            EngineAuth::Bearer(token) => Ok(builder.bearer_auth(token)),
            EngineAuth::ApiKey { header, key } => Ok(builder.header(header, key)),
            EngineAuth::None => Ok(builder),
        }
    }
}

pub mod shamir {
    use anyhow::{bail, ensure, Result};
    use num_bigint::BigUint;
    use num_traits::{Num, One, Zero};
    use std::collections::HashSet;

    pub const EXTENDED_SHARE_LEN: usize = 34;
    pub const LEGACY_SHARE_LEN: usize = 33;
    pub const MAX_SECRET_LEN: usize = 32;

    fn get_field_prime() -> BigUint {
        BigUint::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .expect("valid secp256k1 base field prime")
    }

    fn mod_inv(a: &BigUint, p: &BigUint) -> Result<BigUint> {
        ensure!(!a.is_zero(), "modular inverse of zero is undefined");
        // By Fermat's Little Theorem: a^(p - 2) = a^(-1) (mod p)
        let two = BigUint::from(2u32);
        let exp = p - &two;
        Ok(a.modpow(&exp, p))
    }

    /// Reconstructs a secret from threshold Shamir shares evaluated over
    /// the secp256k1 prime order field.
    pub fn reconstruct_secret(shares: &[&[u8]]) -> Result<Vec<u8>> {
        ensure!(shares.len() >= 2, "at least 2 shares required for reconstruction");

        let is_extended = shares.iter().all(|s| s.len() == EXTENDED_SHARE_LEN);
        let is_legacy = shares.iter().all(|s| s.len() == LEGACY_SHARE_LEN);
        ensure!(
            is_extended || is_legacy,
            "invalid share format: shares must all be 34 bytes (extended) or 33 bytes (legacy)"
        );

        let secret_len = if is_extended {
            let len = shares[0][1] as usize;
            ensure!(
                (1..=MAX_SECRET_LEN).contains(&len),
                "invalid secret length ({}) in share header",
                len
            );
            ensure!(
                shares.iter().all(|s| s[1] as usize == len),
                "inconsistent secret lengths across shares"
            );
            len
        } else {
            MAX_SECRET_LEN
        };

        let y_offset = if is_extended { 2 } else { 1 };
        let p = get_field_prime();

        let mut seen_x = HashSet::new();
        let mut points = Vec::with_capacity(shares.len());

        for share in shares {
            let x_val = share[0];
            ensure!(x_val != 0, "x-coordinate must be non-zero");
            ensure!(seen_x.insert(x_val), "duplicate x-coordinate in shares: {}", x_val);

            let x = BigUint::from(x_val);
            let y = BigUint::from_bytes_be(&share[y_offset..]);
            ensure!(y < p, "y-coordinate exceeds field size");
            points.push((x, y));
        }

        // Lagrange polynomial interpolation evaluated at x = 0:
        // f(0) = sum_i( y_i * prod_{j != i}( -x_j / (x_i - x_j) ) ) mod p
        let mut secret = BigUint::zero();

        for (i, (xi, yi)) in points.iter().enumerate() {
            let mut num = BigUint::one();
            let mut den = BigUint::one();

            for (j, (xj, _)) in points.iter().enumerate() {
                if i == j {
                    continue;
                }
                // (0 - xj) mod p = (p - xj) mod p
                let term_num = (&p - xj) % &p;
                num = (num * term_num) % &p;

                // (xi - xj) mod p
                let term_den = if xi >= xj {
                    (xi - xj) % &p
                } else {
                    (&p - (xj - xi)) % &p
                };
                den = (den * term_den) % &p;
            }

            let basis = (num * mod_inv(&den, &p)?) % &p;
            secret = (secret + (yi * basis)) % &p;
        }

        let secret_bytes = secret.to_bytes_be();
        let mut full = vec![0u8; MAX_SECRET_LEN];
        if secret_bytes.len() <= MAX_SECRET_LEN {
            let offset = MAX_SECRET_LEN - secret_bytes.len();
            full[offset..].copy_from_slice(&secret_bytes);
        } else {
            bail!("reconstructed secret overflowed field bounds");
        }

        Ok(full[MAX_SECRET_LEN - secret_len..].to_vec())
    }
}

#[derive(Debug, Deserialize)]
struct MpcWallet {
    #[serde(rename = "userId")]
    user_id: i64,
    #[serde(rename = "shardAEncrypted")]
    shard_a_encrypted: String,
    #[serde(rename = "shardAIv")]
    shard_a_iv: String,
    #[serde(rename = "shardATag")]
    shard_a_tag: String,
    #[serde(rename = "shardASalt")]
    shard_a_salt: Option<String>,
    #[serde(rename = "shardBId")]
    shard_b_id: String,
}

#[derive(Debug, Serialize)]
struct DecryptShardRequest {
    encrypted: String,
    iv: String,
    tag: String,
    pin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
}

pub struct MpcWalletLoader {
    api_url: String,
    engine_auth: EngineAuth,
}

impl MpcWalletLoader {
    pub fn new(api_url: String, engine_auth: EngineAuth) -> Self {
        Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            engine_auth,
        }
    }

    /// Fetches and reconstructs a 2-of-2 Shamir shared wallet into an `ethers::LocalWallet`.
    pub async fn load_wallet(
        &self,
        mpc_wallet_id: &str,
        pin: &str,
        chain_id: u64,
    ) -> Result<LocalWallet> {
        // 1. Fetch MPC wallet metadata from the internal service endpoint
        let mpc_wallet = self.fetch_mpc_wallet(mpc_wallet_id).await?;

        // 2. Decrypt Shard A via backend service
        let shard_a = self
            .decrypt_shard_a(
                &mpc_wallet.shard_a_encrypted,
                &mpc_wallet.shard_a_iv,
                &mpc_wallet.shard_a_tag,
                mpc_wallet.shard_a_salt.as_deref(),
                pin,
            )
            .await?;

        // 3. Fetch decrypted Shard B
        let shard_b = self
            .fetch_and_decrypt_shard_b(&mpc_wallet.shard_b_id, mpc_wallet.user_id)
            .await?;

        // 4. Reconstruct private key using Shamir Secret Sharing Lagrange interpolation
        let private_key = self.reconstruct_private_key(&shard_a, &shard_b)?;

        // 5. Build LocalWallet
        let wallet = LocalWallet::from_str(&private_key)
            .context("failed to parse reconstructed private key into LocalWallet")?
            .with_chain_id(chain_id);

        Ok(wallet)
    }

    async fn fetch_mpc_wallet(&self, wallet_id: &str) -> Result<MpcWallet> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/internal/mpc-wallet/{}", self.api_url, wallet_id);

        let response = self.engine_auth.apply(client.get(&url))?.send().await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch MPC wallet (HTTP {})",
                response.status()
            ));
        }

        let wallet: MpcWallet = response.json().await?;
        Ok(wallet)
    }

    async fn decrypt_shard_a(
        &self,
        encrypted: &str,
        iv: &str,
        tag: &str,
        salt: Option<&str>,
        pin: &str,
    ) -> Result<Vec<u8>> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/internal/decrypt-shard-a", self.api_url);

        let payload = DecryptShardRequest {
            encrypted: encrypted.to_string(),
            iv: iv.to_string(),
            tag: tag.to_string(),
            pin: pin.to_string(),
            salt: salt.map(|s| s.to_string()),
        };

        let response = self
            .engine_auth
            .apply(client.post(&url))?
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to decrypt shard A (HTTP {})",
                response.status()
            ));
        }

        #[derive(Deserialize)]
        struct DecryptResponse {
            shard: String,
        }

        let result: DecryptResponse = response.json().await?;
        let shard_bytes = hex::decode(&result.shard)?;
        Ok(shard_bytes)
    }

    async fn fetch_and_decrypt_shard_b(&self, shard_b_id: &str, user_id: i64) -> Result<Vec<u8>> {
        let client = reqwest::Client::new();
        let url = format!(
            "{}/api/v1/internal/shard-b/{}?userId={}",
            self.api_url, shard_b_id, user_id
        );

        let response = self.engine_auth.apply(client.get(&url))?.send().await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch shard B (HTTP {})",
                response.status()
            ));
        }

        #[derive(Deserialize)]
        struct ShardBResponse {
            shard: String,
        }

        let result: ShardBResponse = response.json().await?;
        let shard_bytes = hex::decode(&result.shard)?;
        Ok(shard_bytes)
    }

    /// Reconstructs the 32-byte private key from two Shamir shares.
    pub fn reconstruct_private_key(&self, shard_a: &[u8], shard_b: &[u8]) -> Result<String> {
        let secret_bytes = shamir::reconstruct_secret(&[shard_a, shard_b])?;
        if secret_bytes.len() != 32 {
            anyhow::bail!(
                "expected reconstructed secret length 32 for private key, got {}",
                secret_bytes.len()
            );
        }
        Ok(format!("0x{}", hex::encode(secret_bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconstruct_32_byte_secret() {
        // Direct test vectors generated by open-mpc-vault TypeScript ShamirSecretSharing
        let shard_a = hex::decode("01208ba84209bf8d193a6cf670e69133a199ab8f9bfd03de45e7c41a441f7bea7ac8").unwrap();
        let shard_b = hex::decode("0220cb48006cee179ef777bb9ab1c4abe12e58ce0e98973a12a4a3cbb824b89ed278").unwrap();
        let expected_secret = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

        let loader = MpcWalletLoader::new("http://localhost:3000".to_string(), EngineAuth::None);
        let reconstructed = loader.reconstruct_private_key(&shard_a, &shard_b).unwrap();
        assert_eq!(reconstructed, format!("0x{}", expected_secret));
    }

    #[test]
    fn test_reconstruct_16_byte_secret_with_leading_zeros() {
        // 16-byte entropy with leading zeros (e.g. 12-word seed phrase)
        let expected_entropy = hex::decode("0000a1b2c3d4e5f60718293a4b5c6d7e").unwrap();
        let shard_a = hex::decode("011061776daa70515c825e73d9bc0991080977985b4542ef5da52f512a6c18f7608f").unwrap();
        let shard_b = hex::decode("0210c2eedb54e0a2b904bce7b37813221012ef3014d7c209d554578a2b9de69253a0").unwrap();

        let reconstructed = shamir::reconstruct_secret(&[&shard_a, &shard_b]).unwrap();
        assert_eq!(reconstructed, expected_entropy);
    }

    #[test]
    fn test_rejects_insufficient_or_invalid_shares() {
        let shard_a = hex::decode("012005470d9a656885dfb9e830e9dcf589bf4070a25514f0896faea91845bb08f23f").unwrap();
        assert!(shamir::reconstruct_secret(&[&shard_a]).is_err());

        // Duplicate x-coordinate
        assert!(shamir::reconstruct_secret(&[&shard_a, &shard_a]).is_err());

        // Zero x-coordinate
        let mut zero_x = shard_a.clone();
        zero_x[0] = 0;
        assert!(shamir::reconstruct_secret(&[&zero_x, &shard_a]).is_err());
    }
}
