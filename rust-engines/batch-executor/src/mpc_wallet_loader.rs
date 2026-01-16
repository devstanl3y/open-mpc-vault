use anyhow::Result;
use ethers_core::types::Address;
use ethers_signers::{LocalWallet, Signer};
use reqwest;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Deserialize)]
struct MpcWallet {
    id: String,
    #[serde(rename = "shardAEncrypted")]
    shard_a_encrypted: String,
    #[serde(rename = "shardAIv")]
    shard_a_iv: String,
    #[serde(rename = "shardATag")]
    shard_a_tag: String,
    #[serde(rename = "shardBId")]
    shard_b_id: String,
    #[serde(rename = "curveType")]
    curve_type: String,
}

#[derive(Debug, Deserialize)]
struct ShardB {
    #[serde(rename = "encryptedShard")]
    encrypted_shard: String,
}

#[derive(Debug, Serialize)]
struct DecryptShardRequest {
    encrypted: String,
    iv: String,
    tag: String,
    pin: String,
}

pub struct MpcWalletLoader {
    api_url: String,
    engine_secret: String,
}

impl MpcWalletLoader {
    pub fn new(api_url: String, engine_secret: String) -> Self {
        Self {
            api_url,
            engine_secret,
        }
    }

    pub async fn load_wallet(
        &self,
        mpc_wallet_id: &str,
        pin: &str,
        chain_id: u64,
    ) -> Result<LocalWallet> {
        // 1. Fetch MPC wallet metadata from database
        let mpc_wallet = self.fetch_mpc_wallet(mpc_wallet_id).await?;

        // 2. Decrypt Shard A using backend API (has crypto utilities)
        let shard_a = self
            .decrypt_shard_a(
                &mpc_wallet.shard_a_encrypted,
                &mpc_wallet.shard_a_iv,
                &mpc_wallet.shard_a_tag,
                pin,
            )
            .await?;

        // 3. Fetch and decrypt Shard B
        let shard_b = self.fetch_and_decrypt_shard_b(&mpc_wallet.shard_b_id).await?;

        // 4. Reconstruct private key using Shamir Secret Sharing
        let private_key = self.reconstruct_private_key(&shard_a, &shard_b)?;

        // 5. Create LocalWallet
        let wallet = LocalWallet::from_str(&private_key)?.with_chain_id(chain_id);

        Ok(wallet)
    }

    async fn fetch_mpc_wallet(&self, wallet_id: &str) -> Result<MpcWallet> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/internal/mpc-wallet/{}", self.api_url, wallet_id);

        let response = client
            .get(&url)
            .header("x-engine-secret", &self.engine_secret)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to fetch MPC wallet"));
        }

        let wallet: MpcWallet = response.json().await?;
        Ok(wallet)
    }

    async fn decrypt_shard_a(
        &self,
        encrypted: &str,
        iv: &str,
        tag: &str,
        pin: &str,
    ) -> Result<Vec<u8>> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/internal/decrypt-shard-a", self.api_url);

        let payload = DecryptShardRequest {
            encrypted: encrypted.to_string(),
            iv: iv.to_string(),
            tag: tag.to_string(),
            pin: pin.to_string(),
        };

        let response = client
            .post(&url)
            .header("x-engine-secret", &self.engine_secret)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to decrypt shard A"));
        }

        #[derive(Deserialize)]
        struct DecryptResponse {
            shard: String,
        }

        let result: DecryptResponse = response.json().await?;
        let shard_bytes = hex::decode(&result.shard)?;
        Ok(shard_bytes)
    }

    async fn fetch_and_decrypt_shard_b(&self, shard_b_id: &str) -> Result<Vec<u8>> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/internal/shard-b/{}", self.api_url, shard_b_id);

        let response = client
            .get(&url)
            .header("x-engine-secret", &self.engine_secret)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to fetch shard B"));
        }

        #[derive(Deserialize)]
        struct ShardBResponse {
            shard: String,
        }

        let result: ShardBResponse = response.json().await?;
        let shard_bytes = hex::decode(&result.shard)?;
        Ok(shard_bytes)
    }

    fn reconstruct_private_key(&self, shard_a: &[u8], shard_b: &[u8]) -> Result<String> {
        // XOR the two shards to reconstruct the private key
        // This is a simplified 2-of-2 Shamir reconstruction
        if shard_a.len() != shard_b.len() {
            return Err(anyhow::anyhow!("Shard length mismatch"));
        }

        let private_key_bytes: Vec<u8> = shard_a
            .iter()
            .zip(shard_b.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let private_key_hex = hex::encode(&private_key_bytes);
        Ok(format!("0x{}", private_key_hex))
    }
}