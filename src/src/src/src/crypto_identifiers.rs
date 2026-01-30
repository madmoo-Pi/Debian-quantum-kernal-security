// src/crypto_identifiers.rs
use ring::{rand, signature, hmac};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CryptoIdentifier {
    key_pair: signature::Ed25519KeyPair,
    rng: rand::SystemRandom,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessToken {
    pub pid: u32,
    pub parent_token: Option<Vec<u8>>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub capabilities: Vec<Capability>,
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Capability {
    NetworkAccess,
    FilesystemAccess(String),  // Path prefix
    Syscall(u32),
    MemoryAllocation(u64),     // Max bytes
}

impl CryptoIdentifier {
    pub fn new() -> Result<Self, ring::error::Unspecified> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        
        Ok(Self { key_pair, rng })
    }
    
    pub fn generate_process_token(
        &self,
        pid: u32,
        parent_token: Option<&ProcessToken>,
        capabilities: &[Capability],
    ) -> Result<ProcessToken, ring::error::Unspecified> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut nonce = [0u8; 16];
        rand::generate(&self.rng, &mut nonce)?;
        
        // Create token data
        let mut token_data = Vec::new();
        token_data.extend_from_slice(&pid.to_ne_bytes());
        token_data.extend_from_slice(&timestamp.to_ne_bytes());
        token_data.extend_from_slice(&nonce);
        
        if let Some(parent) = parent_token {
            token_data.extend_from_slice(&parent.signature);
        }
        
        for cap in capabilities {
            let cap_bytes = serde_json::to_vec(cap).unwrap();
            token_data.extend_from_slice(&cap_bytes);
        }
        
        // Sign the token
        let signature = self.key_pair.sign(&token_data).as_ref().to_vec();
        
        Ok(ProcessToken {
            pid,
            parent_token: parent_token.map(|t| t.signature.clone()),
            signature,
            timestamp,
            capabilities: capabilities.to_vec(),
            nonce,
        })
    }
    
    pub fn verify_token(&self, token: &ProcessToken) -> Result<bool, ring::error::Unspecified> {
        // Reconstruct token data
        let mut token_data = Vec::new();
        token_data.extend_from_slice(&token.pid.to_ne_bytes());
        token_data.extend_from_slice(&token.timestamp.to_ne_bytes());
        token_data.extend_from_slice(&token.nonce);
        
        if let Some(ref parent_sig) = token.parent_token {
            token_data.extend_from_slice(parent_sig);
        }
        
        for cap in &token.capabilities {
            let cap_bytes = serde_json::to_vec(cap).unwrap();
            token_data.extend_from_slice(&cap_bytes);
        }
        
        // Verify signature
        let peer_public_key_bytes = self.key_pair.public_key().as_ref();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            peer_public_key_bytes,
        );
        
        peer_public_key.verify(&token_data, &token.signature)?;
        Ok(true)
    }
    
    pub fn generate_session_key(&self, token: &ProcessToken) -> [u8; 32] {
        // Derive session key from token
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"session_derivation");
        let session_key = hmac::sign(&key, &token.signature);
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&session_key.as_ref()[0..32]);
        result
    }
    
    pub fn revoke_token(&self, token: &ProcessToken) -> RevocationProof {
        // Create revocation proof (add to CRL)
        let revocation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&token.signature);
        proof_data.extend_from_slice(&revocation_time.to_ne_bytes());
        
        RevocationProof {
            token_signature: token.signature.clone(),
            revoked_at: revocation_time,
            proof: self.key_pair.sign(&proof_data).as_ref().to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RevocationProof {
    pub token_signature: Vec<u8>,
    pub revoked_at: u64,
    pub proof: Vec<u8>,
}
