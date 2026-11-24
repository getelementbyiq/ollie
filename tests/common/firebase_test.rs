// tests/common/firebase_test.rs
//! Firebase test helpers: generate RSA keys, sign ID tokens, mock JWKS server

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::traits::PublicKeyParts;
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct FirebaseTestHelper {
    pub project_id: String,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub kid: String,
}

impl FirebaseTestHelper {
    pub fn new(project_id: &str) -> Self {
        let mut rng = rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        
        Self {
            project_id: project_id.to_string(),
            private_key,
            public_key,
            kid: "test-kid-1".to_string(),
        }
    }

    /// Sign a Firebase ID token with the given claims
    pub fn sign_id_token(&self, email: &str, sub: &str, phone: Option<String>) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        let claims = json!({
            "email": email,
            "email_verified": true,
            "phone_number": phone,
            "sub": sub,
            "iss": format!("https://securetoken.google.com/{}", self.project_id),
            "aud": self.project_id,
            "iat": now,
            "exp": now + 3600,
            "name": email.split('@').next().unwrap_or("Test User"),
        });

        // jsonwebtoken requires PKCS#1 DER format for RSA keys
        let der = self.private_key.to_pkcs1_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        
        encode(&header, &claims, &encoding_key).unwrap()
    }

    /// Generate JWKS JSON (Google's public key format)
    pub fn jwks_json(&self) -> String {
        let n = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &self.public_key.n().to_bytes_be(),
        );
        let e = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &self.public_key.e().to_bytes_be(),
        );

        json!({
            "keys": [{
                "kid": self.kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": n,
                "e": e,
            }]
        }).to_string()
    }

    /// Create a FirebaseAuth instance pre-seeded with this test key
    /// (bypasses HTTP fetch by pre-populating the JWKS cache)
    pub async fn create_seeded_firebase_auth(&self) -> ollie::firebase::FirebaseAuth {
        use std::collections::HashMap;
        
        let fb = ollie::firebase::FirebaseAuth::new(self.project_id.clone());
        
        let n = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &self.public_key.n().to_bytes_be(),
        );
        let e = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &self.public_key.e().to_bytes_be(),
        );
        
        let mut keys_map = HashMap::new();
        keys_map.insert(self.kid.clone(), ollie::firebase::JwkKey {
            kid: self.kid.clone(),
            n,
            e,
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            use_: "sig".to_string(),
        });
        
        let cache = ollie::firebase::JwksCache {
            keys: keys_map,
            fetched_at: SystemTime::now(),
        };
        
        fb.seed_jwks_cache_for_test(cache).await;
        fb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_firebase_helper_signs_valid_token() {
        let helper = FirebaseTestHelper::new("test-project");
        let token = helper.sign_id_token("test@example.com", "user123", None);
        
        // Token should have 3 parts
        assert_eq!(token.split('.').count(), 3);
        
        // Should be verifiable with the helper's public key
        let fb = helper.create_seeded_firebase_auth().await;
        let result = fb.verify_id_token(&token).await;
        assert!(result.is_ok());
        
        let claims = result.unwrap();
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.sub, "user123");
    }
}
