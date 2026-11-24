// src/firebase.rs
//! Firebase Authentication token verification without firebase-admin SDK.
//! 
//! Verifies Firebase ID tokens by fetching Google's public keys (JWKS) and
//! validating token signatures, issuer, audience, and expiry. No service
//! account secret required — uses only the public Firebase project ID.

use crate::error::AppError;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const JWKS_CACHE_TTL_SECS: u64 = 3600; // 1 hour

/// Firebase ID token claims (subset we care about)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirebaseClaims {
    /// Email address
    pub email: String,
    /// Whether email is verified
    #[serde(default)]
    pub email_verified: bool,
    /// Phone number (optional, only present for phone auth)
    pub phone_number: Option<String>,
    /// User ID (UID)
    pub sub: String,
    /// Issuer (should be https://securetoken.google.com/<project-id>)
    pub iss: String,
    /// Audience (should be <project-id>)
    pub aud: String,
    /// Issued at
    pub iat: u64,
    /// Expiry
    pub exp: u64,
    /// Optional name
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwkKey {
    pub kid: String,
    pub n: String,
    pub e: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
}

pub struct JwksCache {
    pub keys: HashMap<String, JwkKey>,
    pub fetched_at: SystemTime,
}

pub struct FirebaseAuth {
    project_id: String,
    jwks_cache: Arc<RwLock<Option<JwksCache>>>,
    http_client: reqwest::Client,
}

impl FirebaseAuth {
    pub fn new(project_id: String) -> Self {
        Self {
            project_id,
            jwks_cache: Arc::new(RwLock::new(None)),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("firebase http client failed to init"),
        }
    }

    /// Test-only: seed the JWKS cache with pre-generated keys (bypasses HTTP fetch)
    #[cfg(test)]
    pub async fn seed_jwks_cache_for_test(&self, cache: JwksCache) {
        let mut guard = self.jwks_cache.write().await;
        *guard = Some(cache);
    }

    /// Verify a Firebase ID token and return the claims.
    pub async fn verify_id_token(&self, token: &str) -> Result<FirebaseClaims, AppError> {
        // 1. Decode header to get kid
        let header = decode_header(token)
            .map_err(|_| AppError::Unauthorized)?;
        let kid = header.kid.ok_or(AppError::Unauthorized)?;

        // 2. Get the public key for this kid
        let jwk = self.get_jwk(&kid).await?;

        // 3. Decode and validate the token
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|_| AppError::Unauthorized)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.project_id]);
        validation.set_issuer(&[&format!("https://securetoken.google.com/{}", self.project_id)]);

        let token_data = decode::<FirebaseClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                tracing::warn!(error = ?e, "firebase token validation failed");
                AppError::Unauthorized
            })?;

        Ok(token_data.claims)
    }

    /// Get a JWK by kid, fetching from Google if needed
    async fn get_jwk(&self, kid: &str) -> Result<JwkKey, AppError> {
        // Check cache first
        {
            let cache_guard = self.jwks_cache.read().await;
            if let Some(cache) = cache_guard.as_ref() {
                let age = SystemTime::now()
                    .duration_since(cache.fetched_at)
                    .unwrap_or(Duration::from_secs(0));
                if age.as_secs() < JWKS_CACHE_TTL_SECS {
                    if let Some(key) = cache.keys.get(kid) {
                        return Ok(key.clone());
                    }
                }
            }
        }

        // Cache miss or expired — fetch from Google
        self.fetch_and_cache_jwks().await?;

        // Try again after fetch
        let cache_guard = self.jwks_cache.read().await;
        cache_guard
            .as_ref()
            .and_then(|c| c.keys.get(kid))
            .cloned()
            .ok_or(AppError::Unauthorized)
    }

    /// Fetch JWKS from Google and cache it
    async fn fetch_and_cache_jwks(&self) -> Result<(), AppError> {
        let resp = self.http_client
            .get(GOOGLE_JWKS_URL)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "failed to fetch firebase jwks");
                AppError::Internal("firebase jwks fetch failed".into())
            })?;

        if !resp.status().is_success() {
            return Err(AppError::Internal(format!(
                "firebase jwks fetch returned {}",
                resp.status()
            )));
        }

        let jwks: JwksResponse = resp.json().await.map_err(|e| {
            tracing::error!(error = ?e, "failed to parse firebase jwks");
            AppError::Internal("firebase jwks parse failed".into())
        })?;

        let mut keys_map = HashMap::new();
        for key in jwks.keys {
            keys_map.insert(key.kid.clone(), key);
        }

        let cache = JwksCache {
            keys: keys_map,
            fetched_at: SystemTime::now(),
        };

        let mut cache_guard = self.jwks_cache.write().await;
        *cache_guard = Some(cache);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs1::EncodeRsaPublicKey;

    // Test helper: generate a test RSA key pair and create a token
    fn generate_test_token(project_id: &str, email: &str) -> (String, String, String) {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);

        // Extract n and e as base64url for JWKS
        let n = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &pub_key.n().to_bytes_be(),
        );
        let e = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &pub_key.e().to_bytes_be(),
        );

        // Create token
        let kid = "test-kid-1".to_string();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.clone());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = FirebaseClaims {
            email: email.to_string(),
            email_verified: true,
            phone_number: None,
            sub: "test-user-id".to_string(),
            iss: format!("https://securetoken.google.com/{}", project_id),
            aud: project_id.to_string(),
            iat: now,
            exp: now + 3600,
            name: Some("Test User".to_string()),
        };

        let pem = priv_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        (token, n, e)
    }

    #[tokio::test]
    async fn test_verify_valid_token_with_matching_jwk() {
        let project_id = "test-project-123";
        let email = "test@example.com";
        
        let (token, n, e) = generate_test_token(project_id, email);

        // Create a FirebaseAuth instance
        let fb = FirebaseAuth::new(project_id.to_string());

        // Manually seed the cache with our test key
        let test_key = JwkKey {
            kid: "test-kid-1".to_string(),
            n,
            e,
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            use_: "sig".to_string(),
        };
        let mut keys_map = HashMap::new();
        keys_map.insert(test_key.kid.clone(), test_key);
        let cache = JwksCache {
            keys: keys_map,
            fetched_at: SystemTime::now(),
        };
        *fb.jwks_cache.write().await = Some(cache);

        // Verify the token
        let result = fb.verify_id_token(&token).await;
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.email, email);
        assert_eq!(claims.sub, "test-user-id");
    }

    #[tokio::test]
    async fn test_verify_expired_token_rejected() {
        let project_id = "test-project-123";
        let fb = FirebaseAuth::new(project_id.to_string());

        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);

        let n = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &pub_key.n().to_bytes_be(),
        );
        let e = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &pub_key.e().to_bytes_be(),
        );

        // Create expired token
        let kid = "test-kid-expired".to_string();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.clone());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = FirebaseClaims {
            email: "test@example.com".to_string(),
            email_verified: true,
            phone_number: None,
            sub: "test-user-id".to_string(),
            iss: format!("https://securetoken.google.com/{}", project_id),
            aud: project_id.to_string(),
            iat: now - 7200,
            exp: now - 3600, // expired 1 hour ago
            name: Some("Test User".to_string()),
        };

        let pem = priv_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // Seed cache
        let test_key = JwkKey {
            kid,
            n,
            e,
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            use_: "sig".to_string(),
        };
        let mut keys_map = HashMap::new();
        keys_map.insert(test_key.kid.clone(), test_key);
        *fb.jwks_cache.write().await = Some(JwksCache {
            keys: keys_map,
            fetched_at: SystemTime::now(),
        });

        // Should reject expired token
        let result = fb.verify_id_token(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_wrong_audience_rejected() {
        let project_id = "test-project-123";
        let wrong_project = "wrong-project-456";
        
        let (token, n, e) = generate_test_token(wrong_project, "test@example.com");

        let fb = FirebaseAuth::new(project_id.to_string());

        // Seed cache
        let test_key = JwkKey {
            kid: "test-kid-1".to_string(),
            n,
            e,
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            use_: "sig".to_string(),
        };
        let mut keys_map = HashMap::new();
        keys_map.insert(test_key.kid.clone(), test_key);
        *fb.jwks_cache.write().await = Some(JwksCache {
            keys: keys_map,
            fetched_at: SystemTime::now(),
        });

        // Should reject wrong audience
        let result = fb.verify_id_token(&token).await;
        assert!(result.is_err());
    }
}
