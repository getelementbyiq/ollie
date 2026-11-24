// src/api/fleet_portal/auth.rs
use crate::{
    AppState,
    error::AppError,
    models::{FleetUserCredentials, FleetUserRecord, FleetUserStatus, permission::Role},
};
use uuid::Uuid;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use utoipa::ToSchema;

use super::jwt::encode_fleet_user_jwt;
use crate::api::refresh_tokens;
use axum::http::header::SET_COOKIE;

// Pre-computed dummy hash used to equalise response time for unknown-email logins.
// Computed once at cost 12 (same as real passwords) so the timing profile matches.
static DUMMY_HASH: OnceLock<String> = OnceLock::new();
pub(crate) fn dummy_hash() -> &'static str {
    DUMMY_HASH.get_or_init(|| bcrypt::hash("dummy-sentinel", 12).expect("bcrypt init failed"))
}

/// Verify a fleet_user's password and maintain the failed-attempt lockout
/// counter. Returns `Ok(true)` on a valid password (resetting the counter) and
/// `Ok(false)` on an invalid one (incrementing `failed_attempts` and applying
/// the lockout backoff). Persists `creds` either way. Callers MUST reject an
/// already-locked account (`creds.locked_until`) BEFORE calling. Shared by
/// `/fleet/auth/login` and `/oauth/authorize` so the lockout gate cannot be
/// bypassed by choosing a different endpoint.
pub(crate) async fn verify_fleet_user_password(
    state: &AppState,
    creds: &mut crate::models::FleetUserCredentials,
    password: &str,
) -> Result<bool, AppError> {
    let pw = password.to_string();
    let hash = creds.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || bcrypt::verify(&pw, &hash))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;

    if !valid {
        creds.failed_attempts += 1;
        if creds.failed_attempts >= 5 {
            let extra_failures = creds.failed_attempts - 5;
            let backoff_mins = 15u64 * 2u64.pow(extra_failures as u32);
            let backoff_mins = backoff_mins.min(24 * 60);
            creds.locked_until = Some(Utc::now() + chrono::Duration::minutes(backoff_mins as i64));
            tracing::warn!(
                failed_attempts = creds.failed_attempts,
                locked_until = ?creds.locked_until,
                "fleet_user lockout"
            );
        }
        creds.updated_at = Utc::now();
        state.db.upsert_fleet_user_credentials(creds).await?;
        return Ok(false);
    }

    creds.failed_attempts = 0;
    creds.locked_until = None;
    creds.updated_at = Utc::now();
    state.db.upsert_fleet_user_credentials(creds).await?;
    Ok(true)
}

// --- Request/Response types ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct FirebaseLoginRequest {
    /// Firebase ID token
    pub id_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FirebaseConfigResponse {
    pub api_key: String,
    pub auth_domain: String,
    pub project_id: String,
    pub app_id: String,
}

// --- Helpers ---

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

// --- Handlers ---

/// Get Firebase configuration for the frontend SDK (unauthenticated).
#[utoipa::path(
    get,
    path = "/fleet/api/v1/firebase-config",
    responses(
        (status = 200, description = "Firebase config", body = FirebaseConfigResponse),
    ),
    tag = "fleet-auth"
)]
pub async fn firebase_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    Ok(Json(FirebaseConfigResponse {
        api_key: state.config.firebase_api_key.clone(),
        auth_domain: state.config.firebase_auth_domain.clone(),
        project_id: state.config.firebase_project_id.clone(),
        app_id: state.config.firebase_app_id.clone(),
    }))
}

/// Login as a fleet_user using Firebase ID token. Maps to ollie fleet_user by email.
#[utoipa::path(
    post,
    path = "/fleet/auth/login",
    request_body(content = FirebaseLoginRequest, description = "Firebase ID token"),
    responses(
        (status = 200, description = "Firebase token accepted (passthrough)", body = LoginResponse),
        (status = 401, description = "Invalid Firebase token or user not found"),
    ),
    tag = "fleet-auth"
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<FirebaseLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Verify Firebase token
    let firebase_claims = state.firebase.verify_id_token(&req.id_token).await
        .map_err(|_| {
            tracing::warn!("firebase token verification failed during login");
            AppError::Unauthorized
        })?;

    let email = normalize_email(&firebase_claims.email);

    // Bootstrap: if no fleet users exist and bootstrap email is set, create owner
    let user_count = state.db.count_fleet_users().await?;
    if user_count == 0 {
        if let Some(bootstrap_email) = &state.config.bootstrap_owner_email {
            let bootstrap_normalized = normalize_email(bootstrap_email);
            if email == bootstrap_normalized {
                tracing::info!(email = %email, "bootstrap: creating owner account from firebase login");
                let now = Utc::now();
                let id = Uuid::new_v4();
                let record = FleetUserRecord {
                    id,
                    email: email.clone(),
                    name: firebase_claims.name.clone().unwrap_or_else(|| email.clone()),
                    status: FleetUserStatus::Active,
                    role: Role::Owner,
                    extra_scopes: Vec::new(),
                    created_at: now,
                    updated_at: now,
                };
                state.db.insert_fleet_user(&record).await?;
                
                // No password-based credentials needed for Firebase users
                tracing::info!(fleet_user_id = %id, "bootstrap owner created");
            }
        }
    }

    // Look up fleet_user by email
    let fleet_user = state.db.get_fleet_user_by_email(&email).await?
        .ok_or_else(|| {
            tracing::warn!(email = %email, "firebase user not found in fleet_users");
            AppError::Unauthorized
        })?;

    if fleet_user.status == FleetUserStatus::Inactive {
        return Err(AppError::Unauthorized);
    }

    tracing::info!(fleet_user_id = %fleet_user.id, email = %email, "fleet user firebase login succeeded");

    // Return the Firebase token itself — the middleware already knows how to verify it
    Ok(Json(LoginResponse { token: req.id_token }))
}

/// Refresh endpoint is deprecated for Firebase auth (Firebase handles token refresh).
/// Kept for backwards compatibility with any existing refresh-token cookies.
#[utoipa::path(
    post,
    path = "/fleet/auth/refresh",
    responses(
        (status = 200, description = "New JWT token", body = LoginResponse),
        (status = 401, description = "Invalid or revoked refresh token"),
    ),
    tag = "fleet-auth"
)]
pub async fn refresh(
    State(_state): State<AppState>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Firebase tokens are refreshed client-side by the Firebase SDK
    Err(AppError::Unauthorized)
}

/// Logout (client-side only for Firebase; this endpoint just clears any legacy cookies).
#[utoipa::path(
    post,
    path = "/fleet/auth/logout",
    responses((status = 200, description = "Logged out")),
    tag = "fleet-auth"
)]
pub async fn logout(
    State(_state): State<AppState>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Firebase logout is handled client-side by calling firebase.auth().signOut()
    // This endpoint exists for backwards compatibility only
    Ok(StatusCode::OK)
}
