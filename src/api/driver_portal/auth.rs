// src/api/driver_portal/auth.rs
use crate::{
    AppState,
    error::AppError,
    models::DriverStatus,
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

// --- Phone normalization ---

pub fn normalize_phone(phone: &str) -> String {
    let stripped: String = phone.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '(' | ')'))
        .collect();
    if stripped.starts_with('+') {
        return stripped;
    }
    if stripped.len() == 10 && stripped.chars().all(|c| c.is_ascii_digit()) {
        return format!("+1{stripped}");
    }
    if stripped.chars().all(|c| c.is_ascii_digit()) {
        return format!("+{stripped}");
    }
    stripped
}

// --- Request/Response types ---

#[derive(Deserialize)]
pub struct FirebaseLoginRequest {
    /// Firebase ID token
    pub id_token: String,
}

// --- Handlers ---

/// Get Firebase configuration for the driver PWA frontend SDK (unauthenticated).
pub async fn firebase_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    Ok(Json(json!({
        "api_key": state.config.firebase_api_key,
        "auth_domain": state.config.firebase_auth_domain,
        "project_id": state.config.firebase_project_id,
        "app_id": state.config.firebase_app_id,
    })))
}

/// Login as a driver using Firebase ID token. Maps to ollie driver by email (and phone if available).
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<FirebaseLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Verify Firebase token
    let firebase_claims = state.firebase.verify_id_token(&req.id_token).await
        .map_err(|_| {
            tracing::warn!("firebase token verification failed during driver login");
            AppError::Unauthorized
        })?;

    let email = normalize_phone(&firebase_claims.email); // Using normalize_phone for consistent format
    
    // Try to find driver by email first
    let mut driver_opt = state.db.get_driver_by_email(&email).await.ok().flatten();
    
    // If not found by email and phone is available, try by phone
    if driver_opt.is_none() {
        if let Some(ref phone) = firebase_claims.phone_number {
            let normalized_phone = normalize_phone(phone);
            driver_opt = state.db.get_driver_by_phone(&normalized_phone).await.ok().flatten();
        }
    }

    let driver = driver_opt.ok_or_else(|| {
        tracing::warn!(email = %firebase_claims.email, phone = ?firebase_claims.phone_number, "firebase driver not found");
        AppError::Unauthorized
    })?;

    if driver.status == DriverStatus::Inactive {
        return Err(AppError::Unauthorized);
    }

    tracing::info!(driver_id = %driver.id, email = %firebase_claims.email, "driver firebase login succeeded");

    // Return the Firebase token itself — the middleware already knows how to verify it
    Ok(Json(json!({ "token": req.id_token })))
}

/// Refresh endpoint is deprecated for Firebase auth (Firebase handles token refresh).
pub async fn refresh(
    State(_state): State<AppState>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Firebase tokens are refreshed client-side by the Firebase SDK
    Err(AppError::Unauthorized)
}

/// Logout (client-side only for Firebase).
pub async fn logout(
    State(_state): State<AppState>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Firebase logout is handled client-side by calling firebase.auth().signOut()
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_phone_e164_unchanged() {
        assert_eq!(normalize_phone("+12125551234"), "+12125551234");
    }

    #[test]
    fn test_normalize_phone_10_digits() {
        assert_eq!(normalize_phone("2125551234"), "+12125551234");
    }

    #[test]
    fn test_normalize_phone_strips_formatting() {
        assert_eq!(normalize_phone("(212) 555-1234"), "+12125551234");
    }

    #[test]
    fn test_normalize_phone_strips_dashes() {
        assert_eq!(normalize_phone("212-555-1234"), "+12125551234");
    }

    #[test]
    fn test_normalize_phone_international_with_plus() {
        assert_eq!(normalize_phone("+442071838750"), "+442071838750");
    }

    #[test]
    fn test_normalize_phone_11_digits_numeric() {
        assert_eq!(normalize_phone("12125551234"), "+12125551234");
    }
}
