// src/api/elearning.rs
//! /elearning section — protected static content requiring Firebase authentication.
//! Uses secure HttpOnly session cookies instead of bearer tokens for browser navigation.

use crate::{AppState, error::AppError};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tower_http::services::ServeDir;
use uuid::Uuid;

const SESSION_COOKIE_NAME: &str = "ollie_elearning_session";
const SESSION_TTL_HOURS: u64 = 24;

/// Firebase login request for /elearning
#[derive(Debug, Deserialize)]
pub struct ElearningLoginRequest {
    pub id_token: String,
}

#[derive(Debug, Serialize)]
pub struct ElearningLoginResponse {
    pub success: bool,
}

/// Middleware: require a valid elearning session cookie
pub async fn require_elearning_session(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract session cookie
    let cookies = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let session_id = cookies
        .split(';')
        .find_map(|cookie| {
            let cookie = cookie.trim();
            cookie.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME))
        });

    let session_id = match session_id {
        Some(id) => id.to_string(),
        None => {
            // No session cookie — redirect to login
            return Ok(Redirect::to("/elearning/login").into_response());
        }
    };

    // Check session validity
    if let Some(entry) = state.elearning_sessions.get(&session_id) {
        let (_, created_at) = entry.value();
        let age = Instant::now().duration_since(*created_at);
        if age.as_secs() < SESSION_TTL_HOURS * 3600 {
            // Valid session
            return Ok(next.run(request).await);
        }
    }

    // Invalid or expired session
    Ok(Redirect::to("/elearning/login").into_response())
}

/// POST /elearning/auth/login — verify Firebase token and set session cookie
pub async fn elearning_login(
    State(state): State<AppState>,
    Json(req): Json<ElearningLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Verify Firebase token
    let claims = state.firebase.verify_id_token(&req.id_token).await
        .map_err(|_| {
            tracing::warn!("elearning: firebase token verification failed");
            AppError::Unauthorized
        })?;

    // Create session
    let session_id = Uuid::new_v4().to_string();
    state.elearning_sessions.insert(
        session_id.clone(),
        (claims.email.clone(), Instant::now()),
    );

    // Build secure HttpOnly cookie
    let cookie_value = format!(
        "{}={}; Path=/elearning; HttpOnly; SameSite=Lax; Max-Age={}{}",
        SESSION_COOKIE_NAME,
        session_id,
        SESSION_TTL_HOURS * 3600,
        if state.config.cookie_secure { "; Secure" } else { "" }
    );

    tracing::info!(email = %claims.email, "elearning session created");

    let mut response = Json(ElearningLoginResponse { success: true }).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie_value.parse().unwrap(),
    );
    Ok(response)
}

/// POST /elearning/auth/logout — clear session cookie
pub async fn elearning_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Extract and remove session
    let cookies = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(session_id) = cookies.split(';').find_map(|cookie| {
        let cookie = cookie.trim();
        cookie.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME))
    }) {
        state.elearning_sessions.remove(session_id);
    }

    // Clear cookie
    let cookie_value = format!(
        "{}=; Path=/elearning; HttpOnly; SameSite=Lax; Max-Age=0{}",
        SESSION_COOKIE_NAME,
        if state.config.cookie_secure { "; Secure" } else { "" }
    );

    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie_value.parse().unwrap(),
    );
    Ok(response)
}

/// GET /elearning/api/firebase-config — public Firebase config
pub async fn elearning_firebase_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    Ok(Json(serde_json::json!({
        "api_key": state.config.firebase_api_key,
        "auth_domain": state.config.firebase_auth_domain,
        "project_id": state.config.firebase_project_id,
        "app_id": state.config.firebase_app_id,
    })))
}

/// Fallback handler for /elearning/* paths — 404 with redirect to index
async fn elearning_fallback(uri: Uri) -> impl IntoResponse {
    tracing::debug!(path = %uri.path(), "elearning path not found, redirecting to index");
    Redirect::to("/elearning/")
}

/// Serve the login page (unauthenticated)
async fn serve_login_page() -> impl IntoResponse {
    match tokio::fs::read_to_string("static/elearning/login.html").await {
        Ok(content) => (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], content).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Login page not found").into_response(),
    }
}

/// Serve the main index (authenticated)
async fn serve_index() -> impl IntoResponse {
    match tokio::fs::read_to_string("static/elearning/index.html").await {
        Ok(content) => (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], content).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Content not found").into_response(),
    }
}

/// Router for /elearning section
pub fn elearning_router(state: &AppState) -> Router<AppState> {
    // Public endpoints (no auth required)
    let public = Router::new()
        .route("/elearning/login", get(serve_login_page))
        .route("/elearning/auth/login", axum::routing::post(elearning_login))
        .route("/elearning/auth/logout", axum::routing::post(elearning_logout))
        .route("/elearning/api/firebase-config", get(elearning_firebase_config));

    // Protected content — requires session (all three path variants)
    let protected = Router::new()
        .route("/elearning", get(serve_index))
        .route("/elearning/", get(serve_index))
        .route("/elearning/index.html", get(serve_index))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_elearning_session,
        ));

    public.merge(protected)
}
