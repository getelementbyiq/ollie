// src/api/oauth/authorize.rs
use crate::{models::{AuthorizationCode, FleetUserStatus}, AppState};
use axum::{
    extract::{Query, State},
    http::{header::LOCATION, StatusCode},
    response::{Html, IntoResponse, Response},
    Form,
};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Deserialize, Clone)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Deserialize)]
pub struct AuthorizeForm {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub id_token: String,
    pub decision: String,
}

fn h(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

async fn validate(state: &AppState, client_id: &str, redirect_uri: &str, challenge: &str, method: &Option<String>)
    -> Result<crate::models::OAuthClient, String>
{
    if challenge.is_empty() { return Err("PKCE code_challenge required".into()); }
    if let Some(m) = method { if m != "S256" { return Err("only S256 supported".into()); } }
    let id: Uuid = client_id.parse().map_err(|_| "unknown client".to_string())?;
    let client = state.db.get_oauth_client(id).await
        .map_err(|e| e.to_string())?
        .ok_or("unknown client")?;
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return Err("redirect_uri mismatch".into());
    }
    Ok(client)
}

pub async fn authorize_page(
    State(state): State<AppState>,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    if p.response_type != "code" {
        return (StatusCode::BAD_REQUEST, "unsupported response_type").into_response();
    }
    let client = match validate(&state, &p.client_id, &p.redirect_uri, &p.code_challenge, &p.code_challenge_method).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Html(format!("<h1>Authorization error</h1><p>{}</p>", h(&e)))).into_response(),
    };
    let client_label = client.client_name.clone().unwrap_or_else(|| client.id.to_string());
    let hidden = |k: &str, v: &str| format!(r#"<input type="hidden" name="{k}" value="{}">"#, h(v));
    let firebase_config = serde_json::json!({
        "apiKey": state.config.firebase_api_key,
        "authDomain": state.config.firebase_auth_domain,
        "projectId": state.config.firebase_project_id,
        "appId": state.config.firebase_app_id,
    });
    let page = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Authorize Ollie</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:system-ui;max-width:24rem;margin:3rem auto;padding:0 1rem}}
button{{padding:.6rem 1rem;margin-right:.5rem;cursor:pointer}}
.btn-primary{{background:#0066cc;color:#fff;border:none;border-radius:4px}}
.btn-secondary{{background:#ccc;color:#000;border:none;border-radius:4px}}
#error{{color:red;margin:1rem 0}}</style></head>
<body><h1>Connect to Ollie</h1>
<p><strong>{client}</strong> wants to access your Ollie fleet account.</p>
<form id="oauth-form" method="post" action="/oauth/authorize">
{p_rt}{p_cid}{p_ru}{p_cc}{p_ccm}{p_state}{p_scope}{p_res}
<input type="hidden" name="id_token" id="id-token" value="">
<button type="button" id="firebase-signin" class="btn-primary">Sign in with Google</button>
<button type="submit" name="decision" value="deny" class="btn-secondary">Deny</button>
</form>
<div id="error"></div>
<script type="module">
const config = {firebase_config};
const {{initializeApp}} = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js');
const {{getAuth, signInWithPopup, GoogleAuthProvider}} = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js');
const app = initializeApp(config);
const auth = getAuth(app);
document.getElementById('firebase-signin').addEventListener('click', async () => {{
  try {{
    const provider = new GoogleAuthProvider();
    const result = await signInWithPopup(auth, provider);
    const idToken = await result.user.getIdToken();
    document.getElementById('id-token').value = idToken;
    document.getElementById('oauth-form').elements['decision'].value = 'allow';
    document.getElementById('oauth-form').submit();
  }} catch (err) {{
    document.getElementById('error').textContent = 'Sign-in failed: ' + err.message;
  }}
}});
</script>
</body></html>"#,
        client = h(&client_label),
        firebase_config = firebase_config,
        p_rt = hidden("response_type", &p.response_type),
        p_cid = hidden("client_id", &p.client_id),
        p_ru = hidden("redirect_uri", &p.redirect_uri),
        p_cc = hidden("code_challenge", &p.code_challenge),
        p_ccm = hidden("code_challenge_method", p.code_challenge_method.as_deref().unwrap_or("S256")),
        p_state = hidden("state", p.state.as_deref().unwrap_or("")),
        p_scope = hidden("scope", p.scope.as_deref().unwrap_or("")),
        p_res = hidden("resource", p.resource.as_deref().unwrap_or("")),
    );
    Html(page).into_response()
}

fn redirect_with(redirect_uri: &str, query: &str) -> Response {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut r = StatusCode::FOUND.into_response();
    r.headers_mut().insert(LOCATION, format!("{redirect_uri}{sep}{query}").parse().unwrap());
    r
}

pub async fn authorize_decision(
    State(state): State<AppState>,
    Form(f): Form<AuthorizeForm>,
) -> Response {
    let client = match validate(&state, &f.client_id, &f.redirect_uri, &f.code_challenge, &f.code_challenge_method).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Html(format!("<h1>Authorization error</h1><p>{}</p>", h(&e)))).into_response(),
    };
    let state_q = f.state.clone().unwrap_or_default();

    if f.decision != "allow" {
        return redirect_with(&f.redirect_uri, &format!("error=access_denied&state={}", urlencode(&state_q)));
    }

    // Verify Firebase ID token
    let firebase_claims = match state.firebase.verify_id_token(&f.id_token).await {
        Ok(c) => c,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Html("<h1>Invalid credentials</h1>".to_string())).into_response();
        }
    };

    let email = firebase_claims.email.trim().to_lowercase();
    let fleet_user = match state.db.get_fleet_user_by_email(&email).await {
        Ok(Some(d)) => d,
        _ => {
            return (StatusCode::UNAUTHORIZED, Html("<h1>Unknown email</h1><p>No fleet user exists with this email address.</p>".to_string())).into_response();
        }
    };

    if fleet_user.status == FleetUserStatus::Inactive {
        return (StatusCode::UNAUTHORIZED, Html("<h1>Account inactive</h1>".to_string())).into_response();
    }

    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    use base64::Engine;
    let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let code_hash = hex::encode(Sha256::digest(code.as_bytes()));
    let resource = if f.resource.as_deref().unwrap_or("").is_empty() {
        super::dispatch_resource(&state)
    } else {
        f.resource.clone().unwrap()
    };
    let record = AuthorizationCode {
        code_hash,
        client_id: client.id,
        redirect_uri: f.redirect_uri.clone(),
        code_challenge: f.code_challenge.clone(),
        subject_type: "fleet_user".into(),
        subject_id: fleet_user.id,
        resource,
        scope: if f.scope.as_deref().unwrap_or("").is_empty() { None } else { f.scope.clone() },
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
        consumed_at: None,
    };
    if let Err(e) = state.db.insert_authorization_code(&record).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("<h1>Server error</h1><p>{}</p>", h(&e.to_string())))).into_response();
    }
    redirect_with(&f.redirect_uri, &format!("code={}&state={}", urlencode(&code), urlencode(&state_q)))
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h_escapes() {
        assert_eq!(h("<a>&\"b\""), "&lt;a&gt;&amp;&quot;b&quot;");
    }

    #[test]
    fn test_redirect_with_separator() {
        let r1 = redirect_with("https://x/cb", "code=1");
        assert_eq!(r1.headers().get(LOCATION).unwrap(), "https://x/cb?code=1");
        let r2 = redirect_with("https://x/cb?foo=1", "code=1");
        assert_eq!(r2.headers().get(LOCATION).unwrap(), "https://x/cb?foo=1&code=1");
    }
}
