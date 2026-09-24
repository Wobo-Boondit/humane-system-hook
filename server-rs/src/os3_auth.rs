//! OS3 embedded-auth login endpoints.
//!
//! The user types email + password in Pin Center. This module performs the
//! login against os3.rabbit.tech server-side and stores only the resulting
//! access token in config.toml. The password exists only in the request body
//! between Center and this server over the pin's LAN; it is never persisted.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::api::ApiState;

const OS3_BASE: &str = "https://os3.rabbit.tech";
const OS3_ORIGIN: &str = "https://os3.rabbit.tech";
const OS3_UA: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36";

pub type CookieJar = Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>;

#[derive(Deserialize)]
struct Os3StartRequest {
    email: String,
}

#[derive(Serialize)]
struct Os3StartResponse {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct Os3VerifyRequest {
    code: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
struct Os3VerifyResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

fn absorb_cookies(jar: &CookieJar, resp: &reqwest::Response) {
    for value in resp.headers().get_all("set-cookie") {
        if let Ok(s) = value.to_str() {
            let kv = s.split(';').next().unwrap_or("");
            if let Some((k, v)) = kv.split_once('=') {
                if let Ok(mut map) = jar.try_lock() {
                    map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
    }
}

fn cookie_header(jar: &CookieJar) -> String {
    jar.try_lock()
        .map(|map| {
            map.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default()
}

async fn os3_post_json(
    http: &reqwest::Client,
    path: &str,
    body: serde_json::Value,
    jar: &CookieJar,
) -> Result<(u16, serde_json::Value), String> {
    let mut req = http
        .post(format!("{OS3_BASE}{path}"))
        .header("Origin", OS3_ORIGIN)
        .header("Referer", format!("{OS3_ORIGIN}/"))
        .header("User-Agent", OS3_UA)
        .json(&body);
    let cookie = cookie_header(jar);
    if !cookie.is_empty() {
        req = req.header("Cookie", cookie);
    }
    let resp = req.send().await.map_err(|e| format!("request failed: {e}"))?;
    absorb_cookies(jar, &resp);
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    Ok((status, json))
}

async fn os3_get_json(
    http: &reqwest::Client,
    path: &str,
    jar: &CookieJar,
) -> Result<(u16, serde_json::Value), String> {
    let cookie = cookie_header(jar);
    let mut req = http
        .get(format!("{OS3_BASE}{path}"))
        .header("Origin", OS3_ORIGIN)
        .header("Referer", format!("{OS3_ORIGIN}/"))
        .header("User-Agent", OS3_UA);
    if !cookie.is_empty() {
        req = req.header("Cookie", cookie);
    }
    let resp = req.send().await.map_err(|e| format!("request failed: {e}"))?;
    absorb_cookies(jar, &resp);
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    Ok((status, json))
}

fn error_response(code: StatusCode, message: impl Into<String>) -> Response {
    (
        code,
        Json(Os3VerifyResponse {
            ok: false,
            error: Some(message.into()),
            next: None,
        }),
    )
        .into_response()
}

/// POST /api/auth/os3/start {email}
/// Begins the embedded login (sends a code) or, if a token is already
/// obtainable, completes immediately.
async fn auth_start(State(state): State<ApiState>, Json(body): Json<Os3StartRequest>) -> Response {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return error_response(StatusCode::BAD_REQUEST, "enter a valid email");
    }

    let jar: CookieJar = Arc::new(tokio::sync::Mutex::new(Default::default()));

    // If an existing browser session already works (rare from this server),
    // mint the token directly.
    if let Ok((200, tok)) = os3_get_json(&state.http_client, "/api/auth/token", &jar).await {
        if let Some(token) = tok.get("accessToken").and_then(|t| t.as_str()) {
            persist_os3_token(&state, token).await;
            *state.os3_auth_jar.0.lock().await = None;
            return (
                StatusCode::OK,
                Json(Os3StartResponse { state: "ok", error: None }),
            )
                .into_response();
        }
    }

    match os3_post_json(
        &state.http_client,
        "/api/auth/embedded/email",
        serde_json::json!({ "email": email }),
        &jar,
    )
    .await
    {
        Ok((200, resp)) => {
            let next = resp.get("next").and_then(|v| v.as_str()).unwrap_or("");
            if next == "verify-email" {
                *state.os3_auth_jar.0.lock().await = Some(email);
                {
                    let mut dst = state.os3_auth_jar.1.lock().unwrap();
                    dst.clear();
                    if let Ok(src) = jar.try_lock() {
                        for (k, v) in src.iter() {
                            dst.insert(k.clone(), v.clone());
                        }
                    }
                }
                (
                    StatusCode::OK,
                    Json(Os3StartResponse { state: "need_code", error: None }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(Os3StartResponse {
                        state: "error",
                        error: Some(format!("unexpected state: {next}")),
                    }),
                )
                    .into_response()
            }
        }
        Ok((status, resp)) => (
            StatusCode::BAD_GATEWAY,
            Json(Os3StartResponse {
                state: "error",
                error: Some(format!(
                    "OS3 said: {}",
                    resp.get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or(&format!("HTTP {status}"))
                )),
            }),
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, "OS3 auth start failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(Os3StartResponse { state: "error", error: Some(e) }),
            )
                .into_response()
        }
    }
}

/// POST /api/auth/os3/verify {code} — submit the emailed code.
/// Response `next` tells Center what to ask for next: "login" or "signup".
async fn auth_verify_code(
    State(state): State<ApiState>,
    Json(body): Json<Os3VerifyRequest>,
) -> Response {
    let Some(code) = body.code.as_deref() else {
        return error_response(StatusCode::BAD_REQUEST, "code required");
    };
    let Some(_email) = state.os3_auth_jar.0.lock().await.clone() else {
        return error_response(StatusCode::BAD_REQUEST, "start the login first");
    };
    let jar: CookieJar = Arc::new(tokio::sync::Mutex::new(
        state.os3_auth_jar.1.lock().unwrap().clone(),
    ));
    match os3_post_json(
        &state.http_client,
        "/api/auth/embedded/verify-email",
        serde_json::json!({ "code": code }),
        &jar,
    )
    .await
    {
        Ok((200, resp)) => {
            let next = resp.get("next").and_then(|v| v.as_str()).unwrap_or("");
            {
                let mut dst = state.os3_auth_jar.1.lock().unwrap();
                dst.clear();
                if let Ok(src) = jar.try_lock() {
                    for (k, v) in src.iter() {
                        dst.insert(k.clone(), v.clone());
                    }
                }
            }
            (
                StatusCode::OK,
                Json(Os3VerifyResponse {
                    ok: true,
                    error: None,
                    next: Some(next.to_string()),
                }),
            )
                .into_response()
        }
        Ok((_, resp)) => (
            StatusCode::OK,
            Json(Os3VerifyResponse {
                ok: false,
                error: resp.get("error").and_then(|e| e.as_str()).map(String::from),
                next: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(Os3VerifyResponse { ok: false, error: Some(e), next: None }),
        )
            .into_response(),
    }
}

/// POST /api/auth/os3/password {password, signup} — submit password for login
/// or signup, then mint and persist the access token.
async fn auth_submit_password(
    State(state): State<ApiState>,
    Json(body): Json<Os3VerifyRequest>,
) -> Response {
    let Some(password) = body.password.as_deref() else {
        return error_response(StatusCode::BAD_REQUEST, "password required");
    };
    let Some(email) = state.os3_auth_jar.0.lock().await.clone() else {
        return error_response(StatusCode::BAD_REQUEST, "start the login first");
    };
    let jar: CookieJar = Arc::new(tokio::sync::Mutex::new(
        state.os3_auth_jar.1.lock().unwrap().clone(),
    ));
    let is_signup = matches!(body.code.as_deref(), Some("signup"));
    let (endpoint, payload) = if is_signup {
        (
            "/api/auth/embedded/signup",
            serde_json::json!({ "password": password }),
        )
    } else {
        (
            "/api/auth/embedded/login",
            serde_json::json!({ "email": email, "password": password }),
        )
    };
    match os3_post_json(&state.http_client, endpoint, payload, &jar).await {
        Ok((200, _)) => match os3_get_json(&state.http_client, "/api/auth/token", &jar).await {
            Ok((200, tok)) => {
                if let Some(token) = tok.get("accessToken").and_then(|t| t.as_str()) {
                    persist_os3_token(&state, token).await;
                    *state.os3_auth_jar.0.lock().await = None;
                    info!("OS3 access token stored for {email}");
                    return (
                        StatusCode::OK,
                        Json(Os3VerifyResponse {
                            ok: true,
                            error: None,
                            next: Some("complete".into()),
                        }),
                    )
                        .into_response();
                }
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "login succeeded but token mint failed",
                )
            }
            Ok((status, resp)) => error_response(
                StatusCode::BAD_GATEWAY,
                format!(
                    "token mint failed: {}",
                    resp.get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or(&format!("HTTP {status}"))
                ),
            ),
            Err(e) => error_response(StatusCode::BAD_GATEWAY, e),
        },
        Ok((_, resp)) => (
            StatusCode::OK,
            Json(Os3VerifyResponse {
                ok: false,
                error: resp
                    .get("error")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string()),
                next: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(Os3VerifyResponse { ok: false, error: Some(e), next: None }),
        )
            .into_response(),
    }
}

async fn persist_os3_token(state: &ApiState, token: &str) {
    {
        let mut config = state.shared_config.write().await;
        config.llm.provider = crate::config::LlmProvider::Os3;
        config.llm.api_key = Some(token.to_string());
    }
    let config = state.shared_config.read().await.clone();
    if let Err(e) = crate::api::persist_config_pub(&state.config_path, &config) {
        error!(error = %e, "failed to persist OS3 token to config");
    }
}

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/os3/start", post(auth_start))
        .route("/os3/verify-code", post(auth_verify_code))
        .route("/os3/password", post(auth_submit_password))
}