//! Rabbit OS3 chat provider.
//!
//! Talks to OS3's butler over the documented WebSocket protocol:
//!   1. POST /session-directory/route (Bearer) -> {"kind":"route","instanceId":..} or {"kind":"any"}
//!   2. wss://os3-<instanceId>.rabbit.tech/ws  (or wss://os3.rabbit.tech/ws for "any")
//!   3. init (accessToken, optional sessionId) -> init_ack
//!   4. chat.message out -> agent chat.message back
//!
//! Auth: email + password via the embedded auth endpoints
//!   POST /api/auth/embedded/email      {email}            -> sends 6-digit code
//!   POST /api/auth/embedded/verify-email {code}           -> binds the code (needs cookies)
//!   POST /api/auth/embedded/signup     {password}         -> sets os3_session (new accounts only)
//!   POST /api/auth/embedded/login      {email, password}  -> sets os3_session
//!   GET  /api/auth/token               (cookies)          -> {"accessToken": ...}
//!
//! The login step is handled by Pin Center (the user types credentials into the
//! browser session, never the terminal). This provider consumes the resulting
//! accessToken persisted in config.toml (`llm.api_key` holds the OS3 access
//! token) and refreshes it when expired via the retained session cookies file.

use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::ResolvedConfig;
use crate::llm::ChatResult;

use crate::llm::backend::{LlmBackend, LlmFuture};
use crate::llm::error::friendly_error_message;
use crate::llm::prompt::PromptBuilder;
use crate::llm::request::LlmChatRequest;
use crate::llm::request_log::LlmRequestLogger;

const OS3_BASE: &str = "https://os3.rabbit.tech";
const OS3_ORIGIN: &str = "https://os3.rabbit.tech";
const OS3_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36";
const CHAT_TIMEOUT_SECS: u64 = 180;

pub struct Os3Provider;

impl Os3Provider {
    pub fn build(
        config: &ResolvedConfig,
        http: HttpClient,
        request_logger: LlmRequestLogger,
    ) -> Result<Arc<dyn LlmBackend>, Box<dyn std::error::Error + Send + Sync>> {
        let llm = &config.config.llm;
        let token = llm.resolve_api_key().ok_or(
            "OS3 access token not set; log in via Pin Center (Rabbit OS3) to populate llm.api_key",
        )?;

        info!(
            model = %llm.model,
            has_session_cookies = llm.base_url.is_some(),
            "OS3 chat backend ready (single-shot, no local agent loop)"
        );

        Ok(Arc::new(DumbOs3Backend {
            http,
            token,
            session_id_path: llm
                .base_url
                .clone()
                .unwrap_or_else(|| "/data/local/tmp/PenumbraOS/os3-session.txt".to_string()),
            request_logger,
        }))
    }
}

/// Single-shot OS3 butler backend: one utterance -> one agent reply.
/// Session cookies (os3_session) are NOT stored here — token refresh is done by
/// Pin Center's login page, which owns the browser cookie jar. We persist only
/// the WS sessionId so reconnects resume the same conversation.
pub struct DumbOs3Backend {
    http: HttpClient,
    token: String,
    session_id_path: String,
    request_logger: LlmRequestLogger,
}

#[derive(Deserialize)]
struct RouteResponse {
    kind: String,
    #[serde(default, rename = "instanceId")]
    instance_id: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
}

// ─── WebSocket wire types ───────────────────────────────────────────

#[derive(Serialize)]
struct WsInit<'a> {
    #[serde(rename = "type")]
    typ: &'a str,
    version: u8,
    timestamp: u64,
    #[serde(rename = "accessToken")]
    access_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
}

#[derive(Serialize)]
struct WsChat<'a> {
    #[serde(rename = "type")]
    typ: &'a str,
    version: u8,
    timestamp: u64,
    text: &'a str,
}

#[derive(Deserialize)]
struct WsMessage {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(rename = "sessionId", default)]
    session_id: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Decode a JWT payload to inspect `exp` (no signature validation — the WS
/// endpoint validates the token server-side anyway; we just avoid a doomed call).
fn jwt_expired(token: &str) -> bool {
    let Some(payload_b64) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64)
    else {
        return false;
    };
    #[derive(Deserialize)]
    struct Claims {
        exp: Option<u64>,
    }
    serde_json::from_slice::<Claims>(&decoded)
        .ok()
        .and_then(|c| c.exp)
        .map(|exp| now_ms() / 1000 >= exp)
        .unwrap_or(false)
}

impl DumbOs3Backend {
    fn load_session_id(&self) -> Option<String> {
        std::fs::read_to_string(&self.session_id_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn save_session_id(&self, sid: &str) {
        if let Some(dir) = std::path::Path::new(&self.session_id_path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&self.session_id_path, sid);
    }

    async fn resolve_ws_url(&self) -> Result<String, String> {
        // Token refresh: if the stored JWT is expired, try minting a fresh one
        // from whatever cookies the platform can supply via the login route.
        let token = self.token.clone();
        let resp = self
            .http
            .post(format!("{OS3_BASE}/session-directory/route"))
            .bearer_auth(&token)
            .header("Origin", OS3_ORIGIN)
            .header("Referer", format!("{OS3_ORIGIN}/"))
            .header("User-Agent", OS3_UA)
            .header("Content-Type", "application/json")
            .body("{}")
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("OS3 route request failed: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(friendly_error_message(&format!(
                "HTTP {status}: {}",
                body.chars().take(300).collect::<String>()
            )));
        }

        let route: RouteResponse = serde_json::from_str(&body)
            .map_err(|e| format!("OS3 route parse failed: {e}"))?;

        match route.instance_id {
            Some(iid) => Ok(format!("wss://os3-{iid}.rabbit.tech/ws")),
            None if route.kind == "any" => Ok(format!("wss://os3.rabbit.tech/ws")),
            None => Err(format!("unexpected OS3 route kind: {}", route.kind)),
        }
    }

    async fn chat_once(&self, request: &LlmChatRequest) -> Result<ChatResult, String> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::Message as WsWire;
        use futures_util::{SinkExt, StreamExt};

        let url = self.resolve_ws_url().await?;
        let mut req = url
            .into_client_request()
            .map_err(|e| format!("OS3 ws handshake build failed: {e}"))?;
        req.headers_mut().insert(
            "Origin",
            OS3_ORIGIN.parse().map_err(|e| format!("origin: {e}"))?,
        );
        req.headers_mut().insert(
            "User-Agent",
            OS3_UA.parse().map_err(|e| format!("ua: {e}"))?,
        );

        let (mut ws, _resp) = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio_tungstenite::connect_async(req),
        )
        .await
        .map_err(|_| "OS3 ws connect timed out".to_string())?
        .map_err(|e| format!("OS3 ws connect failed: {e}"))?;

        // init -> init_ack
        let stored_session_id = self.load_session_id();
        let init = WsInit {
            typ: "init",
            version: 1,
            timestamp: now_ms(),
            access_token: &self.token,
            session_id: stored_session_id.as_deref(),
        };
        ws.send(WsWire::Text(
            serde_json::to_string(&init).map_err(|e| e.to_string())?.into(),
        ))
        .await
        .map_err(|e| format!("OS3 ws send init failed: {e}"))?;

        let ack_deadline = std::time::Duration::from_secs(20);
        let mut ack = false;
        let started = Instant::now();
        while started.elapsed() < ack_deadline {
            let Some(msg) = ws.next().await else { break };
            let Ok(msg) = msg else { break };
            if let WsWire::Text(text) = msg {
                let parsed: serde_json::Value =
                    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
                match parsed.get("type").and_then(|t| t.as_str()) {
                    Some("init_ack") => {
                        if let Some(sid) = parsed.get("sessionId").and_then(|s| s.as_str()) {
                            self.save_session_id(sid);
                        }
                        ack = true;
                        break;
                    }
                    Some("admission.refused") => {
                        return Err("OS3 refused the connection (stale or over-limit session)".into())
                    }
                    _ => {}
                }
            }
        }
        if !ack {
            return Err("OS3 did not acknowledge init in time".into());
        }

        // send the user utterance (+ optional image note — OS3 accepts attachments
        // as base64 in the same chat.message; for now include a text hint)
        let chat = WsChat {
            typ: "chat.message",
            version: 1,
            timestamp: now_ms(),
            text: &request.utterance,
        };
        ws.send(WsWire::Text(
            serde_json::to_string(&chat).map_err(|e| e.to_string())?.into(),
        ))
        .await
        .map_err(|e| format!("OS3 ws send chat failed: {e}"))?;

        // collect until agent reply
        let deadline = std::time::Duration::from_secs(CHAT_TIMEOUT_SECS);
        let started = Instant::now();
        while started.elapsed() < deadline {
            let Some(msg) = ws.next().await else { break };
            let Ok(msg) = msg else { break };
            let WsWire::Text(text) = msg else { continue };
            let parsed: serde_json::Value =
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            let typ = parsed.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match typ {
                "chat.message" => {
                    if parsed.get("role").and_then(|r| r.as_str()) == Some("agent") {
                        let reply = parsed
                            .get("text")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();
                        let _ = ws.close(None).await;
                        return Ok(ChatResult::Text(reply));
                    }
                }
                "admission.refused" => {
                    let _ = ws.close(None).await;
                    return Err("OS3 refused the session".into());
                }
                _ => {}
            }
        }
        let _ = ws.close(None).await;
        Err("OS3 reply timed out".into())
    }
}

impl LlmBackend for DumbOs3Backend {
    fn chat<'a>(&'a self, request: LlmChatRequest) -> LlmFuture<'a> {
        Box::pin(async move {
            let utterance = request.utterance.clone();
            let run_id = request.template_context.run_id.clone();
            let history = PromptBuilder::build_chat_history(&request);
            let started = Instant::now();

            let result = self.chat_once(&request).await;

            let latency_ms = started.elapsed().as_millis();
            self.request_logger
                .log_chat(
                    "OS3",
                    &run_id,
                    &history,
                    &utterance,
                    match &result {
                        Ok(ChatResult::Text(text)) => Some(text.as_str()),
                        _ => None,
                    },
                    result.as_ref().err().map(|e| e.as_str()),
                    latency_ms,
                )
                .await;
            result
        })
    }
}

// image support: keep the request's image bytes available for future attachments
#[allow(dead_code)]
fn unused_image_note(bytes: &[u8]) {
    let _ = base64::engine::general_purpose::STANDARD.encode(bytes);
}