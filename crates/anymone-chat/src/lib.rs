//! Anonymous broadcast chat over anymone.
//!
//! The chat is a broadcast room on one service tag: every participant
//! `subscribe`s, sees every message, and sends to it. The `from` handle is an
//! app-level pseudonym; the network never reveals who sent a message. [`serve`]
//! runs a participant backend plus the web frontend.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use anymone_core::{Anymone, ClientPool, ServiceTag, SpawnClient};
use axum::extract::State;
use axum::http::header;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

/// Label of the chat room's service tag.
pub const CHAT_TAG_LABEL: &str = "anymone.chat";

/// Most recent messages kept in the in-memory transcript.
const TRANSCRIPT_CAP: usize = 200;

pub fn chat_tag() -> ServiceTag {
    ServiceTag::from_label(CHAT_TAG_LABEL)
}

/// The chat payload carried over the channel: a self-chosen handle plus text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub from: String,
    pub text: String,
}

/// One transcript entry as served to the frontend.
#[derive(Debug, Clone, Serialize)]
struct ChatEntry {
    seq: u64,
    from: String,
    text: String,
}

#[derive(Clone)]
struct AppState {
    transcript: Arc<Mutex<VecDeque<ChatEntry>>>,
    /// The clients this backend speaks through: its own, plus virtual clients
    /// while messages are queued behind each other.
    pool: ClientPool,
    /// `Access-Control-Allow-Origin` for `/chat/feed`; `*` if unset.
    dashboard_origin: String,
}

pub(crate) const CHAT_HTML: &str = include_str!("../static/chat.html");

/// Join the chat room as a participant and serve the chat app on `port`. Sends
/// go through this backend's own client plus up to `max_clients - 1` virtual
/// clients minted by `spawn` while messages are queued. Blocks forever; holds
/// `anymone` alive.
pub async fn serve(
    anymone: Anymone,
    port: u16,
    dashboard_origin: Option<String>,
    spawn: SpawnClient,
    max_clients: usize,
) -> Result<()> {
    let transcript: Arc<Mutex<VecDeque<ChatEntry>>> = Arc::new(Mutex::new(VecDeque::new()));
    let pool = ClientPool::new(anymone.clone(), chat_tag(), spawn, max_clients);

    // Connect in the background so the web app is reachable before the room is
    // placed.
    {
        let transcript = transcript.clone();
        tokio::spawn(async move {
            let mut pipe = loop {
                match anymone.subscribe(chat_tag()).await {
                    Ok(p) => break p,
                    Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                }
            };
            let mut seq = 0u64;
            while let Some(inc) = pipe.recv().await {
                if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&inc.payload) {
                    let mut t = transcript.lock().unwrap();
                    t.push_back(ChatEntry {
                        seq,
                        from: msg.from,
                        text: msg.text,
                    });
                    seq += 1;
                    while t.len() > TRANSCRIPT_CAP {
                        t.pop_front();
                    }
                }
            }
        });
    }

    let state = AppState {
        transcript,
        pool,
        dashboard_origin: dashboard_origin.unwrap_or_else(|| "*".to_string()),
    };
    let app = Router::new()
        .route("/", get(|| async { Html(CHAT_HTML) }))
        .route("/chat/feed", get(feed))
        .route("/chat/send", post(send))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind chat app on {addr}"))?;
    tracing::info!(%addr, "chat app live");

    axum::serve(listener, app)
        .await
        .context("chat app server")?;
    Ok(())
}

const BOT_LINES: &[&str] = &[
    "anyone else here?",
    "the broadcast works",
    "no one can tell who sent this",
    "cover traffic hides the real ones",
    "gm from the channel",
];

fn bot_payload(handle: &str, n: usize) -> Vec<u8> {
    serde_json::to_vec(&ChatMessage {
        from: handle.to_string(),
        text: BOT_LINES[n % BOT_LINES.len()].to_string(),
    })
    .expect("ChatMessage serializes")
}

/// Join the chat room as a headless *client* (no service registration) and seed
/// traffic. Cover is the runtime's job: a subscribed client contributes the
/// protocol zero-message every idle round at the default cover rate, so just
/// being here puts the bot in the anonymity set. The bot only decides the real
/// send — a random line with probability `send_rate` each round. One bot = one
/// client.
pub async fn run_bot(anymone: Anymone, handle: String, send_rate: f64) -> Result<()> {
    // An unjoined bot contributes no cover either, so it is absent from the
    // anonymity set rather than merely idle — worth logging the wait.
    let mut waited = 0u32;
    let pipe = loop {
        match anymone.subscribe(chat_tag()).await {
            Ok(p) => {
                if waited > 0 {
                    tracing::info!(
                        handle,
                        waited_ms = waited * 500,
                        "chat bot: joined the room"
                    );
                }
                break p;
            }
            Err(e) => {
                if waited % 20 == 0 {
                    tracing::info!(
                        handle,
                        waited_ms = waited * 500,
                        error = %e,
                        "chat bot: waiting to join the chat room"
                    );
                }
                waited += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };
    let send_p = send_rate.clamp(0.0, 1.0);
    loop {
        // Pace to the protocol round from the adopted config (re-read so it
        // tracks reconfig); one real-message decision per round.
        tokio::time::sleep(anymone.round_duration()).await;
        if rand::random::<f64>() < send_p {
            if let Err(e) = pipe
                .send(bot_payload(&handle, rand::random::<usize>()))
                .await
            {
                tracing::warn!(handle, error = %e, "chat bot: send failed");
            }
        }
    }
}

async fn feed(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    let entries: Vec<ChatEntry> = state.transcript.lock().unwrap().iter().cloned().collect();
    // CORS: the dashboard reads this from another port.
    (
        [(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            state.dashboard_origin.clone(),
        )],
        Json(entries),
    )
}

async fn send(
    State(state): State<AppState>,
    Json(msg): Json<ChatMessage>,
) -> Json<serde_json::Value> {
    let from = msg.from.trim();
    let text = msg.text.trim();
    if from.is_empty() || text.is_empty() {
        return Json(serde_json::json!({ "ok": false, "error": "empty from/text" }));
    }
    let payload = serde_json::to_vec(&ChatMessage {
        from: from.to_string(),
        text: text.to_string(),
    })
    .expect("ChatMessage serializes");
    // The message is on a client, not yet on the wire: it goes out in a later
    // round, and the sender sees it when the room's transcript carries it back.
    match state.pool.send(payload) {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "clients": state.pool.clients(),
        })),
        Err(e) => {
            tracing::warn!(error = %e, "chat: message never reached the room");
            Json(serde_json::json!({ "ok": false, "error": e.to_string() }))
        }
    }
}
