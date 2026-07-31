//! The REST gateway against a real anymone mesh over the in-memory transport:
//! 3 relays, the gateway participant, and one other client on the same channel.
//! Proves both directions of the API — a `POST` body reaches the channel as one
//! message, and what the channel carried comes back out of `GET /messages` in
//! the round it decoded in.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use anymone_core::{
    Anymone, AnymoneRoundConfiguration, ClientPool, Identity, InMemoryNetwork, PanetiereConfig,
    ProtocolConfig, ServiceEntry, ServiceTag, SpawnClient,
};
use anymone_gateway::{router, AppState, Store};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

fn tag() -> ServiceTag {
    ServiceTag::from_label("anymone.gateway.test")
}

async fn call(state: AppState, method: &str, uri: &str, body: &[u8]) -> (StatusCode, Value) {
    let response = router(state)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// Poll `GET /messages` until `count` messages are in, or fail on timeout.
async fn wait_for_messages(state: &AppState, count: usize) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let (_, body) = call(state.clone(), "GET", "/messages", b"").await;
        if body["count"].as_u64().unwrap() as usize >= count {
            return body;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {count} message(s); saw {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Decode rounds of the retrieved messages whose text starts with `prefix`.
fn decode_rounds(body: &Value, prefix: &str) -> Vec<u64> {
    body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["text"].as_str().is_some_and(|t| t.starts_with(prefix)))
        .map(|m| m["round"].as_u64().unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_submit_and_read_back_by_round() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let gateway_id = Identity::generate();
    let client_id = Identity::generate();

    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let cfg = AnymoneRoundConfiguration::singleton_subnet(
        0,
        // Every node here runs real Panetiere crypto in this one debug-build
        // process, and each virtual client the pool mints adds another client
        // round to it. A worker that lags past a round boundary skips the round,
        // which drops the messages staged for it (the pipe does not retry), so
        // the round is long and the carrier is sized just wide enough for the
        // two-in-one-round assertion below.
        ProtocolConfig::Panetiere(PanetiereConfig {
            round_duration_ms: 2000,
            message_size: 128,
            estimated_messages: 3,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [7u8; 32],
            encoding: anymone_core::config::Encoding::default(),
        }),
        relay_pks,
        relays
            .iter()
            .map(|i| (i.pubkey(), i.exchange_keys()))
            .collect(),
        vec![ServiceEntry {
            tag: tag(),
            pubkey: service.pubkey(),
        }],
    )
    .sign_with(&[&committee]);

    let net = InMemoryNetwork::new();
    let mut anymones: Vec<Anymone> = Vec::new();
    for id in &relays {
        anymones.push(
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
                .await,
        );
    }
    let gateway_anymone = Anymone::start_with_config(
        gateway_id.clone(),
        Arc::new(net.handle(gateway_id.pubkey())),
        cfg.clone(),
    )
    .await;
    let client_anymone = Anymone::start_with_config(
        client_id.clone(),
        Arc::new(net.handle(client_id.pubkey())),
        cfg.clone(),
    )
    .await;

    let pipe = gateway_anymone.subscribe(tag()).await.unwrap();
    let mut client_pipe = client_anymone.subscribe(tag()).await.unwrap();

    let store = Arc::new(Store::new(100));
    let round_ms = Arc::new(AtomicU64::new(0));
    // Virtual clients join the same in-memory mesh off the same static config —
    // there is no committee here to publish one to them.
    let spawn: SpawnClient = {
        let net = net.clone();
        let cfg = cfg.clone();
        Arc::new(move || {
            let net = net.clone();
            let cfg = cfg.clone();
            Box::pin(async move {
                let id = Identity::generate();
                let transport = Arc::new(net.handle(id.pubkey()));
                Some(Anymone::start_with_config(id, transport, cfg).await)
            })
        })
    };
    // Two: every node here runs a client round of Panetiere crypto in this one
    // process, and a saturated process makes relay workers skip whole rounds.
    let pool = ClientPool::new(gateway_anymone.clone(), tag(), spawn, 2);
    let state = AppState {
        store: store.clone(),
        pool: pool.clone(),
        round_ms: round_ms.clone(),
        allow_origin: "*".to_string(),
    };
    tokio::spawn(anymone_gateway::gateway_loop(
        gateway_anymone.clone(),
        pipe,
        store.clone(),
        round_ms,
    ));

    // Let both clients appear in a leader-announced canonical set before
    // submitting: a message staged in the round a client joins in can miss that
    // round's set and is then never decoded (the pipe stages, it does not
    // retry), which would make this test flake rather than expose a gateway bug.
    tokio::time::sleep(Duration::from_millis(4000)).await;

    // Ingress: the POST body goes onto the channel as one message, byte for
    // byte, and the other client on the channel receives it.
    let (status, body) = call(state.clone(), "POST", "/messages", b"posted over rest").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["bytes"], serde_json::json!(16));
    let got = tokio::time::timeout(Duration::from_secs(30), client_pipe.recv())
        .await
        .expect("the other client never saw the posted message")
        .expect("pipe closed");
    assert_eq!(got.payload, b"posted over rest");

    // Egress: what the channel carried is retrievable by round. The gateway
    // sees its own submission (a session includes its own output) plus the
    // client's.
    client_pipe.send(b"from the client".to_vec()).await.unwrap();
    let body = wait_for_messages(&state, 2).await;
    let msgs = body["messages"].as_array().unwrap();
    let texts: Vec<&str> = msgs.iter().map(|m| m["text"].as_str().unwrap()).collect();
    assert!(texts.contains(&"posted over rest"), "saw {texts:?}");
    assert!(texts.contains(&"from the client"), "saw {texts:?}");

    // Rounds are the decode rounds, and the frontier covers them.
    let last_round = body["last_round"].as_u64().unwrap();
    let rounds: Vec<u64> = msgs.iter().map(|m| m["round"].as_u64().unwrap()).collect();
    assert!(rounds.iter().all(|r| *r <= last_round), "{rounds:?}");
    assert!(rounds.windows(2).all(|w| w[0] <= w[1]), "oldest first");

    // A range that excludes the first message's round returns only later ones,
    // and the same range as an explicit pair of bounds is inclusive.
    let first = rounds[0];
    let (_, body) = call(
        state.clone(),
        "GET",
        &format!("/messages?from={}", first + 1),
        b"",
    )
    .await;
    assert!(body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["round"].as_u64().unwrap() > first));
    let (_, body) = call(
        state.clone(),
        "GET",
        &format!("/messages?from={first}&to={first}"),
        b"",
    )
    .await;
    assert!(body["count"].as_u64().unwrap() >= 1);

    // /round reports the frontier and the adopted config's cadence.
    let (_, body) = call(state.clone(), "GET", "/round", b"").await;
    assert!(body["last_round"].as_u64().unwrap() >= last_round);
    assert_eq!(body["earliest_round"], serde_json::json!(first));
    assert_eq!(body["round_ms"], serde_json::json!(2000));
    assert_eq!(body["capacity"], serde_json::json!(100));

    // A burst: three submissions at once, where one client can carry one message
    // per round. All are accepted, the pool answers with virtual clients, and
    // every accepted message leaves its client's queue.
    let burst: Vec<_> = (0..3)
        .map(|i| {
            let state = state.clone();
            tokio::spawn(async move {
                call(state, "POST", "/messages", format!("burst {i}").as_bytes()).await
            })
        })
        .collect();
    for handle in burst {
        let (status, _) = handle.await.unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while pool.clients() < 2 || pool.queued() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "burst never drained: {} client(s), {} queued",
            pool.clients(),
            pool.queued()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let body = wait_for_messages(&state, 5).await;
    assert_eq!(
        decode_rounds(&body, "burst ").len(),
        3,
        "burst lost a message: {body}"
    );

    // Now that the pool is warm, a pair submitted together rides two clients and
    // lands in one round — a single client could only manage one per round.
    for i in 0..2 {
        let (status, _) = call(
            state.clone(),
            "POST",
            "/messages",
            format!("pair {i}").as_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    let body = wait_for_messages(&state, 7).await;
    let pair = decode_rounds(&body, "pair ");
    assert_eq!(pair.len(), 2, "pair lost a message: {body}");
    assert_eq!(pair[0], pair[1], "pair decoded a round apart: {pair:?}");

    // Oversize: rejected with the pipe's own verdict rather than truncated.
    let too_big = vec![b'x'; 2048];
    let (status, body) = call(state.clone(), "POST", "/messages", &too_big).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body["error"].as_str().unwrap().contains("too large"));

    drop(anymones);
}
