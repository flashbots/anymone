use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::ScheduledPanetiereConfig;
use anymone_core::{
    AdcnetConfig, Anymone, AnymoneRoundConfiguration, Identity, InMemoryNetwork, PanetiereConfig,
    ProtocolConfig, ScheduledAdcnetConfig, ServiceEntry, ServiceTag,
};
use anymone_remote_session::{HostConfig, RemoteClientBackend, RemoteSessionHost};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn service_echo_through_all_remote_protocols() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let protocols = [
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 700,
            max_payload_bytes: 1024,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            aggregation: None,
        }),
        ProtocolConfig::ScheduledAdcnet(ScheduledAdcnetConfig {
            round_duration_ms: 700,
            message_length: 1024,
            auction_slots: 16,
            min_message_size: 1,
            client_set_min: 0,
            client_set_max: 8,
        }),
        ProtocolConfig::Panetiere(PanetiereConfig {
            round_duration_ms: 1000,
            message_size: 1024,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [7; 32],
            ..Default::default()
        }),
        ProtocolConfig::ScheduledPanetiere(ScheduledPanetiereConfig {
            round_duration_ms: 1000,
            message_size: 1024,
            vector_bytes: 2048,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [7; 32],
            ..Default::default()
        }),
    ];
    for protocol in protocols {
        let committee = Identity::generate();
        let mut relays: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
        relays.sort_by_key(Identity::pubkey);
        let service = Identity::generate();
        let desktop = Identity::generate();
        let tag = ServiceTag::from_label("remote.echo");
        let config = AnymoneRoundConfiguration::singleton_subnet(
            0,
            protocol.clone(),
            relays.iter().map(Identity::pubkey).collect(),
            relays
                .iter()
                .map(|id| (id.pubkey(), id.exchange_keys()))
                .collect(),
            vec![ServiceEntry {
                tag,
                pubkey: service.pubkey(),
            }],
        )
        .sign_with(&[&committee]);
        let host_config = HostConfig {
            subnet: config.body.subnets[0].clone(),
            relay_exchange_keys: config.body.relay_exchange_keys.clone(),
            starting_round: 0,
        };
        let host = RemoteSessionHost::new(None)
            .unwrap()
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let remote = RemoteClientBackend::pair(host.pairing.clone())
            .await
            .unwrap();
        assert!(remote.context().is_none());
        let mut wrong = host_config.subnet.clone();
        wrong.id += 1;
        assert!(!remote.accepts(&wrong, &host_config.relay_exchange_keys));
        let net = InMemoryNetwork::new();
        let mut nodes = Vec::new();
        for id in &relays {
            nodes.push(
                Anymone::start_with_config(
                    id.clone(),
                    Arc::new(net.handle(id.pubkey())),
                    config.clone(),
                )
                .await,
            );
        }
        let service_node = Anymone::start_with_config(
            service.clone(),
            Arc::new(net.handle(service.pubkey())),
            config.clone(),
        )
        .await;
        let desktop_node = Anymone::start_with_config(
            desktop.clone(),
            Arc::new(net.handle(desktop.pubkey())),
            config.clone(),
        )
        .await;
        remote.install(&desktop_node).unwrap();
        let mut service_pipe = service_node.bind(tag).await.unwrap();
        let echo = tokio::spawn(async move {
            while let Some(message) = service_pipe.recv().await {
                service_pipe
                    .send_to(message.return_tag, message.payload)
                    .await
                    .unwrap();
            }
        });
        let mut pipe = desktop_node.open(tag).await.unwrap();
        let payload = b"service request from phone".to_vec();
        pipe.send(payload.clone()).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(40), pipe.recv())
            .await
            .unwrap_or_else(|_| panic!("remote {protocol:?} timed out: {:?}", remote.last_error()))
            .unwrap();
        assert_eq!(reply.payload, payload, "{protocol:?}");
        assert_ne!(remote.context().unwrap().participant, desktop.pubkey());
        assert!(host.session().lock().await.status().next_request > 0);
        remote.close().await.unwrap();
        host.shutdown().await;
        echo.abort();
    }
}


#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn signed_config_change_reaches_phone_without_repairing() {
    use anymone_core::{GovernanceBootstrap, transport::{Topic, Transport}};
    let committee = Identity::generate();
    let relays: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let desktop = Identity::generate();
    let tag = ServiceTag::from_label("remote.reconfigure");
    let mut config = AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 1000, max_payload_bytes: 1024, estimated_messages: 4,
            client_set_min: 0, client_set_max: 8, aggregation: None,
        }),
        relays.iter().map(Identity::pubkey).collect(),
        relays.iter().map(|id| (id.pubkey(), id.exchange_keys())).collect(),
        vec![ServiceEntry { tag, pubkey: service.pubkey() }],
    ).sign_with(&[&committee]);
    let net = InMemoryNetwork::new();
    let gov = GovernanceBootstrap { committee: vec![committee.pubkey()], threshold: 1 };
    let mut preps = Vec::new();
    for id in relays.iter().chain([&service, &desktop]) {
        preps.push(Anymone::prepare(id.clone(), Arc::new(net.handle(id.pubkey())), gov.clone()).await);
    }
    net.handle(committee.pubkey()).publish(Topic::Config, bincode::serialize(&config).unwrap()).await;
    let mut nodes = Vec::new();
    for prep in preps { nodes.push(prep.start().await.unwrap()); }
    let desktop_node = nodes.pop().unwrap();
    let service_node = nodes.pop().unwrap();
    let host = RemoteSessionHost::new(None).unwrap()
        .listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let remote = RemoteClientBackend::pair(host.pairing.clone()).await.unwrap();
    remote.install(&desktop_node).unwrap();
    let mut service_pipe = service_node.bind(tag).await.unwrap();
    let echo = tokio::spawn(async move {
        while let Some(message) = service_pipe.recv().await {
            service_pipe.send_to(message.return_tag, message.payload).await.unwrap();
        }
    });
    let mut pipe = desktop_node.open(tag).await.unwrap();
    pipe.send(b"before update".to_vec()).await.unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(30), pipe.recv()).await.unwrap().unwrap().payload,
        b"before update");
    let before = host.session().lock().await.status();
    config.body.round += 1;
    config.body.subnets[0].protocol = ProtocolConfig::Panetiere(PanetiereConfig {
        round_duration_ms: 1000, message_size: 1024, estimated_messages: 4,
        client_set_min: 0, client_set_max: 8, threshold: 2, setup_seed: [9; 32],
        ..Default::default()
    });
    config.signatures.clear();
    config = config.sign_with(&[&committee]);
    net.handle(committee.pubkey()).publish(Topic::Config, bincode::serialize(&config).unwrap()).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if host.session().lock().await.status().client.as_ref()
                .is_some_and(|client| client.protocol == anymone_core::RemoteProtocol::Panetiere) { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.expect("phone did not receive new protocol configuration");
    pipe.send(b"after update".to_vec()).await.unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(30), pipe.recv()).await.unwrap().unwrap().payload,
        b"after update");
    let after = host.session().lock().await.status();
    assert_eq!(before.session_id, after.session_id);
    assert_eq!(before.client.unwrap().participant, after.client.unwrap().participant);
    remote.close().await.unwrap();
    host.shutdown().await;
    echo.abort();
}
