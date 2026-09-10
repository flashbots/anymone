use crate::RemoteProtocolHost;
use anymone_core::{AdcnetConfig, Identity, ProtocolConfig, Subnet};
use anymone_remote_session::{HostStatus, HostConfig, PairingInfo, RemoteSessionClient};

fn config() -> String {
    let relay = Identity::generate();
    serde_json::to_string(&HostConfig {
        subnet: Subnet::new(
            0,
            vec![relay.pubkey()],
            ProtocolConfig::Adcnet(AdcnetConfig {
                round_duration_ms: 1000,
                max_payload_bytes: 64,
                estimated_messages: 1,
                client_set_min: 0,
                client_set_max: 4,
                aggregation: None,
            }),
        ),
        relay_exchange_keys: vec![(relay.pubkey(), relay.exchange_keys())],
        starting_round: 0,
    })
    .unwrap()
}

#[tokio::test]
async fn remote_host_stops_connections_and_restarts_with_new_keys() {
    let config = config();
    let host = RemoteProtocolHost::start_developer("127.0.0.1:0".into())
        .await
        .unwrap();
    let pairing: PairingInfo = serde_json::from_str(&host.pairing_json().unwrap()).unwrap();
    let (mut client, initial) = RemoteSessionClient::pair(pairing.clone()).await.unwrap();
    assert!(initial.client.is_none());
    let (configured, _) = client.configure(serde_json::from_str(&config).unwrap()).await.unwrap();
    assert!(configured.developer_mode);
    assert!(!client
        .adcnet_contribute(0, Some(b"mobile".to_vec()))
        .await
        .unwrap()
        .is_empty());
    let status: HostStatus =
        serde_json::from_str(&host.status_json().await.unwrap()).unwrap();
    assert_eq!(status.next_request, 2);
    host.stop().await;
    host.stop().await;
    assert!(host.pairing_json().is_err());
    assert!(host.status_json().await.is_err());
    assert!(client.status().await.is_err());
    let restarted = RemoteProtocolHost::start_developer(pairing.address)
        .await
        .unwrap();
    let next: HostStatus =
        serde_json::from_str(&restarted.status_json().await.unwrap()).unwrap();
    assert_ne!(initial.session_id, next.session_id);
    assert!(next.client.is_none());
    let pairing: PairingInfo = serde_json::from_str(&restarted.pairing_json().unwrap()).unwrap();
    let (mut next_client, _) = RemoteSessionClient::pair(pairing).await.unwrap();
    let (next_protocol, _) = next_client.configure(serde_json::from_str(&config).unwrap()).await.unwrap();
    assert_ne!(configured.participant, next_protocol.participant);
    assert_eq!(next.next_request, 0);
    restarted.stop().await;
}

#[tokio::test]
async fn wildcard_address_is_rejected() {
    assert!(RemoteProtocolHost::start_developer("0.0.0.0:0".into()).await.is_err());
}
