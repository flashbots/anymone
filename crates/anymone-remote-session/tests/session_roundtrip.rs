use anymone_core::{AdcnetConfig, Identity, ProtocolConfig, RemoteAttestedSession, Subnet};
use anymone_remote_session::{RemoteSessionClient, RemoteSessionHost, RemoteTransportError};

#[tokio::test]
async fn tls_native_contribution_replay_resume_and_close() {
    let relay = Identity::generate();
    let subnet = Subnet::new(
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
    );
    let session =
        RemoteAttestedSession::developer(&subnet, &[(relay.pubkey(), relay.exchange_keys())], 0)
            .unwrap();
    let expected = session.status();
    let handle = RemoteSessionHost::new(session)
        .unwrap()
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let mut wrong = handle.pairing.clone();
    wrong.certificate_sha256[0] ^= 1;
    assert!(matches!(
        RemoteSessionClient::pair(wrong).await,
        Err(RemoteTransportError::PairingFailed)
    ));
    let mut wrong = handle.pairing.clone();
    wrong.pairing_token[0] ^= 1;
    assert!(RemoteSessionClient::pair(wrong).await.is_err());

    let (mut client, status) = RemoteSessionClient::pair(handle.pairing.clone())
        .await
        .unwrap();
    assert_eq!(status, expected);
    assert!(RemoteSessionClient::pair(handle.pairing.clone())
        .await
        .is_err());
    let first = client
        .adcnet_contribute(0, Some(b"hello".to_vec()))
        .await
        .unwrap();
    assert!(!first.is_empty());
    assert_eq!(
        client.reconnect().await.unwrap().participant,
        expected.participant
    );
    assert_eq!(
        client
            .adcnet_contribute(0, Some(b"hello".to_vec()))
            .await
            .unwrap(),
        first
    );
    assert!(matches!(
        client.adcnet_contribute(0, Some(b"changed".to_vec())).await,
        Err(RemoteTransportError::Protocol(
            anymone_core::RemoteSessionError::RoundConflict
        ))
    ));
    assert!(!client.adcnet_contribute(1, None).await.unwrap().is_empty());
    client.close().await.unwrap();
    assert!(client.status().await.unwrap().closed);
    assert!(client.adcnet_contribute(2, None).await.is_err());
    drop(handle);
    assert!(client.reconnect().await.is_err());
}
