use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::Result;
use anymone_eth_service::EpochBatch;

use crate::{broker::bounded_response, broker::now, broker::Broker};

pub async fn follow(broker: Arc<Broker>, stop_at: u64) -> Result<()> {
    let initial = broker.profile();
    let feed = &initial.services.values().next().expect("validated services").signed.descriptor.feed;
    let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never()).timeout(Duration::from_secs(feed.epoch_seconds.max(1))).build()?;
    let current = feed.epoch(now())?;
    let oldest = current.saturating_sub(u64::from(feed.retained_epochs));
    let mut next = broker.store.cursor(&feed.feed)?.unwrap_or(oldest).max(oldest);
    let period = Duration::from_millis((feed.epoch_seconds.saturating_mul(1000) / 2).max(1));
    let mut tick = 0usize;
    let mut timer = tokio::time::interval(period);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while now() < stop_at {
        timer.tick().await;
        if now() >= stop_at { break; }
        let current = feed.epoch(now())?;
        if current == 0 { continue; }
        let epoch = next.min(current - 1).max(current.saturating_sub(u64::from(feed.retained_epochs)));
        let profile = broker.profile();
        let mirror = &profile.feed_mirrors[tick % profile.feed_mirrors.len()];
        tick = tick.wrapping_add(1);
        let Ok(response) = client.get(format!("{}/epochs/{epoch}", mirror.trim_end_matches('/'))).send().await else { continue; };
        let limit = feed.max_epoch_bytes as usize;
        let Ok(bytes) = bounded_response(response, limit).await else { continue; };
        let Ok(batch) = bincode::deserialize::<EpochBatch>(&bytes) else { continue; };
        if batch.validate(feed, epoch, now()).is_err() { continue; }
        let caps = broker.store.pending(now())?;
        let mut locators = HashMap::new();
        for (index, (cap, _)) in caps.iter().enumerate() {
            let delivery = &cap.delivery;
            if delivery.feed == feed.feed && epoch >= delivery.first_epoch && epoch <= delivery.last_epoch {
                locators.insert(cap.locator(epoch)?, index);
            }
        }
        for packet in &batch.responses {
            if let Some(index) = locators.get(&packet.binding.locator) {
                let (cap, limit) = &caps[*index];
                let limit = limit.or_else(|| initial.services.values().chain(profile.services.values())
                    .find(|service| service.signed.descriptor.signing_key == cap.context.service)
                    .map(|service| service.signed.descriptor.limits.max_response_bytes));
                if let Some(limit) = limit { let _ = broker.store.record(cap, packet, limit, now()); }
            }
        }
        broker.store.advance(&feed.feed, epoch)?;
        next = epoch.saturating_add(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};
    use anymone_core::Identity;
    use anymone_eth_service::{FeedDescriptor, ServiceDescriptor, ServiceLimits, SignedServiceDescriptor, VERSION};
    use crate::{BrokerProfile, ServiceTarget};
    use axum::{extract::Path, http::StatusCode, routing::get, Router};
    use ed25519_dalek::SigningKey;

    #[tokio::test]
    async fn failed_epoch_is_retried_without_an_upload_session() {
        let signer = SigningKey::from_bytes(&[7;32]);
        let identity = Identity::from_secrets(&[3;64]).unwrap();
        let feed = FeedDescriptor { feed:[1;32], genesis_time:now()-20, epoch_seconds:2,
            max_epoch_bytes:16384, retained_epochs:20 };
        let batch = EpochBatch { feed:feed.feed, epoch:0, responses:vec![] };
        let bytes = bincode::serialize(&batch).unwrap();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let server_paths = paths.clone();
        let app = Router::new().route("/epochs/:epoch", get(move |Path(epoch): Path<u64>| {
            let paths = server_paths.clone();
            let bytes = bytes.clone();
            async move {
                let mut paths = paths.lock().unwrap();
                paths.push(epoch);
                if paths.len() == 1 { return Err(StatusCode::SERVICE_UNAVAILABLE); }
                Ok(bytes)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}",listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); });
        let descriptor = ServiceDescriptor { feed_mirrors: vec![], version:VERSION, network:[2;32], chain:1,
            service_identity:identity.pubkey().0, signing_key:signer.verifying_key().to_bytes(),
            request_key:[4;32], tag:"provider".into(), backend_routes:vec!["execution".into()],
            limits:ServiceLimits { max_request_bytes:4096,max_response_bytes:4096,max_batch:8,
                max_log_blocks:100,max_lifetime_seconds:100 },
            feed:feed.clone(), expires_at:now()+100 };
        let target = ServiceTarget { service_identity:identity.pubkey().0, revoked: false,
            signed:SignedServiceDescriptor { signature:identity.sign(&descriptor.signing_bytes().unwrap()),descriptor } };
        let profile = BrokerProfile { services:BTreeMap::from([("provider".into(),target)]), feed_mirrors:vec![endpoint],
            listen:"127.0.0.1:8546".parse().unwrap(),token:"unused".into(),database:":memory:".into(),session_seconds:10 };
        let broker = Broker::new(profile,None).unwrap();
        let reader = tokio::spawn(follow(broker.clone(),now()+10));
        tokio::time::timeout(Duration::from_secs(5), async {
            while broker.store.cursor(&feed.feed).unwrap() != Some(1) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        assert_eq!(&paths.lock().unwrap()[..2], &[0,0]);
        reader.abort();
        server.abort();
    }
}
