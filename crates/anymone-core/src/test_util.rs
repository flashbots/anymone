//! Helpers for spawning full `Anymone` instances inside one process for
//! tests. Feature-gated behind `test-util`; production builds drop it.
//!
//! Currently rides on the in-memory transport (M2). Once libp2p lands the
//! `Node` builder will gain a `start_libp2p` variant that brings up a real
//! swarm on loopback.

use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::config::{AnymoneRoundConfiguration, ExchangePublicKeyWire};
use crate::governance::GovernanceBootstrap;
use crate::identity::Identity;
use crate::runtime::{Anymone, AnymonePrep};
use crate::transport::{InMemoryHandle, InMemoryNetwork};

/// A node spun up against a shared `InMemoryNetwork`. Holds its identity,
/// transport handle, and (once started) its `Anymone` instance.
pub struct Node {
    pub identity_pk: crate::identity::Pubkey,
    keypair: Option<Identity>, // taken when prepare_* consumes it
    exchange_pubkey: ExchangePublicKeyWire,
    handle: InMemoryHandle,
    anymone: Option<Anymone>,
    aux_tasks: Vec<JoinHandle<()>>,
}

/// A node that has subscribed to all of its known governance topics but has
/// not yet started its Anymone subnet runtime. Drive it forward with
/// [`NodePrep::start`] (which awaits the first signed config).
pub struct NodePrep {
    pub identity_pk: crate::identity::Pubkey,
    exchange_pubkey: ExchangePublicKeyWire,
    handle: InMemoryHandle,
    aux_tasks: Vec<JoinHandle<()>>,
    prep: AnymonePrep,
    /// Set for relays/services that need to publish a registration once it's
    /// safe to do so (i.e. the committee has subscribed).
    deferred_registration: Option<crate::scheduling::Registration>,
}

impl Node {
    pub fn fresh(net: &Arc<InMemoryNetwork>) -> Self {
        let id = Identity::generate();
        let pk = id.pubkey();
        let exchange_pubkey = ExchangePublicKeyWire::from_key(&id.exchange_pubkey());
        let handle = net.handle(pk);
        Node {
            identity_pk: pk,
            keypair: Some(id),
            exchange_pubkey,
            handle,
            anymone: None,
            aux_tasks: Vec::new(),
        }
    }

    pub fn exchange_pubkey_wire(&self) -> ExchangePublicKeyWire {
        self.exchange_pubkey.clone()
    }

    pub fn pubkey(&self) -> crate::identity::Pubkey {
        self.identity_pk
    }

    /// The node's identity. Valid only before any `start_*` call moves it
    /// into the runtime. Useful for signing things ahead of startup (e.g.
    /// committee signing the configuration the static publisher will gossip).
    pub fn identity(&self) -> &Identity {
        self.keypair
            .as_ref()
            .expect("identity already consumed by start_*")
    }

    pub fn transport(&self) -> Arc<dyn crate::transport::Transport> {
        Arc::new(self.handle.clone())
    }

    pub fn anymone(&self) -> &Anymone {
        self.anymone
            .as_ref()
            .expect("Node has not been started yet")
    }

    /// Phase 1 — subscribe to the governance topic synchronously and return
    /// a `NodePrep`. After this call, publishes on `anymone/config` won't be
    /// lost by this node. The role-specific publish (registration) is
    /// deferred until [`NodePrep::start`] so all subscribers can be set up
    /// before any publisher fires.
    pub async fn prepare_as_participant(&mut self, bootstrap: GovernanceBootstrap) -> NodePrep {
        self.prepare_inner(bootstrap, None).await
    }

    /// Start directly from a static signed config — no governance watcher, no
    /// registration round. For tests that pin the subnet set up front.
    pub async fn start_with_config(mut self, config: AnymoneRoundConfiguration) -> Self {
        let id = self.keypair.take().expect("identity already consumed");
        let transport = self.transport();
        self.anymone = Some(Anymone::start_with_config(id, transport, config).await);
        self
    }

    /// Phase 1 — same as participant, but defers a relay registration to
    /// phase 2 so the publish happens after all subscribers are in place.
    pub async fn prepare_as_relay(&mut self, bootstrap: GovernanceBootstrap) -> NodePrep {
        let xk = self.exchange_pubkey_wire();
        let reg = crate::scheduling::Registration::relay(self.identity(), xk);
        self.prepare_inner(bootstrap, Some(reg)).await
    }

    /// Phase 1 — same as participant, but defers a service registration.
    pub async fn prepare_as_service(
        &mut self,
        bootstrap: GovernanceBootstrap,
        tag: crate::wire::ServiceTag,
    ) -> NodePrep {
        let xk = self.exchange_pubkey_wire();
        let reg = crate::scheduling::Registration::service(self.identity(), tag, xk);
        self.prepare_inner(bootstrap, Some(reg)).await
    }

    async fn prepare_inner(
        &mut self,
        bootstrap: GovernanceBootstrap,
        deferred_registration: Option<crate::scheduling::Registration>,
    ) -> NodePrep {
        let id = self.keypair.take().expect("identity already consumed");
        let transport = self.transport();
        let prep = Anymone::prepare(id, transport, bootstrap).await;
        NodePrep {
            identity_pk: self.identity_pk,
            exchange_pubkey: self.exchange_pubkey.clone(),
            handle: self.handle.clone(),
            aux_tasks: std::mem::take(&mut self.aux_tasks),
            prep,
            deferred_registration,
        }
    }
}

impl NodePrep {
    pub fn pubkey(&self) -> crate::identity::Pubkey {
        self.identity_pk
    }

    /// Phase 2 — publish any deferred registration (now that every
    /// committee scheduler that should receive it has subscribed in phase 1)
    /// and start the Anymone subnet runtime.
    pub async fn start(self) -> Result<Node, crate::governance::GovernanceError> {
        if let Some(reg) = self.deferred_registration {
            let transport: Arc<dyn crate::transport::Transport> = Arc::new(self.handle.clone());
            transport
                .publish(crate::governance::TOPIC_REGISTRATION, reg.encode())
                .await;
        }
        let anymone = self.prep.start().await?;
        Ok(Node {
            identity_pk: self.identity_pk,
            keypair: None,
            exchange_pubkey: self.exchange_pubkey,
            handle: self.handle,
            anymone: Some(anymone),
            aux_tasks: self.aux_tasks,
        })
    }
}
