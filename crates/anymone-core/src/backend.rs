//! The one place a process's plane is chosen, so binaries stay agnostic about
//! how they reach the network.

use std::sync::Arc;

use crate::bootstrap::{BootstrapConfig, BootstrapError};
use crate::client_pool::SpawnClient;
use crate::governance::GovernanceBootstrap;
use crate::identity::Identity;
use crate::session::GoodClients;
use crate::transport::Transport;

/// Transport for a node that joins the backbone: committee, relay, service, or a
/// discovery bootnode.
pub fn start_node_transport(
    identity: &Identity,
    bootstrap: &BootstrapConfig,
    good_clients: GoodClients,
) -> Result<Arc<dyn Transport>, BootstrapError> {
    let cfg = bootstrap.commonware_config(good_clients)?;
    Ok(crate::cw::CommonwareNetwork::start(identity, cfg))
}

/// Spawner for the virtual clients a service mints to carry queued messages.
/// The service itself stays on the backbone; only its clients use the client
/// plane.
pub fn virtual_client_spawner(
    bootstrap: &BootstrapConfig,
    gov: GovernanceBootstrap,
) -> Result<SpawnClient, BootstrapError> {
    Ok(crate::cw::stream_client_spawner(
        bootstrap.stream_client_config()?,
        gov,
    ))
}

/// Transport and virtual-client spawner for a client-plane process (chat bot,
/// gateway, bridge). These hold streams to nodes rather than joining the
/// backbone, so each virtual client costs a connection, not a node.
pub fn start_client_transport(
    identity: &Identity,
    bootstrap: &BootstrapConfig,
    gov: GovernanceBootstrap,
) -> Result<(Arc<dyn Transport>, SpawnClient), BootstrapError> {
    let cfg = bootstrap.stream_client_config()?;
    let net = crate::cw::StreamClientNetwork::start(identity, cfg.clone());
    Ok((net, crate::cw::stream_client_spawner(cfg, gov)))
}
