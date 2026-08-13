//! Tracing targets, one per subsystem, so `RUST_LOG` selects by concern rather
//! than by module path (the firehose and the signal live in the same modules).
//!
//! Level discipline, uniform across every target:
//!
//! - `trace` — per-message and per-round routine: every wire message, every
//!   normal round's summary, every "not for us" skip.
//! - `debug` — anything that did *not* take the normal path: a dropped or
//!   rejected message, a deferred share, a round that can't decode yet, a
//!   state transition.
//! - `info` — node/config lifecycle.
//! - `warn` — a round's work was actually lost, or a peer's message failed
//!   authentication.
//!
//! So `RUST_LOG=info,anymone=debug` yields a stream where every line means
//! something diverged, and `anymone::wire=trace` opts back into the firehose.
//! Individual subsystems dial independently, e.g.
//! `anymone=info,anymone::panetiere=debug`.

/// Every wire message in or out, and every pipe route. The firehose: one line
/// per message per topic or inbox, `trace` throughout.
pub const WIRE: &str = "anymone::wire";

/// Backbone and stream-plane lifecycle: dials, peer tracking, publish
/// back-pressure, topic-roster admission.
pub const P2P: &str = "anymone::p2p";

/// Panetiere (one-round and scheduled): admission, canonical sets, shares, decode.
pub const PANETIERE: &str = "anymone::panetiere";

/// ADCNet: contributions, client sets, shares, combine.
pub const ADCNET: &str = "anymone::adcnet";

/// Round scheduling and subnet worker lifecycle: arming, cutover, participation
/// draws, per-round outcomes.
pub const SCHED: &str = "anymone::sched";

/// Governance: config fetch/verify/apply, committee proposals and signatures,
/// registrations, fault reports.
pub const GOV: &str = "anymone::gov";
