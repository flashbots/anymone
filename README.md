# Anymone

Anymone provides anonymous broadcast channels shared by applications. A scheduling committee publishes signed subnet configurations; relays run the selected protocol; clients submit messages and cover traffic. Services receive messages by tag and reply through the same channels.

This repository contains the Rust runtime, node binaries, applications, and UniFFI bindings.

## Implemented protocols

| Protocol setting | Subnet behavior |
| --- | --- |
| `adcnet` | Non-threshold ADCNet with payloads encoded directly in an IBLT. |
| `scheduled-adcnet` | Non-threshold ADCNet with an auction followed by payload transmission in the next protocol round. |
| `panetiere` | Threshold Panetiere with a configured decryption threshold. The default. |
| `scheduled-panetiere` | Threshold Panetiere with reservations and a staggered message vector. |
| `noop` | Plain broadcast for exercising the runtime without cryptography. |

Set `protocol` in the bootstrap file's `[committee]` section. Protocol selection is explicit: load and faults do not automatically switch protocols. The runtime can adopt a signed configuration that changes the protocol, and the scheduling committee continues to use Panetiere internally.

The scheduler adjusts subnet count, capacity, and cover rate from observed traffic and handles relay faults. Both Panetiere modes support leader or consensus client-set formation. ADCNet uses a leader-selected client set; its one-round mode can use one aggregator per group. Scheduled ADCNet sends contributions directly to the leader and requires every relay's share. Its total message-vector capacity is rounded to a multiple of 1 KiB to fit the upstream auction's allocation unit.

## Build

Use a Rust toolchain capable of building the pinned dependencies and a native C/C++ build toolchain for their native components.

```sh
cargo build --locked --workspace --jobs 8
```

The protocol dependencies are pinned to Git revisions in `crates/anymone-core/Cargo.toml`. Fetching ADCNet currently uses SSH and requires working GitHub SSH access. A build from an existing Cargo cache does not establish that a fresh anonymous checkout can fetch every dependency.

## Run a local demo

```sh
cargo run --locked -p anymone-observer -- demo
```

Open <http://localhost:7000>. This runs the committee, relays, clients, and services in one process over the in-memory transport. The demo explicitly selects Panetiere. The dashboard exposes traffic and fault controls.

To connect separate clients or services, enable the ordinary loopback network and export bootstrap files:

```sh
cargo run --locked -p anymone-observer -- demo --output target/demo --clients 0
```

Use a fresh output directory for each run. Wait for `Demo ready`; `target/demo/client.toml` contains client connectivity and governance, and `network-config.json` contains the signed configuration. Keep the demo running and run clients from the same working directory. A separate chat client can connect with:

```sh
cargo run --locked -p anymone-chat -- --config target/demo/client.toml --port 8080
```

The demo has no phone or pairing logic. The [remote session driver and service backends](crates/anymone-remote-session/README.md) connect through the same client interface. The network listeners use loopback; run the desktop backend on the demo host. The phone connects to that backend through its independently paired TLS session.

For available options:

```sh
cargo run --locked -p anymone-observer -- demo --help
cargo run --locked -p anymone-node -- --help
```

## Run separate nodes

Start from [anymone.toml.example](anymone.toml.example). Configure each node's identity path and listening addresses, the shared governance committee, and the network bootstrap peers. The example contains placeholders and must be filled in before use.

Generate an identity and use its printed public material in the relevant configurations:

```sh
cargo run --locked -p anymone-node -- keygen --out ./node.identity
```

Keep the generated identity file and its `.exchange` sibling together. Give each node its own identity and configuration. With those files prepared, start the roles in separate processes:

```sh
cargo run --locked -p anymone-node -- run --config committee.toml --role committee
cargo run --locked -p anymone-node -- run --config relay.toml --role relay
cargo run --locked -p anymone-node -- run --config service.toml --role service --service-tag example.echo
```

A node configured as a service provides an echo handler. Application binaries provide other handlers. For example, attach an HTTP gateway and register its channel:

```sh
cargo run --locked -p anymone-gateway -- --config gateway.toml --tag example.channel --announce
```

See [the gateway API](crates/anymone-gateway/API.md) for message submission and retrieval. This gateway exposes Anymone channels over HTTP; it is not a MASQUE proxy.

## Application API

Phone-hosted developer clients can run native protocol actions while chat or gateway keeps the desktop transport. See the [remote client setup and tests](crates/anymone-remote-session/README.md), including iPhone pairing and Android emulator forwarding.

`Anymone::open(tag)` creates a participating client pipe with a return address. `bind(tag)` receives service messages without joining cover participation; replies can still be sent through that pipe. `subscribe(tag)` receives broadcasts and participates in the channel.

`Pipe` sends and receives byte payloads. `Pipe::split()` separates a cloneable sender from the receiver, so receiving need not block sending. Scheduled sessions retain pending transmissions until their reservation or auction can finish.

Chat and gateway binaries use one client identity by default. `--max-clients` greater than one enables virtual-client pooling. The pool bounds waiting submissions and reports saturation when that queue fills.

## Workspace

- `anymone-core`: configuration, scheduling committee, protocol sessions, transport, pipes, and attestation.
- `anymone-ffi`: production UniFFI API.
- `anymone-node`: committee, relay, service, client, and bootnode commands.
- `anymone-observer`: dashboard, local demo, and optional live load generation.
- `anymone-chat`: broadcast chat application.
- `anymone-gateway`: HTTP API for an Anymone channel.
- `anymone-txbus` and `anymone-eth-bridge`: transaction-channel application and Ethereum bridge.

The retained `anymone-example` directory is outside the active workspace.

## Checks

Run the workspace tests with:

```sh
cargo test --locked --workspace --jobs 8
```

The explicit client-set integration target can be run separately:

```sh
cargo test --locked -p anymone-core --test client_set_e2e --jobs 8
```

Optional core features include `tdx-attest`, `mobile-attest`, and `wire-debug`. Relays enforcing an attestation policy need the matching verifier features. Decoded wire tracing requires the `wire-debug` build feature.

## Design documents

[whitepaper.md](whitepaper.md) and [IDEAS.md](IDEAS.md) contain broader designs and open questions. [IMPLEMENTATION.md](IMPLEMENTATION.md) contains implementation notes; older sections may describe previous interfaces.

Nym integration, MASQUE tunnelling, automatic protocol selection, and the broader on-chain governance design are not implemented runtime features. They should be read as design directions rather than supported deployment options.
