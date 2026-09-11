# Anymone

> [!WARNING]
> This repository is under active development, and it has not been audited. Do not use it for any production use case.
> Do use it to experiment with the protocol 💖

Anonymous broadcast channels for applications, with a Rust runtime,
node binaries and UniFFI bindings.

## Build and test

Requires Rust and a native C/C++ toolchain.

```sh
cargo build --locked --workspace --jobs 8
cargo test --locked --workspace --jobs 8 -- --test-threads=1
```

## Local demo

```sh
cargo run --locked -p anymone-observer -- demo
```

Open <http://localhost:7000> for the dashboard.

To connect a separate chat client, start the demo with a fresh output directory:

```sh
cargo run --locked -p anymone-observer -- demo --output target/demo --clients 0
```

Wait for `Demo ready`, then run in another terminal on the same host:

```sh
cargo run --locked -p anymone-chat -- --config target/demo/client.toml --port 8080
```

Open <http://localhost:8080>.

## Deployment

Start from [anymone.toml.example](anymone.toml.example). Generate one identity per
node with `anymone-node keygen --out node.identity`; keep its `.exchange` file
alongside it. Fill in addresses, bootstrap peers and the shared governance
committee, then run `anymone-node run --config node.toml --role committee`
or `--role relay`.

Set `[committee].protocol` to `panetiere` (default), `scheduled-panetiere`,
`adcnet`, `scheduled-adcnet`, or `noop` (unencrypted). Protocol selection is
explicit. Optional core features: `tdx-attest`, `mobile-attest`, `wire-debug`.

- [Ethereum RPC demo](crates/anymone-eth-service/demo.md)
- [RPC service](crates/anymone-eth-service/README.md) and [client](crates/anymone-rpc-client/README.md)
- [Phone clients](crates/anymone-remote-session/README.md)
- [Mobile apps](https://github.com/flashbots/anymone-mobile)

The application API is in `anymone-core`: `open(tag)` creates a client pipe,
`bind(tag)` receives service requests, and `subscribe(tag)` joins a broadcast
channel. See each binary's `--help` for options.
