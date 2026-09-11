# Remote protocol clients

The phone runs Panetiere or ADCNet client actions, including scheduled variants.
The desktop handles networking and round timing. Hosts use ephemeral developer
keys and open subnets; this mode does not use platform attestation.

Build the [mobile app](https://github.com/flashbots/anymone-mobile) against a
compatible Anymone revision.

## Chat demo

From the workspace root, using a fresh output directory:

```sh
cargo run --locked -p anymone-observer -- demo --output target/demo --clients 0
```

Wait for `Demo ready`. On the phone's **Remote** screen, choose its LAN IPv4
address and start the host. Allow Local Network access on iOS.

In another terminal on the demo host:

```sh
cargo run --locked -p anymone-chat -- --config target/demo/client.toml --remote --max-clients 1 --port 8080
```

Select the phone and enter its eight-digit code. Exchange messages between
<http://localhost:8080> and <http://localhost:7001>.

Keep the phone foregrounded. Restarting either host or desktop requires fresh
pairing. Use `--remote IP:PORT` if mDNS discovery is unavailable. A host accepts
one controller and five code attempts.

For an existing deployment, substitute its bootstrap file. The gateway also
supports `--remote --max-clients 1`; use `--announce` only on the gateway
registering the channel. HTTP acceptance means queued, not delivered.

## Automation

Export pairing JSON from the phone's **Automation** section. Chat and gateway
accept it through `--remote-pairing FILE`.

For standalone protocol actions:

```sh
cargo run --locked -p anymone-remote-session -- export-config --bootstrap client.toml --subnet 0 > host-config.json
cargo run --locked -p anymone-remote-session -- drive --config host-config.json --pairing pairing.json --actions actions.json --reconnect-between-actions
```

Use the [action enums](../anymone-core/src/remote_session.rs) and rounds at or
after the exported `starting_round`. The driver prints native outputs and closes
the host; use chat or gateway to check live delivery. `anymone-remote-session host`
provides a desktop host for transport tests.

For an Android emulator, start Remote on `127.0.0.1`, then forward its displayed port:

```sh
adb forward tcp:9443 tcp:PHONE_PORT
```

Connect interactively with `--remote 127.0.0.1:9443`, or pass
`--address 127.0.0.1:9443` to the action driver. ADB forwarding does not carry mDNS.

## Tests

```sh
cargo test --locked -j 8 -p anymone-remote-session -- --test-threads=1
cargo test --locked -j 8 -p anymone-ffi remote_host_tests -- --test-threads=1
```
