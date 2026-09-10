# Remote protocol clients

The phone runs native Panetière or ADCNet client actions, including their scheduled variants. The desktop runs Anymone networking, the round clock and service framing. Native protocol messages and proofs pass through unchanged.

Ordinary (non-scheduled) Panetière is the deployment default. The desktop sends the selected protocol configuration to the phone; an explicit deployment setting takes precedence.

The current host uses ephemeral developer signing keys and supports open subnets. It does not invoke App Attest or Play Integrity.

## Local demo

Start the Rust demo in one terminal:

```sh
cargo run --locked -p anymone-observer -- demo --output target/demo --clients 0
```

This starts the committee, relays and chat service on the host, using ordinary
Panetière and loopback network listeners. Wait for `Demo ready`. The fresh output
directory contains `client.toml` and the adopted signed `network-config.json`.
The dashboard is at <http://localhost:7000>; the demo's chat is at
<http://localhost:7001>. No deployment script or pre-existing committee is needed.

On the phone's **Remote** screen, select its LAN IPv4 address and start the
developer host. Allow Local Network access on iOS. Keep the phone's pairing code
visible and run this in another terminal from the same working directory:

```sh
cargo run --locked -p anymone-chat -- --config target/demo/client.toml --remote --max-clients 1 --port 8080
```

Select the phone in the terminal and enter its eight-digit code. The desktop
sends configuration automatically; no files need transferring. Send from
<http://localhost:8080> and check delivery at the demo's chat on port
7001, then send in the reverse direction. The standalone action driver below is
an alternative test; it closes the phone session, so restart and pair the phone
before switching to sustained chat.

The demo exports ordinary network configuration and has no remote-session
dependency or pairing logic. The desktop backend owns pairing, protocol-action
dispatch and service framing. Local and phone-backed clients use the same
network interface. Run the desktop backend on the demo host because the demo's
network addresses are loopback; the phone itself can be reached over LAN or ADB.

Each demo run uses fresh committee and relay identities, so choose a new output
directory. The desktop sends configuration changes over the existing pairing.
Restarting the desktop process still requires restarting and pairing the host,
because controller credentials live in the desktop process.

## Connect a phone to an existing deployment

Use matching Anymone protocol builds on the desktop, phone and relays. Start the
deployment's committee and relays. Build the mobile app against the current
`anymone-ffi` source. On **Remote**, select the LAN IPv4 address and start the
developer host. The desktop discovers it and prompts for the code shown on the phone.

Start a service client:

```sh
cargo run --locked -p anymone-chat -- --config client.toml --remote --max-clients 1
```

Or run the HTTP gateway:

```sh
cargo run --locked -p anymone-gateway -- --config gateway.toml --tag example.channel --announce --remote --max-clients 1
curl -X POST --data-binary 'remote client test' http://localhost:8090/messages
curl 'http://localhost:8090/messages?from=0'
```

Use `--announce` only on the gateway that registers the channel. HTTP acceptance means queued; check the decoded messages for delivery. Both binaries reject remote operation with more than one client.

The backend selects the lowest-ID supported open subnet and sends its adopted configuration and relay keys to the phone. Later configuration changes for that subnet use the same connection and pairing. Compatible protocol state and signing identity are retained; changed protocol parameters rebuild the native client and return unsent scheduled payloads to the desktop queue. The phone validates supported parameters and resource bounds. Native recipients apply their own protocol checks. A transport failure retains the uncertain request and unacknowledged payloads.

Keep the app foregrounded. Backgrounding or stopping it closes the host and withdraws discovery. Restarting the host creates new keys and requires fresh pairing. Reconnects within the same desktop process retain the controller credential and phone identity; restarting the desktop process requires restarting and pairing the host.

## Discovery and manual connections

The phone advertises `_anymone-remote._tcp` using Bonjour or Android NSD. Discovery carries the endpoint, interface version and code-pairing support, without credentials. `--remote` discovers hosts and prompts for a selection and code. Discovery runs in Rust on Linux and macOS, without external discovery utilities.

```sh
cargo run --locked -p anymone-remote-session -- discover --seconds 5
```

If discovery is unavailable, connect directly and enter the same code:

```sh
cargo run --locked -p anymone-chat -- --config client.toml --remote 192.168.1.20:PHONE_PORT
```

The code authenticates a SPAKE2 exchange bound to the TLS connection. Both sides confirm the derived key before configuration or actions are accepted, and reconnects pin the authenticated certificate. Each host allows five code attempts and one controller. Restart the phone host to obtain a fresh code after exhaustion or a desktop process restart. Pairing files remain supported with `--remote-pairing FILE`; the phone exports them under **Automation**. A phone network change may require restarting its listener.

## Action driver

The standalone driver uses a pairing JSON file exported under **Automation** and a desktop configuration file. Export configuration from a running deployment, then pass it to the driver; the driver sends it to the phone before executing the typed actions. Chat and gateway do this automatically.

```sh
cargo run --locked -p anymone-remote-session -- export-config --bootstrap client.toml --subnet 0 > host-config.json
```

The exporter waits for a committee-signed configuration. The driver prints native outputs as hex and closes the host session when finished:

```sh
cargo run --locked -p anymone-remote-session -- drive --config host-config.json --pairing pairing.json --actions actions.json --reconnect-between-actions
```

For an ordinary Panetière host starting at round zero, this sample prepares and finalizes a `hello` payload, then a cover contribution:

```json
[
  {"Panetiere":{"PrepareRound":{"round":0}}},
  {"Panetiere":{"FinalizeRound":{"round":0,"payload":[104,101,108,108,111]}}},
  {"Panetiere":{"PrepareRound":{"round":1}}},
  {"Panetiere":{"FinalizeRound":{"round":1,"payload":null}}}
]
```

Generate `actions.json` using the exported starting round:

```sh
jq -e '
  if .subnet.protocol.Panetiere then
    .starting_round as $r |
    [
      {"Panetiere":{"PrepareRound":{"round":$r}}},
      {"Panetiere":{"FinalizeRound":{"round":$r,"payload":[104,101,108,108,111]}}},
      {"Panetiere":{"PrepareRound":{"round":($r+1)}}},
      {"Panetiere":{"FinalizeRound":{"round":($r+1),"payload":null}}}
    ]
  else error("Expected ordinary Panetiere in host-config.json")
  end
' host-config.json > actions.json
```

Receipt and repair actions need genuine relay feedback; this standalone sample does not fabricate it. For live delivery and automatic round tracking, use the chat or gateway backend.

For a live exported context, use rounds at or after its `starting_round`. The action enums are defined in `anymone-core::remote_session`. Scheduled clients also expose their native cover-rate setting. Script output alone does not establish successful relay decoding; the service backend exercises that path.

A desktop-only host is available for transport tests:

```sh
cargo run --locked -p anymone-remote-session -- host
```

## Android SDK machine

Copy both current source directories to the SDK machine, with `anymone` beside `anymone-mobile`. Generated bindings must come from the current FFI library. The build needs JDK 17, Gradle, Android SDK 35, an NDK selected by `ANDROID_NDK_HOME`, Rust and `cargo-ndk`. The pinned Cargo dependencies must be accessible there.

From `anymone-mobile`, build for an x86-64 emulator:

```sh
PROFILE=debug WITH_EMULATOR=1 ./scripts/build-android.sh
cd android
gradle --no-daemon -Pemulator assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n net.flashbots.anymone/.MainActivity
```

Start an API 29 or newer emulator before installing. For an ARM64 handset, omit `WITH_EMULATOR=1` and `-Pemulator`. The existing benchmark smoke runner exercises Bench; it does not test Remote.

For a debug APK, start the host without entering configuration:

```sh
adb shell am start --activity-single-top -n net.flashbots.anymone/.MainActivity -a net.flashbots.anymone.START_REMOTE_DEVELOPER
```

This action opens Remote, binds to loopback and keeps the screen awake. Release
APKs ignore it. Read the result until its state becomes `ready` or `error`:

```sh
adb exec-out run-as net.flashbots.anymone cat files/remote-host-result.json
```

The result reports `starting`, `ready`, `error` or `stopped`. After readiness,
extract the pairing data and forward the actual port:

```sh
umask 077
adb exec-out run-as net.flashbots.anymone cat files/remote-host-result.json |
  jq -e 'if .state == "ready" then .pairing else error(.error // .state) end' > pairing.json
PHONE_PORT=$(jq -r '.address | split(":") | last' pairing.json)
adb forward tcp:9443 tcp:"$PHONE_PORT"
```

The result stays in app-private storage and is accessed through `run-as`;
pairing data is not sent to logcat. Rebuild only the APK with
`gradle --no-daemon -Pemulator assembleDebug` after syncing Kotlin-only changes.

Alternatively, on the emulator's Remote screen, use listening address `127.0.0.1` and start. Copy its pairing JSON through the emulator clipboard. Replace `PHONE_PORT` below with the port displayed by the app:

```sh
adb forward tcp:9443 tcp:PHONE_PORT
```

Run the driver from the `anymone` directory on that machine:

```sh
cargo run --locked -p anymone-remote-session -- drive --config host-config.json --pairing pairing.json --address 127.0.0.1:9443 --actions actions.json --reconnect-between-actions
```

To run the desktop driver on a different computer, first open an SSH tunnel to the SDK machine:

```sh
ssh -N -L 9443:127.0.0.1:9443 SDK_HOST
```

Use the same driver address, `127.0.0.1:9443`, on that computer. For interactive chat/gateway through the tunnel, use `--remote 127.0.0.1:9443` and enter the emulator's displayed code. File-based automation still works by changing only `address` in the pairing JSON to `127.0.0.1:9443`. Keep the emulator app foregrounded. After the driver exits successfully, allow a few seconds for the debug result to report `stopped`; a polling failure reports `error` with its cause.

ADB forwarding tests the native host and TLS/protocol integration. Test discovery separately on a reachable LAN; forwarding does not carry mDNS. See [Android emulator networking](https://developer.android.com/studio/run/emulator-networking-interconnect) for emulator network and forwarding behavior.

## Verification

```sh
cargo test --locked -p anymone-remote-session
cargo test --locked -p anymone-ffi remote_host_tests
cargo check --locked --workspace --all-targets
```

The service test runs real relays, service framing and an echo reply through a code-paired TLS host for all four protocols. Transport tests cover code authentication, attempt exhaustion, TLS interception, certificate mismatch, configuration, updates, replay after a lost reply and close. The FFI tests check code pairing, native output, status, stop and restart with new keys. The backend test checks that a disconnected host retains the staged payload without local output. The multicast discovery test is opt-in because it requires local IPv4 multicast networking.

On the phone, repeat with each protocol, verify the displayed participant survives reconnect, and confirm stop/restart changes it. For sustained runs, send uniquely numbered messages through chat or gateway and compare decoded results. Interrupt and restore only the desktop connection to test resumption; stopping the app tests a new session instead. Record latency and handset memory separately. Rust tests and binding generation do not validate native app packaging or device performance.
