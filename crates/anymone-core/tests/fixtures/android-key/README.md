# Android hardware key attestation fixture

`pixel7pro/chain.der` is the unmodified concatenation of DER certificates
(leaf first) exported from a physical Google Pixel 7 Pro running Android 16.
`pixel7pro/metadata.json` records its capture time, security patch level,
package/signing identity and the exact Anymone challenge inputs. It was captured
on 2026-10-02 using the `anymone-mobile` instrumentation capture test, from the
sideloaded debug package `net.flashbots.anymone.fixture`. The generated private
key was deleted immediately after obtaining the chain and is not part of this
fixture.

`google-root.der` was obtained independently from Google's official root list:
<https://android.googleapis.com/attestation/root> (retrieved 2026-10-02).
Its SHA-256 fingerprint is
`cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc`.
The exported chain's last certificate matches this published root byte for byte;
the test pins the separately downloaded root rather than trusting an arbitrary
root supplied by a device.

This device has an **unlocked bootloader**. Its signed RootOfTrust reports
`deviceLocked = false` and `verifiedBootState = 2` (Unverified), so the complete
verifier correctly rejects it. The chain and application identity are valid;
both key and attestation security levels are TrustedEnvironment. This is a real
rejection fixture, not a successful enrollment fixture. A separate capture from
a locked device is still needed for full acceptance coverage.

The tests in `src/tee/android_key_device_tests.rs` use the recorded capture time
for certificate validity checks. Production verification still uses the current
clock. Tests check chain authenticity, challenge binding, app identity, unlocked-boot
rejection, signature tampering and certificate validity. App and chain rejection
checks run directly against those verifier components, so they cannot pass merely
because full verification already rejects the unlocked bootloader. They do not
contact Google, check live revocation, demonstrate root-exploit resistance, or
cover every Android vendor's attestation encoding. Keep the synthetic tests for
controlled negative cases.

To capture another fixture, from the sibling `anymone-mobile` checkout with its
Android libraries/bindings built and a physical device connected:

```sh
bash scripts/capture-android-attestation.sh /tmp/android-attestation-fixture
```

Preserve both exported files. Fetch the official root list independently, check
which root verifies the chain, and record its source/fingerprint. Update the
fixture test inputs if adding a different device. Reproduction creates fresh
keys and certificates, so the evidence bytes will differ.

Run the mobile attestation tests from the `anymone` checkout:

```sh
cargo test -p anymone-core --features mobile-attest --lib tee::
```
