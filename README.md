# jade-client-rs

A Rust client for the [Blockstream Jade](https://blockstream.com/jade/) hardware
wallet.

Jade speaks a JSON-RPC shaped protocol encoded as CBOR, over USB CDC serial or
Bluetooth. This crate implements that protocol, the blind pinserver exchange
that unlocks a PIN protected device, and PSBT signing.

Scope is Bitcoin single signature. Liquid, multisig, firmware updates and the
airgapped QR mode are not covered.

> Status: exercised against a physical Jade v1 (firmware 1.0.41) on macOS over
> both transports, USB serial and Bluetooth: unlock through the pinserver,
> account export, address verification for `wpkh` and `tr`, message signing,
> PSBT signing including a reply large enough to come back fragmented,
> cancellation and logout. Jade Plus and Linux serial remain covered only by the
> scripted mock device.

This is an unofficial client and is not affiliated with Blockstream.

## Install

```toml
[dependencies]
jade-client-rs = "0.1"
```

## Usage

```rust,no_run
use jade_client_rs::{Jade, JadeAddressVariant, JadeNetwork, SerialTransport};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), jade_client_rs::JadeError> {
    let device = jade_client_rs::serial::enumerate_devices()
        .into_iter()
        .next()
        .expect("no Jade attached");

    let transport = Arc::new(SerialTransport::open(&device.path)?);
    let mut jade = Jade::connect(transport).await?;

    println!("firmware {}", jade.version_info().jade_version);

    // Runs the pinserver exchange if the device asks for it. The PIN is entered
    // on the device and never reaches the host.
    jade.unlock(JadeNetwork::Testnet).await?;

    let export = jade
        .account_export(
            JadeNetwork::Testnet,
            0,
            &[JadeAddressVariant::Wpkh, JadeAddressVariant::Tr],
        )
        .await?;

    for account in &export.accounts {
        println!("{} {}", account.derivation_path, account.xpub);
    }

    Ok(())
}
```

Signing a PSBT:

```rust,no_run
# use jade_client_rs::{Jade, JadeNetwork};
# use bitcoin::psbt::Psbt;
# async fn example(jade: &mut Jade, psbt: &Psbt) -> Result<(), jade_client_rs::JadeError> {
let signed = jade.sign_psbt(JadeNetwork::Testnet, psbt).await?;
# Ok(())
# }
```

The PSBT must carry BIP32 key origins for the device's master fingerprint, which
[`Jade::master_fingerprint`] provides. Without them the device signs nothing;
this crate checks for it before the round trip and returns
`JadeError::FingerprintMismatch` rather than letting the failure surface later
as a finalization error.

## Transports

`JadeTransport` is the seam every link goes through. A serial implementation
ships behind the `serial` feature.

Bluetooth is deliberately left to the caller, because BLE permissions, pairing
and lifecycle belong to the platform. [`docs/bluetooth.md`](docs/bluetooth.md)
covers writing one: which shape suits which platform, a complete `btleplug`
implementation, and the macOS behaviour worth knowing before you start.
[`examples/callback_transport.rs`](examples/callback_transport.rs) is the shape
an iOS or Android application wants, where the platform owns the radio and Rust
only moves bytes.

To add one, implement `JadeTransport` against the Nordic UART Service:

| Role | UUID |
|---|---|
| Service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` |
| Write (host to Jade) | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` |
| Notify (Jade to host) | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` |

Three rules matter, and each fails only against real hardware:

1. **Write with response.** Write-without-response silently drops chunks on the
   ESP32 GATT stack.
2. **Do not pause between chunks of one request.** Firmware discards a partially
   received message after two seconds of silence, three on Jade v1, and answers
   with an unattributed error. A 30 KB PSBT is roughly 60 writes.
3. **Clamp the chunk size** into `1..=MAX_CHUNK_BYTES`. For Bluetooth that is
   `min(negotiated_mtu - 3, 509)`.

A write may take as long as it needs. The deadline a caller passes covers the
write as well as the reply, so a stalled link ends in `JadeError::Timeout`
rather than in an operation that never returns.

Two more things matter if you drive Bluetooth from macOS, neither of them this
crate's doing:

- CoreBluetooth rotates the peripheral identifier, because Jade advertises from
  a resolvable private address. A cached peripheral list therefore accumulates
  stale handles for one physical device, and connecting to a stale one hangs
  rather than failing. Take the peripheral from the scan that is running now.
- Dropping the link without disconnecting, which is what killing a process does,
  leaves the device's radio refusing new connections until it is power cycled.
  Disconnect on the way out, on signals included.

### Serial

115200 baud. Ports are matched on the USB descriptors Jade and its DIY bridge
chips present:

| VID:PID | Chip |
|---|---|
| `10c4:ea60` | Silicon Labs CP210x, Jade v1 |
| `1a86:55d4` | WCH CH9102 |
| `0403:6001` | FTDI FT232 |
| `1a86:7523` | WCH CH340 |
| `303a:4001` | Espressif native USB, Jade Plus |
| `303a:1001` | Espressif USB serial/JTAG |

DTR and RTS drive the ESP32's EN and BOOT pins through these bridges, so their
state is not a free choice, and the right state depends on which device node is
opened:

| Path | DTR and RTS | Why |
|---|---|---|
| `/dev/tty*` | cleared | The kernel asserts them on open, which reboots the device. |
| `/dev/cu.*` | left asserted | Clearing them stops a Jade answering at all, and it stays unresponsive until it is power cycled. |

`/dev/cu.*` is the macOS call-out node. Enumeration returns only that node on
macOS, never the `/dev/tty.*` dial-in twin, which blocks on open waiting for a
carrier detect that a Jade never asserts.

## Cancellation

Jade has no cancel message, so the only way to stop a pending confirmation is to
close the link. `Jade::cancel_handle` returns a clonable handle that works while
an operation holds `&mut Jade`:

```rust,no_run
# use jade_client_rs::Jade;
# async fn example(jade: &mut Jade) {
let cancel = jade.cancel_handle();
tokio::spawn(async move {
    // From a cancel button, for example.
    let _ = cancel.cancel().await;
});
# }
```

The operation in flight fails with `JadeError::UserCancelled`. `cancel` both sets
an abort flag and closes the link, and which one the request notices first is a
race, so the flag wins whenever it is set: a cancelled operation never reports a
disconnection the user did not experience.

## Unlocking

A PIN protected Jade is unlocked through a blind pinserver. The exchange is end
to end encrypted between the device and the server, so the host never learns the
PIN; its role is to carry bytes.

The bundled client is behind the `reqwest-pinserver` feature. Because the URL
list arrives from the device, requests are limited to https on port 443, with no
credentials, no onion host, no redirects, and a resolved address that is not
loopback, private, link local, CGNAT or unique local. The resolved address is
pinned onto the connection, which closes the DNS rebinding window. Bodies are
capped at 64 KiB.

To use a different HTTP stack, implement `PinServerHttp` and call
`Jade::unlock_with`. The trait is available without the feature.

## Features

| Feature | Default | Effect |
|---|---|---|
| `serial` | yes | `SerialTransport` and USB descriptor based discovery |
| `reqwest-pinserver` | yes | Bundled HTTPS client for the pinserver exchange |

A mobile consumer that supplies its own Bluetooth transport typically wants
`default-features = false`, since `serialport` has no iOS backend.

## Protocol notes

Three details are worth knowing if you work on this crate, because each produces
code that compiles and then fails against hardware:

- **Binary fields must be CBOR byte strings.** serde encodes a plain `Vec<u8>` as
  an array of integers, and Jade reads `psbt` and `entropy` with
  `rpc_get_bytes_ptr`, which requires major type 2. Every binary field carries
  `#[serde(with = "serde_bytes")]`, and a test asserts the encoded header byte.
- **Replies with id `"00"` are terminal errors, not stray frames.** Jade uses
  that id when it rejects a message before recovering the real one. Discarding
  them turns every such rejection into a full length timeout.
- **An HTTP failure during unlock must still send `pin`, with no params.** The
  device blocks indefinitely waiting for one, so abandoning the exchange leaves
  it consuming the next unrelated request as the awaited reply.

## Testing

```bash
cargo test
```

Everything runs against a scripted mock device and a fake pinserver, so no
hardware or network access is needed.

## License

MIT
