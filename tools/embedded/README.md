# Embedded UART/KISS gate

`reticulum-embedded` is a portable `no_std` adapter. It cross-compiles for
`thumbv7em-none-eabihf` and supplies the complete Embassy UART/KISS pump, while
the board firmware remains responsible for its HAL, pin mapping, hardware RNG,
and Embassy time driver.

Run the platform-independent gates:

```sh
cargo test -p reticulum-embedded
cargo build -p reticulum-embedded --target thumbv7em-none-eabihf
```

To run on a board, initialize an `embedded_io_async::{Read, Write}` UART, wrap
the HAL's CSPRNG with `HardwareRng`, build a `Node<EmbeddedClock>`, register and
announce a destination, then await:

```rust,ignore
run_uart(
    &mut uart,
    &mut node,
    &mut entropy,
    0,
    1024,
    embassy_time::Duration::from_millis(100),
    |event| handle_event(event),
).await?;
```

Connect the UART to the host and run `reticulumd` with a `[[interfaces]]`
entry using `type = "serial"`, the device path, the matching baud rate, and
`framing = "kiss"`.

The live serial gate is hardware-deferred in environments without QEMU serial
support or an attached MCU. The host tests exercise partial/coalesced frames,
reserved-byte escaping, malformed/oversized recovery, and delivery of a real
Reticulum announce into `Node`.

The `insecure-demo-rng` feature is only for emulators without an RNG. It is
predictable and must never be enabled in production firmware.
