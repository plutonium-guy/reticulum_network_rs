# Reticulum mobile bindings

The generated Kotlin and Swift sources are checked in under
`crates/reticulum-ffi/bindings`. Regenerate them on the host with:

```sh
./crates/reticulum-ffi/generate_bindings.sh
```

The device/emulator gate is deferred when Android Studio or a full Xcode SDK
is unavailable. `./tools/interop/run_ffi_interop.sh` remains a live gate: it
drives the same exported façade and exchanges encrypted messages in both
directions with Python RNS 1.4.1 over TCP.

## Android

Install the Rust targets and `cargo-ndk`, then build the native libraries:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o app/src/main/jniLibs build -p reticulum-ffi --release
cp crates/reticulum-ffi/bindings/kotlin/uniffi/reticulum_ffi/reticulum_ffi.kt \
  app/src/main/java/uniffi/reticulum_ffi/
```

Add JNA's Android artifact to the app and package the resulting `jniLibs` plus
generated Kotlin source in the application or an Android library module. Run
the instrumentation test against an RNS TCP server reachable from the
emulator (`10.0.2.2:<port>` for the Android emulator's host loopback).

## iOS

Build device and Apple Silicon simulator archives, create the XCFramework,
and add the generated Swift source to the app target:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build -p reticulum-ffi --release --target aarch64-apple-ios
cargo build -p reticulum-ffi --release --target aarch64-apple-ios-sim
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libreticulum_ffi.a \
  -headers crates/reticulum-ffi/bindings/swift \
  -library target/aarch64-apple-ios-sim/release/libreticulum_ffi.a \
  -headers crates/reticulum-ffi/bindings/swift \
  -output ReticulumFFI.xcframework
```

Add `ReticulumFFI.xcframework`,
`crates/reticulum-ffi/bindings/swift/reticulum_ffi.swift`, and the generated
module map to the Xcode target. The application supplies a
`ReticulumEventHandler`, registers its destination before connecting, and
calls `disconnect()` during lifecycle shutdown.
