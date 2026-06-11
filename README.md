# HSM

A Rust workspace with two projects simulating a Hardware Security Module:

## Projects

| Package | Type | Description |
|---------|------|-------------|
| `hsm_server` | Binary (`.exe`) | REST API server (axum) that signs data with private keys |
| `pkcs11_driver` | Library (`.so`/`.dll`) | PKCS#11 driver library for HSM operations |

## Run the server

```bash
cargo run -p hsm_server
```

Starts on `http://127.0.0.1:3000`.

## Build the driver

```bash
cargo build -p pkcs11_driver
```

Produces a dynamic library (`libpkcs11_driver.so` / `pkcs11_driver.dll`) in `target/debug/`.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/hsm` | Signs a `file_hash` with the key identified by `private_key_token` |

## License

MIT
