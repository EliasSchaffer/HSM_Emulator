# HSM

A lightweight Hardware Security Module simulator built in Rust. Exposes a REST API (via **axum**) for signing data with private keys without exposing key material.

## Endpoints

| Method | Path     | Description                          |
|--------|----------|--------------------------------------|
| GET    | `/health`| Health check — returns `"OK"`        |
| POST   | `/hsm`   | Signs a `file_hash` with the key identified by `private_key_token` and returns a hex-encoded signature |

## Usage

```bash
cargo run
```

The server starts on `http://127.0.0.1:3000`.

## License

MIT
