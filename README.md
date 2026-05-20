# RoyaltyPro Fast Import Helper

Tiny native helper for the RoyaltyPro web app (`member.royaltypro.app`).

Lets composers import multi-GB CSV statements at native speed without crashing the browser. The helper runs as a background process on `127.0.0.1:17891`, accepts the encrypted engine bytes from the web app over localhost, and crunches CSVs natively via the Rust engine (Polars + multi-core).

## Install

```bash
curl -fsSL https://member.royaltypro.app/install | bash
```

## Uninstall

```bash
curl -fsSL https://member.royaltypro.app/uninstall | bash
```

## Privacy

- Helper has **no engine code on disk** — engine bytes are fetched fresh from the RoyaltyPro server each session, decrypted in helper RAM, loaded via `libloading`
- Helper **only processes files you pick** via the native macOS file dialog. It does not scan, watch, or read anything else
- Helper **never sends data anywhere** — output is handed back to the same browser tab over localhost
- Source is open here so you can audit exactly what runs

## How it works

```
Browser (member.royaltypro.app)
    │
    │ 1. Fetches encrypted engine dylib
    │ 2. Sends to helper via localhost POST
    ▼
Helper (127.0.0.1:17891)
    │
    │ 3. Decrypts in RAM, dlopens via libloading
    ▼
Engine dylib (native arm64 Rust)
    │
    │ 4. Processes CSV files chosen by user
    ▼
Encrypted bundle returned to browser
```

## Build from source

```bash
cargo build --release
codesign --sign - --force --timestamp=none target/release/rp_helper_mockup
```

## License

MIT
