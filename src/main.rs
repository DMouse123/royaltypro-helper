// RoyaltyPro Fast Import Helper — phase 3 (real FFI-based engine load).
//
// Localhost HTTP service. Browser POSTs decrypted dylib bytes at session
// start; helper dlopens them and resolves the engine's C ABI surface
// (rp_alloc, rp_free, rp_process, rp_version). Subsequent /process
// requests invoke the loaded engine directly via FFI — no shell-out.
//
// Endpoints:
//   GET  /healthz       → liveness + engine loaded yes/no + version
//   POST /init          → accept dylib bytes (binary body), dlopen, ready
//   POST /process       → run rp_process on the supplied CSV paths
//   GET  /status/{id}   → poll a running job
//
// Engine isolation: the dylib is briefly written to a per-session temp
// file then dlopen'd. When the helper quits the temp file is removed
// (and on next launch a fresh path is used). True RAM-only loading via
// mmap+exec is a v2 polish; on-disk-during-session is the simpler start.

use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::http::header;
use axum::response::IntoResponse;
use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use libloading::{Library, Symbol};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::cors::{AllowOrigin, CorsLayer};
use axum::http::HeaderValue;

const PORT: u16 = 17891;

// ── FFI types matching native_tool/src/lib.rs ─────────────────────────
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RpResult {
    ptr: *mut u8,
    len: usize,
}

type FnRpAlloc = unsafe extern "C" fn(len: usize) -> *mut u8;
type FnRpFree = unsafe extern "C" fn(ptr: *mut u8, len: usize);
type FnRpLastError = unsafe extern "C" fn() -> *const c_char;
type FnRpVersion = unsafe extern "C" fn() -> *const c_char;
type FnRpProcess = unsafe extern "C" fn(
    csv_ptr: *const u8,
    csv_len: usize,
    name_ptr: *const u8,
    name_len: usize,
) -> RpResult;
type FnRpRun = unsafe extern "C" fn(request_ptr: *const u8, request_len: usize) -> RpResult;
type FnRpProgress = unsafe extern "C" fn() -> u64;

// Sendable wrappers — we hold the function pointers across threads.
// Safety: the dylib stays loaded for the helper's lifetime, the
// pointers point at code pages that are immutable, and the engine
// itself uses thread-local state only.
#[derive(Clone)]
struct EngineApi {
    _lib: Arc<Library>, // keep dylib loaded; Drop unloads on shutdown
    alloc: FnRpAlloc,
    free: FnRpFree,
    last_error: FnRpLastError,
    process: FnRpProcess,
    run: FnRpRun,
    progress: Option<FnRpProgress>,
    version: String,
    loaded_at_ms: u128,
    dylib_path: String,
    sha256_hex: String,
}

unsafe impl Send for EngineApi {}
unsafe impl Sync for EngineApi {}

static ENGINE: OnceCell<Mutex<Option<EngineApi>>> = OnceCell::new();
fn engine_slot() -> &'static Mutex<Option<EngineApi>> {
    ENGINE.get_or_init(|| Mutex::new(None))
}

// ── App state ─────────────────────────────────────────────────────────
#[derive(Clone, Default)]
struct AppState {
    jobs: Arc<Mutex<HashMap<String, JobStatus>>>,
}

#[derive(Serialize, Clone)]
struct JobStatus {
    id: String,
    state: String,
    started_ms: u128,
    elapsed_ms: u128,
    paths: Vec<String>,
    bundle_path: Option<String>,
    bundle_size: u64,
    password: Option<String>,
    /// "json" (helper path, no envelope) or "bundle" (.RoyaltyProData).
    format: Option<String>,
    error: Option<String>,
    // Live progress (populated by /status handler each time it's hit, via
    // rp_progress() FFI on the loaded engine). Skipped from serialization
    // if None so older clients ignoring these fields stay compatible.
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_name: Option<String>,
}

// ── Responses ─────────────────────────────────────────────────────────
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    helper_version: &'static str,
    engine_loaded: bool,
    engine_version: Option<String>,
    engine_sha256: Option<String>,
    engine_loaded_at_ms: Option<u128>,
}

#[derive(Serialize)]
struct InitResponse {
    ok: bool,
    engine_version: String,
    sha256: String,
    bytes: usize,
}

#[derive(Deserialize)]
struct ProcessRequest {
    paths: Vec<String>,
}

#[derive(Serialize)]
struct ProcessResponse {
    #[serde(rename = "jobId")]
    job_id: String,
    state: String,
}

// ── HTTP handlers ─────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = AppState::default();

    // v0.0.4: lock CORS to known production + dev origins ONLY.
    // Was: .allow_origin(Any) — accepted requests from ANY origin, including
    // malicious tabs the user happens to have open. With the helper exposing
    // /process (arbitrary file read) and /init (dylib upload + dlopen),
    // wildcard CORS = drive-by file exfiltration + RCE from any web page.
    // The browser sets the Origin header and JS can't spoof it, so a strict
    // allowlist + browser CORS enforcement closes the entire web-borne attack
    // surface. Non-browser callers (curl, native attackers) bypass CORS but
    // already need filesystem access to do harm; web-borne is the real threat.
    let allowed_origins: Vec<HeaderValue> = vec![
        "https://member.royaltypro.app".parse().unwrap(),
        "http://localhost:5173".parse().unwrap(),  // dev vite
        "http://localhost:2222".parse().unwrap(),  // dev node server
    ];
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/init",
            post(init_engine).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
        .route("/pick", post(pick_files))
        .route("/process", post(start_process))
        .route("/status/:id", get(get_status))
        .route("/bundle/:id", get(get_bundle))
        .layer(cors)
        .with_state(state);

    let addr = format!("127.0.0.1:{}", PORT);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("[helper] phase-3 helper listening on http://{}", addr);
    println!("[helper] POST /init with dylib bytes to load the engine");
    axum::serve(listener, app).await.unwrap();
}

async fn healthz() -> Json<HealthResponse> {
    let guard = engine_slot().lock().unwrap();
    let resp = match guard.as_ref() {
        Some(eng) => HealthResponse {
            status: "ok".to_string(),
            helper_version: env!("CARGO_PKG_VERSION"),
            engine_loaded: true,
            engine_version: Some(eng.version.clone()),
            engine_sha256: Some(eng.sha256_hex.clone()),
            engine_loaded_at_ms: Some(eng.loaded_at_ms),
        },
        None => HealthResponse {
            status: "no_engine".to_string(),
            helper_version: env!("CARGO_PKG_VERSION"),
            engine_loaded: false,
            engine_version: None,
            engine_sha256: None,
            engine_loaded_at_ms: None,
        },
    };
    Json(resp)
}

async fn init_engine(body: Bytes) -> Result<Json<InitResponse>, (StatusCode, String)> {
    if body.len() < 1000 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("init body too small: {} bytes", body.len()),
        ));
    }

    // True SHA-256 of the dylib bytes — must match what the member portal
    // returns in the X-Engine-SHA256 header so the web app can detect when
    // its in-RAM engine is out of sync with the server's current dylib.
    // Helper v0.0.2 and earlier used a non-cryptographic DefaultHasher
    // here and labelled it sha256_hex — never matched real SHA-256, which
    // broke auto-sync.
    let sha256_hex = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let digest = hasher.finalize();
        let mut s = String::with_capacity(64);
        for b in digest { use std::fmt::Write as _; let _ = write!(&mut s, "{:02x}", b); }
        s
    };
    // Old DefaultHasher path kept here as dead code reference for future
    // git-blame digs. Remove after v0.0.3 is widely deployed.
    let _ = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        body.as_ref().hash(&mut h);
        format!("{:016x}", h.finish())
    };

    // Write to a per-session temp file then dlopen.
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join(format!(
        "rp-engine-{}-{}.dylib",
        std::process::id(),
        chrono_ish_now_millis()
    ));
    if let Err(e) = std::fs::write(&path, body.as_ref()) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write dylib temp: {}", e),
        ));
    }

    // dlopen + resolve symbols
    let lib = match unsafe { Library::new(&path) } {
        Ok(l) => l,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("dlopen failed: {} (path: {})", e, path.display()),
            ));
        }
    };

    // Resolve all symbols
    let alloc: Symbol<FnRpAlloc> = match unsafe { lib.get(b"rp_alloc\0") } {
        Ok(s) => s,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("rp_alloc: {}", e))),
    };
    let free: Symbol<FnRpFree> = match unsafe { lib.get(b"rp_free\0") } {
        Ok(s) => s,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("rp_free: {}", e))),
    };
    let last_error: Symbol<FnRpLastError> = match unsafe { lib.get(b"rp_last_error\0") } {
        Ok(s) => s,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("rp_last_error: {}", e))),
    };
    let process: Symbol<FnRpProcess> = match unsafe { lib.get(b"rp_process\0") } {
        Ok(s) => s,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("rp_process: {}", e))),
    };
    let version_fn: Symbol<FnRpVersion> = match unsafe { lib.get(b"rp_version\0") } {
        Ok(s) => s,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("rp_version: {}", e))),
    };
    let run: Symbol<FnRpRun> = match unsafe { lib.get(b"rp_run\0") } {
        Ok(s) => s,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("rp_run: {}", e))),
    };
    // rp_progress is optional — older dylib versions don't ship it. If
    // resolving fails we just don't expose progress to the web app; the
    // import still works, just without per-file feedback.
    let progress_sym: Option<Symbol<FnRpProgress>> = unsafe { lib.get(b"rp_progress\0").ok() };
    let progress: Option<FnRpProgress> = progress_sym.as_deref().copied();

    let version_str = unsafe {
        let p = version_fn();
        CStr::from_ptr(p).to_string_lossy().into_owned()
    };

    let api = EngineApi {
        // Capture raw function pointers — we drop the Symbol borrow but
        // keep the Library alive via the Arc.
        alloc: *alloc,
        free: *free,
        last_error: *last_error,
        process: *process,
        run: *run,
        progress,
        version: version_str.clone(),
        loaded_at_ms: chrono_ish_now_millis(),
        dylib_path: path.to_string_lossy().into_owned(),
        sha256_hex: sha256_hex.clone(),
        _lib: Arc::new(lib),
    };

    println!(
        "[helper] engine loaded: version={} sha256(short)={} bytes={} path={}",
        version_str,
        sha256_hex,
        body.len(),
        path.display()
    );

    let mut guard = engine_slot().lock().unwrap();
    *guard = Some(api);

    Ok(Json(InitResponse {
        ok: true,
        engine_version: version_str,
        sha256: sha256_hex,
        bytes: body.len(),
    }))
}

async fn start_process(
    State(state): State<AppState>,
    Json(req): Json<ProcessRequest>,
) -> (StatusCode, Json<ProcessResponse>) {
    let job_id = format!("job_{}", chrono_ish_now_millis());
    let now = chrono_ish_now_millis();

    // Engine must be loaded first
    if engine_slot().lock().unwrap().is_none() {
        let s = JobStatus {
            id: job_id.clone(),
            state: "error".to_string(),
            started_ms: now,
            elapsed_ms: 0,
            paths: req.paths.clone(),
            bundle_path: None,
            bundle_size: 0,
            password: None,
            format: None,
            error: Some("engine not loaded — POST /init first".to_string()),
            stage: None, current_index: None, total: None, current_name: None,
        };
        state.jobs.lock().unwrap().insert(job_id.clone(), s);
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(ProcessResponse {
                job_id,
                state: "error".to_string(),
            }),
        );
    }

    let initial = JobStatus {
        id: job_id.clone(),
        state: "running".to_string(),
        started_ms: now,
        elapsed_ms: 0,
        paths: req.paths.clone(),
        bundle_path: None,
        bundle_size: 0,
        password: None,
        format: None,
        error: None,
        stage: None, current_index: None, total: None, current_name: None,
    };
    state.jobs.lock().unwrap().insert(job_id.clone(), initial);

    let jobs = state.jobs.clone();
    let job_id_bg = job_id.clone();
    tokio::task::spawn_blocking(move || {
        run_engine_process(jobs, job_id_bg, req.paths);
    });

    (
        StatusCode::ACCEPTED,
        Json(ProcessResponse {
            job_id,
            state: "running".to_string(),
        }),
    )
}

/// Native file picker via AppleScript. Mac-only for now; cross-platform
/// can use the `rfd` crate later. Returns absolute paths the user selected,
/// or an empty array if they cancelled.
async fn pick_files() -> Result<Json<Vec<String>>, (StatusCode, String)> {
    // osascript blocks until the user closes the dialog — run in spawn_blocking
    let paths = tokio::task::spawn_blocking(|| {
        let output = std::process::Command::new("osascript")
            .args([
                "-e",
                r#"set theFiles to choose file with prompt "Select CSV files to import" with multiple selections allowed
set posixList to {}
repeat with f in theFiles
    set end of posixList to POSIX path of f
end repeat
set AppleScript's text item delimiters to "\n"
return posixList as text"#,
            ])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout);
                s.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
            }
            Ok(_) => Vec::new(), // user cancelled
            Err(_) => Vec::new(),
        }
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("pick: {}", e)))?;
    println!("[helper] pick returned {} paths", paths.len());
    Ok(Json(paths))
}

async fn get_bundle(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (bundle_path, body_format) = {
        let map = state.jobs.lock().unwrap();
        let job = map.get(&id).ok_or((StatusCode::NOT_FOUND, "job not found".to_string()))?;
        if job.state != "done" {
            return Err((
                StatusCode::PRECONDITION_FAILED,
                format!("job state={}, not done", job.state),
            ));
        }
        let path = job
            .bundle_path
            .clone()
            .ok_or((StatusCode::NOT_FOUND, "no bundle path".to_string()))?;
        let fmt = job.format.clone().unwrap_or_else(|| "bundle".to_string());
        (path, fmt)
    };
    let bytes = std::fs::read(&bundle_path).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("read bundle: {}", e))
    })?;
    let ct = match body_format.as_str() {
        "json" => "application/json",
        "ndjson" => "application/x-ndjson",
        _ => "application/octet-stream",
    };
    Ok(([(header::CONTENT_TYPE, ct)], bytes))
}

async fn get_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JobStatus>, StatusCode> {
    // Snapshot the job + the live engine progress under separate locks so
    // we don't hold the jobs lock across the engine FFI call.
    let mut s = {
        let map = state.jobs.lock().unwrap();
        match map.get(&id) {
            Some(status) => status.clone(),
            None => return Err(StatusCode::NOT_FOUND),
        }
    };
    if s.state == "running" {
        s.elapsed_ms = chrono_ish_now_millis() - s.started_ms;
        // Pull live progress from the engine's atomic counter. Decode the
        // packed u64 set by set_progress() in native_tool:
        //   bits 0..32  = current_index (0-based)
        //   bits 32..40 = stage  (1=parsing, 2=summary_scan, 3=bundling, 4=done)
        //   bits 40..64 = total  (file count for this run)
        let progress_fn = engine_slot()
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|api| api.progress);
        if let Some(progress_fn) = progress_fn {
            let packed = unsafe { progress_fn() };
            let current = (packed & 0xFFFFFFFF) as u32;
            let stage_code = ((packed >> 32) & 0xFF) as u32;
            let total = ((packed >> 40) & 0xFFFFFF) as u32;
            let stage_name = match stage_code {
                1 => Some("parsing".to_string()),
                2 => Some("summary_scan".to_string()),
                3 => Some("bundling".to_string()),
                4 => Some("done".to_string()),
                _ => None,
            };
            if stage_code != 0 {
                s.stage = stage_name;
                s.current_index = Some(current);
                s.total = Some(if total > 0 { total } else { s.paths.len() as u32 });
                // Resolve current file name from paths array. During the
                // parsing stage `current` is the file index; during summary
                // scan it's the chunk index which usually matches file count.
                if (current as usize) < s.paths.len() {
                    s.current_name = std::path::PathBuf::from(&s.paths[current as usize])
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.to_string());
                }
            }
        }
    }
    Ok(Json(s))
}

fn run_engine_process(
    jobs: Arc<Mutex<HashMap<String, JobStatus>>>,
    job_id: String,
    paths: Vec<String>,
) {
    let started = Instant::now();

    let api = {
        let guard = engine_slot().lock().unwrap();
        match guard.as_ref() {
            Some(e) => e.clone(),
            None => {
                let mut m = jobs.lock().unwrap();
                if let Some(s) = m.get_mut(&job_id) {
                    s.state = "error".to_string();
                    s.error = Some("engine vanished mid-job".to_string());
                }
                return;
            }
        }
    };

    // Build the JSON request the dylib's rp_run expects.
    // `encrypt: false` — return raw inner JSON bytes instead of the
    // PBKDF2/AES-wrapped .RoyaltyProData bundle. The browser can parse the
    // JSON directly, sidestepping Chrome's SubtleCrypto 500MB AES-GCM wall.
    let request = serde_json::json!({
        "paths": paths,
        "password": "",     // ignored when encrypt=false
        "row_limit": 0,
        "encrypt": false,
    });
    let request_bytes = request.to_string().into_bytes();

    // Call rp_run via FFI
    let result = unsafe { (api.run)(request_bytes.as_ptr(), request_bytes.len()) };
    if result.ptr.is_null() || result.len == 0 {
        let err_str = unsafe {
            let p = (api.last_error)();
            if p.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        let mut m = jobs.lock().unwrap();
        if let Some(s) = m.get_mut(&job_id) {
            s.state = "error".to_string();
            s.elapsed_ms = started.elapsed().as_millis();
            s.error = Some(format!("rp_run: {}", err_str));
        }
        println!("[helper] job {} FAILED: {}", job_id, err_str);
        return;
    }

    // Result format: "HDR{json}\n<bundle bytes>"
    let total_len = result.len;
    let returned_bytes = unsafe { std::slice::from_raw_parts(result.ptr, total_len).to_vec() };
    unsafe { (api.free)(result.ptr, total_len) };

    // Parse the HDR line
    let newline_pos = returned_bytes.iter().position(|&b| b == b'\n');
    let (password, body_format, bundle_bytes) = match newline_pos {
        Some(pos) if returned_bytes.starts_with(b"HDR") => {
            let hdr_str = std::str::from_utf8(&returned_bytes[3..pos]).unwrap_or("{}");
            let hdr_json: serde_json::Value =
                serde_json::from_str(hdr_str).unwrap_or(serde_json::Value::Null);
            let pw = hdr_json
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let fmt = hdr_json
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("bundle")
                .to_string();
            let bundle = returned_bytes[pos + 1..].to_vec();
            (pw, fmt, bundle)
        }
        _ => {
            let mut m = jobs.lock().unwrap();
            if let Some(s) = m.get_mut(&job_id) {
                s.state = "error".to_string();
                s.elapsed_ms = started.elapsed().as_millis();
                s.error = Some("rp_run returned bytes without HDR prefix".to_string());
            }
            return;
        }
    };

    // Write body to OS temp dir. Extension matches the format so a human
    // poking around can tell which is which at a glance.
    let ext = match body_format.as_str() {
        "json" => "json",
        "ndjson" => "ndjson",
        _ => "RoyaltyProData",
    };
    let bundle_path = std::env::temp_dir().join(format!("rp-import-{}.{}", chrono_ish_now_millis(), ext));
    if let Err(e) = std::fs::write(&bundle_path, &bundle_bytes) {
        let mut m = jobs.lock().unwrap();
        if let Some(s) = m.get_mut(&job_id) {
            s.state = "error".to_string();
            s.elapsed_ms = started.elapsed().as_millis();
            s.error = Some(format!("write bundle: {}", e));
        }
        return;
    }

    let elapsed_ms = started.elapsed().as_millis();
    let bundle_size = bundle_bytes.len() as u64;
    let bundle_str = bundle_path.to_string_lossy().into_owned();

    let mut m = jobs.lock().unwrap();
    if let Some(s) = m.get_mut(&job_id) {
        s.state = "done".to_string();
        s.elapsed_ms = elapsed_ms;
        s.bundle_path = Some(bundle_str.clone());
        s.bundle_size = bundle_size;
        s.password = Some(password.clone());
        s.format = Some(body_format.clone());
    }
    println!(
        "[helper] job {} done in {}ms: {} body {} ({} bytes, pw={})",
        job_id, elapsed_ms, body_format, bundle_str, bundle_size, password
    );
}

fn chrono_ish_now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
