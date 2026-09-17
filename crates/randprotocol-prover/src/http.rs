//! The job API (spec §5): submit, status, result, health.

use crate::{check_bind, Config, Refusal, Service, Shared};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::net::SocketAddr;

/// A job is a program of at most a few hundred KB plus inputs; 8 MiB bounds a malicious body
/// long before it costs anything.
const MAX_JOB_BYTES: usize = 8 * 1024 * 1024;

pub async fn serve(addr: SocketAddr, cfg: Config) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    check_bind(addr, &cfg)?;
    let svc = Service::new(cfg);
    let app = Router::new()
        .route("/v1/jobs", post(submit))
        .route("/v1/jobs/:id", get(status))
        .route("/v1/jobs/:id/result", get(result))
        .route("/v1/health", get(health))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_JOB_BYTES))
        .with_state(svc);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
            tracing::error!("prover server exited: {e}");
        }
    });
    Ok((bound, task))
}

/// The bearer, compared without leaking where it first differs.
///
/// A byte-by-byte `==` returns sooner the earlier it disagrees, and a caller who can time a few
/// thousand 401s can walk a token out of that. Both sides are hashed and the 32-byte digests
/// compared in constant time: equal digests mean equal tokens, and the digest of a guess tells an
/// attacker nothing about the secret. The scheme name is matched case-insensitively — RFC 7235
/// says it is case-insensitive, and a client that sends `bearer` is not an unauthorized one.
fn authorized(headers: &HeaderMap, svc: &Service) -> bool {
    let Some(t) = &svc.cfg.token else { return true };
    let Some(got) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim_start)
        .and_then(|v| v.get(..7).filter(|s| s.eq_ignore_ascii_case("bearer ")).map(|_| &v[7..]))
    else {
        return false;
    };
    blake3::hash(got.as_bytes()) == blake3::hash(t.as_bytes())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "missing or wrong bearer token" }))).into_response()
}

async fn submit(State(svc): State<Shared>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&headers, &svc) {
        return unauthorized();
    }
    match svc.submit(&body, peer.ip()) {
        Ok((id, position)) => (StatusCode::ACCEPTED, Json(json!({ "id": id, "position": position }))).into_response(),
        Err(Refusal::Bad(e)) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
        Err(Refusal::Busy(e, retry)) => (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": e, "retry_after_secs": retry }))).into_response(),
    }
}

async fn status(State(svc): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if !authorized(&headers, &svc) {
        return unauthorized();
    }
    match svc.status(&id) {
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown job" }))).into_response(),
        Some((state, position, elapsed)) => {
            let mut v = json!({ "state": state.as_str() });
            if let Some(p) = position { v["position"] = json!(p); }
            if let Some(ms) = elapsed { v["elapsed_ms"] = json!(ms as u64); }
            Json(v).into_response()
        }
    }
}

/// The sealed result, once there is one. Only a `done` or `failed` job ever has one: a job
/// that `expired` was never proved, so this stays 404 for it, and a wallet treats `expired` as
/// terminal and does not come here.
async fn result(State(svc): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if !authorized(&headers, &svc) {
        return unauthorized();
    }
    match svc.result(&id) {
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "no result for that job" }))).into_response(),
        Some(sealed) => ([(header::CONTENT_TYPE, "application/octet-stream")], randprotocol_zkvm::delegate::encode(&sealed)).into_response(),
    }
}

/// Open on purpose: a wallet checks the address it pinned before it sends a token or a job.
async fn health(State(svc): State<Shared>) -> Response {
    let (queue_depth, proving) = svc.queue_depth();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "backend": svc.backend_name(),
        "slots": svc.cfg.slots,
        "queue_depth": queue_depth,
        "proving": proving,
        "address": svc.cfg.key.address.to_string(),
    }))
    .into_response()
}
