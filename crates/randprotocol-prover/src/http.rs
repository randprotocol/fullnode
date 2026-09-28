//! The `prover_*` JSON-RPC listener: JSON-RPC 2.0 on `POST /`, one request object per body (no
//! batches, no notifications), four methods over a [`Service`]. Nothing here logs a request body:
//! a sealed job is opaque bytes to this layer and is handed straight to [`Service::submit`].

use crate::service::{Config, Refusal, Service, Shared};
use crate::wire::MAX_SEALED_JOB_BYTES;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use std::net::SocketAddr;

/// A sealed job travels as hex, which doubles it; 4 KiB covers the JSON-RPC envelope.
pub const MAX_BODY_BYTES: usize = 2 * MAX_SEALED_JOB_BYTES + 4096;

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const BAD_JOB: i64 = -32000;
pub const UNKNOWN_JOB: i64 = -32001;
pub const UNPAIRED: i64 = -32003;
pub const WITNESS_KIND: i64 = -32004;
pub const BUSY: i64 = -32005;

/// Binds `addr`, starts the [`Service`] on the current runtime and serves it. Returns the bound
/// address (for `:0`), the service and the server task.
pub async fn serve(addr: SocketAddr, cfg: Config) -> anyhow::Result<(SocketAddr, Shared, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let svc = Service::start(cfg);
    let app = Router::new()
        .route("/", post(handle))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(svc.clone());
    let task = tokio::spawn(async move {
        let app = app.into_make_service_with_connect_info::<SocketAddr>();
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("prover listener exited: {e}");
        }
    });
    Ok((bound, svc, task))
}

struct RpcError { code: i64, message: String, data: Option<Value> }

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> RpcError { RpcError { code, message: message.into(), data: None } }
    fn with_data(mut self, data: Value) -> RpcError { self.data = Some(data); self }
}

fn error_value(id: Value, e: RpcError) -> Value {
    let mut err = Map::new();
    err.insert("code".into(), json!(e.code));
    err.insert("message".into(), json!(e.message));
    if let Some(d) = e.data { err.insert("data".into(), d); }
    json!({ "jsonrpc": "2.0", "id": id, "error": Value::Object(err) })
}

async fn handle(State(svc): State<Shared>, body: Result<Bytes, BytesRejection>) -> (StatusCode, Json<Value>) {
    let body = match body {
        Ok(b) => b,
        // axum's own status (413 over the limit), with a body a JSON-RPC client can read.
        Err(rejection) => {
            let msg = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                format!("request body is larger than the {MAX_BODY_BYTES}-byte limit")
            } else {
                "the request body could not be read".to_string()
            };
            return (rejection.status(), Json(error_value(Value::Null, RpcError::new(INVALID_REQUEST, msg))));
        }
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::OK, Json(error_value(Value::Null, RpcError::new(PARSE_ERROR, "parse error")))),
    };
    (StatusCode::OK, Json(dispatch_one(&svc, req)))
}

fn dispatch_one(svc: &Service, req: Value) -> Value {
    let Value::Object(obj) = req else {
        let why = if req.is_array() { "batches are not served; send one request object" } else { "expected a request object" };
        return error_value(Value::Null, RpcError::new(INVALID_REQUEST, why));
    };
    let Some(id) = obj.get("id").cloned() else {
        return error_value(Value::Null, RpcError::new(INVALID_REQUEST, "notifications are not served; every request must carry an id"));
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return error_value(id, RpcError::new(INVALID_REQUEST, "jsonrpc must be \"2.0\""));
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return error_value(id, RpcError::new(INVALID_REQUEST, "missing method"));
    };
    let empty = Vec::new();
    let params = match obj.get("params") {
        None => &empty,
        Some(Value::Array(a)) => a,
        Some(_) => return error_value(id, RpcError::new(INVALID_PARAMS, "params must be an array")),
    };
    match dispatch(svc, method, params) {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(e) => error_value(id, e),
    }
}

fn one_string<'a>(params: &'a [Value], what: &str) -> Result<&'a str, RpcError> {
    match params {
        [Value::String(s)] => Ok(s),
        _ => Err(RpcError::new(INVALID_PARAMS, format!("expected one parameter: {what}"))),
    }
}

fn dispatch(svc: &Service, method: &str, params: &[Value]) -> Result<Value, RpcError> {
    match method {
        "prover_info" => serde_json::to_value(svc.info()).map_err(|e| RpcError::new(BAD_JOB, e.to_string())),
        "prover_submit" => {
            let sealed = hex::decode(one_string(params, "the sealed job as hex")?)
                .map_err(|_| RpcError::new(INVALID_PARAMS, "the sealed job is not hex"))?;
            match svc.submit(&sealed) {
                Ok(job) => Ok(json!({ "job": job })),
                Err(Refusal::Bad(reason)) => Err(RpcError::new(BAD_JOB, "bad job").with_data(json!({ "reason": reason }))),
                Err(Refusal::Unpaired) => Err(RpcError::new(UNPAIRED, "the job's token is not paired with this prover")),
                Err(Refusal::WitnessKind(reason)) => {
                    Err(RpcError::new(WITNESS_KIND, "witness kind not accepted").with_data(json!({ "reason": reason })))
                }
                Err(Refusal::Busy { depth, max }) => {
                    Err(RpcError::new(BUSY, "busy").with_data(json!({ "depth": depth, "max": max })))
                }
            }
        }
        "prover_status" => {
            let id = one_string(params, "the job id")?;
            let s = svc.status(id).ok_or_else(|| RpcError::new(UNKNOWN_JOB, "unknown job"))?;
            let mut out = Map::new();
            out.insert("state".into(), json!(s.state.as_str()));
            if let Some(p) = s.position { out.insert("position".into(), json!(p)); }
            if let Some(r) = s.reply { out.insert("reply".into(), json!(hex::encode(r))); }
            if let Some(e) = s.error { out.insert("error".into(), json!(e)); }
            Ok(Value::Object(out))
        }
        "prover_cancel" => {
            let id = one_string(params, "the job id")?;
            if svc.status(id).is_none() {
                return Err(RpcError::new(UNKNOWN_JOB, "unknown job"));
            }
            Ok(json!({ "cancelled": svc.cancel(id) }))
        }
        _ => Err(RpcError::new(METHOD_NOT_FOUND, "method not found")),
    }
}
