use axum::Router;
use axum::body::Body;
use std::time::Duration;

use axum::http::{Request, StatusCode};
use lfsx_server::config::{Auth, Config};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn app(root: &tempfile::TempDir) -> Router {
    app_with_grace(root, std::time::Duration::from_secs(14 * 24 * 60 * 60))
}

fn app_with_grace(root: &tempfile::TempDir, gc_grace: std::time::Duration) -> Router {
    lfsx_server::app(Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        storage_root: root.path().to_path_buf(),
        public_url: Some("https://lfs.example".into()),
        action_lifetime: 1800,
        gc_grace,
        staging_max_age: Duration::from_secs(86400),
        lock_max_age: None,
        max_object_size: None,
        max_concurrent_transfers: 128,
        repo_quota: None,
        compression: None,
        encryption_key: None,
        storage: lfsx_server::config::Storage::Local,
        auth: Auth::Disabled,
    })
}

fn oid_of(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

async fn put(app: Router, oid: &str, payload: &[u8]) -> StatusCode {
    let request = Request::builder()
        .method("PUT")
        .uri(format!("/FerrLabs/Demo/objects/{oid}"))
        .header("content-length", payload.len())
        .body(Body::from(payload.to_vec()))
        .unwrap();

    app.oneshot(request).await.unwrap().status()
}

async fn batch(app: Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/FerrLabs/Demo/objects/batch")
        .header("content-type", "application/vnd.git-lfs+json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    (status, serde_json::from_slice(&bytes).unwrap())
}

// The object count is the client's to choose, and each one costs a round trip
// against storage the operator pays per request for. No client sends anything
// near this, so a batch that does is refused rather than served slowly.
#[tokio::test]
async fn a_batch_past_the_ceiling_is_refused_and_says_so() {
    let root = tempfile::tempdir().unwrap();

    let objects: Vec<_> = (0..1_001)
        .map(|n| serde_json::json!({ "oid": oid_of(format!("object {n}").as_bytes()), "size": 1 }))
        .collect();

    let (status, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "download",
            "transfers": ["basic"],
            "objects": objects
        }),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("1000"),
        "refusing without naming the ceiling leaves the client nothing to do about it: {body}"
    );
}

// A thousand is the ceiling, so a thousand is served. A backstop that refuses
// what a client might legitimately send would be a policy nobody chose.
#[tokio::test]
async fn a_batch_at_the_ceiling_is_answered() {
    let root = tempfile::tempdir().unwrap();

    let objects: Vec<_> = (0..1_000)
        .map(|n| serde_json::json!({ "oid": oid_of(format!("object {n}").as_bytes()), "size": 1 }))
        .collect();

    let (status, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "download",
            "transfers": ["basic"],
            "objects": objects
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["objects"].as_array().unwrap().len(), 1_000);
}

// The objects are resolved a few at a time, so the answers do not arrive in the
// order they were asked for. They have to be returned in it.
#[tokio::test]
async fn a_batch_answers_in_the_order_it_was_asked() {
    let root = tempfile::tempdir().unwrap();

    let asked: Vec<String> = (0..200)
        .map(|n| oid_of(format!("object {n} of an ordered batch").as_bytes()))
        .collect();
    let objects: Vec<_> = asked
        .iter()
        .map(|oid| serde_json::json!({ "oid": oid, "size": 1 }))
        .collect();

    let (status, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "download",
            "transfers": ["basic"],
            "objects": objects
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let answered: Vec<&str> = body["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|object| object["oid"].as_str().unwrap())
        .collect();

    assert_eq!(
        answered, asked,
        "a reordered batch is a batch a client cannot match up"
    );
}

#[tokio::test]
async fn stored_object_comes_back_byte_for_byte() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"some genuinely heavy assets".repeat(1000);
    let oid = oid_of(&payload);

    assert_eq!(put(app(&root), &oid, &payload).await, StatusCode::OK);

    let request = Request::builder()
        .uri(format!("/FerrLabs/Demo/objects/{oid}"))
        .body(Body::empty())
        .unwrap();
    let response = app(&root).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn content_that_does_not_hash_to_the_declared_oid_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let lie = oid_of(b"what the client claims to send");

    let status = put(app(&root), &lie, b"what it actually sends").await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let stored = walkdir(root.path());
    assert!(stored.is_empty(), "a corrupt object was kept");
}

#[tokio::test]
async fn a_truncated_upload_is_rejected_and_leaves_nothing_behind() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"the complete payload".to_vec();
    let oid = oid_of(&payload);

    let request = Request::builder()
        .method("PUT")
        .uri(format!("/FerrLabs/Demo/objects/{oid}"))
        .header("content-length", payload.len() + 10)
        .body(Body::from(payload))
        .unwrap();

    let status = app(&root).oneshot(request).await.unwrap().status();

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(walkdir(root.path()).is_empty());
}

#[tokio::test]
async fn an_oid_that_is_not_a_sha256_digest_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let status = put(app(&root), "../../../etc/passwd", b"x").await;
    assert_ne!(status, StatusCode::OK);
}

#[tokio::test]
async fn downloading_an_unknown_object_reports_it_per_object() {
    let root = tempfile::tempdir().unwrap();
    let (status, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "download",
            "transfers": ["basic"],
            "objects": [{ "oid": oid_of(b"never pushed"), "size": 12 }]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["objects"][0]["error"]["code"], 404);
    assert!(body["objects"][0]["actions"].is_null());
}

#[tokio::test]
async fn an_object_already_stored_is_not_asked_for_again() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"already here".to_vec();
    let oid = oid_of(&payload);
    put(app(&root), &oid, &payload).await;

    let (_, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "upload",
            "transfers": ["basic"],
            "objects": [{ "oid": oid, "size": payload.len() }]
        }),
    )
    .await;

    assert!(
        body["objects"][0]["actions"].is_null(),
        "the client would re-upload an object already stored"
    );
    assert!(body["objects"][0]["error"].is_null());
}

// git-lfs asks for the verify action only once the upload has finished, and
// an expired one sends it back to the batch for a fresh upload. With an expiry
// on verify, an upload slower than the lifetime starts over, forever.
#[tokio::test]
async fn a_verify_action_never_expires() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"a slow upload".to_vec();
    let oid = oid_of(&payload);

    let (_, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "upload",
            "transfers": ["basic"],
            "objects": [{ "oid": oid, "size": payload.len() }]
        }),
    )
    .await;

    let verify = &body["objects"][0]["actions"]["verify"];
    assert!(verify["href"].is_string(), "no verify action: {body}");
    assert!(
        verify["expires_in"].is_null() && verify["expires_at"].is_null(),
        "an upload that outlasts the expiry is sent again from the start: {body}"
    );
}

#[tokio::test]
async fn batch_never_claims_a_transfer_through_this_server_is_pre_authenticated() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"payload".to_vec();
    let oid = oid_of(&payload);
    put(app(&root), &oid, &payload).await;

    let (_, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "download",
            "transfers": ["basic"],
            "objects": [{ "oid": oid, "size": payload.len() }]
        }),
    )
    .await;

    assert!(
        body["objects"][0]["authenticated"].is_null(),
        "advertising authenticated for a URL that points back here makes the client transfer \n\
             with no credentials at all, and loop on the 401 that follows. The only href this server \n\
             signs is a pre-signed bucket URL, and this is not one"
    );
}

async fn retain(app: Router, oids: &[&str], dry_run: bool) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "oids": oids, "dry_run": dry_run });
    let request = Request::builder()
        .method("POST")
        .uri("/FerrLabs/Demo/objects/retain")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn is_stored(app: Router, oid: &str) -> bool {
    let request = Request::builder()
        .uri(format!("/FerrLabs/Demo/objects/{oid}"))
        .body(Body::empty())
        .unwrap();

    app.oneshot(request).await.unwrap().status() == StatusCode::OK
}

#[tokio::test]
async fn an_object_nothing_references_any_more_is_swept() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"an asset a rewritten history left behind".repeat(10);
    let oid = oid_of(&payload);
    let app = app_with_grace(&root, Duration::ZERO);

    assert_eq!(put(app.clone(), &oid, &payload).await, StatusCode::OK);
    let (status, report) = retain(app.clone(), &[], false).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(report["swept"], 1);
    assert_eq!(report["bytes"], payload.len());
    assert!(!is_stored(app, &oid).await, "the object survived the sweep");
}

#[tokio::test]
async fn an_object_uploaded_but_not_yet_referenced_survives() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"pushed before the commit that references it".to_vec();
    let oid = oid_of(&payload);
    let app = app_with_grace(&root, Duration::from_secs(3600));

    assert_eq!(put(app.clone(), &oid, &payload).await, StatusCode::OK);
    let (_, report) = retain(app.clone(), &[], false).await;

    assert_eq!(report["swept"], 0);
    assert_eq!(report["within_grace"], 1);
    assert!(
        is_stored(app, &oid).await,
        "an object still inside the grace period was collected mid-push"
    );
}

#[tokio::test]
async fn a_referenced_object_is_kept_however_old_it_is() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"still pointed at by a commit".to_vec();
    let oid = oid_of(&payload);
    let app = app_with_grace(&root, Duration::ZERO);

    assert_eq!(put(app.clone(), &oid, &payload).await, StatusCode::OK);
    let (_, report) = retain(app.clone(), &[&oid], false).await;

    assert_eq!(report["swept"], 0);
    assert!(is_stored(app, &oid).await);
}

#[tokio::test]
async fn a_dry_run_reports_what_it_would_free_and_frees_nothing() {
    let root = tempfile::tempdir().unwrap();
    let first = b"the first orphan".to_vec();
    let second = b"the second orphan".to_vec();
    let app = app_with_grace(&root, Duration::ZERO);

    put(app.clone(), &oid_of(&first), &first).await;
    put(app.clone(), &oid_of(&second), &second).await;

    let (_, report) = retain(app.clone(), &[], true).await;

    assert_eq!(report["swept"], 2);
    assert_eq!(report["bytes"], first.len() + second.len());
    assert_eq!(report["dry_run"], true);
    assert!(is_stored(app.clone(), &oid_of(&first)).await);
    assert!(is_stored(app, &oid_of(&second)).await);
}

#[tokio::test]
async fn a_transfer_in_flight_is_not_swept_from_under_the_client() {
    let root = tempfile::tempdir().unwrap();
    let oid = oid_of(b"whatever it will hash to");
    let staging = root
        .path()
        .join("FerrLabs/Demo")
        .join(&oid[0..2])
        .join(&oid[2..4]);
    std::fs::create_dir_all(&staging).unwrap();
    let staged = staging.join(format!("{oid}.0.part"));
    std::fs::write(&staged, b"half an upload").unwrap();

    let (_, report) = retain(app_with_grace(&root, Duration::ZERO), &[], false).await;

    assert_eq!(report["swept"], 0);
    assert!(staged.exists(), "a staging file was collected mid-upload");
}

async fn get(app: Router, path: &str) -> StatusCode {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();

    app.oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn readiness_and_liveness_are_both_green_on_a_working_store() {
    let root = tempfile::tempdir().unwrap();

    assert_eq!(get(app(&root), "/health").await, StatusCode::OK);
    assert_eq!(get(app(&root), "/ready").await, StatusCode::OK);
}

#[tokio::test]
async fn a_storage_root_that_cannot_be_written_fails_readiness_but_not_liveness() {
    let root = tempfile::tempdir().unwrap();
    let blocked = root.path().join("occupied");
    std::fs::write(&blocked, b"a file where the storage root should be").unwrap();

    let app = lfsx_server::app(Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        storage_root: blocked.join("objects"),
        public_url: Some("https://lfs.example".into()),
        action_lifetime: 1800,
        gc_grace: Duration::ZERO,
        staging_max_age: Duration::from_secs(86400),
        lock_max_age: None,
        max_object_size: None,
        max_concurrent_transfers: 128,
        repo_quota: None,
        compression: None,
        encryption_key: None,
        storage: lfsx_server::config::Storage::Local,
        auth: Auth::Disabled,
    });

    assert_eq!(
        get(app.clone(), "/ready").await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a broken mount must take the instance out of rotation"
    );
    assert_eq!(
        get(app, "/health").await,
        StatusCode::OK,
        "the process is alive, restarting it would not help"
    );
}

fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }

    found
}

#[tokio::test]
async fn transfers_are_advertised_on_the_host_the_client_asked_for() {
    let root = tempfile::tempdir().unwrap();
    let app = lfsx_server::app(Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        storage_root: root.path().to_path_buf(),
        public_url: None,
        action_lifetime: 1800,
        gc_grace: Duration::ZERO,
        staging_max_age: Duration::from_secs(86400),
        lock_max_age: None,
        max_object_size: None,
        max_concurrent_transfers: 128,
        repo_quota: None,
        compression: None,
        encryption_key: None,
        storage: lfsx_server::config::Storage::Local,
        auth: Auth::Disabled,
    });

    let request = Request::builder()
        .method("POST")
        .uri("/FerrLabs/Demo/objects/batch")
        .header("host", "lfs.home")
        .header("x-forwarded-proto", "https")
        .header("content-type", "application/vnd.git-lfs+json")
        .body(Body::from(
            serde_json::json!({
                "operation": "upload",
                "objects": [{ "oid": oid_of(b"asset"), "size": 5 }],
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    let href = body["objects"][0]["actions"]["upload"]["href"]
        .as_str()
        .unwrap();
    assert!(
        href.starts_with("https://lfs.home/"),
        "a server reachable under two names must answer on the one the client used, got {href}"
    );
}

#[tokio::test]
async fn a_configured_public_url_wins_over_the_request() {
    let root = tempfile::tempdir().unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/FerrLabs/Demo/objects/batch")
        .header("host", "sneaky.example")
        .header("content-type", "application/vnd.git-lfs+json")
        .body(Body::from(
            serde_json::json!({
                "operation": "upload",
                "objects": [{ "oid": oid_of(b"asset"), "size": 5 }],
            })
            .to_string(),
        ))
        .unwrap();

    let response = app(&root).oneshot(request).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    assert!(
        body["objects"][0]["actions"]["upload"]["href"]
            .as_str()
            .unwrap()
            .starts_with("https://lfs.example/"),
        "an explicit LFSX_PUBLIC_URL must not be overridable by a request header"
    );
}

async fn download_range(
    app: Router,
    oid: &str,
    range: Option<&str>,
) -> (StatusCode, Vec<u8>, String) {
    let mut request = Request::builder().uri(format!("/FerrLabs/Demo/objects/{oid}"));
    if let Some(range) = range {
        request = request.header("range", range);
    }

    let response = app
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_range = response
        .headers()
        .get("content-range")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    (status, bytes.to_vec(), content_range)
}

#[tokio::test]
async fn a_range_returns_exactly_those_bytes() {
    let root = tempfile::tempdir().unwrap();
    let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let oid = oid_of(&payload);
    put(app(&root), &oid, &payload).await;

    let (status, body, content_range) =
        download_range(app(&root), &oid, Some("bytes=1000-1999")).await;

    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, payload[1000..=1999]);
    assert_eq!(content_range, "bytes 1000-1999/4096");
}

#[tokio::test]
async fn an_interrupted_download_resumes_from_where_it_stopped() {
    let root = tempfile::tempdir().unwrap();
    let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let oid = oid_of(&payload);
    put(app(&root), &oid, &payload).await;

    let (_, first, _) = download_range(app(&root), &oid, Some("bytes=0-2047")).await;
    let (status, rest, content_range) = download_range(app(&root), &oid, Some("bytes=2048-")).await;

    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(content_range, "bytes 2048-4095/4096");
    assert_eq!(
        [first, rest].concat(),
        payload,
        "the two halves have to reassemble into the object byte for byte, which is the whole point"
    );
}

#[tokio::test]
async fn a_whole_object_still_answers_200_and_advertises_ranges() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"an ordinary asset".to_vec();
    let oid = oid_of(&payload);
    put(app(&root), &oid, &payload).await;

    let request = Request::builder()
        .uri(format!("/FerrLabs/Demo/objects/{oid}"))
        .body(Body::empty())
        .unwrap();
    let response = app(&root).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["accept-ranges"], "bytes");
    assert_eq!(response.headers()["content-length"], "17");
}

#[tokio::test]
async fn a_range_past_the_object_is_refused_with_its_real_size() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"small".to_vec();
    let oid = oid_of(&payload);
    put(app(&root), &oid, &payload).await;

    let (status, _, content_range) =
        download_range(app(&root), &oid, Some("bytes=9000-9999")).await;

    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        content_range, "bytes */5",
        "the client needs the real size to work out what it may ask for"
    );
}

// The boundary the Oid type made explicit. A name that is not a digest never
// reaches storage: a download of one is the same absent object a well-formed
// missing digest is, an upload of one is refused per object instead of being
// handed a URL whose transfer was always going to fail, and the transfer
// routes answer 422 for it themselves.
#[tokio::test]
async fn a_name_that_is_not_a_digest_never_reaches_storage() {
    let root = tempfile::tempdir().unwrap();

    let (status, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "download",
            "transfers": ["basic"],
            "objects": [{ "oid": "../../etc/passwd", "size": 1 }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["objects"][0]["error"]["code"], 404);

    let (status, body) = batch(
        app(&root),
        serde_json::json!({
            "operation": "upload",
            "transfers": ["basic"],
            "objects": [{ "oid": "not-a-digest", "size": 1 }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["objects"][0]["error"]["code"], 422,
        "an upload URL for a name that can never verify tells the client to \
         spend the bytes first: {body}"
    );
    assert!(body["objects"][0]["actions"].is_null(), "{body}");

    assert_eq!(
        put(app(&root), "abc", b"payload").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
