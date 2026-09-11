// These run against a real S3 implementation, which is the only place the
// claims this backend makes can be checked at all. The stub the unit tests use
// proves the layout and the wire format; it cannot prove that SigV4 binds the
// method, that a pre-signed URL is honoured with no credentials, or that a
// prefix listing answers the way the usage figures assume — because it is a
// stub, and it agrees with whatever it is sent.
//
// Point LFSX_TEST_S3_ENDPOINT at MinIO, Garage or AWS and they run. CI always
// sets it. Locally:
//
//   docker run -d -p 9100:9000 -e MINIO_ROOT_USER=lfsxkey \
//     -e MINIO_ROOT_PASSWORD=lfsxsecret quay.io/minio/minio server /data
//   LFSX_TEST_S3_ENDPOINT=http://127.0.0.1:9100 cargo test --test bucket

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use lfsx_server::config::{Auth, Config, Storage};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

struct Bucket {
    endpoint: String,
    bucket: String,
    access_key: String,
    secret_key: String,
}

fn configured() -> Option<Bucket> {
    let endpoint = std::env::var("LFSX_TEST_S3_ENDPOINT")
        .ok()
        .filter(|value| !value.is_empty())?;

    Some(Bucket {
        endpoint,
        bucket: std::env::var("LFSX_TEST_S3_BUCKET").unwrap_or_else(|_| "lfsx-test".into()),
        access_key: std::env::var("LFSX_TEST_S3_ACCESS_KEY").unwrap_or_else(|_| "lfsxkey".into()),
        secret_key: std::env::var("LFSX_TEST_S3_SECRET_KEY")
            .unwrap_or_else(|_| "lfsxsecret".into()),
    })
}

macro_rules! bucket_or_skip {
    () => {
        match configured() {
            Some(bucket) => bucket,
            None => {
                eprintln!("skipped: set LFSX_TEST_S3_ENDPOINT to run this against a real bucket");
                return;
            }
        }
    };
}

// Collection honours a grace window, and everything a test pushes is seconds
// old, so a sweep with the deployment default would only ever report
// within_grace. These tests are about what happens once the window has passed.
fn collecting(root: &tempfile::TempDir, bucket: &Bucket) -> Router {
    lfsx_server::app(lfsx_server::config::Config {
        gc_grace: Duration::ZERO,
        ..bucket_config(root, bucket, false, None, None, false)
    })
}

fn app(root: &tempfile::TempDir, bucket: &Bucket, presign: bool) -> Router {
    expiring(root, bucket, presign, None)
}

fn expiring(
    root: &tempfile::TempDir,
    bucket: &Bucket,
    presign: bool,
    lock_max_age: Option<Duration>,
) -> Router {
    built(root, bucket, presign, lock_max_age, None, false)
}

// Compression and encryption used to be refused against a bucket. They are the
// point of these last cases, so the helper has to be able to turn them on.
fn framing(
    root: &tempfile::TempDir,
    bucket: &Bucket,
    compression: Option<i32>,
    encrypted: bool,
) -> Router {
    built(root, bucket, false, None, compression, encrypted)
}

fn built(
    root: &tempfile::TempDir,
    bucket: &Bucket,
    presign: bool,
    lock_max_age: Option<Duration>,
    compression: Option<i32>,
    encrypted: bool,
) -> Router {
    lfsx_server::app(bucket_config(
        root,
        bucket,
        presign,
        lock_max_age,
        compression,
        encrypted,
    ))
}

fn bucket_config(
    root: &tempfile::TempDir,
    bucket: &Bucket,
    presign: bool,
    lock_max_age: Option<Duration>,
    compression: Option<i32>,
    encrypted: bool,
) -> Config {
    let encryption_key = encrypted.then(|| {
        let key = root.path().join("key");
        std::fs::write(&key, hex::encode([9u8; 32])).unwrap();
        lfsx_server::config::KeySource::File(key)
    });

    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        storage_root: root.path().to_path_buf(),
        public_url: Some("https://lfs.example".into()),
        action_lifetime: 1800,
        gc_grace: Duration::from_secs(14 * 24 * 60 * 60),
        staging_max_age: Duration::from_secs(86400),
        lock_max_age,
        max_object_size: None,
        max_concurrent_transfers: 128,
        repo_quota: None,
        compression,
        encryption_key,
        storage: Storage::Bucket {
            endpoint: bucket.endpoint.clone(),
            bucket: bucket.bucket.clone(),
            region: "us-east-1".into(),
            access_key: bucket.access_key.clone(),
            secret_key: bucket.secret_key.clone(),
            path_style: true,
            presign,
            cache: None,
            locking: true,
        },
        auth: Auth::Disabled,
    }
}

// The classification production makes before serving: `main` runs
// `verify_locking`, and a store that cannot arbitrate `If-None-Match: *` gets
// locking turned off, so taking a lock answers 501 instead of being handed to
// two people. The tests that assert a refusal are specifying an arbitrating
// store, so they ask the same question first and step aside where production
// would never run naive locking. Garage 1.x is such a store; MinIO arbitrates.
async fn store_arbitrates(bucket: &Bucket) -> bool {
    let root = tempfile::tempdir().unwrap();
    let mut config = bucket_config(&root, bucket, false, None, None, false);
    lfsx_server::verify_locking(&mut config).await;
    match config.storage {
        Storage::Bucket { locking, .. } => locking,
        Storage::Local => unreachable!("this file only builds bucket configs"),
    }
}

macro_rules! arbitration_or_skip {
    ($bucket:expr) => {
        if !store_arbitrates($bucket).await {
            eprintln!(
                "skipped: this store does not arbitrate `If-None-Match: *`, so production                  answers 501 here instead of taking locks"
            );
            return;
        }
    };
}

// Distinct bytes per test and per run. Per test so nothing here depends on the
// bucket being empty when it starts; per run because an object already under
// its content key is not uploaded again, so a fixed payload would quietly stop
// exercising the upload path from the second run onwards.
fn payload(what: &str) -> Vec<u8> {
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("an asset that only {what} pushes, run {run}: ")
        .repeat(4096)
        .into_bytes()
}

// A repository nothing else has pushed to. The bucket outlives a test run, and
// `objects/stats` sums a whole repository, so a shared name would report every
// object every previous run left behind.
fn repository(what: &str) -> String {
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("{what}{run}")
}

// Past two four-megabyte frames, so a range has to pick the frames it covers
// rather than the only one there is.
fn several_frames(what: &str) -> Vec<u8> {
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("vertex 0.7071 normal 1.0000 for {what} on run {run}, ")
        .repeat(200_000)
        .into_bytes()
}

// `.incoming/` is one prefix for the whole bucket and the reclaimer sweeps it
// whole. It has no way to tell an abandoned upload from one still in flight,
// because in production there is nothing to tell apart: the age window is what
// protects a live push, and a test sweeping with a zero window has taken that
// protection away for everybody. So the tests that leave something under that
// prefix take turns rather than deleting each other's uploads.
static INCOMING: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn oid_of(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

async fn push(app: Router, repo: &str, oid: &str, payload: &[u8]) -> StatusCode {
    let request = Request::builder()
        .method("PUT")
        .uri(format!("/FerrLabs/{repo}/objects/{oid}"))
        .header("content-length", payload.len())
        .body(Body::from(payload.to_vec()))
        .unwrap();

    app.oneshot(request).await.unwrap().status()
}

async fn batch(app: Router, repo: &str, oid: &str, size: usize) -> serde_json::Value {
    let body = serde_json::json!({
        "operation": "download",
        "transfers": ["basic"],
        "objects": [{ "oid": oid, "size": size }]
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/FerrLabs/{repo}/objects/batch"))
        .header("content-type", "application/vnd.git-lfs+json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    serde_json::from_slice(&bytes).unwrap()
}

// The cache is a copy of the bucket, so the only thing that matters is that a
// download served from it is the same download. The second read here is the one
// the cache answers, and the object it returns has to hash to what was pushed.
//
// Filling happens behind the request, so the first download returns before the
// copy exists: the wait is for that, not for the transfer.
#[tokio::test]
async fn a_cached_download_is_the_same_download() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("the cached path");
    let oid = oid_of(&payload);
    let cache = root.path().join("cache");

    let cached = || {
        lfsx_server::app(Config {
            storage: match bucket_config(&root, &bucket, false, None, None, false).storage {
                Storage::Bucket {
                    endpoint,
                    bucket,
                    region,
                    access_key,
                    secret_key,
                    path_style,
                    presign,
                    locking,
                    ..
                } => Storage::Bucket {
                    endpoint,
                    bucket,
                    region,
                    access_key,
                    secret_key,
                    path_style,
                    presign,
                    cache: Some(lfsx_server::config::DiskCache {
                        dir: cache.clone(),
                        max_bytes: 64 * 1024 * 1024,
                    }),
                    locking,
                },
                Storage::Local => unreachable!("this file only builds bucket configs"),
            },
            ..bucket_config(&root, &bucket, false, None, None, false)
        })
    };

    assert_eq!(
        push(cached(), "Cached", &oid, &payload).await,
        StatusCode::OK
    );
    assert_eq!(
        download(cached(), "Cached", &oid).await.status(),
        StatusCode::OK
    );

    for _ in 0..40 {
        if cache.join(&oid).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        cache.join(&oid).exists(),
        "a download the bucket answered has to leave a copy behind, or nothing is cached"
    );

    let response = download(cached(), "Cached", &oid).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        oid_of(&body),
        oid,
        "the copy has to be the object, not something that merely has its name"
    );
}

#[tokio::test]
async fn an_object_pushed_through_the_server_comes_back_byte_for_byte() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("the streamed path");
    let oid = oid_of(&payload);

    assert_eq!(
        push(app(&root, &bucket, false), "Streamed", &oid, &payload).await,
        StatusCode::OK
    );

    let request = Request::builder()
        .uri(format!("/FerrLabs/Streamed/objects/{oid}"))
        .body(Body::empty())
        .unwrap();
    let response = app(&root, &bucket, false).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let restored = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(oid_of(&restored), oid);
}

// The whole point of the redirect: the client fetches from the bucket with no
// credentials of any kind, because the URL carries its own. If this ever comes
// back needing an Authorization header, `authenticated: true` becomes the lie
// that sends git-lfs into a 401 loop.
#[tokio::test]
async fn a_pre_signed_download_is_fetched_with_no_credentials_at_all() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("the redirected path");
    let oid = oid_of(&payload);

    push(app(&root, &bucket, true), "Redirected", &oid, &payload).await;
    let answer = batch(app(&root, &bucket, true), "Redirected", &oid, payload.len()).await;

    assert_eq!(
        answer["objects"][0]["authenticated"],
        serde_json::json!(true)
    );
    let href = answer["objects"][0]["actions"]["download"]["href"]
        .as_str()
        .expect("a redirecting server hands out an href");
    assert!(
        href.starts_with(&bucket.endpoint),
        "the client is being sent to the bucket, not back here: {href}"
    );

    let fetched = reqwest::Client::new()
        .get(href)
        .send()
        .await
        .expect("the bucket answered");

    assert_eq!(fetched.status(), 200, "{href}");
    assert_eq!(oid_of(&fetched.bytes().await.unwrap()), oid);
}

// A range against the pre-signed URL is what a resumed clone does, and the
// bucket is the one serving it once the redirect is on.
#[tokio::test]
async fn a_pre_signed_url_serves_a_range() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("a resumed clone");
    let oid = oid_of(&payload);

    push(app(&root, &bucket, true), "Resumed", &oid, &payload).await;
    let answer = batch(app(&root, &bucket, true), "Resumed", &oid, payload.len()).await;
    let href = answer["objects"][0]["actions"]["download"]["href"]
        .as_str()
        .unwrap()
        .to_owned();

    let fetched = reqwest::Client::new()
        .get(&href)
        .header("range", "bytes=4096-8191")
        .send()
        .await
        .unwrap();

    assert_eq!(fetched.status(), 206, "{href}");
    assert_eq!(fetched.bytes().await.unwrap(), payload[4096..8192]);
}

// The marker is the proof of possession, and a signature is cut after it is
// checked rather than instead of it. Otherwise knowing a digest — which is all
// a leaked pointer file is — would be enough to read another project's assets
// out of a keyspace they share.
#[tokio::test]
async fn a_repository_that_never_pushed_the_object_is_signed_nothing() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("one project only");
    let oid = oid_of(&payload);

    push(app(&root, &bucket, true), "Owner", &oid, &payload).await;
    let answer = batch(app(&root, &bucket, true), "Stranger", &oid, payload.len()).await;

    assert_eq!(answer["objects"][0]["error"]["code"], 404);
    assert!(answer["objects"][0]["actions"].is_null());
    assert!(answer["objects"][0]["authenticated"].is_null());
}

// Two repositories pushing the same bytes pay the bucket once, and each holds
// its own marker. The unit tests assert this against a stub that stores what it
// is sent; here it is the real keyspace.
#[tokio::test]
async fn two_repositories_sharing_an_asset_store_it_once() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("both projects");
    let oid = oid_of(&payload);

    push(app(&root, &bucket, false), "First", &oid, &payload).await;
    push(app(&root, &bucket, false), "Second", &oid, &payload).await;

    for repo in ["First", "Second"] {
        let answer = batch(app(&root, &bucket, false), repo, &oid, payload.len()).await;
        assert!(
            answer["objects"][0]["error"].is_null(),
            "{repo} pushed it and should hold it: {answer}"
        );
    }
}

// The reason locks belong in the bucket at all. Two apps over one bucket are two
// replicas: they share nothing but the store, which is exactly the deployment
// `LFSX_STORAGE=s3` exists to make possible.
fn replicas(bucket: &Bucket) -> (tempfile::TempDir, tempfile::TempDir, Router, Router) {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let one = app(&first, bucket, false);
    let two = app(&second, bucket, false);

    (first, second, one, two)
}

async fn lock(app: Router, repo: &str, path: &str) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/FerrLabs/{repo}/locks"))
        .header("content-type", "application/vnd.git-lfs+json")
        .body(Body::from(serde_json::json!({ "path": path }).to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

async fn locks_on(app: Router, repo: &str) -> serde_json::Value {
    let request = Request::builder()
        .uri(format!("/FerrLabs/{repo}/locks"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    serde_json::from_slice(&bytes).unwrap()
}

fn scene(what: &str) -> String {
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("assets/{what}-{run}.unity")
}

#[tokio::test]
async fn a_lock_taken_on_one_replica_is_refused_on_the_other() {
    let bucket = bucket_or_skip!();
    arbitration_or_skip!(&bucket);
    let (_first, _second, one, two) = replicas(&bucket);
    let path = scene("arena");

    let (taken, _) = lock(one, "Locks", &path).await;
    assert_eq!(taken, StatusCode::CREATED);

    let (again, body) = lock(two, "Locks", &path).await;

    assert_eq!(
        again,
        StatusCode::CONFLICT,
        "the second replica handed out a scene the first had already given away, which is two \
             artists editing the same file and one of them losing the afternoon: {body}"
    );
    assert_eq!(body["lock"]["path"], path.as_str());
}

#[tokio::test]
async fn a_lock_is_listed_by_a_replica_that_never_took_it() {
    let bucket = bucket_or_skip!();
    let (_first, _second, one, two) = replicas(&bucket);
    let path = scene("listed");

    lock(one, "Listed", &path).await;
    let seen = locks_on(two, "Listed").await;

    let paths: Vec<_> = seen["locks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|lock| lock["path"].as_str().unwrap_or_default().to_owned())
        .collect();

    assert!(
        paths.contains(&path),
        "a lock nobody else can see is a lock nobody else respects: {paths:?}"
    );
}

#[tokio::test]
async fn releasing_on_one_replica_frees_it_on_the_other() {
    let bucket = bucket_or_skip!();
    let (_first, _second, one, two) = replicas(&bucket);
    let path = scene("released");

    let (_, created) = lock(one.clone(), "Released", &path).await;
    let id = created["lock"]["id"].as_str().unwrap().to_owned();

    let request = Request::builder()
        .method("POST")
        .uri(format!("/FerrLabs/Released/locks/{id}/unlock"))
        .header("content-type", "application/vnd.git-lfs+json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(one.oneshot(request).await.unwrap().status(), StatusCode::OK);

    let (retaken, _) = lock(two, "Released", &path).await;

    assert_eq!(
        retaken,
        StatusCode::CREATED,
        "a release that only one replica knows about leaves the file locked forever everywhere else"
    );
}

// What the probe promises has to be what the store then does. MinIO refuses
// the second conditional write; Garage 1.x accepts the header and writes
// anyway. Either answer is livable, the two paths disagreeing is not: a probe
// that says Enforced over a store that writes twice hands the same lock to two
// people, and a probe that trusts something one implementation happens to do
// is exactly what a second dialect in CI exists to catch.
#[tokio::test]
async fn the_locking_probe_matches_what_the_store_actually_does() {
    let bucket = bucket_or_skip!();
    let (_first, _second, one, two) = replicas(&bucket);
    let path = scene("probe-truth");

    let (first, _) = lock(one, "ProbeTruth", &path).await;
    assert_eq!(first, StatusCode::CREATED);
    let (second, _) = lock(two, "ProbeTruth", &path).await;
    let refused = second == StatusCode::CONFLICT;

    assert_eq!(
        store_arbitrates(&bucket).await,
        refused,
        "the probe and the store disagree about who wins a race for the same lock"
    );
}

// The mutual exclusion the whole design rests on, asked of the store directly.
// `create_new` gives it on a filesystem; in a bucket it is a conditional write,
// and a store that ignored the condition would accept both writers silently.
#[tokio::test]
async fn the_store_itself_refuses_the_second_writer() {
    let bucket = bucket_or_skip!();
    arbitration_or_skip!(&bucket);
    let (_first, _second, one, two) = replicas(&bucket);
    let path = scene("conditional");

    let (first, _) = lock(one, "Conditional", &path).await;
    let (second, complaint) = lock(two, "Conditional", &path).await;

    assert_eq!(
        (first, second),
        (StatusCode::CREATED, StatusCode::CONFLICT),
        "both replicas were told they hold it, so the bucket is not honouring `If-None-Match: *`: \
             {complaint}"
    );
}

// The setting reached the local lock store and not the bucket one, and every
// test here passed because this file always configured it off. A deployment with
// `LFSX_STORAGE=s3` got a dead takeover path and a page that tinted locks as
// takeable which the server then refused forever.
//
// A one-second ceiling and a wait, rather than reaching into the bucket to
// rewrite the stored claim: the server writes the lock, reads it back and decides,
// which is the path that was broken.
#[tokio::test]
async fn a_maximum_lock_age_applies_to_a_bucket_too() {
    let bucket = bucket_or_skip!();
    arbitration_or_skip!(&bucket);
    let root = tempfile::tempdir().unwrap();
    let second = Duration::from_secs(1);
    let path = scene("expiring");

    let expiring = || expiring(&root, &bucket, false, Some(second));

    assert_eq!(
        lock(expiring(), "Expiring", &path).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        lock(expiring(), "Expiring", &path).await.0,
        StatusCode::CONFLICT,
        "still fresh, so still the first caller's"
    );

    tokio::time::sleep(second + Duration::from_millis(300)).await;

    let (taken, body) = lock(expiring(), "Expiring", &path).await;

    assert_eq!(
        taken,
        StatusCode::CREATED,
        "the ceiling has to hold wherever the locks live, or the page tints a lock as takeable \
             and the server refuses it forever"
    );
    assert_eq!(body["lock"]["path"], path.as_str());
}

// #104 was fixed by refusing to compress into a bucket at all, because a framed
// object was only readable through the file the codec opened. It reads from a
// bucket now, so the frames go up as they are.
#[tokio::test]
async fn a_compressed_object_survives_a_bucket() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("a compressible mesh");
    let oid = oid_of(&payload);
    let repo = repository("Zstd");

    assert_eq!(
        push(
            framing(&root, &bucket, Some(3), false),
            &repo,
            &oid,
            &payload
        )
        .await,
        StatusCode::OK
    );

    let request = Request::builder()
        .uri(format!("/FerrLabs/{repo}/objects/{oid}"))
        .body(Body::empty())
        .unwrap();
    let response = framing(&root, &bucket, Some(3), false)
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let length = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let restored = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    assert_eq!(oid_of(&restored), oid);
    assert_eq!(
        length,
        payload.len().to_string(),
        "the client is promised the plaintext length, read from the header rather than from what \
             the bucket holds"
    );

    let held = stats(framing(&root, &bucket, Some(3), false), &repo).await;
    assert!(
        held < payload.len() as u64 / 4,
        "the bucket holds {held} bytes for a {} byte mesh, so the frames went up uncompressed and \
             the round trip above proved only that raw bytes survive",
        payload.len()
    );
}

#[tokio::test]
async fn an_encrypted_object_survives_a_bucket_and_is_not_the_object_in_it() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("an asset for a bucket somebody else operates");
    let oid = oid_of(&payload);
    let repo = repository("Sealed");

    push(framing(&root, &bucket, None, true), &repo, &oid, &payload).await;

    // What the bucket holds, asked of the server rather than of the bucket: the
    // figure comes from a HEAD on the content key, so it is the stored length.
    // Sealing adds a header and a tag per frame, so equal lengths would mean the
    // plaintext went up untouched.
    let held = stats(framing(&root, &bucket, None, true), &repo).await;
    assert!(
        held > payload.len() as u64,
        "the bucket holds {held} bytes for a {} byte object, so nothing was sealed on the way in",
        payload.len()
    );

    let request = Request::builder()
        .uri(format!("/FerrLabs/{repo}/objects/{oid}"))
        .body(Body::empty())
        .unwrap();
    let response = framing(&root, &bucket, None, true)
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        oid_of(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
        ),
        oid,
        "and it still comes back as the object it is named after"
    );
}

// A listing answers a page at a time and says whether there is more. Asking for
// one page and reporting the answer as the whole is how a repository past the
// page size came to have its capacity silently understated — and understated
// quietly, because a thousand objects is a plausible number to read.
//
// S3 caps a page at a thousand keys, so this pushes past it. It is the slowest
// test here and it is worth it: nothing smaller distinguishes a listing that
// follows the continuation token from one that stops.
#[tokio::test]
async fn a_repository_past_one_listing_page_is_counted_whole() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let repo = repository("Paged");
    let app = app(&root, &bucket, false);

    let objects = 1_001;
    for n in 0..objects {
        let payload = format!("object {n} of {repo}").into_bytes();
        assert_eq!(
            push(app.clone(), &repo, &oid_of(&payload), &payload).await,
            StatusCode::OK
        );
    }

    assert_eq!(
        counted(app, &repo).await,
        objects,
        "every object counts, not the first page of them"
    );
}

async fn counted(app: Router, repo: &str) -> u64 {
    let request = Request::builder()
        .uri(format!("/FerrLabs/{repo}/objects/stats"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    body["objects"].as_u64().unwrap()
}

// Readiness exists so an orchestrator stops sending traffic to an instance that
// cannot serve. Once the objects live in a bucket, the volume is a write buffer
// and says nothing about whether this server can reach them.
#[tokio::test]
async fn an_instance_that_cannot_reach_its_bucket_is_not_ready() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();

    assert_eq!(
        readiness(app(&root, &bucket, false)).await,
        StatusCode::OK,
        "a bucket it can reach is a bucket it can serve from"
    );

    // What a deleted bucket or a rotated key looks like from here: the staging
    // volume is untouched and perfectly writable, and every transfer this
    // instance is handed will still fail.
    let gone = Bucket {
        bucket: format!("{}-gone", bucket.bucket),
        ..bucket
    };
    let root = tempfile::tempdir().unwrap();

    assert_eq!(
        readiness(app(&root, &gone, false)).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a scratch disk that works is not the question readiness is asking"
    );
}

async fn readiness(app: Router) -> StatusCode {
    let request = Request::builder()
        .uri("/ready")
        .body(Body::empty())
        .unwrap();

    app.oneshot(request).await.unwrap().status()
}

// What a repository holds is remembered for a minute so a quota check does not
// list the bucket on every negotiation. Remembering it means adding to it when
// something is stored, and that arithmetic has to agree with the bucket: an
// object the repository already holds costs it no room, and counting it twice
// refuses space that was never used.
#[tokio::test]
async fn re_pushing_an_object_does_not_grow_what_the_repository_is_said_to_hold() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let repo = repository("Repushed");
    let payload = payload("an object pushed twice");
    let oid = oid_of(&payload);
    let app = app(&root, &bucket, false);

    assert_eq!(
        push(app.clone(), &repo, &oid, &payload).await,
        StatusCode::OK
    );
    let once = stats(app.clone(), &repo).await;
    assert_eq!(once, payload.len() as u64, "one object, its own size");

    // A retried push, an interrupted clone resumed, a second machine with the
    // same asset: all of them send bytes the repository already has.
    assert_eq!(
        push(app.clone(), &repo, &oid, &payload).await,
        StatusCode::OK
    );

    assert_eq!(
        stats(app, &repo).await,
        once,
        "nothing was stored, so nothing was gained"
    );
}

// Locks share the bucket with the objects, so a sweep walks past them. It must
// leave them alone: a collection that released a lock would hand an artist a
// scene somebody else is editing.
#[tokio::test]
async fn collecting_a_repository_leaves_its_locks_alone() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let repo = repository("Locked");
    let app = collecting(&root, &bucket);

    let taken = lock(app.clone(), &repo, "scenes/arena.unity").await;
    assert_eq!(taken.0, StatusCode::CREATED, "{:?}", taken.1);

    let report = retain(app.clone(), &repo, &[], false).await;
    assert_eq!(report["swept"], 0, "there was nothing to collect: {report}");

    let locks = locks_on(app, &repo).await;
    assert_eq!(
        locks["locks"].as_array().map(Vec::len),
        Some(1),
        "the sweep released a lock it had no business touching: {locks}"
    );
}

async fn retain(app: Router, repo: &str, oids: &[&str], dry_run: bool) -> serde_json::Value {
    let body = serde_json::json!({ "oids": oids, "dry_run": dry_run });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/FerrLabs/{repo}/objects/retain"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

// The case that loses data if it is wrong. Two repositories holding the same
// bytes each own a marker, and the first to let go must free nothing, because
// the second still has a claim. A sweep that counted the shared object as freed
// would delete bytes the other repository is still serving.
#[tokio::test]
async fn collecting_one_repository_leaves_an_object_another_still_holds() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let shared = payload("an asset pack two projects use");
    let oid = oid_of(&shared);
    let (first, second) = (repository("Sharing"), repository("Sharing2"));
    let app = collecting(&root, &bucket);

    for repo in [&first, &second] {
        assert_eq!(push(app.clone(), repo, &oid, &shared).await, StatusCode::OK);
    }

    let report = retain(app.clone(), &first, &[], true).await;
    assert_eq!(report["swept"], 1, "the marker is collectable: {report}");
    assert_eq!(
        report["bytes"], 0,
        "the other repository still holds the bytes, so nothing is freed: {report}"
    );

    let report = retain(app.clone(), &first, &[], false).await;
    assert_eq!(report["bytes"], 0, "{report}");

    assert_eq!(
        download(app, &second, &oid).await.status(),
        StatusCode::OK,
        "collecting one repository took bytes another was still holding"
    );
}

// And when the last claim goes, the bytes go with it.
#[tokio::test]
async fn the_last_repository_to_let_go_frees_the_bytes() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("an asset only one project uses");
    let oid = oid_of(&payload);
    let repo = repository("Alone");
    let app = collecting(&root, &bucket);

    assert_eq!(
        push(app.clone(), &repo, &oid, &payload).await,
        StatusCode::OK
    );

    let report = retain(app.clone(), &repo, &[], false).await;
    assert_eq!(report["swept"], 1, "{report}");
    assert_eq!(
        report["bytes"],
        payload.len(),
        "the last claim went, so the bytes are freed: {report}"
    );

    assert_eq!(
        download(app, &repo, &oid).await.status(),
        StatusCode::NOT_FOUND,
        "the object was collected"
    );
}

// What the client still references is what survives, which is the contract of
// the endpoint.
#[tokio::test]
async fn a_retained_object_is_not_collected() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let kept = payload("still referenced by a branch");
    let dropped = payload("no longer referenced by anything");
    let (kept_oid, dropped_oid) = (oid_of(&kept), oid_of(&dropped));
    let repo = repository("Retained");
    let app = collecting(&root, &bucket);

    assert_eq!(
        push(app.clone(), &repo, &kept_oid, &kept).await,
        StatusCode::OK
    );
    assert_eq!(
        push(app.clone(), &repo, &dropped_oid, &dropped).await,
        StatusCode::OK
    );

    let report = retain(app.clone(), &repo, &[&kept_oid], false).await;
    assert_eq!(report["swept"], 1, "only the unreferenced one: {report}");

    assert_eq!(
        download(app.clone(), &repo, &kept_oid).await.status(),
        StatusCode::OK,
        "a retained object must survive"
    );
    assert_eq!(
        download(app, &repo, &dropped_oid).await.status(),
        StatusCode::NOT_FOUND
    );
}

// A dry run promises. It must not deliver.
#[tokio::test]
async fn a_dry_run_reports_without_removing_anything() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("a dry run must not touch this");
    let oid = oid_of(&payload);
    let repo = repository("DryRun");
    let app = collecting(&root, &bucket);

    assert_eq!(
        push(app.clone(), &repo, &oid, &payload).await,
        StatusCode::OK
    );

    let report = retain(app.clone(), &repo, &[], true).await;
    assert_eq!(report["dry_run"], true, "{report}");
    assert_eq!(report["swept"], 1, "{report}");
    assert_eq!(report["bytes"], payload.len(), "{report}");

    assert_eq!(
        download(app, &repo, &oid).await.status(),
        StatusCode::OK,
        "a dry run that removed the object is not a dry run"
    );
}

async fn stats(app: Router, repo: &str) -> u64 {
    let request = Request::builder()
        .uri(format!("/FerrLabs/{repo}/objects/stats"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    body["bytes"].as_u64().unwrap()
}

// A range is the case the format exists for: the frames it covers are fetched,
// not everything before them.
#[tokio::test]
async fn a_range_over_a_framed_object_in_a_bucket_lands() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = several_frames("a resumed clone");
    let oid = oid_of(&payload);
    push(
        framing(&root, &bucket, Some(3), true),
        "Ranged",
        &oid,
        &payload,
    )
    .await;

    let request = Request::builder()
        .uri(format!("/FerrLabs/Ranged/objects/{oid}"))
        .header(axum::http::header::RANGE, "bytes=5000000-5004095")
        .body(Body::empty())
        .unwrap();
    let response = framing(&root, &bucket, Some(3), true)
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        payload[5_000_000..5_004_096]
    );
}

// The whole flow: negotiate, PUT straight to the bucket with the headers the
// server signed, then report back so the object becomes this repository's.
async fn negotiate_upload(app: Router, repo: &str, oid: &str, size: usize) -> serde_json::Value {
    negotiate_upload_as(app, repo, oid, size, None).await
}

async fn negotiate_upload_as(
    app: Router,
    repo: &str,
    oid: &str,
    size: usize,
    authorization: Option<&str>,
) -> serde_json::Value {
    let body = serde_json::json!({
        "operation": "upload",
        "transfers": ["basic"],
        "objects": [{ "oid": oid, "size": size }]
    });
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/FerrLabs/{repo}/objects/batch"))
        .header("content-type", "application/vnd.git-lfs+json");
    if let Some(authorization) = authorization {
        request = request.header(axum::http::header::AUTHORIZATION, authorization);
    }
    let request = request.body(Body::from(body.to_string())).unwrap();

    let response = app.oneshot(request).await.unwrap();
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn report(app: Router, repo: &str, oid: &str, size: usize) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/FerrLabs/{repo}/objects/verify"))
        .header("content-type", "application/vnd.git-lfs+json")
        .body(Body::from(
            serde_json::json!({ "oid": oid, "size": size }).to_string(),
        ))
        .unwrap();

    app.oneshot(request).await.unwrap().status()
}

async fn put_signed(action: &serde_json::Value, body: Vec<u8>) -> reqwest::StatusCode {
    let mut request = reqwest::Client::new()
        .put(action["href"].as_str().unwrap())
        .header("content-length", body.len());

    for (name, value) in action["header"].as_object().unwrap() {
        request = request.header(name, value.as_str().unwrap());
    }

    request.body(body).send().await.unwrap().status()
}

async fn download(app: Router, repo: &str, oid: &str) -> axum::response::Response {
    let request = Request::builder()
        .uri(format!("/FerrLabs/{repo}/objects/{oid}"))
        .body(Body::empty())
        .unwrap();

    app.oneshot(request).await.unwrap()
}

#[tokio::test]
async fn a_client_uploads_straight_to_the_bucket_and_then_owns_the_object() {
    let bucket = bucket_or_skip!();
    let _incoming = INCOMING.lock().await;
    let root = tempfile::tempdir().unwrap();
    let payload = payload("a presigned upload");
    let oid = oid_of(&payload);
    let repo = repository("Direct");

    let answer = negotiate_upload(app(&root, &bucket, true), &repo, &oid, payload.len()).await;
    assert_eq!(
        answer["objects"][0]["authenticated"],
        serde_json::json!(true)
    );
    let action = &answer["objects"][0]["actions"]["upload"];
    assert!(
        action["header"]["x-amz-checksum-sha256"].is_string(),
        "the digest has to travel as a header the store will check: {answer}"
    );

    assert!(put_signed(action, payload.clone()).await.is_success());

    assert_eq!(
        download(app(&root, &bucket, true), &repo, &oid)
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "an upload nobody has reported is not yet this repository's"
    );

    assert_eq!(
        report(app(&root, &bucket, true), &repo, &oid, payload.len()).await,
        StatusCode::OK
    );

    let response = download(app(&root, &bucket, true), &repo, &oid).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        oid_of(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
        ),
        oid
    );
}

// `authenticated: true` tells the client that every action on the object carries
// its own credentials, so git-lfs sends the verify with nothing but the headers
// the action names. Behind any auth provider, a verify with no credentials is a
// 401, and every pre-signed push fails after its bytes have already arrived.
#[tokio::test]
async fn a_pre_signed_upload_is_verified_with_the_credentials_it_was_negotiated_with() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("an upload that has to be reported");
    let oid = oid_of(&payload);
    let repo = repository("Reported");
    let credentials = "Basic dXNlcjp0b2tlbg==";

    let answer = negotiate_upload_as(
        app(&root, &bucket, true),
        &repo,
        &oid,
        payload.len(),
        Some(credentials),
    )
    .await;

    assert_eq!(
        answer["objects"][0]["authenticated"],
        serde_json::json!(true)
    );
    assert_eq!(
        answer["objects"][0]["actions"]["verify"]["header"]["Authorization"],
        serde_json::json!(credentials),
        "the client sends the verify bare unless the action names the credentials: {answer}"
    );
}

// The reason the digest is bound into the signature rather than trusted. Without
// it a client holding an upload URL could put anything under a key the server
// will later adopt as the object it is named after.
#[tokio::test]
async fn the_store_refuses_bytes_that_are_not_the_object() {
    let bucket = bucket_or_skip!();
    let _incoming = INCOMING.lock().await;
    let root = tempfile::tempdir().unwrap();
    let payload = payload("the object it claims");
    let oid = oid_of(&payload);
    let repo = repository("Wrong");

    let answer = negotiate_upload(app(&root, &bucket, true), &repo, &oid, payload.len()).await;
    let action = &answer["objects"][0]["actions"]["upload"];

    let refused = put_signed(action, b"something else entirely".to_vec()).await;

    assert!(
        refused.is_client_error(),
        "the store took bytes that do not hash to the digest the URL was signed for, so a \
             pre-signed upload could not be trusted to hold the object: {refused}"
    );
    assert_eq!(
        report(app(&root, &bucket, true), &repo, &oid, payload.len()).await,
        StatusCode::NOT_FOUND,
        "and nothing arrived, so there is nothing to adopt"
    );
}

// Possession is the invariant the marker stands for everywhere else. A repository
// that knows a digest and nothing more must not come to hold the object: a leaked
// pointer file is exactly that much knowledge.
#[tokio::test]
async fn knowing_a_digest_is_not_holding_the_object() {
    let bucket = bucket_or_skip!();
    let _incoming = INCOMING.lock().await;
    let root = tempfile::tempdir().unwrap();
    let payload = payload("somebody elses asset");
    let oid = oid_of(&payload);
    let (owner, stranger) = (repository("Owner"), repository("Stranger"));

    let answer = negotiate_upload(app(&root, &bucket, true), &owner, &oid, payload.len()).await;
    put_signed(&answer["objects"][0]["actions"]["upload"], payload.clone()).await;
    report(app(&root, &bucket, true), &owner, &oid, payload.len()).await;

    assert_eq!(
        report(app(&root, &bucket, true), &stranger, &oid, payload.len()).await,
        StatusCode::NOT_FOUND,
        "the bytes are in the shared keyspace, and that must not be enough: without an upload of \
             its own this repository has no claim on them"
    );
    assert_eq!(
        download(app(&root, &bucket, true), &stranger, &oid)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

// Nothing measured these bytes on the way past, so the size the client declared
// is checked against what actually arrived before the object is adopted.
#[tokio::test]
async fn a_declared_size_that_does_not_match_what_arrived_is_refused() {
    let bucket = bucket_or_skip!();
    let _incoming = INCOMING.lock().await;
    let root = tempfile::tempdir().unwrap();
    let payload = payload("a misdeclared object");
    let oid = oid_of(&payload);
    let repo = repository("Misdeclared");

    let answer = negotiate_upload(app(&root, &bucket, true), &repo, &oid, payload.len()).await;
    put_signed(&answer["objects"][0]["actions"]["upload"], payload.clone()).await;

    assert_eq!(
        report(app(&root, &bucket, true), &repo, &oid, payload.len() - 1).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the declared size is a claim, and this is the only place left to check it"
    );
}

// The guarantee encryption makes is about what the storage provider can read, and
// an object the client writes itself arrives as it is. So a keyed server keeps
// carrying uploads rather than handing out a URL that would put plaintext in
// somebody else's bucket.
#[tokio::test]
async fn a_keyed_server_does_not_hand_out_upload_urls() {
    let bucket = bucket_or_skip!();
    let root = tempfile::tempdir().unwrap();
    let payload = payload("an object that must not go up in the clear");
    let oid = oid_of(&payload);
    let repo = repository("Keyed");

    let keyed = built(&root, &bucket, true, None, None, true);
    let answer = negotiate_upload(keyed, &repo, &oid, payload.len()).await;
    let action = &answer["objects"][0]["actions"]["upload"];

    assert!(
        action["header"].is_null(),
        "a signed upload URL would let the client write the object unencrypted: {answer}"
    );
    assert!(
        action["href"]
            .as_str()
            .unwrap()
            .starts_with("https://lfs.example"),
        "the upload has to come back through this server, which seals it: {answer}"
    );
    assert!(answer["objects"][0]["authenticated"].is_null());
}

// A client can negotiate, PUT the object, and never report it. Nothing else will
// ever look at those bytes, and until now nothing removed them either: the local
// path has had a reclaimer since the beginning and the bucket had none.
#[tokio::test]
async fn an_upload_nobody_reported_is_reclaimed() {
    let bucket = bucket_or_skip!();
    let _incoming = INCOMING.lock().await;
    let root = tempfile::tempdir().unwrap();
    let payload = payload("an abandoned upload");
    let oid = oid_of(&payload);
    let repo = repository("Abandoned");

    let answer = negotiate_upload(app(&root, &bucket, true), &repo, &oid, payload.len()).await;
    assert!(
        put_signed(&answer["objects"][0]["actions"]["upload"], payload.clone())
            .await
            .is_success()
    );

    // Nothing reports it. The bytes are in the bucket and belong to nobody.
    let config = lfsx_server::config::Config {
        staging_max_age: Duration::ZERO,
        ..bucket_config(&root, &bucket, true, None, None, false)
    };
    lfsx_server::reclaim(&config).await;

    assert_eq!(
        report(app(&root, &bucket, true), &repo, &oid, payload.len()).await,
        StatusCode::NOT_FOUND,
        "the abandoned bytes are gone, so there is nothing left to adopt"
    );
}

// A slow client on a bad connection is not an abandoned one, and sweeping it
// would turn a long push into a failed one.
#[tokio::test]
async fn an_upload_still_within_the_window_is_left_alone() {
    let bucket = bucket_or_skip!();
    let _incoming = INCOMING.lock().await;
    let root = tempfile::tempdir().unwrap();
    let payload = payload("a slow upload");
    let oid = oid_of(&payload);
    let repo = repository("Slow");

    let answer = negotiate_upload(app(&root, &bucket, true), &repo, &oid, payload.len()).await;
    put_signed(&answer["objects"][0]["actions"]["upload"], payload.clone()).await;

    let config = lfsx_server::config::Config {
        staging_max_age: Duration::from_secs(3600),
        ..bucket_config(&root, &bucket, true, None, None, false)
    };
    lfsx_server::reclaim(&config).await;

    assert_eq!(
        report(app(&root, &bucket, true), &repo, &oid, payload.len()).await,
        StatusCode::OK,
        "an upload made a moment ago must survive a sweep, or a slow push becomes a failed one"
    );
}
