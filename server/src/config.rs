use axum::http::{HeaderMap, header};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::model::Action;
use crate::namespace::Namespace;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub storage_root: PathBuf,
    pub public_url: Option<String>,
    pub action_lifetime: u32,
    pub gc_grace: Duration,
    pub staging_max_age: Duration,
    // How long a lock may go untouched before anyone can take it. Unset means
    // never, which is what happened before this existed and what a team that has
    // not thought about it yet should keep getting.
    pub lock_max_age: Option<Duration>,
    pub max_object_size: Option<u64>,
    // How many uploads and downloads may hold this server's disk and network
    // open at once. A backstop for the bare deployment with nothing in front:
    // the expensive thing here is a transfer held open, not a request counted,
    // and anything smarter belongs to the reverse proxy.
    pub max_concurrent_transfers: usize,
    pub repo_quota: Option<u64>,
    pub compression: Option<i32>,
    // Never the key itself: a key in the environment is in the pod spec, in
    // `docker inspect`, and in every log that dumps the environment. A file
    // comes from a Kubernetes Secret mount without any of that, and a command
    // is the one interface every KMS, Vault and SOPS already speaks, for the
    // operator whose keys must never rest on disk at all.
    pub encryption_key: Option<KeySource>,
    pub storage: Storage,
    pub auth: Auth,
}

#[derive(Debug, Clone)]
pub enum Storage {
    Local,
    // Endpoint, bucket and credentials all have to be there: a bucket the server
    // cannot reach is a server that answers every push with an error, and
    // discovering that on the first upload rather than at boot is the wrong
    // order.
    Bucket {
        endpoint: String,
        bucket: String,
        region: String,
        access_key: String,
        secret_key: String,
        path_style: bool,
        // Whether a download is redirected to the bucket instead of streamed
        // through this server. Off by default: the streamed path is the one
        // that counts bytes, serves ranges and holds the ceiling, and an
        // operator should choose to give those up rather than discover it.
        presign: bool,
        // A local copy of what the bucket holds, so a second reader does not
        // pay the round trip again. None is no cache at all, which is what a
        // deployment that never set it keeps getting.
        cache: Option<DiskCache>,
        // Whether locks can be taken here. Not read from the environment: it
        // starts true and the startup probes turn it off, the same way they turn
        // `presign` off, when the store will not prove it can arbitrate between
        // two writers racing for the same key.
        locking: bool,
    },
}

impl Storage {
    fn from_env() -> Self {
        if std::env::var("LFSX_STORAGE").as_deref() != Ok("s3") {
            return Self::Local;
        }

        let required = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| panic!("LFSX_STORAGE=s3 needs {name}"))
        };

        Self::Bucket {
            endpoint: required("LFSX_S3_ENDPOINT"),
            bucket: required("LFSX_S3_BUCKET"),
            region: std::env::var("LFSX_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            access_key: required("LFSX_S3_ACCESS_KEY"),
            secret_key: required("LFSX_S3_SECRET_KEY"),
            path_style: std::env::var("LFSX_S3_PATH_STYLE").as_deref() != Ok("false"),
            presign: std::env::var("LFSX_S3_PRESIGN").as_deref() == Ok("true"),
            cache: disk_cache(
                std::env::var("LFSX_S3_CACHE_DIR").ok().as_deref(),
                std::env::var("LFSX_S3_CACHE_MAX_BYTES").ok().as_deref(),
            ),
            locking: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Auth {
    Forge {
        provider: Provider,
        api_url: String,
        // A GitHub App identity for the server's own calls, so the anonymous
        // lookup spends the App installation's quota instead of the 60-an-hour
        // unauthenticated one. A file path for the key, never the key itself,
        // same discipline as the encryption key.
        github_app: Option<GithubApp>,
        cache_ttl: Duration,
        rejection_ttl: Duration,
        // Lookups a minute this server will spend on the forge, counted only
        // when neither cache could answer. None is no ceiling at all.
        lookup_budget: Option<u32>,
        // Whether a request with no credentials is resolved against the forge
        // instead of refused. On by default, because that is what cloning a
        // public repository does everywhere else.
        anonymous_read: bool,
    },
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCache {
    pub dir: PathBuf,
    pub max_bytes: u64,
}

// A directory and a ceiling, together or not at all. A cache with nowhere to
// live is nothing, and one with no ceiling fills the disk the server also
// stages uploads on, which is a worse outage than the bucket round trips it
// was meant to save.
fn disk_cache(dir: Option<&str>, max_bytes: Option<&str>) -> Option<DiskCache> {
    let dir = dir.filter(|dir| !dir.is_empty())?;

    let Some(max_bytes) = max_bytes
        .map(str::trim)
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ceiling| *ceiling > 0)
    else {
        tracing::warn!(
            "LFSX_S3_CACHE_DIR is set without a usable LFSX_S3_CACHE_MAX_BYTES, so nothing is \
             cached: a cache with no ceiling would fill the volume this server stages uploads on"
        );
        return None;
    };

    Some(DiskCache {
        dir: PathBuf::from(dir),
        max_bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    File(PathBuf),
    Command(String),
}

// One source or none. Both is a configuration that says two things, and which
// of them the operator trusts with the store is not a guess this server makes.
fn encryption_key(file: Option<&str>, command: Option<&str>) -> Option<KeySource> {
    let file = file.filter(|path| !path.is_empty());
    let command = command.filter(|hook| !hook.is_empty());

    match (file, command) {
        (None, None) => None,
        (Some(path), None) => Some(KeySource::File(PathBuf::from(path))),
        (None, Some(hook)) => Some(KeySource::Command(hook.to_owned())),
        (Some(_), Some(_)) => panic!(
            "LFSX_ENCRYPTION_KEY_FILE and LFSX_ENCRYPTION_KEY_COMMAND are both set: they are two \
             answers to where the keys live, and picking one for you is how the wrong keys get used"
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubApp {
    pub app_id: String,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Github,
    Gitlab,
    // Gitea and Forgejo, which are one API: Forgejo is a fork of Gitea and
    // answers the same routes, so the only thing that tells two instances apart
    // is the root they are reached at.
    Gitea,
}

impl Provider {
    // None where there is no such thing as the instance.
    //
    // github.com and gitlab.com are where a repository is unless the operator
    // says otherwise, so defaulting there is nearly always right. Gitea is
    // software rather than a place. gitea.com exists, but an operator who names
    // this provider is almost certainly running their own, and quietly resolving
    // their namespaces against a stranger's forge is worse than not starting: a
    // public repository there that happens to share a name would hand out
    // anonymous read on objects it has nothing to do with.
    fn default_api_url(self) -> Option<&'static str> {
        match self {
            Self::Github => Some("https://api.github.com"),
            Self::Gitlab => Some("https://gitlab.com/api/v4"),
            Self::Gitea => None,
        }
    }

    fn api_url_variable(self) -> &'static str {
        match self {
            Self::Github => "LFSX_GITHUB_API_URL",
            Self::Gitlab => "LFSX_GITLAB_API_URL",
            Self::Gitea => "LFSX_GITEA_API_URL",
        }
    }
}

const CACHE_TTL: Duration = Duration::from_secs(60);
const REJECTION_TTL: Duration = Duration::from_secs(10);
// Generous enough that a busy server never meets it, since a lookup is one
// distinct token against one repository per cache lifetime rather than one per
// request, and tight enough that a flood costs ten a second instead of whatever
// the network will carry.
const LOOKUP_BUDGET: u32 = 600;
const TRANSFER_CAP: usize = 128;
const GC_GRACE: Duration = Duration::from_secs(14 * 24 * 60 * 60);
const STAGING_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

impl Config {
    pub fn from_env() -> Self {
        let bind = std::env::var("LFSX_BIND")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080)));

        let storage_root = std::env::var("LFSX_STORAGE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/lfsx"));

        let public_url = std::env::var("LFSX_PUBLIC_URL")
            .ok()
            .filter(|url| !url.is_empty())
            .map(|url| url.trim_end_matches('/').to_owned());

        Self {
            bind,
            storage_root,
            public_url,
            action_lifetime: 1800,
            gc_grace: seconds("LFSX_GC_GRACE").unwrap_or(GC_GRACE),
            staging_max_age: seconds("LFSX_STAGING_MAX_AGE").unwrap_or(STAGING_MAX_AGE),
            lock_max_age: seconds("LFSX_LOCK_MAX_AGE"),
            max_object_size: bytes("LFSX_MAX_OBJECT_SIZE"),
            max_concurrent_transfers: transfer_cap(
                std::env::var("LFSX_MAX_CONCURRENT_TRANSFERS")
                    .ok()
                    .as_deref(),
            ),
            repo_quota: bytes("LFSX_REPO_QUOTA"),
            compression: compression(),
            encryption_key: encryption_key(
                std::env::var("LFSX_ENCRYPTION_KEY_FILE").ok().as_deref(),
                std::env::var("LFSX_ENCRYPTION_KEY_COMMAND").ok().as_deref(),
            ),
            storage: Storage::from_env(),
            auth: Auth::from_env(),
        }
    }

    pub fn base_url(&self, headers: &HeaderMap) -> String {
        if let Some(configured) = &self.public_url {
            return configured.clone();
        }

        // Neither of these is this deployment speaking. They are what the caller
        // sent, and what comes out of here is the URL that caller will send the
        // object to, with its credential attached. So both are checked for being
        // the thing they claim to be before either goes into a URL.
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|scheme| matches!(*scheme, "http" | "https"))
            .unwrap_or("http");

        let authority = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|host| is_an_authority(host))
            .unwrap_or("localhost");

        format!("{scheme}://{authority}")
    }

    pub fn object_url(&self, base: &str, ns: &Namespace, oid: &str) -> String {
        format!("{base}/{ns}/objects/{oid}")
    }

    pub fn verify_url(&self, base: &str, ns: &Namespace) -> String {
        format!("{base}/{ns}/objects/verify")
    }

    pub fn action(&self, href: String) -> Action {
        Action {
            href,
            header: None,
            expires_in: self.action_lifetime,
        }
    }

    pub fn signed_action(&self, href: String, headers: Vec<(String, String)>) -> Action {
        Action {
            href,
            header: Some(headers.into_iter().collect()),
            expires_in: self.action_lifetime,
        }
    }

    pub fn authorized_action(&self, href: String, authorization: Option<&str>) -> Action {
        match authorization {
            Some(credentials) => self.signed_action(
                href,
                vec![("Authorization".to_owned(), credentials.to_owned())],
            ),
            None => self.action(href),
        }
    }
}

// Opt in, not opt out. Serving objects to a caller with no credentials at all is
// a decision an operator should make on purpose: it costs them the bandwidth of
// anyone who finds the endpoint, on a server whose whole job is to move files
// measured in gigabytes. Nothing confidential is at stake, since a request with
// no credentials is still resolved against the forge and a private repository is
// still refused, but "anyone may pull from you" is not a sensible thing to
// inherit by default.
//
// Only the exact string opens it. A typo, an empty value or a `1` leaves it
// closed, because the failure that matters here is the one that opens the door
// when nobody meant to.
fn anonymous_read(value: Option<&str>) -> bool {
    value == Some("true")
}

impl Auth {
    fn from_env() -> Self {
        if std::env::var("LFSX_AUTH").as_deref() == Ok("disabled") {
            tracing::warn!(
                "LFSX_AUTH=disabled: every request is accepted, run this on a trusted network only"
            );
            return Self::Disabled;
        }

        let provider = provider(std::env::var("LFSX_AUTH").ok().as_deref());

        Self::Forge {
            provider,
            api_url: api_url(
                provider,
                std::env::var(provider.api_url_variable()).ok().as_deref(),
            ),
            cache_ttl: seconds("LFSX_AUTH_CACHE_TTL").unwrap_or(CACHE_TTL),
            rejection_ttl: seconds("LFSX_AUTH_REJECTION_TTL").unwrap_or(REJECTION_TTL),
            lookup_budget: lookup_budget(std::env::var("LFSX_AUTH_LOOKUP_BUDGET").ok().as_deref()),
            github_app: github_app(provider),
            anonymous_read: anonymous_read(std::env::var("LFSX_ANONYMOUS_READ").ok().as_deref()),
        }
    }
}

// Both variables or neither. One without the other is a configuration that
// says two things at once, and an operator who set up an App meant to have its
// quota, so the mistake is refused at boot instead of quietly ignored.
fn github_app(provider: Provider) -> Option<GithubApp> {
    let id = std::env::var("LFSX_GITHUB_APP_ID")
        .ok()
        .filter(|id| !id.is_empty());
    let key_file = std::env::var("LFSX_GITHUB_APP_KEY_FILE")
        .ok()
        .filter(|path| !path.is_empty());

    match (id, key_file) {
        (None, None) => None,
        (Some(app_id), Some(key_file)) => {
            if provider != Provider::Github {
                tracing::warn!(
                    "LFSX_GITHUB_APP_ID is set but LFSX_AUTH is not github, so it does nothing"
                );
                return None;
            }
            Some(GithubApp {
                app_id,
                key_file: PathBuf::from(key_file),
            })
        }
        _ => panic!(
            "LFSX_GITHUB_APP_ID and LFSX_GITHUB_APP_KEY_FILE come together: one without the \
             other is half an identity, and guessing which half was meant is worse than stopping"
        ),
    }
}

// Zero is the one value that cannot mean what it says. A ceiling of no lookups
// is a server that refuses every caller it has not already seen, so it is read as
// the operator turning the ceiling off, which is the only other thing they could
// have meant. Anything unparseable is the default rather than a refusal to start:
// this bounds a cost, and getting it wrong should not take the server down.
fn lookup_budget(value: Option<&str>) -> Option<u32> {
    match value.map(str::trim).map(str::parse::<u32>) {
        Some(Ok(0)) => None,
        Some(Ok(budget)) => Some(budget),
        Some(Err(_)) | None => Some(LOOKUP_BUDGET),
    }
}

// Anything unrecognised is GitHub, which is what an operator who set nothing
// almost certainly meant. Forgejo is named alongside Gitea because they are one
// API, and somebody running Forgejo should not have to know it began as a fork.
fn provider(value: Option<&str>) -> Provider {
    match value {
        Some("gitlab") => Provider::Gitlab,
        Some("gitea") | Some("forgejo") => Provider::Gitea,
        _ => Provider::Github,
    }
}

// The trailing slash matters: every route is built by appending to this, so one
// left on the end produces `//repos/...`, which some forges answer and others do
// not, and the ones that do not answer 404 for a repository that is right there.
fn api_url(provider: Provider, configured: Option<&str>) -> String {
    let variable = provider.api_url_variable();

    configured
        .map(str::to_owned)
        .or_else(|| provider.default_api_url().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!(
                "{variable} must be set: a self-hosted forge has no default API root, and guessing \
                 one would resolve your repositories against somebody else's"
            )
        })
        .trim_end_matches('/')
        .to_owned()
}

// Is this a host and a port, and nothing else?
//
// A `Host` carrying a `/` or an `@` is not one, and both change where the URL
// built from it points. `real.example@evil.example` resolves to the second name
// with the first read as a username, which turns a header somebody sent into a
// redirect nobody wrote, and the client follows it carrying its token.
//
// Anything that fails this falls back to `localhost`, which is useless to
// everybody and dangerous to nobody. `LFSX_PUBLIC_URL` is the fix, and startup
// says so.
fn is_an_authority(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}

// Unset means unlimited, which is what a server on its own volume wants. Zero
// would refuse every push, so it is read as a typo rather than as a policy
// nobody would choose deliberately.
// zstd level 3 is the default because it is the one that costs nothing you can
// measure: it compresses faster than a spinning disk writes, and the meshes and
// uncompressed raster that make up most of an LFS store give most of their
// ground at any level. Higher levels are there for a store that is short on
// room rather than on time.
fn compression() -> Option<i32> {
    match std::env::var("LFSX_COMPRESSION").ok()?.trim() {
        "" | "none" | "off" => None,
        "zstd" => Some(3),
        other => match other
            .strip_prefix("zstd:")
            .and_then(|level| level.parse().ok())
        {
            Some(level @ 1..=19) => Some(level),
            _ => {
                tracing::warn!(
                    "LFSX_COMPRESSION={other} is not a codec this server knows, storing objects as they arrive"
                );
                None
            }
        },
    }
}

// Same posture as the lookup budget: this bounds a cost, so an unparseable
// value falls back to the default with a warning rather than refusing to start.
fn transfer_cap(value: Option<&str>) -> usize {
    match value.map(str::trim).map(str::parse) {
        Some(Ok(cap)) => cap,
        None => TRANSFER_CAP,
        Some(Err(_)) => {
            tracing::warn!(
                "LFSX_MAX_CONCURRENT_TRANSFERS is not a number, keeping the default of {TRANSFER_CAP}"
            );
            TRANSFER_CAP
        }
    }
}

fn bytes(variable: &str) -> Option<u64> {
    let configured = std::env::var(variable).ok()?.trim().parse().ok()?;

    if configured == 0 {
        tracing::warn!("{variable}=0 would refuse every upload, ignoring it");
        return None;
    }

    Some(configured)
}

fn seconds(variable: &str) -> Option<Duration> {
    std::env::var(variable)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests;
