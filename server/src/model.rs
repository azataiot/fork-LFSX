use serde::{Deserialize, Serialize};

use crate::locks::Lock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Upload,
    Download,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObjectId {
    pub oid: String,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
pub struct BatchRequest {
    pub operation: Operation,
    #[serde(default)]
    pub transfers: Vec<String>,
    pub objects: Vec<ObjectId>,
    #[serde(rename = "ref")]
    pub reference: Option<Reference>,
}

#[derive(Debug, Deserialize)]
pub struct RetainRequest {
    pub oids: Vec<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize)]
pub struct CompressRequest {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize)]
pub struct DedupeRequest {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct BatchResponse {
    pub transfer: &'static str,
    pub objects: Vec<ObjectSpec>,
}

#[derive(Debug, Serialize)]
pub struct ObjectSpec {
    #[serde(flatten)]
    pub id: ObjectId,
    // Set only when the href carries its own credentials, which is true of a
    // pre-signed bucket URL and of nothing else this server hands out. Claiming
    // it for a URL pointing back here makes the client transfer with no
    // credentials at all, and loop on the 401 that follows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Actions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ObjectError>,
}

#[derive(Debug, Default, Serialize)]
pub struct Actions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<Action>,
}

#[derive(Debug, Serialize)]
pub struct Action {
    pub href: String,
    // Headers the client must send with the request. Not advice: for a
    // pre-signed upload the digest is bound into the signature, so an altered or
    // missing header is a refused request rather than a weaker one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ObjectError {
    pub code: u16,
    pub message: String,
}

impl ObjectSpec {
    pub fn missing(id: ObjectId) -> Self {
        Self {
            id,
            authenticated: None,
            actions: None,
            error: Some(ObjectError {
                code: 404,
                message: "object not found".into(),
            }),
        }
    }

    // The oid never reaches storage: it failed to parse at the boundary, so
    // nothing was looked up and 404 would be a lie. 422 is what the rest of
    // the request's class gets, and the message is the parser's own.
    pub fn malformed(id: ObjectId) -> Self {
        Self {
            id,
            authenticated: None,
            actions: None,
            error: Some(ObjectError {
                code: 422,
                message: crate::error::Error::MalformedOid.to_string(),
            }),
        }
    }

    pub fn too_large(id: ObjectId, limit: u64) -> Self {
        Self {
            error: Some(ObjectError {
                code: 413,
                message: format!(
                    "object is {} bytes, over the {limit} byte limit this server accepts",
                    id.size
                ),
            }),
            id,
            authenticated: None,
            actions: None,
        }
    }

    pub fn over_quota(id: ObjectId, used: u64, limit: u64) -> Self {
        Self {
            id,
            authenticated: None,
            actions: None,
            error: Some(ObjectError {
                code: 507,
                message: format!(
                    "this repository holds {used} bytes of its {limit} byte budget: collect what \
                     it no longer references, or ask for more room"
                ),
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateLockRequest {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct ListLocksQuery {
    pub path: Option<String>,
    pub id: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    // Accepted and not acted on: see `refs` in the README. Rejecting it would
    // break a client that sends what the specification tells it to send.
    #[serde(rename = "refspec")]
    pub refspec: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VerifyLocksRequest {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    #[serde(rename = "ref")]
    pub reference: Option<Reference>,
}

#[derive(Debug, Deserialize)]
pub struct Reference {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct LockResponse {
    pub lock: Lock,
}

#[derive(Debug, Serialize)]
pub struct ListLocksResponse {
    pub locks: Vec<Lock>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_cursor: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyLocksResponse {
    pub ours: Vec<Lock>,
    pub theirs: Vec<Lock>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_cursor: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub objects: u64,
    pub bytes: u64,
    pub locks: usize,
}
