// Copyright © 2026 @sudocelestia. All rights reserved.
//
// PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
//
// No licence, permission or authorisation is granted to use, copy, modify,
// compile, execute, distribute, publish, sublicense or otherwise exploit this
// file, except to the limited extent unavoidably permitted by applicable law
// or GitHub's Terms of Service.
//
// See the LICENSE file at the repository root for the complete terms.

use serde::Serialize;
use std::io::{self, Write};
use std::time::Instant;

pub(crate) const MAX_OUTPUT_BYTES: usize = 8_192;

#[derive(Serialize)]
pub(crate) struct Response<'a> {
    pub(crate) protocol_version: u8,
    pub(crate) operation_id: &'static str,
    pub(crate) operation_version: u8,
    pub(crate) attempt_id: &'a str,
    pub(crate) request_nonce: &'a str,
    pub(crate) worker_id: &'static str,
    pub(crate) worker_version: &'static str,
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_media_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output: Option<String>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) duration_ns: u64,
}

#[derive(Serialize)]
pub(crate) struct Diagnostic {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

pub(crate) fn write(response: &Response<'_>) -> Result<(), ()> {
    write_to(response, &mut io::stdout())
}

pub(crate) fn write_to(response: &Response<'_>, writer: &mut impl Write) -> Result<(), ()> {
    let encoded = serde_json::to_vec(&response).map_err(|_| ())?;
    writer.write_all(&encoded).map_err(|_| ())?;
    writer.flush().map_err(|_| ())
}

pub(crate) fn duration_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .min(2_000_000_000)
}
