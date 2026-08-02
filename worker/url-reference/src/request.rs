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

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{self, Read};

const MAX_REQUEST_BYTES: u64 = 65_536;
pub(crate) const MAX_INPUT_BYTES: usize = 4_096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    protocol_version: u8,
    operation_id: String,
    operation_version: u8,
    pub(crate) attempt_id: String,
    pub(crate) request_nonce: String,
    pub(crate) input_media_type: String,
    input_length: usize,
    input_sha256: String,
    pub(crate) mode: Mode,
    deadline: String,
    timeout_ms: u64,
    limits: Limits,
    pub(crate) input: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    Fang,
    Defang,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    input_bytes: usize,
    output_bytes: usize,
    stderr_bytes: usize,
    memory_bytes: usize,
    processes: usize,
}

pub(crate) fn read() -> Result<Vec<u8>, ()> {
    let mut data = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| ())?;
    if data.is_empty() || data.len() > usize::try_from(MAX_REQUEST_BYTES).map_err(|_| ())? {
        return Err(());
    }
    Ok(data)
}

pub(crate) fn parse(data: &[u8]) -> Result<Request, ()> {
    if !is_compact_frame(data) {
        return Err(());
    }
    let request: Request = serde_json::from_slice(data).map_err(|_| ())?;
    validate(&request)?;
    Ok(request)
}

fn is_compact_frame(data: &[u8]) -> bool {
    let mut escaped = false;
    let mut in_string = false;
    for byte in data {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
        } else if *byte == b'"' {
            in_string = true;
        } else if matches!(*byte, b' ' | b'\t' | b'\n' | b'\r') {
            return false;
        }
    }
    true
}

pub(crate) fn validate(request: &Request) -> Result<(), ()> {
    if request.protocol_version != 1
        || request.operation_id != "url-reference"
        || request.operation_version != 1
        || request.input_media_type != "text/plain; charset=utf-8"
        || request.timeout_ms != 2_000
        || request.input.is_empty()
        || request.input.len() > MAX_INPUT_BYTES
        || request.input_length != request.input.len()
        || request.input_sha256 != sha256(&request.input)
        || !valid_deadline(&request.deadline)
    {
        return Err(());
    }
    if request.limits.input_bytes != 4_096
        || request.limits.output_bytes != 8_192
        || request.limits.stderr_bytes != 8_192
        || request.limits.memory_bytes != 67_108_864
        || request.limits.processes != 1
    {
        return Err(());
    }
    if !valid_identity(&request.attempt_id)
        || !valid_identity(&request.request_nonce)
        || request.attempt_id == request.request_nonce
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn valid_identity(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && matches!(
            value.as_bytes()[42],
            b'A' | b'E'
                | b'I'
                | b'M'
                | b'Q'
                | b'U'
                | b'Y'
                | b'c'
                | b'g'
                | b'k'
                | b'o'
                | b's'
                | b'w'
                | b'0'
                | b'4'
                | b'8'
        )
}

pub(crate) fn valid_deadline(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len()) || bytes.last() != Some(&b'Z') {
        return false;
    }
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|&(index, expected)| bytes.get(index) != Some(&expected))
    {
        return false;
    }
    if !bytes[..19]
        .iter()
        .enumerate()
        .all(|(index, byte)| separators.iter().any(|&(i, _)| i == index) || byte.is_ascii_digit())
    {
        return false;
    }
    let values = [
        parse_decimal(&bytes[0..4]),
        parse_decimal(&bytes[5..7]),
        parse_decimal(&bytes[8..10]),
        parse_decimal(&bytes[11..13]),
        parse_decimal(&bytes[14..16]),
        parse_decimal(&bytes[17..19]),
    ];
    let [
        Some(year),
        Some(month),
        Some(day),
        Some(hour),
        Some(minute),
        Some(second),
    ] = values
    else {
        return false;
    };
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return false;
    }
    if bytes.len() == 20 {
        return true;
    }
    bytes.get(19) == Some(&b'.')
        && bytes[20..bytes.len() - 1].len() <= 9
        && !bytes[20..bytes.len() - 1].is_empty()
        && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)
        && bytes[bytes.len() - 2] != b'0'
}

fn parse_decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || year.is_multiple_of(4) && !year.is_multiple_of(100) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub(crate) fn sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
