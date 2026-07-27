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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Instant;

const MAX_REQUEST_BYTES: u64 = 65_536;
const MAX_INPUT_BYTES: usize = 4_096;
const MAX_OUTPUT_BYTES: usize = 8_192;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol_version: u8,
    operation_id: String,
    operation_version: u8,
    attempt_id: String,
    request_nonce: String,
    input_media_type: String,
    input_length: usize,
    input_sha256: String,
    mode: Mode,
    deadline: String,
    timeout_ms: u64,
    limits: Limits,
    input: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
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

#[derive(Serialize)]
struct Response<'a> {
    protocol_version: u8,
    operation_id: &'static str,
    operation_version: u8,
    attempt_id: &'a str,
    request_nonce: &'a str,
    worker_id: &'static str,
    worker_version: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_media_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    diagnostics: Vec<Diagnostic>,
    duration_ns: u64,
}

#[derive(Serialize)]
struct Diagnostic {
    code: &'static str,
    message: &'static str,
}

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(()) => ExitCode::from(3),
    }
}

fn run() -> Result<ExitCode, ()> {
    let start = Instant::now();
    let data = read_request()?;
    if !is_compact_frame(&data) {
        return Err(());
    }
    let request: Request = serde_json::from_slice(&data).map_err(|_| ())?;
    validate_request(&request)?;
    let output = match transform(&request.input, &request.mode) {
        Ok(output) => output,
        Err(()) => {
            let response = Response {
                protocol_version: 0,
                operation_id: "url-reference",
                operation_version: 0,
                attempt_id: &request.attempt_id,
                request_nonce: &request.request_nonce,
                worker_id: "celestia-url-reference",
                worker_version: "0",
                status: "rejected",
                output_media_type: None,
                output_length: None,
                output_sha256: None,
                output: None,
                diagnostics: vec![Diagnostic {
                    code: "invalid_reference",
                    message: "input does not satisfy the URL-reference contract",
                }],
                duration_ns: duration_ns(start),
            };
            write_response(&response)?;
            return Ok(ExitCode::from(2));
        }
    };
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(());
    }
    let response = Response {
        protocol_version: 0,
        operation_id: "url-reference",
        operation_version: 0,
        attempt_id: &request.attempt_id,
        request_nonce: &request.request_nonce,
        worker_id: "celestia-url-reference",
        worker_version: "0",
        status: "completed",
        output_media_type: Some(&request.input_media_type),
        output_length: Some(output.len()),
        output_sha256: Some(sha256(&output)),
        output: Some(output),
        diagnostics: Vec::new(),
        duration_ns: duration_ns(start),
    };
    write_response(&response)?;
    Ok(ExitCode::SUCCESS)
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

fn write_response(response: &Response<'_>) -> Result<(), ()> {
    let encoded = serde_json::to_vec(&response).map_err(|_| ())?;
    let mut stdout = io::stdout();
    stdout.write_all(&encoded).map_err(|_| ())?;
    stdout.flush().map_err(|_| ())
}

fn duration_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .min(2_000_000_000)
}

fn read_request() -> Result<Vec<u8>, ()> {
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

fn validate_request(request: &Request) -> Result<(), ()> {
    if request.protocol_version != 0
        || request.operation_id != "url-reference"
        || request.operation_version != 0
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

fn valid_identity(value: &str) -> bool {
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

fn valid_deadline(value: &str) -> bool {
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

fn transform(input: &str, mode: &Mode) -> Result<String, ()> {
    validate_text(input)?;
    let scheme_end = input.find("://").ok_or(())?;
    let authority_start = scheme_end + 3;
    let authority_end = input[authority_start..]
        .find(['/', '?', '#'])
        .map_or(input.len(), |index| authority_start + index);
    let authority = &input[authority_start..authority_end];
    let host_end = validate_authority(authority)?;
    let host = &authority[..host_end];
    let scheme = &input[..scheme_end];
    let scheme_defanged = scheme_state(scheme)?;
    let host_state = validate_host(host)?;
    if let Some(host_defanged) = host_state
        && host_defanged != scheme_defanged
    {
        return Err(());
    }
    validate_suffix(&input[authority_end..])?;
    let target_defanged = matches!(mode, Mode::Defang);
    let transformed_scheme = transform_scheme(scheme, target_defanged)?;
    let transformed_host = transform_host(host, target_defanged)?;
    Ok(format!(
        "{transformed_scheme}{}{transformed_host}{}",
        &input[scheme_end..authority_start],
        &input[authority_start + host_end..]
    ))
}

fn validate_text(input: &str) -> Result<(), ()> {
    if input.is_empty()
        || input.len() > MAX_OUTPUT_BYTES
        || input.starts_with('\u{feff}')
        || input.chars().any(rejected_character)
    {
        return Err(());
    }
    Ok(())
}

fn rejected_character(value: char) -> bool {
    value == '\0'
        || value <= '\u{1f}'
        || value == '\u{7f}'
        || matches!(
            value,
            '\u{20}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
}

fn scheme_state(scheme: &str) -> Result<bool, ()> {
    match scheme {
        "http" | "https" => Ok(false),
        "hxxp" | "hxxps" => Ok(true),
        _ => Err(()),
    }
}

fn validate_authority(authority: &str) -> Result<usize, ()> {
    if authority.is_empty() || authority.contains('@') {
        return Err(());
    }
    if authority.starts_with('[') {
        let end = authority.find(']').map(|index| index + 1).ok_or(())?;
        validate_ipv6(&authority[..end])?;
        validate_port_suffix(&authority[end..])?;
        return Ok(end);
    }
    let host_end = authority.rfind(':').unwrap_or(authority.len());
    if authority[..host_end].contains(':') {
        return Err(());
    }
    if host_end < authority.len() {
        validate_port(&authority[host_end + 1..])?;
    }
    if host_end == 0 {
        return Err(());
    }
    Ok(host_end)
}

fn validate_port_suffix(suffix: &str) -> Result<(), ()> {
    if suffix.is_empty() {
        return Ok(());
    }
    let port = suffix.strip_prefix(':').ok_or(())?;
    validate_port(port)
}

fn validate_port(port: &str) -> Result<(), ()> {
    if port.is_empty()
        || port.len() > 5
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().map_err(|_| ())? == 0
    {
        return Err(());
    }
    Ok(())
}

fn validate_ipv6(host: &str) -> Result<(), ()> {
    let value = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(())?;
    if value.is_empty()
        || value.contains(['.', '%'])
        || !value
            .bytes()
            .all(|byte| byte == b':' || byte.is_ascii_hexdigit())
        || Ipv6Addr::from_str(value).is_err()
    {
        return Err(());
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<Option<bool>, ()> {
    if host.starts_with('[') {
        return Ok(None);
    }
    let has_defanged = host.contains("[.]");
    let without_markers = host.replace("[.]", "");
    let has_active = without_markers.contains('.');
    if has_active && has_defanged {
        return Err(());
    }
    let (separator, defanged) = if has_defanged {
        ("[.]", true)
    } else {
        (".", false)
    };
    let mut labels: Vec<&str> = host.split(separator).collect();
    let trailing_root = labels.len() > 1 && labels.last() == Some(&"");
    if trailing_root {
        labels.pop();
    }
    let mut all_decimal = labels.len() == 4;
    for label in &labels {
        validate_label(label)?;
        all_decimal &= label.bytes().all(|byte| byte.is_ascii_digit());
    }
    if all_decimal {
        validate_ipv4(&labels)?;
    } else if logical_host_length(&labels) > 253 {
        return Err(());
    }
    if labels.len() == 1 && !trailing_root {
        Ok(None)
    } else {
        Ok(Some(defanged))
    }
}

fn validate_label(label: &str) -> Result<(), ()> {
    if label.is_empty()
        || label.len() > 63
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(());
    }
    Ok(())
}

fn validate_ipv4(labels: &[&str]) -> Result<(), ()> {
    for label in labels {
        if label.len() > 1 && label.starts_with('0') || label.parse::<u8>().is_err() {
            return Err(());
        }
    }
    Ok(())
}

fn logical_host_length(labels: &[&str]) -> usize {
    labels.iter().map(|label| label.len()).sum::<usize>() + labels.len() - 1
}

fn validate_suffix(suffix: &str) -> Result<(), ()> {
    let bytes = suffix.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn transform_scheme(scheme: &str, defang: bool) -> Result<&'static str, ()> {
    match (scheme, defang) {
        ("http", true) | ("hxxp", true) => Ok("hxxp"),
        ("https", true) | ("hxxps", true) => Ok("hxxps"),
        ("http", false) | ("hxxp", false) => Ok("http"),
        ("https", false) | ("hxxps", false) => Ok("https"),
        _ => Err(()),
    }
}

fn transform_host(host: &str, defang: bool) -> Result<String, ()> {
    if host.starts_with('[') || !host.contains('.') && !host.contains("[.]") {
        return Ok(host.to_owned());
    }
    let defanged = host.contains("[.]");
    let active = host.replace("[.]", "").contains('.');
    if active && defanged {
        return Err(());
    }
    if defanged == defang {
        return Ok(host.to_owned());
    }
    if defang {
        Ok(host.replace('.', "[.]"))
    } else {
        Ok(host.replace("[.]", "."))
    }
}

fn sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests;
