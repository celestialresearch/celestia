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

mod protocol;
mod transform;

use protocol::{
    Diagnostic, MAX_OUTPUT_BYTES, Response, duration_ns, parse_request, read_request, sha256,
    write_response,
};
use std::process::ExitCode;
use std::time::Instant;
use transform::transform;

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(()) => ExitCode::from(3),
    }
}

fn run() -> Result<ExitCode, ()> {
    let start = Instant::now();
    let data = read_request()?;
    let request = parse_request(&data)?;
    let output = match transform(&request.input, &request.mode) {
        Ok(output) => output,
        Err(()) => {
            let response = Response {
                protocol_version: 1,
                operation_id: "url-reference",
                operation_version: 1,
                attempt_id: &request.attempt_id,
                request_nonce: &request.request_nonce,
                worker_id: "celestia-url-reference",
                worker_version: "1",
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
        protocol_version: 1,
        operation_id: "url-reference",
        operation_version: 1,
        attempt_id: &request.attempt_id,
        request_nonce: &request.request_nonce,
        worker_id: "celestia-url-reference",
        worker_version: "1",
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

#[cfg(test)]
mod tests;
