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

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const IDENTITY: &str = "oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoYA";

#[test]
fn writes_completed_response() {
    let output = run_worker(request("https://example.test/", "defang"));

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.ends_with(b"\n"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("valid response JSON");
    assert_eq!(response["status"], "completed");
    assert_eq!(response["output"], "hxxps://example[.]test/");
    assert_eq!(response["attempt_id"], IDENTITY);
    assert_eq!(response["request_nonce"], IDENTITY);
    assert_eq!(response["diagnostics"], json!([]));
}

#[test]
fn writes_rejected_response() {
    let output = run_worker(request("https://user@example.test/", "defang"));

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).expect("valid response JSON");
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["diagnostics"][0]["code"], "invalid_reference");
    assert!(response.get("output").is_none());
    assert!(response.get("output_length").is_none());
    assert!(response.get("output_sha256").is_none());
    assert!(response.get("output_media_type").is_none());
}

#[test]
fn rejects_malformed_frame() {
    let output = run_worker(b"{".to_vec());

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn request(input: &str, mode: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "protocol_version": 0,
        "operation_id": "url-reference",
        "operation_version": 0,
        "attempt_id": IDENTITY,
        "request_nonce": IDENTITY,
        "input_media_type": "text/plain; charset=utf-8",
        "input_length": input.len(),
        "input_sha256": sha256(input),
        "mode": mode,
        "deadline": "2026-07-25T12:34:56.123456789Z",
        "timeout_ms": 2000,
        "limits": {
            "input_bytes": 4096,
            "output_bytes": 8192,
            "stderr_bytes": 8192,
            "memory_bytes": 67108864,
            "processes": 1
        },
        "input": input
    }))
    .expect("serialise request")
}

fn sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn run_worker(input: Vec<u8>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_celestia-url-reference"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start worker");
    child
        .stdin
        .take()
        .expect("worker stdin")
        .write_all(&input)
        .expect("write request");
    child.wait_with_output().expect("wait for worker")
}
