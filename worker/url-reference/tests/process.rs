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
use std::io::{self, Write};
use std::process::{Child, Command, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const ATTEMPT_ID: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const REQUEST_NONCE: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";

#[test]
fn writes_completed_response() {
    let output = run_worker(request("https://example.test/", "defang"));

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.ends_with(b"\n"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("valid response JSON");
    assert_eq!(response["status"], "completed");
    assert_eq!(response["output"], "hxxps://example[.]test/");
    assert_eq!(response["attempt_id"], ATTEMPT_ID);
    assert_eq!(response["request_nonce"], REQUEST_NONCE);
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

#[test]
fn rejects_non_compact_frame() {
    let mut input = request("https://example.test/", "defang");
    input.push(b'\n');
    let output = run_worker(input);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn rejects_repeated_correlation() {
    let mut frame: Value =
        serde_json::from_slice(&request("https://example.test/", "defang")).expect("request JSON");
    frame["request_nonce"] = Value::String(ATTEMPT_ID.to_owned());
    let output = run_worker(serde_json::to_vec(&frame).expect("serialise request"));

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn request(input: &str, mode: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "protocol_version": 0,
        "operation_id": "url-reference",
        "operation_version": 0,
        "attempt_id": ATTEMPT_ID,
        "request_nonce": REQUEST_NONCE,
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
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn run_worker(input: Vec<u8>) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    let child = Command::new(env!("CARGO_BIN_EXE_celestia-url-reference"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start worker");
    let mut child = ChildGuard::new(child);
    let mut stdin = child.child_mut().stdin.take().expect("worker stdin");
    let mut writer = Some(thread::spawn(move || stdin.write_all(&input)));
    let mut failure = None;
    loop {
        if let Some(handle) = writer.take_if(|handle| handle.is_finished())
            && join_writer(handle).is_err()
        {
            failure = Some("write request");
            break;
        }
        match child.child_mut().try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(_) => {
                failure = Some("query worker");
                break;
            }
        }
        if Instant::now() >= deadline {
            failure = Some("worker exceeded test deadline");
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if let Some(reason) = failure {
        let cleanup = child.terminate();
        if let Some(handle) = writer {
            let _ = join_writer(handle);
        }
        match cleanup {
            Ok(()) => panic!("{reason}"),
            Err(error) => panic!("{reason}; clean up worker: {error}"),
        }
    }
    if let Some(handle) = writer {
        join_writer(handle).expect("write request");
    }
    child.output().expect("collect worker output")
}

fn join_writer(writer: JoinHandle<io::Result<()>>) -> io::Result<()> {
    writer
        .join()
        .map_err(|_| io::Error::other("worker input thread panicked"))?
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("owned worker")
    }

    fn terminate(&mut self) -> io::Result<()> {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            if let Err(error) = child.kill() {
                if child.try_wait()?.is_some() {
                    return Ok(());
                }
                return Err(error);
            }
            child.wait()?;
        }
        Ok(())
    }

    fn output(mut self) -> io::Result<Output> {
        self.child.take().expect("owned worker").wait_with_output()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}
