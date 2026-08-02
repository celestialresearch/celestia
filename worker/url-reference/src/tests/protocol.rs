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

use crate::protocol::{
    Response, parse_request, sha256, valid_deadline, valid_identity, validate_request,
    write_response_to,
};
use crate::transform::transform;
use std::io::{self, Write};

#[derive(Default)]
struct RecordingWriter {
    data: Vec<u8>,
    flushes: usize,
    fail_flush: bool,
}

impl Write for RecordingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.data.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            return Err(io::Error::other("flush"));
        }
        Ok(())
    }
}

#[test]
fn response_write_requires_flush() {
    let response = Response {
        protocol_version: 1,
        operation_id: "url-reference",
        operation_version: 1,
        attempt_id: "attempt",
        request_nonce: "nonce",
        worker_id: "celestia-url-reference",
        worker_version: "1",
        status: "failed",
        output_media_type: None,
        output_length: None,
        output_sha256: None,
        output: None,
        diagnostics: Vec::new(),
        duration_ns: 0,
    };
    let mut writer = RecordingWriter::default();
    assert_eq!(write_response_to(&response, &mut writer), Ok(()));
    assert_eq!(writer.flushes, 1);
    assert!(!writer.data.is_empty());
    writer.fail_flush = true;
    assert_eq!(write_response_to(&response, &mut writer), Err(()));
    assert_eq!(writer.flushes, 2);
}

#[test]
fn checks_identifiers() {
    assert!(valid_identity(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    ));
    assert!(!valid_identity(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9"
    ));
    assert!(!valid_identity("invalid"));
}

#[test]
fn checks_deadlines() {
    assert!(valid_deadline("2026-07-25T12:34:56Z"));
    assert!(valid_deadline("2026-07-25T12:34:56.123456789Z"));
    assert!(valid_deadline("2024-02-29T23:59:59.1Z"));
    assert!(!valid_deadline("2026-07-25T12:34:56+00:00"));
    assert!(!valid_deadline("2026-07-25T12:34:56.Z"));
    assert!(!valid_deadline("2026-02-29T12:34:56Z"));
    assert!(!valid_deadline("2026-13-25T12:34:56Z"));
    assert!(!valid_deadline("2026-07-25T24:34:56Z"));
    assert!(!valid_deadline("2026-07-25T12:34:60Z"));
    assert!(!valid_deadline("2026-07-25T12:34:56.10Z"));
    assert!(!valid_deadline("not-a-deadline"));
}

#[test]
fn mutated_request_frames_are_deterministic_and_bounded() {
    let seed = valid_request_frame();
    assert!(parse_request(&seed).is_ok());
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for iteration in 0..25_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut candidate = seed.clone();
        let index =
            usize::try_from(state).expect("u64 fits usize on supported workers") % candidate.len();
        match iteration % 4 {
            0 => candidate[index] ^= u8::try_from(state >> 56).expect("shifted byte fits u8"),
            1 => {
                candidate.remove(index);
            }
            2 => candidate.insert(
                index,
                u8::try_from(state >> 56).expect("shifted byte fits u8"),
            ),
            _ => candidate.truncate(index),
        }
        let first = parse_request(&candidate);
        let second = parse_request(&candidate);
        assert_eq!(first.is_ok(), second.is_ok());
        if let Ok(request) = first {
            assert!(validate_request(&request).is_ok());
            assert!(transform(&request.input, &request.mode).is_ok());
        }
    }
}

fn valid_request_frame() -> Vec<u8> {
    let input = "https://example.test/";
    format!(
        concat!(
            "{{\"protocol_version\":1,\"operation_id\":\"url-reference\",",
            "\"operation_version\":1,",
            "\"attempt_id\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\",",
            "\"request_nonce\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",",
            "\"input_media_type\":\"text/plain; charset=utf-8\",",
            "\"input_length\":{},\"input_sha256\":\"{}\",",
            "\"mode\":\"defang\",\"deadline\":\"2026-07-25T12:34:56Z\",",
            "\"timeout_ms\":2000,\"limits\":{{\"input_bytes\":4096,",
            "\"output_bytes\":8192,\"stderr_bytes\":8192,",
            "\"memory_bytes\":67108864,\"processes\":1}},",
            "\"input\":\"{}\"}}"
        ),
        input.len(),
        sha256(input),
        input,
    )
    .into_bytes()
}
