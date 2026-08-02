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

use crate::request::{parse, sha256, valid_deadline, valid_identity, validate};
use crate::transform::transform;

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
    assert!(parse(&seed).is_ok());
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
        let first = parse(&candidate);
        let second = parse(&candidate);
        assert_eq!(first.is_ok(), second.is_ok());
        if let Ok(request) = first {
            assert!(validate(&request).is_ok());
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
