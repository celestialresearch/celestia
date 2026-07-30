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

use super::{
    Mode, Response, parse_request, sha256, transform, valid_deadline, valid_identity,
    validate_request, write_response_to,
};
use serde::Deserialize;
use std::io::{self, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceFixture {
    version: u8,
    boundaries: ConformanceBounds,
    accepted: Vec<ConformanceCase>,
    rejected: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceBounds {
    label_max: usize,
    host_max: usize,
    input_max: usize,
    port_digits_max: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceCase {
    input: String,
    fang: String,
    defang: String,
}

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
fn matches_conformance_fixture() {
    let fixture: ConformanceFixture =
        serde_json::from_str(include_str!("../../../testdata/url-reference-v1.json"))
            .expect("valid conformance fixture");
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.boundaries.label_max, 63);
    assert_eq!(fixture.boundaries.host_max, 253);
    assert_eq!(fixture.boundaries.input_max, 4_096);
    assert_eq!(fixture.boundaries.port_digits_max, 5);
    assert_conformance_boundaries(&fixture.boundaries);
    assert!(!fixture.accepted.is_empty());
    assert!(!fixture.rejected.is_empty());
    for case in fixture.accepted {
        assert_eq!(transform(&case.input, &Mode::Fang), Ok(case.fang));
        assert_eq!(transform(&case.input, &Mode::Defang), Ok(case.defang));
    }
    for input in fixture.rejected {
        for (name, mode) in [("fang", Mode::Fang), ("defang", Mode::Defang)] {
            assert_eq!(transform(&input, &mode), Err(()), "{name}: {input}");
        }
    }
}

fn assert_conformance_boundaries(bounds: &ConformanceBounds) {
    let label = "a".repeat(bounds.label_max);
    let host = format!("{label}.{label}.{label}.{}", "a".repeat(61));
    let prefix = "https://example.test/";
    let accepted = [
        format!("https://{label}.test/"),
        format!("https://{host}/"),
        "https://example.test:1/".to_owned(),
        "https://example.test:65535/".to_owned(),
        format!("{prefix}{}", "a".repeat(bounds.input_max - prefix.len())),
    ];
    let rejected = [
        format!("https://{}.test/", "a".repeat(bounds.label_max + 1)),
        format!("https://{host}a/"),
        "https://example.test:0/".to_owned(),
        "https://example.test:65536/".to_owned(),
        format!(
            "{prefix}{}",
            "a".repeat(bounds.input_max - prefix.len() + 1)
        ),
    ];
    for input in accepted {
        assert!(
            transform(&input, &Mode::Fang).is_ok(),
            "rejected boundary input"
        );
    }
    for input in rejected {
        assert!(
            transform(&input, &Mode::Fang).is_err(),
            "accepted out-of-bound input: length={} input={input}",
            input.len()
        );
    }
}

#[test]
fn transforms_references() {
    assert_eq!(
        transform("https://example.test/a.b", &Mode::Defang),
        Ok("hxxps://example[.]test/a.b".to_owned())
    );
    assert_eq!(
        transform("hxxps://example[.]test/a.b", &Mode::Fang),
        Ok("https://example.test/a.b".to_owned())
    );
    assert_eq!(
        transform("https://[2001:db8::1]:443/", &Mode::Defang),
        Ok("hxxps://[2001:db8::1]:443/".to_owned())
    );
}

#[test]
fn rejects_mixed_hosts() {
    assert_eq!(transform("https://example[.]test/", &Mode::Defang), Err(()));
}

#[test]
fn rejects_invalid_references() {
    let inputs = [
        "",
        "example.test",
        "HTTPS://example.test",
        "https:///path",
        "https://example.test:",
        "https://example.test:0",
        "https://example.test:65536",
        "https://user@example.test/",
        "https://256.0.2.1/",
        "https://192.00.2.1/",
        "https://2001:db8::1/",
        "https://[::ffff:192.0.2.1]/",
        "https://[fe80::1%25eth0]/",
        "https://bücher.example/",
        "https://example。test/",
        "https://example.test/%2",
        " https://example.test/",
        "https://example.test/ ",
        "hxxps://a[.]b.c/",
    ];
    for input in inputs {
        assert_eq!(
            transform(input, &Mode::Defang),
            Err(()),
            "accepted {input:?}"
        );
    }
}

#[test]
fn preserves_round_trips() {
    let inputs = [
        "http://example.test",
        "https://sub.example.test:00443/a.b?q=1.2#x.y",
        "https://192.0.2.10/",
        "https://[2001:db8::1]/",
        "https://xn--bcher-kva.example/",
    ];
    for input in inputs {
        let defanged = transform(input, &Mode::Defang).expect("valid active reference");
        assert_eq!(transform(&defanged, &Mode::Defang), Ok(defanged.clone()));
        assert_eq!(transform(&defanged, &Mode::Fang), Ok(input.to_owned()));
    }
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
