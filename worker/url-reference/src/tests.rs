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

use super::{Mode, transform, valid_deadline, valid_identity};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceFixture {
    version: u8,
    accepted: Vec<ConformanceCase>,
    rejected: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceCase {
    input: String,
    fang: String,
    defang: String,
}

#[test]
fn matches_conformance_fixture() {
    let fixture: ConformanceFixture =
        serde_json::from_str(include_str!("../../../testdata/url-reference-v0.json"))
            .expect("valid conformance fixture");
    assert_eq!(fixture.version, 0);
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
