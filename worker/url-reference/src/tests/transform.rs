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

use crate::request::Mode;
use crate::transform::transform;
use serde::Deserialize;

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

#[test]
fn matches_conformance_fixture() {
    let fixture: ConformanceFixture =
        serde_json::from_str(include_str!("../../../../testdata/url-reference-v1.json"))
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
