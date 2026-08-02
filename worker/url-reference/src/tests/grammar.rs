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

use crate::grammar::parse;

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
        assert!(parse(input).is_err(), "accepted {input:?}");
    }
}

#[test]
fn rejects_mixed_hosts() {
    assert!(parse("https://example[.]test/").is_err());
}
