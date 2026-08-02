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

use crate::response::{Response, write_to};
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
    assert_eq!(write_to(&response, &mut writer), Ok(()));
    assert_eq!(writer.flushes, 1);
    assert!(!writer.data.is_empty());
    writer.fail_flush = true;
    assert_eq!(write_to(&response, &mut writer), Err(()));
    assert_eq!(writer.flushes, 2);
}
