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

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::ptr;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn main() {
    match env::args().nth(1).as_deref() {
        Some("child") => child(),
        Some("grandchild") => hang(),
        _ => run_fixture(),
    }
}

fn run_fixture() {
    let mut request = String::new();
    io::stdin()
        .read_to_string(&mut request)
        .expect("read fixture request");
    if request.starts_with('{') {
        semantic_lie(&request);
        return;
    }
    let (mode, value) = request.split_once('\n').unwrap_or((&request, ""));
    match mode {
        "malformed" => print!("{{"),
        "partial" => {
            print!("{{\"partial\":");
            std::process::exit(7);
        }
        "stdout_overflow" => write_repeated(io::stdout(), b'x', 131_072),
        "stderr_overflow" => write_repeated(io::stderr(), b'x', 131_072),
        "hang" => hang(),
        "descendant" => spawn_descendant(),
        "descendant_exit" => spawn_descendant_and_exit(),
        "grandchild" => spawn_child(),
        "network" => report(connect(value)),
        "file" => report(fs::read(value).is_ok()),
        "credentials" => report(credentials_available()),
        "memory" => exhaust_memory(),
        _ => std::process::exit(64),
    }
}

fn semantic_lie(request: &str) {
    let request: Value = serde_json::from_str(request).expect("decode request");
    let output = request["input"].as_str().expect("request input");
    if output.contains("rejected.test") {
        terminal_response(&request, "rejected", "fixture_rejected", 2);
    }
    if output.contains("failed.test") {
        terminal_response(&request, "failed", "fixture_failed", 3);
    }
    if output.contains("malformed.test") {
        print!("{{");
        return;
    }
    if output.contains("partial.test") {
        print!("{{\"partial\":");
        std::process::exit(7);
    }
    let digest = Sha256::digest(output.as_bytes()).iter().fold(
        String::with_capacity(64),
        |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("encode digest");
            encoded
        },
    );
    let response = json!({
        "protocol_version": 0,
        "operation_id": "url-reference",
        "operation_version": 0,
        "attempt_id": request["attempt_id"],
        "request_nonce": request["request_nonce"],
        "worker_id": "celestia-url-reference",
        "worker_version": "0",
        "status": "completed",
        "output_media_type": "text/plain; charset=utf-8",
        "output_length": output.len(),
        "output_sha256": digest,
        "output": output,
        "diagnostics": [],
        "duration_ns": 1
    });
    print!(
        "{}",
        serde_json::to_string(&response).expect("encode response")
    );
}

fn terminal_response(request: &Value, status: &str, code: &str, exit: i32) -> ! {
    let response = json!({
        "protocol_version": 0,
        "operation_id": "url-reference",
        "operation_version": 0,
        "attempt_id": request["attempt_id"],
        "request_nonce": request["request_nonce"],
        "worker_id": "celestia-url-reference",
        "worker_version": "0",
        "status": status,
        "diagnostics": [{"code": code, "message": "hostile fixture terminal response"}],
        "duration_ns": 1
    });
    print!(
        "{}",
        serde_json::to_string(&response).expect("encode terminal response")
    );
    std::process::exit(exit);
}

fn write_repeated(mut output: impl Write, value: u8, count: usize) {
    let block = vec![value; count];
    output.write_all(&block).expect("write fixture output");
}

fn spawn_descendant() {
    let child = Command::new(env::current_exe().expect("fixture path"))
        .arg("grandchild")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(child) => {
            print!("{}", child.id());
            io::stdout().flush().expect("flush descendant identity");
            hang();
        }
        Err(_) => print!("blocked"),
    }
}

#[allow(
    clippy::zombie_processes,
    reason = "hostile fixture leaves the child for supervisor qualification"
)]
fn spawn_descendant_and_exit() {
    let child = Command::new(env::current_exe().expect("fixture path"))
        .arg("grandchild")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(child) => {
            print!("{}", child.id());
            io::stdout().flush().expect("flush descendant identity");
        }
        Err(_) => print!("blocked"),
    }
}

#[allow(
    clippy::zombie_processes,
    reason = "hostile fixture deliberately leaves descendants for the supervisor"
)]
fn spawn_child() {
    let Ok(mut child) = Command::new(env::current_exe().expect("fixture path"))
        .arg("child")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        print!("blocked");
        return;
    };
    let mut identity = String::new();
    BufReader::new(child.stdout.take().expect("child output"))
        .read_line(&mut identity)
        .expect("read grandchild identity");
    print!("{identity}");
    io::stdout().flush().expect("flush grandchild identity");
    hang();
}

#[allow(
    clippy::zombie_processes,
    reason = "hostile fixture deliberately leaves descendants for the supervisor"
)]
fn child() {
    let Ok(grandchild) = Command::new(env::current_exe().expect("fixture path"))
        .arg("grandchild")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        print!("blocked");
        return;
    };
    println!("{}", grandchild.id());
    io::stdout().flush().expect("flush grandchild identity");
    hang();
}

fn hang() -> ! {
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn report(allowed: bool) {
    print!("{}", if allowed { "allowed" } else { "denied" });
}

#[cfg(windows)]
fn credentials_available() -> bool {
    type Dword = u32;
    type Bool = i32;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn CredEnumerateW(
            filter: *const u16,
            flags: Dword,
            count: *mut Dword,
            credentials: *mut *mut *mut core::ffi::c_void,
        ) -> Bool;
        fn CredFree(buffer: *mut core::ffi::c_void);
    }
    let mut count = 0;
    let mut credentials = ptr::null_mut();
    // SAFETY: Windows owns the returned array and CredFree releases it.
    let allowed = unsafe { CredEnumerateW(ptr::null(), 0, &mut count, &mut credentials) } != 0;
    if allowed && !credentials.is_null() {
        // SAFETY: CredEnumerateW returned this allocation on success.
        unsafe { CredFree(credentials.cast()) };
    }
    allowed
}

#[cfg(not(windows))]
fn credentials_available() -> bool {
    false
}

fn exhaust_memory() {
    let mut memory = Vec::<u8>::new();
    if memory.try_reserve_exact(134_217_728).is_err() {
        report(false);
        return;
    }
    memory.resize(134_217_728, 1);
    report(memory.len() == 134_217_728);
}

fn connect(value: &str) -> bool {
    let Ok(address) = value.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
}
