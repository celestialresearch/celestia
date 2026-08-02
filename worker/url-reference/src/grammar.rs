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

use crate::request::MAX_INPUT_BYTES;
use crate::response::MAX_OUTPUT_BYTES;
use std::net::Ipv6Addr;
use std::str::FromStr;

pub(crate) struct Reference<'a> {
    pub(crate) scheme: &'a str,
    pub(crate) separator: &'a str,
    pub(crate) host: &'a str,
    pub(crate) suffix: &'a str,
    pub(crate) defanged: bool,
}

pub(crate) fn parse(input: &str) -> Result<Reference<'_>, ()> {
    if input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err(());
    }
    validate_text(input)?;
    let scheme_end = input.find("://").ok_or(())?;
    let authority_start = scheme_end + 3;
    let authority_end = input[authority_start..]
        .find(['/', '?', '#'])
        .map_or(input.len(), |index| authority_start + index);
    let authority = &input[authority_start..authority_end];
    let host_end = validate_authority(authority)?;
    let scheme = &input[..scheme_end];
    let defanged = scheme_state(scheme)?;
    if let Some(host_defanged) = validate_host(&authority[..host_end])?
        && host_defanged != defanged
    {
        return Err(());
    }
    validate_suffix(&input[authority_end..])?;
    Ok(Reference {
        scheme,
        separator: &input[scheme_end..authority_start],
        host: &authority[..host_end],
        suffix: &input[authority_start + host_end..],
        defanged,
    })
}

fn validate_text(input: &str) -> Result<(), ()> {
    if input.len() > MAX_OUTPUT_BYTES || input.chars().any(rejected_character) {
        return Err(());
    }
    Ok(())
}

fn rejected_character(value: char) -> bool {
    value == '\0'
        || value <= '\u{1f}'
        || value == '\u{7f}'
        || matches!(
            value,
            '\u{20}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
}

fn scheme_state(scheme: &str) -> Result<bool, ()> {
    match scheme {
        "http" | "https" => Ok(false),
        "hxxp" | "hxxps" => Ok(true),
        _ => Err(()),
    }
}

fn validate_authority(authority: &str) -> Result<usize, ()> {
    if authority.is_empty() || authority.contains('@') {
        return Err(());
    }
    if authority.starts_with('[') {
        let end = authority.find(']').map(|index| index + 1).ok_or(())?;
        validate_ipv6(&authority[..end])?;
        validate_port_suffix(&authority[end..])?;
        return Ok(end);
    }
    let host_end = authority.rfind(':').unwrap_or(authority.len());
    if authority[..host_end].contains(':') {
        return Err(());
    }
    if host_end < authority.len() {
        validate_port(&authority[host_end + 1..])?;
    }
    if host_end == 0 {
        return Err(());
    }
    Ok(host_end)
}

fn validate_port_suffix(suffix: &str) -> Result<(), ()> {
    if suffix.is_empty() {
        return Ok(());
    }
    validate_port(suffix.strip_prefix(':').ok_or(())?)
}

fn validate_port(port: &str) -> Result<(), ()> {
    if port.is_empty()
        || port.len() > 5
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().map_err(|_| ())? == 0
    {
        return Err(());
    }
    Ok(())
}

fn validate_ipv6(host: &str) -> Result<(), ()> {
    let value = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(())?;
    if value.is_empty()
        || value.contains(['.', '%'])
        || !value
            .bytes()
            .all(|byte| byte == b':' || byte.is_ascii_hexdigit())
        || Ipv6Addr::from_str(value).is_err()
    {
        return Err(());
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<Option<bool>, ()> {
    if host.starts_with('[') {
        return Ok(None);
    }
    let has_defanged = host.contains("[.]");
    let has_active = host.replace("[.]", "").contains('.');
    if has_active && has_defanged {
        return Err(());
    }
    let (separator, defanged) = if has_defanged {
        ("[.]", true)
    } else {
        (".", false)
    };
    let mut labels: Vec<&str> = host.split(separator).collect();
    let trailing_root = labels.len() > 1 && labels.last() == Some(&"");
    if trailing_root {
        labels.pop();
    }
    let mut all_decimal = labels.len() == 4;
    for label in &labels {
        validate_label(label)?;
        all_decimal &= label.bytes().all(|byte| byte.is_ascii_digit());
    }
    if all_decimal {
        validate_ipv4(&labels)?;
    } else if logical_host_length(&labels) > 253 {
        return Err(());
    }
    if labels.len() == 1 && !trailing_root {
        Ok(None)
    } else {
        Ok(Some(defanged))
    }
}

fn validate_label(label: &str) -> Result<(), ()> {
    if label.is_empty()
        || label.len() > 63
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(());
    }
    Ok(())
}

fn validate_ipv4(labels: &[&str]) -> Result<(), ()> {
    for label in labels {
        if label.len() > 1 && label.starts_with('0') || label.parse::<u8>().is_err() {
            return Err(());
        }
    }
    Ok(())
}

fn logical_host_length(labels: &[&str]) -> usize {
    labels.iter().map(|label| label.len()).sum::<usize>() + labels.len() - 1
}

fn validate_suffix(suffix: &str) -> Result<(), ()> {
    let bytes = suffix.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}
