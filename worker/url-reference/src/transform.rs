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

use crate::grammar;
use crate::request::Mode;

pub(crate) fn transform(input: &str, mode: &Mode) -> Result<String, ()> {
    let reference = grammar::parse(input)?;
    let target_defanged = matches!(mode, Mode::Defang);
    let transformed_scheme = transform_scheme(reference.scheme, target_defanged)?;
    let transformed_host = transform_host(reference.host, target_defanged, reference.defanged);
    Ok(format!(
        "{transformed_scheme}{}{transformed_host}{}",
        reference.separator, reference.suffix
    ))
}

fn transform_scheme(scheme: &str, defang: bool) -> Result<&'static str, ()> {
    match (scheme, defang) {
        ("http", true) | ("hxxp", true) => Ok("hxxp"),
        ("https", true) | ("hxxps", true) => Ok("hxxps"),
        ("http", false) | ("hxxp", false) => Ok("http"),
        ("https", false) | ("hxxps", false) => Ok("https"),
        _ => Err(()),
    }
}

fn transform_host(host: &str, defang: bool, currently_defanged: bool) -> String {
    if host.starts_with('[') || currently_defanged == defang {
        return host.to_owned();
    }
    if defang {
        host.replace('.', "[.]")
    } else {
        host.replace("[.]", ".")
    }
}
