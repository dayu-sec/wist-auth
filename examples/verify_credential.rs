//! 验证示例程序：拿一条凭据 + 一张登记表，在**本地**判断它还能不能用。
//!
//! ```sh
//! cargo run --features credential --example verify_credential -- \
//!   --store ./credentials.json \
//!   --token "wcr_..." \
//!   --audience wist-center \
//!   --known-roles read,investigation:run
//! ```
//!
//! - 成功：打印 `{"ok":true,"credential":{...}}`，退出码 `0`。
//! - 失败：打印 `{"ok":false,"code":"token_revoked",...}`，退出码 `1`。
//!
//! 这个程序**不联网**：登记的摘要来自 `wist-cred` 推来的（或落盘同步的）文件。
//! 省略 `--known-roles` 时按表里出现过的角色全集处理（方便演示）；给出时演示 D9 的裁剪。

use std::process::ExitCode;

use serde_json::json;
use wist_auth::credential::{CredentialError, CredentialStore, StoreParams};

struct Args {
    store: String,
    token: String,
    audience: String,
    known_roles: Option<Vec<String>>,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: verify_credential --store <file> --token <token> --audience <aud> \
                 [--known-roles a,b,c]"
            );
            return ExitCode::from(2);
        }
    };

    // 没给 --known-roles 时，直接从**原始 JSON** 里取角色全集——
    // 不能用 `CredentialStore::open` 探：open 会按策略裁剪，用空策略探会把角色全裁没。
    let params = match args.known_roles {
        Some(roles) => StoreParams {
            known_roles: roles,
            ..StoreParams::default()
        },
        None => match roles_in_store(&args.store) {
            Ok(roles) => StoreParams {
                known_roles: roles,
                ..StoreParams::default()
            },
            Err(message) => {
                eprintln!("{message}");
                return ExitCode::from(2);
            }
        },
    };

    let store = match CredentialStore::open(&args.store, params) {
        Ok(store) => store,
        Err(error) => return report(&error),
    };

    match store.verify(&args.token, &args.audience) {
        Ok(verified) => {
            println!(
                "{}",
                json!({
                    "ok": true,
                    "credential": {
                        "credential_id": verified.credential_id,
                        "subject": verified.subject,
                        "roles": verified.roles,
                        "resources": verified.resources,
                        "audience": verified.audience,
                        "expires_at": verified.expires_at,
                    }
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => report(&error),
    }
}

fn report(error: &CredentialError) -> ExitCode {
    println!(
        "{}",
        json!({
            "ok": false,
            "code": error.code(),
            "status": error.status(),
            "error": error.to_string(),
        })
    );
    ExitCode::from(1)
}

/// 表里出现过的角色全集（**不做裁剪**，只读原始 JSON）。
fn roles_in_store(path: &str) -> Result<Vec<String>, String> {
    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(default)]
        credentials: Vec<Item>,
    }
    #[derive(serde::Deserialize)]
    struct Item {
        #[serde(default)]
        roles: Vec<String>,
    }

    let text = std::fs::read_to_string(path).map_err(|err| format!("read store {path}: {err}"))?;
    let raw: Raw =
        serde_json::from_str(&text).map_err(|err| format!("parse store {path}: {err}"))?;
    let mut roles: Vec<String> = raw
        .credentials
        .into_iter()
        .flat_map(|item| item.roles)
        .collect();
    roles.sort_unstable();
    roles.dedup();
    Ok(roles)
}

fn parse_args() -> Result<Args, String> {
    let mut store = None;
    let mut token = None;
    let mut audience = None;
    let mut known_roles = None;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--store" => store = Some(value),
            "--token" => token = Some(value),
            "--audience" => audience = Some(value),
            "--known-roles" => {
                known_roles = Some(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                );
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }

    Ok(Args {
        store: store.ok_or("--store is required")?,
        token: token.ok_or("--token is required")?,
        audience: audience.ok_or("--audience is required")?,
        known_roles,
    })
}
