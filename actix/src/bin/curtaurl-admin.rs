// SPDX-FileCopyrightText: 2023 Sayantan Santra <sayantan.santra689@gmail.com>
// SPDX-License-Identifier: MIT

use serde::Deserialize;
use serde_json::json;
use std::env;

use chrono::{TimeZone, Utc};


#[derive(Deserialize)]
struct ApiError {
    reason: Option<String>,
}

#[derive(Deserialize)]
struct CreateKeyResponse {
    success: bool,
    error: bool,
    id: i64,
    name: String,
    key: String,
    created_at: i64,
}

#[derive(Deserialize)]
struct ApiKeyRecord {
    id: i64,
    name: String,
    created_at: i64,
    last_used_at: Option<i64>,
    revoked_at: Option<i64>,
    notes: Option<String>,
}

#[derive(Deserialize)]
struct KeyListResponse {
    success: bool,
    error: bool,
    keys: Vec<ApiKeyRecord>,
}

#[derive(Deserialize)]
struct KeyRevokeResponse {
    success: bool,
    error: bool,
    id: i64,
    revoked: bool,
}

fn main() {
    dotenvy::dotenv().ok();
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        std::process::exit(1);
    };

    if command == "-h" || command == "--help" {
        print_usage();
        return;
    }

    let base_url = env::var("CURTAURL_URL").unwrap_or_else(|_| "http://localhost:4567".to_string());
    let api_key = match env::var("CURTAURL_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            eprintln!("CURTAURL_API_KEY is required.");
            std::process::exit(1);
        }
    };

    match command.as_str() {
        "create" => {
            let mut name = None;
            let mut notes = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--name" => name = args.next(),
                    "--notes" => notes = args.next(),
                    "-h" | "--help" => {
                        print_usage();
                        return;
                    }
                    _ => {
                        eprintln!("Unknown argument: {arg}");
                        print_usage();
                        std::process::exit(1);
                    }
                }
            }

            let Some(name) = name else {
                eprintln!("--name is required for create.");
                std::process::exit(1);
            };

            let payload = json!({
                "name": name,
                "notes": notes,
            });

            let resp = ureq::post(&format!("{base_url}/api/keys"))
                .set("X-API-Key", &api_key)
                .send_json(payload);

            match resp {
                Ok(response) => {
                    let body: CreateKeyResponse = response
                        .into_json()
                        .unwrap_or_else(|_| exit_with_error("Invalid response payload."));
                    if body.success {
                        println!("Created key {id} ({name})", id = body.id, name = body.name);
                        println!("Key: {key}", key = body.key);
                        let created = format_ts(body.created_at);
                        println!("Created at: {created}");
                    } else if body.error {
                        eprintln!("Server error while creating key.");
                        std::process::exit(1);
                    }
                }
                Err(err) => {
                    report_api_error(err);
                    std::process::exit(1);
                }
            }
        }
        "list" => {
            let resp = ureq::get(&format!("{base_url}/api/keys"))
                .set("X-API-Key", &api_key)
                .call();

            match resp {
                Ok(response) => {
                    let body: KeyListResponse = response
                        .into_json()
                        .unwrap_or_else(|_| exit_with_error("Invalid response payload."));
                    if body.success {
                        if body.keys.is_empty() {
                            println!("No managed API keys found.");
                        } else {
                            let headers = [
                                "ID",
                                "Name",
                                "Created",
                                "Last Used",
                                "Revoked",
                                "Notes",
                            ];
                            let mut rows: Vec<Vec<String>> = Vec::new();
                            for key in body.keys {
                                let notes = key.notes.unwrap_or_else(|| "-".to_string());
                                rows.push(vec![
                                    key.id.to_string(),
                                    key.name,
                                    format_ts(key.created_at),
                                    format_opt_ts(key.last_used_at),
                                    format_opt_ts(key.revoked_at),
                                    notes,
                                ]);
                            }

                            let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
                            for row in &rows {
                                for (idx, cell) in row.iter().enumerate() {
                                    if cell.len() > widths[idx] {
                                        widths[idx] = cell.len();
                                    }
                                }
                            }

                            let header_row =
                                headers.iter().map(|h| h.to_string()).collect::<Vec<_>>();
                            println!("{}", format_row(&header_row, &widths));
                            println!("{}", format_sep(&widths));
                            for row in rows {
                                println!("{}", format_row(&row, &widths));
                            }
                        }
                    } else if body.error {
                        eprintln!("Server error while listing keys.");
                        std::process::exit(1);
                    }
                }
                Err(err) => {
                    report_api_error(err);
                    std::process::exit(1);
                }
            }
        }
        "revoke" => {
            let mut key_id = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--id" => key_id = args.next(),
                    "-h" | "--help" => {
                        print_usage();
                        return;
                    }
                    _ => {
                        eprintln!("Unknown argument: {arg}");
                        print_usage();
                        std::process::exit(1);
                    }
                }
            }

            let Some(key_id) = key_id else {
                eprintln!("--id is required for revoke.");
                std::process::exit(1);
            };
            let key_id: i64 = key_id
                .parse()
                .unwrap_or_else(|_| exit_with_error("--id must be a number."));

            let resp = ureq::post(&format!("{base_url}/api/keys/{key_id}/revoke"))
                .set("X-API-Key", &api_key)
                .call();

            match resp {
                Ok(response) => {
                    let body: KeyRevokeResponse = response
                        .into_json()
                        .unwrap_or_else(|_| exit_with_error("Invalid response payload."));
                    if body.success {
                        if body.revoked {
                            println!("Revoked key {id}.", id = body.id);
                        } else {
                            println!("Key {id} was already revoked.", id = body.id);
                        }
                    } else if body.error {
                        eprintln!("Server error while revoking key.");
                        std::process::exit(1);
                    }
                }
                Err(err) => {
                    report_api_error(err);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("Unknown command: {command}");
            print_usage();
            std::process::exit(1);
        }
    }
}




fn format_row(cells: &[String], widths: &[usize]) -> String {
    let mut out = String::from("|");
    for (idx, cell) in cells.iter().enumerate() {
        out.push(' ');
        out.push_str(&format!("{:width$}", cell, width = widths[idx]));
        out.push(' ');
        out.push('|');
    }
    out
}

fn format_sep(widths: &[usize]) -> String {
    let mut out = String::from("|");
    for width in widths {
        out.push(' ');
        out.push_str(&"-".repeat(*width));
        out.push(' ');
        out.push('|');
    }
    out
}

fn format_ts(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

fn format_opt_ts(ts: Option<i64>) -> String {
    ts.map(format_ts).unwrap_or_else(|| "-".to_string())
}

fn report_api_error(err: ureq::Error) {
    match err {
        ureq::Error::Status(code, response) => {
            let body: Result<ApiError, _> = response.into_json();
            if let Ok(err_body) = body {
                if let Some(reason) = err_body.reason {
                    eprintln!("API error {code}: {reason}");
                    return;
                }
            }
            eprintln!("API error {code}.");
        }
        ureq::Error::Transport(err) => {
            eprintln!("Transport error: {err}");
        }
    }
}

fn exit_with_error(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

fn print_usage() {
    println!(
        "curtaurl-admin <command> [options]\n\nCommands:\n  create --name <name> [--notes <notes>]\n  list\n  revoke --id <id>\n\nEnvironment variables:\n  CURTAURL_URL (default: http://localhost:4567)\n  CURTAURL_API_KEY (required)"
    );
}
