// SPDX-FileCopyrightText: 2023 Sayantan Santra <sayantan.santra689@gmail.com>
// SPDX-License-Identifier: MIT

use actix_files::NamedFile;
use actix_session::Session;
use actix_web::{
    delete, get,
    http::StatusCode,
    post, put,
    web::{self, Redirect},
    Either, HttpRequest, HttpResponse, Responder,
};
use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use chrono::Utc;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::env;

use crate::AppState;
use crate::{auth, database};
use crate::{auth::is_session_valid, utils};
use ChhotoError::{ClientError, ServerError};

// Store the version number
const VERSION: &str = env!("CARGO_PKG_VERSION");

// Error types
pub enum ChhotoError {
    ServerError,
    ClientError { reason: String },
}

// Define JSON struct for returning success/error data
#[derive(Serialize)]
pub struct JSONResponse {
    pub success: bool,
    pub error: bool,
    pub reason: String,
}

#[derive(Deserialize)]
struct CreateKeyRequest {
    name: String,
    notes: Option<String>,
}

#[derive(Serialize)]
struct CreateKeyResponse {
    success: bool,
    error: bool,
    id: i64,
    name: String,
    key: String,
    created_at: i64,
}

#[derive(Serialize)]
struct KeyListResponse {
    success: bool,
    error: bool,
    keys: Vec<database::ApiKeyRecord>,
}

#[derive(Serialize)]
struct KeyRevokeResponse {
    success: bool,
    error: bool,
    id: i64,
    revoked: bool,
}

// Define JSON struct for returning backend config
#[derive(Serialize)]
struct BackendConfig {
    version: String,
    site_url: Option<String>,
    allow_capital_letters: bool,
    public_mode: bool,
    public_mode_expiry_delay: i64,
    slug_style: String,
    slug_length: usize,
    try_longer_slug: bool,
}

// Needed to return the short URL to make it easier for programs leveraging the API
#[derive(Serialize)]
struct CreatedURL {
    success: bool,
    error: bool,
    shorturl: String,
    expiry_time: i64,
}

// Struct for returning information about a shortlink in expand
#[derive(Serialize)]
struct LinkInfo {
    success: bool,
    error: bool,
    longurl: String,
    hits: i64,
    expiry_time: i64,
}

// Struct for query params in /api/all
#[derive(Deserialize)]
pub struct GetReqParams {
    pub page_after: Option<String>,
    pub page_no: Option<i64>,
    pub page_size: Option<i64>,
}

// Define the routes

// Add new links
#[post("/api/new")]
pub async fn add_link(
    req: String,
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    // Call is_api_ok() function, pass HttpRequest
    let result = auth::is_api_ok(http, config, &data.db);
    // If success, add new link
    if result.success {
        match utils::add_link(&req, &data.db, config, false) {
            Ok((shorturl, expiry_time)) => {
                let site_url = config.site_url.clone();
                let shorturl = if let Some(url) = site_url {
                    format!("{url}/{shorturl}")
                } else {
                    let protocol = if config.port == 443 { "https" } else { "http" };
                    let port_text = if [80, 443].contains(&config.port) {
                        String::new()
                    } else {
                        format!(":{}", config.port)
                    };
                    format!("{protocol}://localhost{port_text}/{shorturl}")
                };
                let response = CreatedURL {
                    success: true,
                    error: false,
                    shorturl,
                    expiry_time,
                };
                HttpResponse::Created().json(response)
            }
            Err(ServerError) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when adding the link.".to_string(),
                };
                HttpResponse::InternalServerError().json(response)
            }
            Err(ClientError { reason }) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::Conflict().json(response)
            }
        }
    } else if result.error {
        HttpResponse::Unauthorized().json(result)
    // If password authentication or public mode is used - keeps backwards compatibility
    } else {
        let result = if auth::is_session_valid(session, config) {
            utils::add_link(&req, &data.db, config, false)
        } else if config.public_mode {
            utils::add_link(&req, &data.db, config, true)
        } else {
            return HttpResponse::Unauthorized().body("Not logged in!");
        };
        match result {
            Ok((shorturl, _)) => HttpResponse::Created().body(shorturl),
            Err(ServerError) => HttpResponse::InternalServerError()
                .body("Something went wrong when adding the link.".to_string()),
            Err(ClientError { reason }) => HttpResponse::Conflict().body(reason),
        }
    }
}

// Return all active links
#[get("/api/all")]
pub async fn getall(
    data: web::Data<AppState>,
    session: Session,
    params: web::Query<GetReqParams>,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    // Call is_api_ok() function, pass HttpRequest
    let result = auth::is_api_ok(http, config, &data.db);
    // If success, return all links
    if result.success {
        HttpResponse::Ok().body(utils::getall(&data.db, params.into_inner()))
    } else if result.error {
        HttpResponse::Unauthorized().json(result)
    // If password authentication is used - keeps backwards compatibility
    } else if auth::is_session_valid(session, config) {
        HttpResponse::Ok().body(utils::getall(&data.db, params.into_inner()))
    } else {
        HttpResponse::Unauthorized().body("Not logged in!")
    }
}

// Get information about a single shortlink
#[post("/api/expand")]
pub async fn expand(req: String, data: web::Data<AppState>, http: HttpRequest) -> HttpResponse {
    let result = auth::is_api_ok(http, &data.config, &data.db);
    if result.success {
        match database::find_url(&req, &data.db) {
            Ok((longurl, hits, expiry_time)) => {
                let body = LinkInfo {
                    success: true,
                    error: false,
                    longurl,
                    hits,
                    expiry_time,
                };
                HttpResponse::Ok().json(body)
            }
            Err(ServerError) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when finding the link.".to_string(),
                };
                HttpResponse::BadRequest().json(body)
            }
            Err(ClientError { reason }) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::BadRequest().json(body)
            }
        }
    } else {
        HttpResponse::Unauthorized().json(result)
    }
}

// Get information about a single shortlink
#[put("/api/edit")]
pub async fn edit_link(
    req: String,
    session: Session,
    data: web::Data<AppState>,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config, &data.db);
    if result.success || is_session_valid(session, config) {
        match utils::edit_link(&req, &data.db, config) {
            Ok(()) => {
                let body = JSONResponse {
                    success: true,
                    error: false,
                    reason: String::from("Edit was successful."),
                };
                HttpResponse::Created().json(body)
            }
            Err(ServerError) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when editing the link.".to_string(),
                };
                HttpResponse::InternalServerError().json(body)
            }
            Err(ClientError { reason }) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::BadRequest().json(body)
            }
        }
    } else {
        HttpResponse::Unauthorized().json(result)
    }
}

// Get the site URL
// This is deprecated, and might be removed in the future.
// Use /api/getconfig instead
#[get("/api/siteurl")]
pub async fn siteurl(data: web::Data<AppState>) -> HttpResponse {
    if let Some(url) = &data.config.site_url {
        HttpResponse::Ok().body(url.clone())
    } else {
        HttpResponse::Ok().body("unset")
    }
}

// Get the version number
// This is deprecated, and might be removed in the future.
// Use /api/getconfig instead
#[get("/api/version")]
pub async fn version() -> HttpResponse {
    HttpResponse::Ok().body(format!("CurtaURL v{VERSION}"))
}

// Get the user's current role
#[get("/api/whoami")]
pub async fn whoami(
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config, &data.db);
    let acting_user = if result.success || is_session_valid(session, config) {
        "admin"
    } else if config.public_mode {
        "public"
    } else {
        "nobody"
    };
    HttpResponse::Ok().body(acting_user)
}

// Get some useful backend config
#[get("/api/getconfig")]
pub async fn getconfig(
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config, &data.db);
    if result.success || is_session_valid(session, config) || data.config.public_mode {
        let backend_config = BackendConfig {
            version: VERSION.to_string(),
            allow_capital_letters: config.allow_capital_letters,
            public_mode: config.public_mode,
            public_mode_expiry_delay: config.public_mode_expiry_delay,
            site_url: config.site_url.clone(),
            slug_style: config.slug_style.clone(),
            slug_length: config.slug_length,
            try_longer_slug: config.try_longer_slug,
        };
        HttpResponse::Ok().json(backend_config)
    } else {
        HttpResponse::Unauthorized().json(result)
    }
}

// Create a managed API key
#[post("/api/keys")]
pub async fn create_key(
    req: String,
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config, &data.db);
    if !(result.success || auth::is_session_valid(session, config)) {
        return if result.error {
            HttpResponse::Unauthorized().json(result)
        } else {
            HttpResponse::Unauthorized().body("Not logged in!")
        };
    }

    let Ok(payload) = serde_json::from_str::<CreateKeyRequest>(&req) else {
        let response = JSONResponse {
            success: false,
            error: true,
            reason: "Malformed request!".to_string(),
        };
        return HttpResponse::BadRequest().json(response);
    };
    if payload.name.trim().is_empty() {
        let response = JSONResponse {
            success: false,
            error: true,
            reason: "Key name must not be empty.".to_string(),
        };
        return HttpResponse::BadRequest().json(response);
    }

    let secret = auth::gen_key();
    let key_hash = auth::gen_managed_key_hash(&secret);
    match database::create_api_key(&payload.name, &key_hash, payload.notes.as_deref(), &data.db) {
        Ok(key_id) => {
            let response = CreateKeyResponse {
                success: true,
                error: false,
                id: key_id,
                name: payload.name,
                key: format!("cu_{key_id}_{secret}"),
                created_at: Utc::now().timestamp(),
            };
            HttpResponse::Created().json(response)
        }
        Err(ServerError) => {
            let response = JSONResponse {
                success: false,
                error: true,
                reason: "Something went wrong while creating the key.".to_string(),
            };
            HttpResponse::InternalServerError().json(response)
        }
        Err(ClientError { reason }) => {
            let response = JSONResponse {
                success: false,
                error: true,
                reason,
            };
            HttpResponse::Conflict().json(response)
        }
    }
}

// List managed API keys
#[get("/api/keys")]
pub async fn list_keys(
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config, &data.db);
    if !(result.success || auth::is_session_valid(session, config)) {
        return if result.error {
            HttpResponse::Unauthorized().json(result)
        } else {
            HttpResponse::Unauthorized().body("Not logged in!")
        };
    }

    let keys = database::list_api_keys(&data.db);
    let response = KeyListResponse {
        success: true,
        error: false,
        keys,
    };
    HttpResponse::Ok().json(response)
}

// Revoke a managed API key
#[post("/api/keys/{id}/revoke")]
pub async fn revoke_key(
    key_id: web::Path<i64>,
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config, &data.db);
    if !(result.success || auth::is_session_valid(session, config)) {
        return if result.error {
            HttpResponse::Unauthorized().json(result)
        } else {
            HttpResponse::Unauthorized().body("Not logged in!")
        };
    }

    match database::revoke_api_key(*key_id, &data.db) {
        Ok(revoked) => {
            let response = KeyRevokeResponse {
                success: true,
                error: false,
                id: *key_id,
                revoked,
            };
            HttpResponse::Ok().json(response)
        }
        Err(ServerError) => {
            let response = JSONResponse {
                success: false,
                error: true,
                reason: "Something went wrong while revoking the key.".to_string(),
            };
            HttpResponse::InternalServerError().json(response)
        }
        Err(ClientError { reason }) => {
            let response = JSONResponse {
                success: false,
                error: true,
                reason,
            };
            HttpResponse::Conflict().json(response)
        }
    }
}

// 404 error page
pub async fn error404() -> impl Responder {
    NamedFile::open_async("./resources/static/404.html")
        .await
        .customize()
        .with_status(StatusCode::NOT_FOUND)
}

// Handle a given shortlink
#[get("/{shortlink}")]
pub async fn link_handler(
    shortlink: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    let shortlink_str = shortlink.as_str();
    if let Ok(longlink) = database::find_and_add_hit(shortlink_str, &data.db) {
        if data.config.use_temp_redirect {
            Either::Left(Redirect::to(longlink))
        } else {
            // Defaults to permanent redirection
            Either::Left(Redirect::to(longlink).permanent())
        }
    } else {
        Either::Right(
            NamedFile::open_async("./resources/static/404.html")
                .await
                .customize()
                .with_status(StatusCode::NOT_FOUND),
        )
    }
}

// Handle login
#[post("/api/login")]
pub async fn login(req: String, session: Session, data: web::Data<AppState>) -> HttpResponse {
    let config = &data.config;
    // Check if password is hashed using Argon2. More algorithms maybe added later.
    let authorized = if let Some(password) = &config.password {
        if config.hash_algorithm.is_some() {
            debug!("Using Argon2 hash for password validation.");
            let hash = PasswordHash::new(password).expect("The provided password hash is invalid.");
            Some(
                Argon2::default()
                    .verify_password(req.as_bytes(), &hash)
                    .is_ok(),
            )
        } else {
            // If hashing is not enabled, use the plaintext password for matching
            Some(password == &req)
        }
    } else {
        None
    };
    if config.api_key.is_some() {
        if let Some(valid_pass) = authorized {
            if !valid_pass {
                warn!("Failed login attempt!");
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Wrong password!".to_string(),
                };
                return HttpResponse::Unauthorized().json(response);
            }
        }
        // Return Ok if no password was set on the server side
        session
            .insert("curta-url-auth", auth::gen_token())
            .expect("Error inserting auth token.");

        let response = JSONResponse {
            success: true,
            error: false,
            reason: "Correct password!".to_string(),
        };
        info!("Successful login.");
        HttpResponse::Ok().json(response)
    } else {
        // Keep this function backwards compatible
        if let Some(valid_pass) = authorized {
            if !valid_pass {
                warn!("Failed login attempt!");
                return HttpResponse::Unauthorized().body("Wrong password!");
            }
        }
        // Return Ok if no password was set on the server side
        session
            .insert("curta-url-auth", auth::gen_token())
            .expect("Error inserting auth token.");

        info!("Successful login.");
        HttpResponse::Ok().body("Correct password!")
    }
}

// Handle logout
// There's no reason to be calling this route with an API key
#[delete("/api/logout")]
pub async fn logout(session: Session) -> HttpResponse {
    if session.remove("curta-url-auth").is_some() {
        info!("Successful logout.");
        HttpResponse::Ok().body("Logged out!")
    } else {
        HttpResponse::Unauthorized().body("You don't seem to be logged in.")
    }
}

// Delete a given shortlink
#[delete("/api/del/{shortlink}")]
pub async fn delete_link(
    shortlink: web::Path<String>,
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    // Call is_api_ok() function, pass HttpRequest
    let result = auth::is_api_ok(http, config, &data.db);
    // If success, delete shortlink
    if result.success {
        match utils::delete_link(&shortlink, &data.db, data.config.allow_capital_letters) {
            Ok(()) => {
                let response = JSONResponse {
                    success: true,
                    error: false,
                    reason: format!("Deleted {shortlink}"),
                };
                HttpResponse::Ok().json(response)
            }
            Err(ServerError) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when deleting the link.".to_string(),
                };
                HttpResponse::InternalServerError().json(response)
            }
            Err(ClientError { reason }) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::NotFound().json(response)
            }
        }
    } else if result.error {
        HttpResponse::Unauthorized().json(result)
    // If using password - keeps backwards compatibility
    } else if auth::is_session_valid(session, config) {
        if utils::delete_link(&shortlink, &data.db, data.config.allow_capital_letters).is_ok() {
            HttpResponse::Ok().body(format!("Deleted {shortlink}"))
        } else {
            HttpResponse::NotFound().body("Not found!")
        }
    } else {
        HttpResponse::Unauthorized().body("Not logged in!")
    }
}
