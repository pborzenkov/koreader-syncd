use std::time::SystemTime;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post, put},
    Router,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tracing::info;

enum Error {
    Internal,
    Unauthorized,
    UserExists,
    InvalidRequest,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct JsonError {
            code: i32,
            message: &'static str,
        }

        let (status, body) = match self {
            Error::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonError {
                    code: 2000,
                    message: "Unknown server error",
                },
            ),
            Error::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                JsonError {
                    code: 2001,
                    message: "Unauthorized",
                },
            ),
            Error::UserExists => (
                StatusCode::PAYMENT_REQUIRED,
                JsonError {
                    code: 2002,
                    message: "Username is already registered",
                },
            ),
            Error::InvalidRequest => (
                StatusCode::FORBIDDEN,
                JsonError {
                    code: 2003,
                    message: "Invalid request",
                },
            ),
        };

        (status, Json(body)).into_response()
    }
}

type Result<T> = std::result::Result<T, Error>;

pub fn get_router(pool: SqlitePool, enable_register: bool) -> Router {
    let router = if enable_register {
        Router::new().route("/users/create", post(register))
    } else {
        Router::new()
    };
    router
        .merge(
            Router::new()
                .route("/users/auth", get(check_authorized))
                .route("/syncs/progress", put(put_progress))
                .route("/syncs/progress/:document", get(get_progress))
                .route_layer(middleware::from_fn_with_state(pool.clone(), authorize)),
        )
        .with_state(pool)
}

async fn authorize(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse> {
    let (username, password) = (
        headers
            .get("x-auth-user")
            .ok_or(Error::Unauthorized)?
            .to_str()
            .map_err(|_| Error::InvalidRequest)?,
        headers
            .get("x-auth-key")
            .ok_or(Error::Unauthorized)?
            .to_str()
            .map_err(|_| Error::InvalidRequest)?,
    );

    info!(user = username, "authorize");

    let (password_hash,): (String,) =
        sqlx::query_as(r#"SELECT password FROM users WHERE username = ?1"#)
            .bind(username)
            .fetch_optional(&pool)
            .await
            .map_err(|_| Error::Internal)?
            .ok_or(Error::Unauthorized)?;
    let parsed_hash = PasswordHash::new(&password_hash).map_err(|_| Error::Internal)?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| Error::Unauthorized)?;

    Ok(next.run(request).await)
}

#[derive(Deserialize)]
struct RegisterInput {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    username: String,
}

async fn register(
    State(pool): State<SqlitePool>,
    Json(input): Json<RegisterInput>,
) -> Result<impl IntoResponse> {
    info!(user = input.username, "register");

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password = argon2
        .hash_password(input.password.as_bytes(), &salt)
        .map_err(|_| Error::Internal)?
        .to_string();

    sqlx::query(r#"INSERT INTO users (username, password) VALUES (?1, ?2)"#)
        .bind(&input.username)
        .bind(&password)
        .execute(&pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(de) if de.code().as_deref() == Some("1555") => Error::UserExists,
            _ => Error::Internal,
        })?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            username: input.username,
        }),
    ))
}

#[derive(Serialize)]
struct CheckAuthorizedResponse {
    authorized: String,
}

async fn check_authorized() -> Result<impl IntoResponse> {
    Ok((
        StatusCode::OK,
        Json(CheckAuthorizedResponse {
            authorized: "OK".into(),
        }),
    ))
}

#[derive(Deserialize)]
struct PutProgressInput {
    document: String,
    progress: String,
    percentage: f32,
    device: String,
    device_id: String,
}

#[derive(Deserialize, Serialize)]
struct PutProgressResponse {
    document: String,
    timestamp: u64,
}

async fn put_progress(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    Json(input): Json<PutProgressInput>,
) -> Result<impl IntoResponse> {
    let username = headers["x-auth-user"].to_str().unwrap();

    info!(
        user = username,
        document = input.document,
        device = input.device,
        device_id = input.device_id,
        percentage = input.percentage,
        "put_progress"
    );

    let now_unix = SystemTime::UNIX_EPOCH
        .elapsed()
        .map_err(|_| Error::Internal)?
        .as_secs();

    sqlx::query(
        r#"
INSERT INTO progress
    (document, username, device, device_id, progress, percentage, timestamp)
VALUES
    (?1, ?2, ?3, ?4, ?5, ?6, ?7)
ON CONFLICT (document, username) DO UPDATE SET
    device = excluded.device,
    device_id = excluded.device_id,
    progress = excluded.progress,
    percentage = excluded.percentage,
    timestamp = excluded.timestamp
        "#,
    )
    .bind(&input.document)
    .bind(username)
    .bind(input.device)
    .bind(input.device_id)
    .bind(input.progress)
    .bind(input.percentage)
    .bind(now_unix as i64)
    .execute(&pool)
    .await
    .map_err(|_| Error::Internal)?;

    Ok((
        StatusCode::OK,
        Json(PutProgressResponse {
            document: input.document,
            timestamp: now_unix,
        }),
    ))
}

#[derive(Default, Serialize)]
struct GetProgressResponse {
    document: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    percentage: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
}

async fn get_progress(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    Path(document): Path<String>,
) -> Result<impl IntoResponse> {
    let username = headers["x-auth-user"].to_str().unwrap();

    info!(user = username, document = document, "get_progress");

    #[derive(sqlx::FromRow)]
    struct Row {
        device: String,
        device_id: String,
        progress: String,
        percentage: f32,
        timestamp: i64,
    }

    let record = sqlx::query_as::<_, Row>(
        r#"
SELECT 
    device, device_id, progress, percentage, timestamp
FROM
    progress
WHERE
    document = ?1 AND username = ?2
        "#,
    )
    .bind(&document)
    .bind(username)
    .fetch_optional(&pool)
    .await
    .map_err(|_| Error::Internal)?;

    Ok((
        StatusCode::OK,
        Json(match record {
            Some(r) => GetProgressResponse {
                document,
                progress: Some(r.progress.clone()),
                percentage: Some(r.percentage),
                device: Some(r.device.clone()),
                device_id: Some(r.device_id.clone()),
                timestamp: Some(r.timestamp as u64),
            },
            None => GetProgressResponse {
                document,
                ..Default::default()
            },
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{get_router, PutProgressInput, PutProgressResponse};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        response::Response,
        Router,
    };
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use sqlx::SqlitePool;
    use tokio::time::sleep;

    async fn run_req(app: Router, req: Request<Body>) -> Response {
        use tower::ServiceExt;

        app.oneshot(req).await.unwrap()
    }

    async fn assert_json(response: Response, json: Value) {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body, json);
    }

    fn create_user_req(username: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method(http::Method::POST)
            .uri("/users/create")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "username": username,
                    "password": password,
                }))
                .unwrap(),
            ))
            .unwrap()
    }

    fn check_authorized_req(username: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method(http::Method::GET)
            .uri("/users/auth")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header("x-auth-user", username)
            .header("x-auth-key", password)
            .body(Body::empty())
            .unwrap()
    }

    fn put_progress_req(username: &str, password: &str, req: &PutProgressInput) -> Request<Body> {
        Request::builder()
            .method(http::Method::PUT)
            .uri("/syncs/progress")
            .header("x-auth-user", username)
            .header("x-auth-key", password)
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "document": req.document,
                    "progress": req.progress,
                    "percentage": req.percentage,
                    "device": req.device,
                    "device_id": req.device_id,
                }))
                .unwrap(),
            ))
            .unwrap()
    }

    fn get_progress_req(username: &str, password: &str, document: &str) -> Request<Body> {
        Request::builder()
            .method(http::Method::GET)
            .uri(&format!("/syncs/progress/{}", document))
            .header("x-auth-user", username)
            .header("x-auth-key", password)
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::empty())
            .unwrap()
    }

    #[sqlx::test]
    async fn test_register(pool: SqlitePool) {
        let app = get_router(pool, true);

        for username in &vec!["username1", "username2"] {
            let response = run_req(app.clone(), create_user_req(username, "password")).await;
            assert_eq!(response.status(), StatusCode::CREATED);
            assert_json(response, json!({ "username": username })).await;
        }

        // Now try to register a username that already exists
        let response = run_req(app.clone(), create_user_req("username1", "password")).await;
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_json(
            response,
            json!({ "code": 2002, "message": "Username is already registered"}),
        )
        .await;
    }

    #[sqlx::test]
    async fn test_check_auth(pool: SqlitePool) {
        let app = get_router(pool, true);

        let response = run_req(app.clone(), check_authorized_req("username", "password")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_json(response, json!({ "code": 2001, "message": "Unauthorized"})).await;

        let _ = run_req(app.clone(), create_user_req("username", "password")).await;

        let response = run_req(app.clone(), check_authorized_req("username", "password")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_json(response, json!({ "authorized": "OK"})).await;

        let response = run_req(app.clone(), check_authorized_req("username", "")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_json(response, json!({ "code": 2001, "message": "Unauthorized"})).await;

        let response = run_req(app.clone(), check_authorized_req("username", "badpassword")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_json(response, json!({ "code": 2001, "message": "Unauthorized"})).await;
    }

    #[sqlx::test]
    async fn test_sync_progress(pool: SqlitePool) {
        let app = get_router(pool, true);

        let _ = run_req(app.clone(), create_user_req("username", "password")).await;

        let response = run_req(
            app.clone(),
            get_progress_req("username", "password", "document1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_json(response, json!({ "document": "document1" })).await;

        let response = run_req(
            app.clone(),
            put_progress_req(
                "username",
                "password",
                &PutProgressInput {
                    document: "document1".into(),
                    progress: "progress1".into(),
                    percentage: 25.,
                    device: "device1".into(),
                    device_id: "device_id1".into(),
                },
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: PutProgressResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.document, "document1");
        let ts1 = body.timestamp;

        let response = run_req(
            app.clone(),
            get_progress_req("username", "password", "document1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_json(
            response,
            json!({
                "document": "document1",
                "progress": "progress1",
                "percentage": 25.,
                "device": "device1",
                "device_id": "device_id1",
                "timestamp": ts1,
            }),
        )
        .await;

        sleep(Duration::from_secs(1)).await;

        let response = run_req(
            app.clone(),
            put_progress_req(
                "username",
                "password",
                &PutProgressInput {
                    document: "document1".into(),
                    progress: "progress2".into(),
                    percentage: 50.,
                    device: "device2".into(),
                    device_id: "device_id2".into(),
                },
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: PutProgressResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.document, "document1");
        let ts2 = body.timestamp;

        assert!(ts2 > ts1);

        let response = run_req(
            app.clone(),
            get_progress_req("username", "password", "document1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_json(
            response,
            json!({
                "document": "document1",
                "progress": "progress2",
                "percentage": 50.,
                "device": "device2",
                "device_id": "device_id2",
                "timestamp": ts2,
            }),
        )
        .await;
    }
}
