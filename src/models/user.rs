use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub theme: String,
    pub message_count_today: i32,
    pub last_message_date: Option<NaiveDate>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub identity_key_pair: Vec<u8>,
    pub public_identity_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserState {
    pub user_id: i64,
    pub sleep_status: Option<String>,
    pub workday_status: Option<String>,
    pub calories: Option<i32>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: i64,
    pub username: String,
    pub theme: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThemeUpdateRequest {
    pub theme: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserStateUpdateRequest {
    pub sleep_status: Option<String>,
    pub workday_status: Option<String>,
    pub calories: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: i64,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub username: String,
    pub exp: usize, // expiration time
    pub iat: usize, // issued at
}