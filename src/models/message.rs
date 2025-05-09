use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Message {
    pub id: i64,
    pub sender_id: i64,
    pub recipient_id: i64,
    #[serde(skip_serializing)]
    pub encrypted_content: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptedMessage {
    pub id: i64,
    pub sender_id: i64,
    pub recipient_id: i64,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewMessage {
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageResponse {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageListResponse {
    pub messages: Vec<DecryptedMessage>,
    pub remaining_today: i32,
}

// For storing Signal Protocol session state
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct EncryptionSession {
    pub id: i64,
    pub user_id: i64,
    pub recipient_id: i64,
    pub session_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// For storing Signal Protocol pre-keys
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct PreKey {
    pub id: i64,
    pub user_id: i64,
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

// For storing Signal Protocol signed pre-keys
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct SignedPreKey {
    pub id: i64,
    pub user_id: i64,
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
}