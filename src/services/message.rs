use crate::error::Error;
use crate::models::{DecryptedMessage, Message, MessageListResponse, MessageResponse, NewMessage};
use crate::repositories::message_repository::MessageRepository;
use crate::repositories::user_repository::UserRepository;
use crate::services::encryption::EncryptionService;
use chrono::{NaiveDate, Utc};
use sqlx::PgPool;

pub struct MessageService {
    pub db_pool: PgPool,
    pub encryption_service: EncryptionService,
}

impl MessageService {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool: db_pool.clone(),
            encryption_service: EncryptionService::new(db_pool),
        }
    }

    // Send a message to Gaurav (user_id 1)
    pub async fn send_message(
        &self,
        user_id: i64,
        content: &str,
    ) -> Result<MessageResponse, Error> {
        // Check message length
        if content.chars().count() > 256 {
            return Err(Error::BadRequest("Message exceeds 256 character limit".into()));
        }

        // Check daily message limit
        let user = UserRepository::find_by_id(&self.db_pool, user_id)
            .await?
            .ok_or_else(|| Error::NotFound("User not found".into()))?;

        let today = Utc::now().date_naive();
        let last_message_date = user.last_message_date.unwrap_or(today - chrono::Duration::days(1));

        let message_count = if last_message_date == today {
            user.message_count_today
        } else {
            0
        };

        if message_count >= 16 {
            return Err(Error::BadRequest("Daily message limit (16) reached".into()));
        }

        // Encrypt message (assuming Gaurav has user_id 1)
        let gaurav_id = 1;
        let encrypted_content = self
            .encryption_service
            .encrypt_message(user_id, gaurav_id, content)
            .await?;

        // Store message
        let message = MessageRepository::create(
            &self.db_pool,
            user_id,
            gaurav_id,
            &encrypted_content,
        )
        .await?;

        // Update user's message count
        UserRepository::update_message_count(
            &self.db_pool,
            user_id,
            message_count + 1,
            today,
        )
        .await?;

        Ok(MessageResponse {
            id: message.id,
            created_at: message.created_at,
            status: "sent".to_string(),
        })
    }

    // Get messages for a user
    pub async fn get_messages(&self, user_id: i64) -> Result<MessageListResponse, Error> {
        // Get user to check message count
        let user = UserRepository::find_by_id(&self.db_pool, user_id)
            .await?
            .ok_or_else(|| Error::NotFound("User not found".into()))?;

        // Calculate remaining messages for today
        let today = Utc::now().date_naive();
        let last_message_date = user.last_message_date.unwrap_or(today - chrono::Duration::days(1));

        let message_count = if last_message_date == today {
            user.message_count_today
        } else {
            0
        };

        let remaining_today = 16 - message_count;

        // Get messages
        let encrypted_messages = MessageRepository::find_by_user_id(&self.db_pool, user_id).await?;

        // Decrypt messages
        let mut decrypted_messages = Vec::new();
        for message in encrypted_messages {
            let content = self
                .encryption_service
                .decrypt_message(user_id, message.sender_id, &message.encrypted_content)
                .await?;

            decrypted_messages.push(DecryptedMessage {
                id: message.id,
                sender_id: message.sender_id,
                recipient_id: message.recipient_id,
                content,
                created_at: message.created_at,
            });
        }

        Ok(MessageListResponse {
            messages: decrypted_messages,
            remaining_today,
        })
    }

    // Get a single message by ID
    pub async fn get_message(&self, user_id: i64, message_id: i64) -> Result<DecryptedMessage, Error> {
        // Get message
        let message = MessageRepository::find_by_id(&self.db_pool, message_id)
            .await?
            .ok_or_else(|| Error::NotFound("Message not found".into()))?;

        // Check if user is sender or recipient
        if message.sender_id != user_id && message.recipient_id != user_id {
            return Err(Error::Forbidden("Access denied".into()));
        }

        // Decrypt message
        let content = self
            .encryption_service
            .decrypt_message(user_id, message.sender_id, &message.encrypted_content)
            .await?;

        Ok(DecryptedMessage {
            id: message.id,
            sender_id: message.sender_id,
            recipient_id: message.recipient_id,
            content,
            created_at: message.created_at,
        })
    }

    // Simulate a response from Gaurav or the AI
    pub async fn simulate_gaurav_response(&self, to_user_id: i64) -> Result<MessageResponse, Error> {
        // In a real implementation, this would either:
        // 1. Notify Gaurav to respond
        // 2. Use the AI model to generate a response based on training data

        // For now, we'll just send a simple response
        let gaurav_id = 1; // Gaurav's user ID
        let response_content = "Thanks for your message! I'll get back to you soon.";

        // Encrypt the response
        let encrypted_content = self
            .encryption_service
            .encrypt_message(gaurav_id, to_user_id, response_content)
            .await?;

        // Store the response
        let message = MessageRepository::create(
            &self.db_pool,
            gaurav_id,
            to_user_id,
            &encrypted_content,
        )
        .await?;

        Ok(MessageResponse {
            id: message.id,
            created_at: message.created_at,
            status: "sent".to_string(),
        })
    }
}