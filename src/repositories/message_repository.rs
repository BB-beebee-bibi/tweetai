use crate::error::Error;
use crate::models::Message;
use sqlx::PgPool;

pub struct MessageRepository;

impl MessageRepository {
    pub async fn find_by_id(pool: &PgPool, id: i64) -> Result<Option<Message>, Error> {
        let message = sqlx::query_as!(
            Message,
            r#"
            SELECT * FROM messages WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?;

        Ok(message)
    }

    pub async fn find_by_user_id(pool: &PgPool, user_id: i64) -> Result<Vec<Message>, Error> {
        let messages = sqlx::query_as!(
            Message,
            r#"
            SELECT * FROM messages 
            WHERE sender_id = $1 OR recipient_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(pool)
        .await
        .map_err(Error::Database)?;

        Ok(messages)
    }

    pub async fn create(
        pool: &PgPool,
        sender_id: i64,
        recipient_id: i64,
        encrypted_content: &[u8],
    ) -> Result<Message, Error> {
        let message = sqlx::query_as!(
            Message,
            r#"
            INSERT INTO messages (
                sender_id, 
                recipient_id, 
                encrypted_content, 
                created_at
            )
            VALUES ($1, $2, $3, NOW())
            RETURNING *
            "#,
            sender_id,
            recipient_id,
            encrypted_content
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(message)
    }

    pub async fn delete(pool: &PgPool, id: i64) -> Result<(), Error> {
        sqlx::query!(
            r#"
            DELETE FROM messages WHERE id = $1
            "#,
            id
        )
        .execute(pool)
        .await
        .map_err(Error::Database)?;

        Ok(())
    }

    // For AI training purposes - get messages with Gaurav's responses
    pub async fn get_gaurav_responses(pool: &PgPool) -> Result<Vec<Message>, Error> {
        let gaurav_id = 1; // Gaurav's user ID
        
        let messages = sqlx::query_as!(
            Message,
            r#"
            SELECT * FROM messages 
            WHERE sender_id = $1
            ORDER BY created_at ASC
            "#,
            gaurav_id
        )
        .fetch_all(pool)
        .await
        .map_err(Error::Database)?;

        Ok(messages)
    }

    // For conversation context - get recent conversation between two users
    pub async fn get_conversation(
        pool: &PgPool,
        user1_id: i64,
        user2_id: i64,
        limit: i64,
    ) -> Result<Vec<Message>, Error> {
        let messages = sqlx::query_as!(
            Message,
            r#"
            SELECT * FROM messages 
            WHERE (sender_id = $1 AND recipient_id = $2)
               OR (sender_id = $2 AND recipient_id = $1)
            ORDER BY created_at DESC
            LIMIT $3
            "#,
            user1_id,
            user2_id,
            limit
        )
        .fetch_all(pool)
        .await
        .map_err(Error::Database)?;

        Ok(messages)
    }
}