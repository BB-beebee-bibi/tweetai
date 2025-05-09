use crate::error::Error;
use crate::models::{EncryptionSession, PreKey, SignedPreKey};
use sqlx::PgPool;

pub struct EncryptionRepository;

impl EncryptionRepository {
    // Session management
    pub async fn find_session(
        pool: &PgPool,
        user_id: i64,
        recipient_id: i64,
    ) -> Result<Option<EncryptionSession>, Error> {
        let session = sqlx::query_as!(
            EncryptionSession,
            r#"
            SELECT * FROM encryption_sessions 
            WHERE user_id = $1 AND recipient_id = $2
            "#,
            user_id,
            recipient_id
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?;

        Ok(session)
    }

    pub async fn create_session(
        pool: &PgPool,
        user_id: i64,
        recipient_id: i64,
        session_data: &[u8],
    ) -> Result<EncryptionSession, Error> {
        let session = sqlx::query_as!(
            EncryptionSession,
            r#"
            INSERT INTO encryption_sessions (
                user_id, 
                recipient_id, 
                session_data, 
                created_at, 
                updated_at
            )
            VALUES ($1, $2, $3, NOW(), NOW())
            RETURNING *
            "#,
            user_id,
            recipient_id,
            session_data
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(session)
    }

    pub async fn update_session(
        pool: &PgPool,
        user_id: i64,
        recipient_id: i64,
        session_data: &[u8],
    ) -> Result<EncryptionSession, Error> {
        let session = sqlx::query_as!(
            EncryptionSession,
            r#"
            UPDATE encryption_sessions
            SET session_data = $3, updated_at = NOW()
            WHERE user_id = $1 AND recipient_id = $2
            RETURNING *
            "#,
            user_id,
            recipient_id,
            session_data
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(session)
    }

    // Pre-key management
    pub async fn get_pre_key(
        pool: &PgPool,
        user_id: i64,
    ) -> Result<Option<PreKey>, Error> {
        let pre_key = sqlx::query_as!(
            PreKey,
            r#"
            SELECT * FROM pre_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?;

        Ok(pre_key)
    }

    pub async fn create_pre_key(
        pool: &PgPool,
        user_id: i64,
        key_id: i32,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<PreKey, Error> {
        let pre_key = sqlx::query_as!(
            PreKey,
            r#"
            INSERT INTO pre_keys (
                user_id, 
                key_id, 
                public_key, 
                private_key, 
                created_at
            )
            VALUES ($1, $2, $3, $4, NOW())
            RETURNING *
            "#,
            user_id,
            key_id,
            public_key,
            private_key
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(pre_key)
    }

    // Signed pre-key management
    pub async fn get_signed_pre_key(
        pool: &PgPool,
        user_id: i64,
    ) -> Result<Option<SignedPreKey>, Error> {
        let signed_pre_key = sqlx::query_as!(
            SignedPreKey,
            r#"
            SELECT * FROM signed_pre_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?;

        Ok(signed_pre_key)
    }

    pub async fn create_signed_pre_key(
        pool: &PgPool,
        user_id: i64,
        key_id: i32,
        public_key: &[u8],
        private_key: &[u8],
        signature: &[u8],
    ) -> Result<SignedPreKey, Error> {
        let signed_pre_key = sqlx::query_as!(
            SignedPreKey,
            r#"
            INSERT INTO signed_pre_keys (
                user_id, 
                key_id, 
                public_key, 
                private_key, 
                signature, 
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING *
            "#,
            user_id,
            key_id,
            public_key,
            private_key,
            signature
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(signed_pre_key)
    }

    // Rotate keys (for security)
    pub async fn rotate_keys(
        pool: &PgPool,
        user_id: i64,
        new_pre_key_id: i32,
        new_pre_key_public: &[u8],
        new_pre_key_private: &[u8],
        new_signed_pre_key_id: i32,
        new_signed_pre_key_public: &[u8],
        new_signed_pre_key_private: &[u8],
        new_signature: &[u8],
    ) -> Result<(), Error> {
        // Start a transaction
        let mut tx = pool.begin().await.map_err(Error::Database)?;

        // Create new pre-key
        sqlx::query!(
            r#"
            INSERT INTO pre_keys (
                user_id, 
                key_id, 
                public_key, 
                private_key, 
                created_at
            )
            VALUES ($1, $2, $3, $4, NOW())
            "#,
            user_id,
            new_pre_key_id,
            new_pre_key_public,
            new_pre_key_private
        )
        .execute(&mut tx)
        .await
        .map_err(Error::Database)?;

        // Create new signed pre-key
        sqlx::query!(
            r#"
            INSERT INTO signed_pre_keys (
                user_id, 
                key_id, 
                public_key, 
                private_key, 
                signature, 
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
            user_id,
            new_signed_pre_key_id,
            new_signed_pre_key_public,
            new_signed_pre_key_private,
            new_signature
        )
        .execute(&mut tx)
        .await
        .map_err(Error::Database)?;

        // Commit transaction
        tx.commit().await.map_err(Error::Database)?;

        Ok(())
    }
}