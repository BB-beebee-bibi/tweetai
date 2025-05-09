use crate::error::Error;
use crate::models::User;
use chrono::{NaiveDate, Utc};
use sqlx::PgPool;

pub struct UserRepository;

impl UserRepository {
    pub async fn find_by_id(pool: &PgPool, id: i64) -> Result<Option<User>, Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT * FROM users WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?;

        Ok(user)
    }

    pub async fn find_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT * FROM users WHERE username = $1
            "#,
            username
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?;

        Ok(user)
    }

    pub async fn create(
        pool: &PgPool,
        username: &str,
        password_hash: &str,
        theme: &str,
        identity_key_pair: &[u8],
        public_identity_key: &[u8],
    ) -> Result<User, Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (
                username, 
                password_hash, 
                theme, 
                message_count_today, 
                identity_key_pair,
                public_identity_key,
                created_at, 
                updated_at
            )
            VALUES ($1, $2, $3, 0, $4, $5, NOW(), NOW())
            RETURNING *
            "#,
            username,
            password_hash,
            theme,
            identity_key_pair,
            public_identity_key
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(user)
    }

    pub async fn update_theme(pool: &PgPool, user_id: i64, theme: &str) -> Result<User, Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET theme = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING *
            "#,
            theme,
            user_id
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(user)
    }

    pub async fn update_message_count(
        pool: &PgPool,
        user_id: i64,
        message_count: i32,
        date: NaiveDate,
    ) -> Result<User, Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET message_count_today = $1, 
                last_message_date = $2,
                updated_at = NOW()
            WHERE id = $3
            RETURNING *
            "#,
            message_count,
            date,
            user_id
        )
        .fetch_one(pool)
        .await
        .map_err(Error::Database)?;

        Ok(user)
    }

    pub async fn update_user_state(
        pool: &PgPool,
        user_id: i64,
        sleep_status: Option<&str>,
        workday_status: Option<&str>,
        calories: Option<i32>,
    ) -> Result<(), Error> {
        // Check if user state exists
        let exists = sqlx::query!(
            r#"
            SELECT 1 FROM user_states WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?
        .is_some();

        if exists {
            // Update existing state
            sqlx::query!(
                r#"
                UPDATE user_states
                SET sleep_status = COALESCE($1, sleep_status),
                    workday_status = COALESCE($2, workday_status),
                    calories = COALESCE($3, calories),
                    last_updated = NOW()
                WHERE user_id = $4
                "#,
                sleep_status,
                workday_status,
                calories,
                user_id
            )
            .execute(pool)
            .await
            .map_err(Error::Database)?;
        } else {
            // Create new state
            sqlx::query!(
                r#"
                INSERT INTO user_states (
                    user_id, 
                    sleep_status, 
                    workday_status, 
                    calories, 
                    last_updated
                )
                VALUES ($1, $2, $3, $4, NOW())
                "#,
                user_id,
                sleep_status,
                workday_status,
                calories
            )
            .execute(pool)
            .await
            .map_err(Error::Database)?;
        }

        Ok(())
    }

    pub async fn get_user_state(
        pool: &PgPool,
        user_id: i64,
    ) -> Result<Option<(Option<String>, Option<String>, Option<i32>)>, Error> {
        let state = sqlx::query!(
            r#"
            SELECT sleep_status, workday_status, calories
            FROM user_states
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_optional(pool)
        .await
        .map_err(Error::Database)?;

        Ok(state.map(|s| (s.sleep_status, s.workday_status, s.calories)))
    }
}