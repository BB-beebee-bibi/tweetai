use crate::error::Error;
use crate::models::{AuthResponse, LoginRequest, NewUser};
use crate::repositories::UserRepository;
use crate::services::{
    create_jwt, generate_identity_keypair, hash_password, validate_jwt, validate_registration_input,
    verify_password,
};
use actix_web::{web, HttpResponse};
use sqlx::PgPool;

// User registration handler
pub async fn register(
    db_pool: web::Data<PgPool>,
    user_data: web::Json<NewUser>,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, Error> {
    // Validate input
    validate_registration_input(&user_data.username, &user_data.password)?;

    // Check if user exists
    let existing_user = UserRepository::find_by_username(&db_pool, &user_data.username).await?;
    if existing_user.is_some() {
        return Err(Error::BadRequest("Username already taken".into()));
    }

    // Hash password with Argon2id
    let password_hash = hash_password(&user_data.password)?;

    // Generate Signal Protocol identity key
    let (identity_keypair, public_identity_key) = generate_identity_keypair()?;

    // Create user
    let user = UserRepository::create(
        &db_pool,
        &user_data.username,
        &password_hash,
        "Agora", // Default theme
        &identity_keypair,
        &public_identity_key,
    )
    .await?;

    // Return JWT token
    let token = create_jwt(
        &user.id,
        &user.username,
        &config.jwt_secret,
        config.jwt_expiration,
    )?;

    Ok(HttpResponse::Created().json(AuthResponse {
        token,
        user_id: user.id,
        username: user.username,
        theme: user.theme,
    }))
}

// User login handler
pub async fn login(
    db_pool: web::Data<PgPool>,
    login_data: web::Json<LoginRequest>,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, Error> {
    // Find user by username
    let user = UserRepository::find_by_username(&db_pool, &login_data.username)
        .await?
        .ok_or_else(|| Error::Auth("Invalid username or password".into()))?;

    // Verify password
    let is_valid = verify_password(&login_data.password, &user.password_hash)?;
    if !is_valid {
        return Err(Error::Auth("Invalid username or password".into()));
    }

    // Create JWT token
    let token = create_jwt(
        &user.id,
        &user.username,
        &config.jwt_secret,
        config.jwt_expiration,
    )?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        token,
        user_id: user.id,
        username: user.username,
        theme: user.theme,
    }))
}

// Validate token handler
pub async fn validate_token(
    token: web::Json<String>,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, Error> {
    let claims = validate_jwt(&token, &config.jwt_secret)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": true,
        "user_id": claims.sub,
        "username": claims.username,
        "expires_at": claims.exp
    })))
}