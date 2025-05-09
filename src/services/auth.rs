use crate::error::Error;
use crate::models::{AuthResponse, Claims, User};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng as RandOsRng;
use secrecy::{ExposeSecret, Secret};
use signalprotocol_rs::IdentityKeyPair;

pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| Error::Argon2Error(e.to_string()))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| Error::Argon2Error(e.to_string()))?;
    
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn create_jwt(user_id: &i64, username: &str, jwt_secret: &str, expiration: i64) -> Result<String, Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(expiration))
        .expect("valid timestamp")
        .timestamp() as usize;
    
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        exp: expiration,
        iat: Utc::now().timestamp() as usize,
    };
    
    let header = Header::default();
    let encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());
    
    encode(&header, &claims, &encoding_key)
        .map_err(Error::JwtError)
}

pub fn validate_jwt(token: &str, jwt_secret: &str) -> Result<Claims, Error> {
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let validation = Validation::default();
    
    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => Error::Auth("Token expired".into()),
                _ => Error::Auth("Invalid token".into()),
            }
        })?;
    
    Ok(token_data.claims)
}

pub fn generate_identity_keypair() -> Result<(Vec<u8>, Vec<u8>), Error> {
    let identity_keypair = IdentityKeyPair::generate(&mut RandOsRng::default());
    let serialized_identity = identity_keypair.serialize();
    let public_key = identity_keypair.public_key().serialize().to_vec();
    
    Ok((serialized_identity, public_key))
}

pub fn validate_registration_input(username: &str, password: &str) -> Result<(), Error> {
    // Username validation
    if username.len() < 3 || username.len() > 30 {
        return Err(Error::BadRequest("Username must be between 3 and 30 characters".into()));
    }
    
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(Error::BadRequest("Username can only contain alphanumeric characters, underscores, hyphens, and dots".into()));
    }
    
    // Password validation
    if password.len() < 8 {
        return Err(Error::BadRequest("Password must be at least 8 characters long".into()));
    }
    
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(Error::BadRequest("Password must contain at least one uppercase letter".into()));
    }
    
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(Error::BadRequest("Password must contain at least one lowercase letter".into()));
    }
    
    if !password.chars().any(|c| c.is_numeric()) {
        return Err(Error::BadRequest("Password must contain at least one number".into()));
    }
    
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(Error::BadRequest("Password must contain at least one special character".into()));
    }
    
    Ok(())
}