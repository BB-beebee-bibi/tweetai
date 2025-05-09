use crate::error::Error;
use crate::models::{AuthenticatedUser, ThemeUpdateRequest};
use crate::repositories::UserRepository;
use crate::utils::validate_theme;
use actix_web::{web, HttpResponse};
use sqlx::PgPool;

// Update user theme
pub async fn update_theme(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
    theme_data: web::Json<ThemeUpdateRequest>,
) -> Result<HttpResponse, Error> {
    // Validate theme
    validate_theme(&theme_data.theme)?;

    // Update user's theme
    let updated_user = UserRepository::update_theme(&db_pool, auth_user.user_id, &theme_data.theme).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "theme": updated_user.theme
    })))
}

// Get current theme
pub async fn get_theme(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    // Get user
    let user = UserRepository::find_by_id(&db_pool, auth_user.user_id)
        .await?
        .ok_or_else(|| Error::NotFound("User not found".into()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "theme": user.theme
    })))
}

// Get available themes
pub async fn get_available_themes() -> Result<HttpResponse, Error> {
    let themes = vec!["Agora", "Sky", "Castle", "Mountaintop", "Wild Card"];

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "themes": themes
    })))
}