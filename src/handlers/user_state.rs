use crate::error::Error;
use crate::models::{AuthenticatedUser, UserStateUpdateRequest};
use crate::repositories::UserRepository;
use crate::utils::validate_user_state;
use actix_web::{web, HttpResponse};
use sqlx::PgPool;

// Update user state
pub async fn update_user_state(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
    state_data: web::Json<UserStateUpdateRequest>,
) -> Result<HttpResponse, Error> {
    // Validate state data
    validate_user_state(
        state_data.sleep_status.as_deref(),
        state_data.workday_status.as_deref(),
        state_data.calories,
    )?;

    // Update user state
    UserRepository::update_user_state(
        &db_pool,
        auth_user.user_id,
        state_data.sleep_status.as_deref(),
        state_data.workday_status.as_deref(),
        state_data.calories,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "User state updated successfully"
    })))
}

// Get user state
pub async fn get_user_state(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    // Get user state
    let state = UserRepository::get_user_state(&db_pool, auth_user.user_id).await?;

    match state {
        Some((sleep_status, workday_status, calories)) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "sleep_status": sleep_status,
                "workday_status": workday_status,
                "calories": calories
            })))
        }
        None => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "sleep_status": null,
                "workday_status": null,
                "calories": null
            })))
        }
    }
}