use crate::error::Error;
use crate::models::{AuthenticatedUser, DecryptedMessage, MessageListResponse, NewMessage};
use crate::services::MessageService;
use crate::utils::validate_message_content;
use actix_web::{web, HttpResponse};
use sqlx::PgPool;

// Send a message to Gaurav
pub async fn send_message(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
    message_data: web::Json<NewMessage>,
) -> Result<HttpResponse, Error> {
    // Validate message content
    validate_message_content(&message_data.content)?;

    // Create message service
    let message_service = MessageService::new(db_pool.get_ref().clone());

    // Send message
    let message_response = message_service
        .send_message(auth_user.user_id, &message_data.content)
        .await?;

    // Simulate a response from Gaurav (in a real app, this would be handled asynchronously)
    let _ = message_service
        .simulate_gaurav_response(auth_user.user_id)
        .await;

    Ok(HttpResponse::Created().json(message_response))
}

// Get all messages for the authenticated user
pub async fn get_messages(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    // Create message service
    let message_service = MessageService::new(db_pool.get_ref().clone());

    // Get messages
    let messages = message_service.get_messages(auth_user.user_id).await?;

    Ok(HttpResponse::Ok().json(messages))
}

// Get a specific message by ID
pub async fn get_message(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
    path: web::Path<i64>,
) -> Result<HttpResponse, Error> {
    let message_id = path.into_inner();

    // Create message service
    let message_service = MessageService::new(db_pool.get_ref().clone());

    // Get message
    let message = message_service
        .get_message(auth_user.user_id, message_id)
        .await?;

    Ok(HttpResponse::Ok().json(message))
}

// Get message count for today
pub async fn get_message_count(
    db_pool: web::Data<PgPool>,
    auth_user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    // Create message service
    let message_service = MessageService::new(db_pool.get_ref().clone());

    // Get messages (we'll just use the response from get_messages which includes the count)
    let messages = message_service.get_messages(auth_user.user_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_today": 16 - messages.remaining_today,
        "remaining_today": messages.remaining_today
    })))
}