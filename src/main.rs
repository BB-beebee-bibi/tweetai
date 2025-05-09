mod config;
mod error;
mod handlers;
mod middleware;
mod models;
mod repositories;
mod services;
mod utils;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use middleware::{Authentication, RateLimiter, cleanup_rate_limiter};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();

    // Initialize logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Load configuration
    let config = match config::Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            log::error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Create database connection pool
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            log::error!("Failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };

    // Create rate limiter store
    let rate_limiter_store = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let rate_limiter_store_clone = Arc::clone(&rate_limiter_store);

    // Start rate limiter cleanup task
    let requests_per_minute = env::var("REQUESTS_PER_MINUTE")
        .unwrap_or_else(|_| "60".to_string())
        .parse::<u32>()
        .unwrap_or(60);

    // Spawn cleanup task
    tokio::spawn(async move {
        cleanup_rate_limiter(rate_limiter_store_clone).await;
    });

    // Start HTTP server
    log::info!("Starting server at {}", config.server_binding());
    HttpServer::new(move || {
        // CORS configuration
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000") // Frontend URL
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .max_age(3600);

        // Create app with middleware and routes
        App::new()
            .wrap(cors)
            .wrap(RateLimiter::new(requests_per_minute))
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config.clone()))
            .service(
                web::scope("/api")
                    // Public routes
                    .service(
                        web::scope("/auth")
                            .route("/register", web::post().to(handlers::register))
                            .route("/login", web::post().to(handlers::login))
                            .route("/validate", web::post().to(handlers::validate_token)),
                    )
                    // Protected routes
                    .service(
                        web::scope("")
                            .wrap(Authentication::new(config.jwt_secret.clone()))
                            .service(
                                web::scope("/messages")
                                    .route("", web::post().to(handlers::send_message))
                                    .route("", web::get().to(handlers::get_messages))
                                    .route("/count", web::get().to(handlers::get_message_count))
                                    .route("/{id}", web::get().to(handlers::get_message)),
                            )
                            .service(
                                web::scope("/theme")
                                    .route("", web::get().to(handlers::get_theme))
                                    .route("", web::put().to(handlers::update_theme))
                                    .route("/available", web::get().to(handlers::get_available_themes)),
                            )
                            .service(
                                web::scope("/user-state")
                                    .route("", web::get().to(handlers::get_user_state))
                                    .route("", web::put().to(handlers::update_user_state)),
                            ),
                    ),
            )
    })
    .bind(config.server_binding())?
    .run()
    .await
}
