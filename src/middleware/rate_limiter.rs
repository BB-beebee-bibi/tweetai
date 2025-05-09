use crate::error::Error;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error as ActixError, HttpMessage,
};
use futures::future::{ready, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

// Simple in-memory rate limiter
// In production, you would use a distributed solution like Redis
pub struct RateLimiter {
    requests_per_minute: u32,
    store: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Transform = RateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterMiddleware {
            service,
            requests_per_minute: self.requests_per_minute,
            store: Arc::clone(&self.store),
        }))
    }
}

pub struct RateLimiterMiddleware<S> {
    service: S,
    requests_per_minute: u32,
    store: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Get client IP address as the rate limit key
        let key = match req.connection_info().realip_remote_addr() {
            Some(ip) => ip.to_string(),
            None => "unknown".to_string(),
        };

        // Check rate limit
        let is_rate_limited = {
            let mut store = self.store.lock().unwrap();
            let now = Instant::now();
            
            // Get or create timestamps for this client
            let timestamps = store.entry(key.clone()).or_insert_with(Vec::new);
            
            // Remove timestamps older than 1 minute
            let one_minute_ago = now - Duration::from_secs(60);
            timestamps.retain(|&ts| ts > one_minute_ago);
            
            // Check if rate limit is exceeded
            let is_limited = timestamps.len() >= self.requests_per_minute as usize;
            
            // Add current timestamp if not limited
            if !is_limited {
                timestamps.push(now);
            }
            
            is_limited
        };

        if is_rate_limited {
            return Box::pin(async move {
                Err(Error::RateLimitExceeded(format!(
                    "Rate limit of {} requests per minute exceeded",
                    self.requests_per_minute
                ))
                .into())
            });
        }

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

// Cleanup task to remove old entries from the rate limiter store
pub async fn cleanup_rate_limiter(store: Arc<Mutex<HashMap<String, Vec<Instant>>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        
        let mut store = store.lock().unwrap();
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);
        
        // Remove old timestamps and empty entries
        store.retain(|_, timestamps| {
            timestamps.retain(|&ts| ts > one_minute_ago);
            !timestamps.is_empty()
        });
    }
}