use crate::error::Error;
use crate::models::AuthenticatedUser;
use crate::services::validate_jwt;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error as ActixError, HttpMessage,
};
use futures::future::{ready, LocalBoxFuture, Ready};
use std::rc::Rc;
use std::task::{Context, Poll};

pub struct Authentication {
    jwt_secret: Rc<String>,
}

impl Authentication {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret: Rc::new(jwt_secret),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Authentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Transform = AuthenticationMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware {
            service,
            jwt_secret: Rc::clone(&self.jwt_secret),
        }))
    }
}

pub struct AuthenticationMiddleware<S> {
    service: S,
    jwt_secret: Rc<String>,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
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
        let jwt_secret = Rc::clone(&self.jwt_secret);
        let mut authenticated = false;
        let mut user_id = 0;
        let mut username = String::new();

        // Extract the token from the Authorization header
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = auth_str.trim_start_matches("Bearer ");
                    
                    // Validate the token
                    if let Ok(claims) = validate_jwt(token, &jwt_secret) {
                        if let Ok(id) = claims.sub.parse::<i64>() {
                            authenticated = true;
                            user_id = id;
                            username = claims.username;
                        }
                    }
                }
            }
        }

        if !authenticated {
            return Box::pin(async move {
                Err(Error::Auth("Authentication required".into()).into())
            });
        }

        // Add the authenticated user to the request extensions
        req.extensions_mut().insert(AuthenticatedUser {
            user_id,
            username,
        });

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}