# TweetAI

A secure, minimal messaging platform with end-to-end encryption built in Rust.

## Features

- **Secure Authentication**: JWT-based authentication with Argon2id password hashing
- **End-to-End Encryption**: All messages are encrypted using the Signal Protocol
- **Message Constraints**: 256 character limit per message, 16 messages per day limit
- **Visual Themes**: 5 distinct visual themes (Agora, Sky, Castle, Mountaintop, Wild Card)
- **User State Tracking**: Track user state (sleep, workday, calories)
- **Rate Limiting**: Protect against abuse with rate limiting
- **AI Integration**: Gradual transition to AI-powered responses based on Gaurav's communication style

## Technology Stack

- **Backend**: Rust with Actix-web framework
- **Database**: PostgreSQL with sqlx for type-safe queries
- **Authentication**: JWT with Argon2id password hashing
- **Encryption**: Signal Protocol via signalprotocol-rs
- **API**: RESTful endpoints with JSON
- **Validation**: Strict request validation with serde
- **Logging**: Structured logging with tracing
- **Configuration**: Environment variables with dotenv

## Project Structure

```
tweetai/
├── Cargo.toml                 # Project dependencies
├── .env.example               # Example environment variables
├── src/
│   ├── main.rs                # Application entry point
│   ├── config.rs              # Configuration loading
│   ├── error.rs               # Error handling
│   ├── models/                # Database models
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   └── message.rs
│   ├── handlers/              # Request handlers
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── messages.rs
│   │   ├── theme.rs
│   │   └── user_state.rs
│   ├── services/              # Business logic
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── message.rs
│   │   └── encryption.rs
│   ├── repositories/          # Database access
│   │   ├── mod.rs
│   │   ├── user_repository.rs
│   │   ├── message_repository.rs
│   │   └── encryption_repository.rs
│   ├── middleware/            # HTTP middleware
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   └── rate_limiter.rs
│   └── utils/                 # Utility functions
│       ├── mod.rs
│       └── validation.rs
└── migrations/                # Database migrations
    └── 20250509_initial_schema.sql
```

## Getting Started

### Prerequisites

- Rust (latest stable version)
- PostgreSQL

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/tweetai.git
   cd tweetai
   ```

2. Create a `.env` file based on `.env.example`:
   ```
   cp .env.example .env
   ```

3. Update the `.env` file with your configuration.

4. Set up the database:
   ```
   psql -U postgres -c "CREATE DATABASE tweetai"
   psql -U postgres -d tweetai -f migrations/20250509_initial_schema.sql
   ```

5. Build and run the application:
   ```
   cargo run
   ```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and get JWT token
- `POST /api/auth/validate` - Validate JWT token

### Messages

- `POST /api/messages` - Send a message to Gaurav
- `GET /api/messages` - Get all messages
- `GET /api/messages/{id}` - Get a specific message
- `GET /api/messages/count` - Get message count for today

### Theme

- `GET /api/theme` - Get current theme
- `PUT /api/theme` - Update theme
- `GET /api/theme/available` - Get available themes

### User State

- `GET /api/user-state` - Get user state
- `PUT /api/user-state` - Update user state

## Security Features

1. **Password Security**
   - Argon2id password hashing (memory-hard, resistant to GPU attacks)
   - Strong password requirements enforced

2. **End-to-End Encryption**
   - Signal Protocol implementation for perfect forward secrecy
   - Messages encrypted on the client before transmission
   - Server cannot read message contents

3. **API Security**
   - JWT authentication with secure token handling
   - Rate limiting to prevent abuse
   - Input validation on all endpoints
   - CORS protection

4. **Data Protection**
   - Sensitive data encrypted at rest
   - Minimal data collection
   - Secure key management

## License

This project is licensed under the MIT License - see the LICENSE file for details.