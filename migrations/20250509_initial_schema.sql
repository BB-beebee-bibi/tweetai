-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(30) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    theme VARCHAR(20) NOT NULL DEFAULT 'Agora',
    message_count_today INTEGER NOT NULL DEFAULT 0,
    last_message_date DATE,
    identity_key_pair BYTEA NOT NULL,
    public_identity_key BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create messages table
CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_content BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT sender_recipient_different CHECK (sender_id != recipient_id)
);

-- Create user_states table for tracking user state
CREATE TABLE IF NOT EXISTS user_states (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sleep_status VARCHAR(20),
    workday_status VARCHAR(20),
    calories INTEGER,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT user_id_unique UNIQUE (user_id)
);

-- Create encryption_sessions table for Signal Protocol sessions
CREATE TABLE IF NOT EXISTS encryption_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_data BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT user_recipient_unique UNIQUE (user_id, recipient_id),
    CONSTRAINT user_recipient_different CHECK (user_id != recipient_id)
);

-- Create pre_keys table for Signal Protocol pre-keys
CREATE TABLE IF NOT EXISTS pre_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    private_key BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT user_key_id_unique UNIQUE (user_id, key_id)
);

-- Create signed_pre_keys table for Signal Protocol signed pre-keys
CREATE TABLE IF NOT EXISTS signed_pre_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    private_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT user_key_id_unique UNIQUE (user_id, key_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient_id ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_encryption_sessions_user_id ON encryption_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_encryption_sessions_recipient_id ON encryption_sessions(recipient_id);
CREATE INDEX IF NOT EXISTS idx_pre_keys_user_id ON pre_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_signed_pre_keys_user_id ON signed_pre_keys(user_id);

-- Create Gaurav user (ID 1) if not exists
INSERT INTO users (
    id, 
    username, 
    password_hash, 
    theme, 
    identity_key_pair, 
    public_identity_key, 
    created_at, 
    updated_at
) 
VALUES (
    1, 
    'gaurav', 
    '$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$WVaJ1Qs+2PcYl6Hdw/o6dA', -- placeholder, will be replaced
    'Agora',
    E'\\x0000', -- placeholder, will be replaced
    E'\\x0000', -- placeholder, will be replaced
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;