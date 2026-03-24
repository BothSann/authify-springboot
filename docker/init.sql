CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- enables gen_random_uuid()

-- Users table
CREATE TABLE IF NOT EXISTS users (
                                     id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) UNIQUE NOT NULL,
    password    VARCHAR(255) NOT NULL,
    first_name  VARCHAR(100),
    last_name   VARCHAR(100),
    role        VARCHAR(20) DEFAULT 'USER',
    enabled     BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW()
    );

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
                                              id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token       TEXT UNIQUE NOT NULL,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMP NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
    );

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
                                                     id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token       VARCHAR(255) UNIQUE NOT NULL,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMP NOT NULL,
    used        BOOLEAN DEFAULT FALSE
    );

-- Seed admin user
-- password = 'Admin@1234' (BCrypt hashed)
INSERT INTO users (email, password, first_name, last_name, role)
VALUES (
           'admin@authify.com',
           '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQyCg2uVcTBRCBtRDf2g8e3Aq',
           'Super',
           'Admin',
           'ADMIN'
       ) ON CONFLICT (email) DO NOTHING;