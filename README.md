# Authify

> A production-grade JWT authentication REST API built with Spring Boot and PostgreSQL.

Authify is a learning project that implements a complete, real-world authentication backend from the ground up — covering stateless JWT authentication, refresh token rotation, role-based access control, and password reset flows. Every design decision follows security best practices used in production systems.

![Java](https://img.shields.io/badge/Java-25-orange?logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-4.0.4-brightgreen?logo=springboot)
![Spring Security](https://img.shields.io/badge/Spring_Security-7.x-brightgreen?logo=springsecurity)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-blue?logo=postgresql)
![JWT](https://img.shields.io/badge/JWT-JJWT_0.13-black?logo=jsonwebtokens)
![Maven](https://img.shields.io/badge/Maven-3.9+-red?logo=apachemaven)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Architecture & Design Decisions](#architecture--design-decisions)
- [Prerequisites](#prerequisites)
- [Local Setup](#local-setup)
- [API Reference](#api-reference)
- [Response Format](#response-format)
- [Testing with Postman](#testing-with-postman)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Features

- **Stateless JWT authentication** — short-lived access tokens (15 min) paired with long-lived refresh tokens (7 days)
- **Refresh token rotation** — every `/refresh` call issues a brand-new token and invalidates the old one, limiting the reuse window of any intercepted token
- **Server-side token revocation** — refresh tokens are stored in the database, so logout immediately invalidates the session regardless of expiry
- **Role-based access control** — `USER` and `ADMIN` roles enforced at both the route level and method level (`@PreAuthorize`)
- **Password reset flow** — time-limited (15 min), single-use tokens sent via email
- **User enumeration prevention** — login and forgot-password always return generic responses regardless of whether the email exists
- **Centralized exception handling** — all errors follow a consistent JSON envelope with field-level validation details
- **Automatic audit timestamps** — `createdAt` and `updatedAt` populated automatically on all entities via Spring Data JPA Auditing
- **Graceful email no-op** — the app starts and runs fully without SMTP credentials; email sending is skipped with a log warning

---

## Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| Java | 24 | Language |
| Spring Boot | 4.0.4 | Application framework |
| Spring Security | 7.x | Authentication & authorization filter chain |
| Spring Data JPA | (Boot-managed) | ORM and repository abstraction |
| Hibernate | (Boot-managed) | JPA implementation |
| PostgreSQL | 14+ | Relational database |
| JJWT | 0.13.0 | JWT generation, signing, and validation |
| Lombok | (Boot-managed) | Boilerplate reduction (`@Builder`, `@Slf4j`, etc.) |
| Maven | 3.9+ | Build and dependency management |

---

## Project Structure

The project follows a **by-feature** package layout with **layer sub-packages** inside each domain. Each domain is fully self-contained — its controller, service, repository, entity, and DTOs all live together.

```
src/main/java/com/bothsann/authify/
│
├── auth/                        # Authentication flows
│   ├── controller/              # POST /api/auth/*
│   ├── dto/                     # RegisterRequest, LoginRequest, AuthResponse, etc.
│   └── service/
│       ├── AuthService.java     # Interface
│       └── impl/
│           └── AuthServiceImpl.java
│
├── user/                        # User profile management
│   ├── controller/              # GET / PUT /api/users/me
│   ├── dto/                     # UserResponse, UpdateProfileRequest
│   ├── entity/                  # User.java (implements UserDetails), Role.java
│   ├── repository/
│   └── service/
│       ├── UserService.java
│       └── impl/
│
├── admin/                       # Admin-only operations
│   └── controller/              # GET / DELETE /api/admin/users
│
├── token/                       # Refresh token lifecycle
│   ├── entity/                  # RefreshToken.java
│   ├── repository/
│   └── service/
│       ├── RefreshTokenService.java
│       └── impl/
│
├── passwordreset/               # Password reset flow
│   ├── entity/                  # PasswordResetToken.java
│   ├── repository/
│   └── service/
│
├── security/                    # Spring Security infrastructure
│   ├── SecurityConfig.java      # Filter chain, CORS, authorization rules
│   ├── JwtService.java          # JWT generation & validation
│   ├── JwtAuthFilter.java       # OncePerRequestFilter — reads Bearer token
│   ├── CustomAuthenticationProvider.java
│   └── CustomUserDetailsService.java
│
├── exception/                   # Error handling
│   ├── GlobalExceptionHandler.java   # @RestControllerAdvice
│   ├── ErrorResponse.java
│   └── (custom exception classes)
│
├── config/                      # Application configuration beans
│   ├── ApplicationConfig.java   # PasswordEncoder, AuthenticationManager
│   └── AuditConfig.java         # @EnableJpaAuditing
│
└── common/                      # Shared helpers (no infrastructure concern)
    ├── audit/                   # Auditable base class
    ├── email/                   # EmailService + Gmail SMTP impl
    └── response/                # ApiResponse<T> success envelope
```

---

## Architecture & Design Decisions

### Authentication Flow

```
Register  →  hash password (BCrypt)  →  save User  →  issue access + refresh token pair
Login     →  CustomAuthenticationProvider verifies email/password
          →  load User  →  issue access + refresh token pair
Refresh   →  validate refresh token  →  rotate (delete old, create new)  →  issue new access token
Logout    →  delete refresh token from DB  →  session immediately invalidated
```

### Why Server-Side Refresh Tokens?

Access tokens are stateless JWTs — once issued, they cannot be revoked before expiry. Refresh tokens solve this by being stored in the database. This enables:

- **Logout that actually works** — deleting the DB row immediately invalidates the session
- **Token rotation** — every `/refresh` call replaces the old token, limiting damage from interception
- **Single-session enforcement** — each user can only have one active refresh token at a time

### Token Rotation

Every call to `POST /api/auth/refresh` deletes the old refresh token and creates a brand-new one. If an attacker steals a refresh token and tries to use it after the legitimate user has already refreshed, it will be gone — forcing them to log in again.

### User Enumeration Prevention

Both `POST /api/auth/login` and `POST /api/auth/forgot-password` return the same generic response whether or not the email exists in the database. An attacker probing the API cannot determine which email addresses are registered. Specifically:

- Login: `"Invalid email or password"` for both unknown email **and** wrong password (identical HTTP status + message)
- Forgot-password: `"If that email is registered, a reset link has been sent."` — always 200, always the same message

### Defense in Depth on Admin Routes

Admin endpoints are protected at two independent layers:

1. **Route-level** — `SecurityConfig` denies any request to `/api/admin/**` that does not carry an ADMIN-role JWT
2. **Method-level** — `@PreAuthorize("hasRole('ADMIN')")` on `AdminController` provides a second check

If one layer is ever accidentally misconfigured, the other still protects the endpoint.

### Package Structure Rationale

Organizing by **feature domain first** (auth, user, token, etc.) rather than by **layer first** (all controllers together, all services together) means related code is always co-located. When you need to understand or change the password reset flow, every file you need is under `passwordreset/`. Cross-cutting concerns (security infrastructure, exception handling, configuration) are lifted to their own top-level packages so they are easy to find without belonging to any single domain.

---

## Prerequisites

Ensure the following are installed before cloning:

| Requirement | Version | Download |
|---|---|---|
| Java (JDK) | 24+ | [adoptium.net](https://adoptium.net/) |
| Apache Maven | 3.9+ | [maven.apache.org](https://maven.apache.org/download.cgi) |
| PostgreSQL | 14+ | [postgresql.org](https://www.postgresql.org/download/) |
| Git | any | [git-scm.com](https://git-scm.com/) |

**Optional (for email features):**
- A Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) generated (2FA must be enabled on the account)

---

## Local Setup

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-username/authify.git
cd authify
```

### Step 2 — Create the PostgreSQL database

Connect to PostgreSQL as a superuser:

```bash
psql -U postgres
```

Then run:

```sql
CREATE USER authify_user WITH PASSWORD 'authify_secret_password';
CREATE DATABASE authify_db OWNER authify_user;
GRANT ALL PRIVILEGES ON DATABASE authify_db TO authify_user;
\q
```

> You can use any username and password — just make sure they match what you set in your `.env` file in the next step.

### Step 3 — Configure environment variables

Copy the provided template:

```bash
cp .env.example .env
```

Open `.env` and fill in the values:

```env
# PostgreSQL — match the credentials you created in Step 2
POSTGRES_DB=authify_db
POSTGRES_USER=authify_user
POSTGRES_PASSWORD=authify_secret_password
POSTGRES_PORT=5432

# JWT — generate a secure random key (see command below)
JWT_SECRET_KEY=

# Mail — optional; leave blank to run without email features
MAIL_USERNAME=
MAIL_PASSWORD=

# Frontend — the origin allowed by CORS
FRONTEND_URL=http://localhost:3000
```

**Generating a JWT secret key:**

`JWT_SECRET_KEY` must be a Base64-encoded 256-bit (32-byte) random string. Generate one with:

```bash
# On macOS / Linux
openssl rand -base64 32

# On Windows (PowerShell)
[Convert]::ToBase64String((1..32 | ForEach-Object { [byte](Get-Random -Max 256) }))
```

Paste the output as the value of `JWT_SECRET_KEY` in your `.env` file.

**Environment variable reference:**

| Variable | Required | Default | Description |
|---|---|---|---|
| `POSTGRES_DB` | Yes | `authify_db` | PostgreSQL database name |
| `POSTGRES_USER` | Yes | `authify_user` | PostgreSQL username |
| `POSTGRES_PASSWORD` | Yes | — | PostgreSQL password |
| `POSTGRES_PORT` | No | `5432` | PostgreSQL port |
| `JWT_SECRET_KEY` | **Yes** | none | Base64 256-bit secret for signing JWTs |
| `MAIL_USERNAME` | No | *(empty)* | Gmail address for sending reset emails |
| `MAIL_PASSWORD` | No | *(empty)* | Gmail App Password |
| `FRONTEND_URL` | No | `http://localhost:3000` | Allowed CORS origin |

> **`JWT_SECRET_KEY` is the only variable with no default.** The app will fail to start if it is missing or blank.

### Step 4 — Run the application

```bash
mvn spring-boot:run
```

Spring Boot will automatically create (or update) the database tables on first run via Hibernate's `ddl-auto: update`.

### Step 5 — Verify it started

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/auth/login \
  -X POST -H "Content-Type: application/json" -d '{}'
```

You should receive `400` (validation error for missing fields) — which confirms the app is running and responding correctly.

---

## API Reference

All endpoints are served at `http://localhost:8080`.

### Auth Endpoints (public — no token required)

| Method | Endpoint | Status | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | 201 | Register a new user account |
| `POST` | `/api/auth/login` | 200 | Authenticate and receive a token pair |
| `POST` | `/api/auth/refresh` | 200 | Rotate refresh token and get a new access token |
| `POST` | `/api/auth/logout` | 200 | Revoke the refresh token (server-side logout) |
| `POST` | `/api/auth/forgot-password` | 200 | Request a password reset email |
| `POST` | `/api/auth/reset-password` | 200 | Complete password reset with the token from the email |

### User Endpoints (requires valid JWT — any role)

| Method | Endpoint | Status | Description |
|---|---|---|---|
| `GET` | `/api/users/me` | 200 | Retrieve the authenticated user's profile |
| `PUT` | `/api/users/me` | 200 | Update the authenticated user's first and last name |

### Admin Endpoints (requires valid JWT — ADMIN role only)

| Method | Endpoint | Status | Description |
|---|---|---|---|
| `GET` | `/api/admin/users` | 200 | List all registered user accounts |
| `DELETE` | `/api/admin/users/{id}` | 200 | Permanently delete a user by UUID |

---

## Response Format

### Success — `ApiResponse<T>`

All successful responses use this envelope:

```json
{
  "status": 200,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
  },
  "timestamp": "2025-03-25T10:00:00"
}
```

### Error — `ErrorResponse`

All error responses use this envelope. The `fieldErrors` map is only included for validation failures (400):

```json
{
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed",
  "timestamp": "2025-03-25T10:00:00",
  "path": "/api/auth/register",
  "fieldErrors": {
    "email": "must be a valid email address",
    "password": "must contain at least one uppercase letter, one digit, and one special character"
  }
}
```

### HTTP Status Code Reference

| Status | Meaning | When |
|---|---|---|
| 200 | OK | Successful GET, POST, PUT, DELETE |
| 201 | Created | Successful register |
| 400 | Bad Request | Validation failure or invalid/used token |
| 401 | Unauthorized | Wrong credentials, expired token, missing token |
| 403 | Forbidden | Authenticated but insufficient role |
| 409 | Conflict | Duplicate email on register |
| 500 | Internal Server Error | Unhandled server-side error |

---

## Testing with Postman

Ready-made Postman files are included in the [`postman/`](postman/) folder — no manual setup required.

### Quick Import

1. Open Postman and click **Import** (top-left)
2. Drag and drop **both files** from the `postman/` folder:
   - `Authify API.postman_collection.json` — all 10 endpoints, organized into folders, with automated `pm.test()` scripts and token auto-capture
   - `Authify — Local.postman_environment.json` — pre-configured environment with all required variables (`base_url`, `access_token`, `refresh_token`, `admin_access_token`, `reset_token`, `delete_user_id`)
3. In Postman, select the **`Authify — Local`** environment from the top-right dropdown
4. Set `base_url` to `http://localhost:8080`

### What's Included

- All 10 endpoints across 3 folders: **Auth**, **User**, and **Admin**
- Collection-level Bearer token inheritance — tokens are set once and inherited by all requests
- Automated `pm.test()` scripts on every request — assert status codes, validate response fields, and capture tokens into environment variables automatically
- Recommended testing order: register → login → profile → update profile → refresh → logout → admin list → delete → forgot-password → reset-password

### Promoting a User to ADMIN

Admin endpoints require the `ADMIN` role. To promote a user, connect to PostgreSQL and run:

```sql
UPDATE users SET role = 'ADMIN' WHERE email = 'your-email@example.com';
```

Then log in again to receive a new JWT that carries the `ADMIN` role.

---

## Security Considerations

This project implements the following security practices:

| Practice | Implementation |
|---|---|
| Password hashing | BCrypt with strength 12 (~300ms per hash — intentionally slow) |
| JWT signing | HMAC-SHA256 with a 256-bit secret key |
| Token revocation | Refresh tokens stored server-side; logout deletes the DB row immediately |
| Token rotation | Every `/refresh` call issues a new token and invalidates the old one |
| User enumeration prevention | Login and forgot-password return identical responses for valid/invalid emails |
| Single-use reset tokens | Password reset tokens are marked `used=true` after first successful reset |
| Time-limited reset tokens | Password reset tokens expire after 15 minutes |
| Stateless sessions | No `HttpSession` created; no CSRF vulnerability |
| CORS | Requests allowed only from the configured `FRONTEND_URL` |
| Defense in depth | Admin routes protected at both route level (SecurityConfig) and method level (@PreAuthorize) |

---

## License

This project is licensed under the [MIT License](LICENSE).
