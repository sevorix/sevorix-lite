# SevorixHub

> **Policy Artifact Registry for Sevorix Watchtower**

SevorixHub is a centralized registry for managing policy artifacts used by Sevorix Watchtower. It provides REST API endpoints and CLI tools for publishing, discovering, and downloading security policies.

---

## Overview

SevorixHub serves as the policy artifact registry for the Sevorix security platform. It enables:

- **Policy Distribution**: Share and version security policies across teams and environments
- **Discovery**: Search and find policies by name, tags, or description
- **Trust System**: Endorsements verify policy authenticity and safety
- **Access Control**: Visibility controls for public, private, and draft policies

### Key Features

- RESTful API for artifact management
- JWT-based authentication with Argon2 password hashing
- Support for both filesystem and Google Cloud Storage backends
- PostgreSQL database for metadata with Cloud SQL support
- Endorsement system for trust verification

---

## REST API Documentation

### Base URL

```
http://localhost:8080/api/v1
```

In production: `https://<cloud-run-url>/api/v1`

---

### Authentication Endpoints

#### Register a New User

**POST** `/api/v1/register`

Creates a new user account.

**Request Body:**
```json
{
  "email": "alice@example.com",
  "password": "securepassword123"
}
```

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "alice@example.com"
}
```

**Error Responses:**
- `400 Bad Request`: Missing email or password
- `409 Conflict`: Email already registered

**Example:**
```bash
curl -X POST https://hub.sevorix.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "securepassword123"}'
```

---

#### Login

**POST** `/api/v1/login`

Authenticates a user and returns a JWT token.

**Request Body:**
```json
{
  "email": "alice@example.com",
  "password": "securepassword123"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "email": "alice@example.com",
  "is_admin": false,
  "is_endorsed": false
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid credentials

**Example:**
```bash
curl -X POST https://hub.sevorix.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "securepassword123"}'
```

---

### User Endpoints

#### Get Current User

**GET** `/api/v1/me`

Returns the authenticated user's profile.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "alice@example.com",
  "is_admin": false,
  "is_endorsed": false,
  "created_at": "2026-02-26T10:30:00Z"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token

---

#### Get User Profile

**GET** `/api/v1/users/:user_id`

Returns a public user profile.

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "alice@example.com",
  "is_admin": false,
  "is_endorsed": false,
  "created_at": "2026-02-26T10:30:00Z"
}
```

**Error Responses:**
- `404 Not Found`: User not found

---

### Artifact Endpoints

#### Push Artifact

**POST** `/api/v1/artifacts`

Uploads a new policy artifact.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "financial-policy",
  "version": "1.0.0",
  "description": "Blocks unauthorized financial transactions",
  "tags": ["finance", "security", "production"],
  "content": "{\"policies\": [...]}",
  "visibility": "public"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Artifact identifier (e.g., "my-policy") |
| `version` | string | Yes | Semantic version (e.g., "1.0.0") |
| `description` | string | No | Human-readable description |
| `tags` | string[] | No | Tags for categorization and search |
| `content` | string | Yes | JSON policy content (must be valid JSON) |
| `visibility` | string | No | "public", "private", or "draft" (default: "public") |

**Response (201 Created):**
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440000",
  "name": "financial-policy",
  "version": "1.0.0",
  "description": "Blocks unauthorized financial transactions",
  "owner": "alice",
  "tags": ["finance", "security", "production"],
  "visibility": "public",
  "downloads": 0,
  "created_at": "2026-02-26T12:00:00Z"
}
```

**Error Responses:**
- `400 Bad Request`: Missing required fields or invalid JSON content
- `401 Unauthorized`: Missing or invalid token
- `409 Conflict`: Artifact with same name and version already exists

**Example:**
```bash
curl -X POST https://hub.sevorix.com/api/v1/artifacts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "financial-policy",
    "version": "1.0.0",
    "description": "Blocks unauthorized financial transactions",
    "tags": ["finance", "security"],
    "content": "{\"policies\": [{\"type\": \"Keyword\", \"pattern\": \"WIRE\"}]}"
  }'
```

---

#### Pull Artifact

**GET** `/api/v1/artifacts/:name/:version`

Downloads an artifact by name and version. Increments the download counter.

**Headers (optional for public artifacts):**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440000",
  "name": "financial-policy",
  "version": "1.0.0",
  "description": "Blocks unauthorized financial transactions",
  "owner": "alice",
  "owner_is_endorsed": false,
  "tags": ["finance", "security", "production"],
  "visibility": "public",
  "downloads": 42,
  "created_at": "2026-02-26T12:00:00Z",
  "content": {
    "policies": [...]
  }
}
```

**Visibility Rules:**
- **Public**: Accessible to everyone
- **Private**: Accessible to owner and admins only
- **Draft**: Accessible to owner and admins only

**Error Responses:**
- `404 Not Found`: Artifact not found or no access

**Example:**
```bash
curl -X GET https://hub.sevorix.com/api/v1/artifacts/financial-policy/1.0.0
```

---

#### Search Artifacts

**GET** `/api/v1/artifacts/search`

Searches for artifacts by name, description, or tag.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `q` | string | Search query (matches name and description) |
| `tag` | string | Filter by tag |
| `limit` | integer | Max results (default: 20, max: 100) |
| `offset` | integer | Pagination offset (default: 0) |

**Headers (optional):**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "results": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440000",
      "name": "financial-policy",
      "version": "1.0.0",
      "description": "Blocks unauthorized financial transactions",
      "owner": "alice",
      "owner_is_endorsed": false,
      "tags": ["finance", "security"],
      "visibility": "public",
      "downloads": 42,
      "created_at": "2026-02-26T12:00:00Z"
    }
  ],
  "total": 15
}
```

**Visibility Rules:**
- Anonymous users see only public artifacts
- Authenticated users see public + their own private/draft artifacts
- Admins see all artifacts

**Examples:**
```bash
# Search by query
curl -X GET "https://hub.sevorix.com/api/v1/artifacts/search?q=financial"

# Filter by tag
curl -X GET "https://hub.sevorix.com/api/v1/artifacts/search?tag=security"

# Combined search with pagination
curl -X GET "https://hub.sevorix.com/api/v1/artifacts/search?q=financial&limit=10&offset=0"
```

---

### Endorsement Endpoints

#### Create Endorsement

**POST** `/api/v1/artifacts/:artifact_id/endorsements`

Endorse an artifact to verify its authenticity or safety.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "level": "verified"
}
```

**Endorsement Levels:**
| Level | Description |
|-------|-------------|
| `verified` | Basic verification (default) |
| `trusted_author` | Endorsed by a trusted author |
| `official` | Official endorsement from project maintainers |

**Response (201 Created):**
```json
{
  "id": "770e8400-e29b-41d4-a716-446655440000",
  "artifact_id": "660e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "alice@example.com",
  "user_is_admin": false,
  "user_is_endorsed": false,
  "level": "verified",
  "created_at": "2026-02-26T14:00:00Z"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `404 Not Found`: Artifact not found
- `409 Conflict`: Already endorsed this artifact

**Example:**
```bash
curl -X POST https://hub.sevorix.com/api/v1/artifacts/660e8400-e29b-41d4-a716-446655440000/endorsements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"level": "verified"}'
```

---

#### List Endorsements

**GET** `/api/v1/artifacts/:artifact_id/endorsements`

List all endorsements for an artifact.

**Response (200 OK):**
```json
[
  {
    "id": "770e8400-e29b-41d4-a716-446655440000",
    "artifact_id": "660e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "user_is_admin": false,
    "user_is_endorsed": false,
    "level": "verified",
    "created_at": "2026-02-26T14:00:00Z"
  }
]
```

**Error Responses:**
- `404 Not Found`: Artifact not found

---

#### Delete Endorsement

**DELETE** `/api/v1/artifacts/:artifact_id/endorsements/:endorsement_id`

Remove an endorsement. Only the endorsement creator or an admin can delete.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (204 No Content):** No body returned on success.

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Cannot delete others' endorsements
- `404 Not Found`: Endorsement or artifact not found

---

## CLI Usage

The `sevorix hub` commands provide CLI access to SevorixHub.

### Configuration

**Environment Variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `SEVORIX_HUB_URL` | Hub server URL | `https://sevorix-hub-668536931811.us-central1.run.app` |

**Token Storage:**

Authentication tokens are stored at:
```
~/.config/sevorix/hub_token
```

The token file has restrictive permissions (mode 0600) on Unix systems.

---

### hub login

Authenticate with SevorixHub and store the token locally.

**Usage:**
```bash
sevorix hub login [OPTIONS] --email <EMAIL>
```

**Options:**
| Option | Description |
|--------|-------------|
| `--hub-url <URL>` | SevorixHub server URL (or set `SEVORIX_HUB_URL`) |
| `-e, --email <EMAIL>` | Email for authentication |
| `-p, --password <PASSWORD>` | Password (will prompt if not provided) |

**Example:**
```bash
# Interactive (prompts for password)
sevorix hub login --email alice@example.com

# With password (not recommended for scripts)
sevorix hub login --email alice@example.com --password $PASSWORD

# Custom hub URL
sevorix hub login --hub-url https://hub.sevorix.com --email alice@example.com
```

---

### hub push

Upload a policy artifact to SevorixHub.

**Usage:**
```bash
sevorix hub push [OPTIONS] --name <NAME> --version <VERSION> --file <FILE>
```

**Options:**
| Option | Description |
|--------|-------------|
| `--hub-url <URL>` | SevorixHub server URL |
| `-n, --name <NAME>` | Artifact name |
| `-v, --version <VERSION>` | Artifact version |
| `-f, --file <FILE>` | Path to policy JSON file |
| `-d, --description <DESC>` | Optional description |
| `-t, --tag <TAG>` | Tags (can be specified multiple times) |

**Example:**
```bash
# Basic push
sevorix hub push \
  --name financial-policy \
  --version 1.0.0 \
  --file ./policies/financial.json

# With description and tags
sevorix hub push \
  --name financial-policy \
  --version 1.0.0 \
  --file ./policies/financial.json \
  --description "Blocks unauthorized financial transactions" \
  --tag finance \
  --tag security \
  --tag production
```

---

### hub pull

Download a policy artifact from SevorixHub.

**Usage:**
```bash
sevorix hub pull [OPTIONS] <NAME> <VERSION>
```

**Arguments:**
- `NAME` - Artifact name
- `VERSION` - Artifact version

**Options:**
| Option | Description |
|--------|-------------|
| `--hub-url <URL>` | SevorixHub server URL |
| `-o, --output <FILE>` | Output file path (prints to stdout if not specified) |

**Example:**
```bash
# Download and print to stdout
sevorix hub pull financial-policy 1.0.0

# Save to file
sevorix hub pull financial-policy 1.0.0 --output ./downloaded-policy.json
```

---

### hub search

Search for policy artifacts.

**Usage:**
```bash
sevorix hub search [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--hub-url <URL>` | SevorixHub server URL |
| `-q, --query <QUERY>` | Search query (matches name and description) |
| `-t, --tag <TAG>` | Filter by tag |
| `-l, --limit <LIMIT>` | Max results (default: 20) |

**Example:**
```bash
# Search by name/description
sevorix hub search --query financial

# Filter by tag
sevorix hub search --tag security

# Combined search
sevorix hub search --query policy --tag production --limit 10
```

---

## Authentication Mechanism

SevorixHub uses JWT-based application-layer authentication. The Cloud Run service is publicly accessible, with security enforced at the application level through:

- **User Approval System**: New users must be approved by an admin before accessing the API
- **Rate Limiting**: IP-based rate limiting prevents abuse
- **Audit Logging**: All security-relevant events are logged for monitoring

### JWT Authentication (API Access)

API operations require a JWT token obtained via `/api/v1/login`:

**Token Lifecycle:**
- **Expiration**: 30 days from issuance
- **Storage**: `~/.config/sevorix/hub_token`
- **Permissions**: File mode 0600 (owner read/write only)

**Token Structure:**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "alice@example.com",
  "exp": 1709047200
}
```

**Token Refresh Flow:**
1. Token expires after 30 days
2. Client receives `401 Unauthorized` response
3. Client calls `/api/v1/login` to obtain new token
4. New token is stored and used for subsequent requests

---

## Security

### Password Security

- **Hashing Algorithm**: Argon2 (winner of the Password Hashing Competition)
- **Salt**: Random salt generated per password using `OsRng`
- **Parameters**: Default Argon2 parameters (memory-hard, resistant to GPU attacks)

### JWT Security

- **Signing Algorithm**: HMAC-SHA256 (HS256)
- **Secret Key**: Configured via `JWT_SECRET` environment variable
- **Claims**: User ID (sub), email, expiration timestamp

### Private Artifact Visibility

**Visibility Levels:**

| Level | Access |
|-------|--------|
| `public` | Everyone (including anonymous users) |
| `private` | Owner and admins only |
| `draft` | Owner and admins only (for work-in-progress) |

**Endorsed Users:**
- Endorsed users (`is_endorsed: true`) are displayed in search results
- Endorsements from endorsed users carry more trust weight
- The `owner_is_endorsed` flag is included in pull responses

### Executable Policy Security Warnings

When pulling an artifact, the CLI checks for `Executable` policy types:

```rust
// From src/hub.rs
pub fn check_executable_policy(content: &serde_json::Value) -> Vec<String>
```

**Warning Example:**
```
⚠ Warning: Policy 'custom-command' uses Executable type which can run arbitrary commands
```

Users are warned before using policies that can execute arbitrary commands.

### Cloud Run Public Access

The Cloud Run service is configured for public access via the `allUsers` invoker role:

- **IAM Binding**: `allUsers` granted `roles/run.invoker`
- **Authentication**: Handled at the application layer via JWT
- **Security Layers**: User approval, rate limiting, and audit logging protect the service

The Terraform configuration includes the IAM binding:
```hcl
resource "google_cloud_run_service_iam_member" "allusers_invoker" {
  location = var.region
  service  = "sevorix-hub"
  role     = "roles/run.invoker"
  member   = "allUsers"
}
```

---

## Deployment

### Cloud Run Configuration

**Service Name:** `sevorix-hub`

**Required Environment Variables:**

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@/db?host=/cloudsql/project:region:instance` |
| `JWT_SECRET` | Secret key for JWT signing | Minimum 32 characters, cryptographically random |
| `STORAGE_BACKEND` | Storage type | `filesystem` or `gcs` |
| `PORT` | Listen port (default: 8080) | `8080` |

**Optional Environment Variables:**

| Variable | Description | Required When |
|----------|-------------|---------------|
| `GCS_BUCKET` | GCS bucket name | `STORAGE_BACKEND=gcs` |
| `ARTIFACTS_DIR` | Local artifacts directory | `STORAGE_BACKEND=filesystem` (default: `~/.local/share/sevorix-hub/artifacts`) |

### Cloud SQL Connection

Connect to Cloud SQL via Unix socket:

```bash
DATABASE_URL="postgresql://sevorix_user:password@/sevorix_hub?host=/cloudsql/my-project:us-central1:sevorix-db"
```

**Cloud SQL Proxy Sidecar:**
- Not required on Cloud Run (native Unix socket support)
- Required for local development connecting to Cloud SQL

### Artifact Storage

**Filesystem Backend (Development):**
```bash
STORAGE_BACKEND=filesystem
ARTIFACTS_DIR=/var/lib/sevorix-hub/artifacts
```

Artifacts are stored as JSON files: `<artifacts_dir>/<uuid>.json`

**GCS Backend (Production):**
```bash
STORAGE_BACKEND=gcs
GCS_BUCKET=sevorix-hub-artifacts
```

Artifacts are stored as: `gs://<bucket>/artifacts/<uuid>.json`

**GCS IAM Requirements:**
- Service account needs `roles/storage.objectAdmin` on the bucket
- Cloud Run automatically obtains access token via metadata server

### Building the Docker Image

```bash
# Build for Cloud Run
docker build -t sevorix-hub -f sevorix-hub/Dockerfile .

# Run locally
docker run -p 8080:8080 \
  -e DATABASE_URL="postgresql://..." \
  -e JWT_SECRET="your-secret-key" \
  sevorix-hub
```

### Deploying to Cloud Run

```bash
# Build and push to GCR
gcloud builds submit --tag gcr.io/my-project/sevorix-hub

# Deploy to Cloud Run
gcloud run deploy sevorix-hub \
  --image gcr.io/my-project/sevorix-hub \
  --region us-central1 \
  --set-env-vars "DATABASE_URL=...,JWT_SECRET=...,STORAGE_BACKEND=gcs,GCS_BUCKET=..." \
  --add-cloudsql-instances my-project:us-central1:sevorix-db \
  --no-allow-unauthenticated
```

---

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin    BOOLEAN NOT NULL DEFAULT false,
    is_endorsed BOOLEAN NOT NULL DEFAULT false,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Artifacts Table

```sql
CREATE TABLE artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(128) NOT NULL,
    version     VARCHAR(64) NOT NULL,
    description TEXT,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    downloads   INTEGER NOT NULL DEFAULT 0,
    visibility  VARCHAR(16) NOT NULL DEFAULT 'public',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT artifacts_name_version_unique UNIQUE(name, version)
);
```

### Endorsements Table

```sql
CREATE TABLE endorsements (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    level       VARCHAR(32) NOT NULL DEFAULT 'verified',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT endorsements_user_artifact_unique UNIQUE(artifact_id, user_id)
);
```

---

## Error Handling

All API errors return JSON with an `error` field:

```json
{
  "error": "Description of the error"
}
```

**HTTP Status Codes:**

| Status | Meaning |
|--------|---------|
| `200 OK` | Request successful |
| `201 Created` | Resource created successfully |
| `204 No Content` | Deletion successful |
| `400 Bad Request` | Invalid request body or parameters |
| `401 Unauthorized` | Missing or invalid authentication |
| `403 Forbidden` | Authenticated but not authorized |
| `404 Not Found` | Resource not found |
| `409 Conflict` | Resource already exists |
| `500 Internal Server Error` | Server error (check logs) |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Submit a pull request

---

## License

Proprietary - All rights reserved.
