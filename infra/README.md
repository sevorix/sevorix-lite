# Sevorix Hub GCP Infrastructure

This directory contains Terraform configuration for deploying sevorix-hub to Google Cloud Platform.

## Architecture

- **Cloud Run**: Serverless container hosting for sevorix-hub
- **Cloud SQL (PostgreSQL)**: Managed PostgreSQL database
- **Cloud Storage**: Artifact storage (replaces local filesystem)
- **Secret Manager**: Secure storage for DATABASE_URL and JWT_SECRET
- **Artifact Registry**: Docker image storage
- **Cloud Build**: CI/CD pipeline

## Prerequisites

1. GCP Project with billing enabled
2. `gcloud` CLI configured with appropriate permissions
3. Terraform >= 1.0
4. GitHub repository connected to Cloud Build (for CI/CD)

## Deployment

### 1. Initialize Terraform

```bash
cd infra
terraform init
```

### 2. Create terraform.tfvars

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
```

### 3. Plan and Apply

```bash
terraform plan
terraform apply
```

### 4. Connect GitHub Repository

After applying, connect your GitHub repository to Cloud Build:

1. Go to Cloud Build > Triggers in the GCP Console
2. Click "Connect Repository"
3. Select GitHub and authorize Cloud Build
4. Select the sevorix repository

The trigger will automatically deploy on pushes to `main`.

## Manual Deployment

To deploy manually without CI/CD:

```bash
# Build and push image
gcloud builds submit --config=cloudbuild.yaml .

# Or deploy directly
gcloud run deploy sevorix-hub \
  --image=gcr.io/PROJECT_ID/sevorix-hub:latest \
  --region=us-central1 \
  --platform=managed \
  --set-env-vars=STORAGE_BACKEND=gcs,GCS_BUCKET=PROJECT_ID-artifacts
```

## Local Development with Cloud SQL Auth Proxy

For local development, use the Cloud SQL Auth Proxy to connect to the Cloud SQL instance securely.

### Prerequisites

1. Install the Cloud SQL Auth Proxy:
   ```bash
   # Linux (x86_64)
   curl -o cloud-sql-proxy https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.8.1/cloud-sql-proxy.linux.amd64
   chmod +x cloud-sql-proxy
   sudo mv cloud-sql-proxy /usr/local/bin/

   # Or using gcloud
   gcloud components install cloud-sql-proxy
   ```

2. Authenticate with gcloud:
   ```bash
   gcloud auth login
   gcloud config set project sevorix
   ```

### Running the Proxy

```bash
# Start the Cloud SQL Auth Proxy (runs in foreground)
cloud-sql-proxy --unix-socket /tmp/cloudsql sevorix:us-central1:sevorix-hub-db

# Or run in background
cloud-sql-proxy --unix-socket /tmp/cloudsql sevorix:us-central1:sevorix-hub-db &

# The proxy creates a local Unix socket at:
# /tmp/cloudsql/sevorix:us-central1:sevorix-hub-db/.s.PGSQL.5432
```

### Connection String for Local Development

```bash
# Using Unix socket (default proxy behavior)
export DATABASE_URL="postgresql://sevorix:<password>@/sevorix_hub?host=/tmp/cloudsql/sevorix:us-central1:sevorix-hub-db"

# Or using TCP port (simpler for some clients)
cloud-sql-proxy --port 5432 sevorix:us-central1:sevorix-hub-db &
export DATABASE_URL="postgresql://sevorix:<password>@localhost:5432/sevorix_hub"
```

### Retrieving the Database Password

```bash
# From Secret Manager (after Terraform apply)
gcloud secrets versions access latest --secret="sevorix-hub-database-url"

# Or extract from Terraform state
terraform output -raw database_connection_name
```

## Cloud Run Connection String Format

Cloud Run services connect to Cloud SQL using Unix sockets. The connection string format is:

```
postgresql://<user>:<password>@/<database>?host=/cloudsql/<connection_name>
```

Where:
- `<user>`: Database username (default: `sevorix`)
- `<password>`: Database password (stored in Secret Manager)
- `<database>`: Database name (default: `sevorix_hub`)
- `<connection_name>`: Cloud SQL connection name (format: `project:region:instance`)

Example for the sevorix-hub deployment:
```
postgresql://sevorix:<password>@/sevorix_hub?host=/cloudsql/sevorix:us-central1:sevorix-hub-db
```

The full connection string is stored in Secret Manager as `sevorix-hub-database-url`.

### Cloud Run Service Configuration

The Cloud Run service needs:
1. The Cloud SQL instance attached
2. Access to the secret containing the DATABASE_URL

```bash
gcloud run deploy sevorix-hub \
  --image=gcr.io/sevorix/sevorix-hub:latest \
  --region=us-central1 \
  --add-cloudsql-instances=sevorix:us-central1:sevorix-hub-db \
  --set-secrets=DATABASE_URL=sevorix-hub-database-url:latest
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes (from Secret Manager) |
| `JWT_SECRET` | Secret for JWT signing | Yes (from Secret Manager) |
| `STORAGE_BACKEND` | `filesystem` or `gcs` | Yes |
| `GCS_BUCKET` | GCS bucket name | If STORAGE_BACKEND=gcs |
| `PORT` | Server port (default: 8080) | No |

## Provisioned Resources

The following resources have been provisioned manually (pending Terraform migration):

### Cloud SQL Instance

| Property | Value |
|----------|-------|
| Instance Name | `sevorix-hub-db` |
| Database Version | PostgreSQL 15 |
| Region | us-central1-c |
| Tier | db-f1-micro |
| Public IP | 34.58.240.112 |
| Connection Name | `sevorix:us-central1:sevorix-hub-db` |

### Database

| Property | Value |
|----------|-------|
| Database Name | `sevorix_hub` |
| User | `sevorix` |

### Quick Connection

```bash
# Connect via Cloud SQL Auth Proxy
cloud-sql-proxy --unix-socket /tmp/cloudsql sevorix:us-central1:sevorix-hub-db &

# Then connect with psql (Unix socket)
psql "host=/tmp/cloudsql/sevorix:us-central1:sevorix-hub-db user=sevorix dbname=sevorix_hub"

# Or using TCP port
cloud-sql-proxy --port 5432 sevorix:us-central1:sevorix-hub-db &
psql "host=localhost port=5432 user=sevorix dbname=sevorix_hub"
```

## Cost Estimate

For a minimal deployment:
- Cloud Run: ~$0-10/month (free tier + minimal usage)
- Cloud SQL (db-f1-micro): ~$15-25/month
- Cloud Storage: ~$0.02/GB/month
- Artifact Registry: ~$0.10/GB/month

Total: ~$20-40/month for development workloads.

## Security

- Database has public IP (consider configuring SSL-only connections)
- Secrets should be stored in Secret Manager (requires API enablement)
- Service account with minimal permissions
- VPC connector planned for secure Cloud Run to Cloud SQL communication

**Note:** For production, consider:
1. Disabling public IP and using private network only
2. Enabling SSL for all connections
3. Configuring Cloud SQL Auth Proxy for all access

## Cleanup

```bash
terraform destroy
```

Note: This will delete all resources including the database. Make sure to backup any important data first.
