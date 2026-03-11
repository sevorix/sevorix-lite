# Terraform configuration for sevorix-hub GCP infrastructure

terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # Backend configuration - update with your GCS bucket
  # backend "gcs" {
  #   bucket = "sevorix-terraform-state"
  #   prefix = "sevorix-hub"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "vpcaccess.googleapis.com",
    "servicenetworking.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

# Cloud Storage bucket for artifacts
resource "google_storage_bucket" "artifacts" {
  name          = "${var.project_id}-artifacts"
  location      = var.region
  force_destroy = false

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 365 # Delete objects older than 1 year
    }
  }

  depends_on = [google_project_service.required_apis]
}

# VPC Connector for Cloud Run to Cloud SQL
resource "google_vpc_access_connector" "hub_connector" {
  name          = "sevorix-hub-connector"
  region        = var.region
  network       = "default"
  ip_cidr_range = "10.8.0.0/28"

  depends_on = [google_project_service.required_apis]
}

# Cloud SQL PostgreSQL instance
resource "google_sql_database_instance" "hub_db" {
  name             = "sevorix-hub-db"
  database_version = "POSTGRES_15"
  region           = var.region

  settings {
    tier              = var.db_tier
    availability_type = var.db_availability_type

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/${var.project_id}/global/networks/default"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    maintenance_window {
      day  = 7  # Sunday
      hour = 3  # 3 AM
    }
  }

  depends_on = [
    google_project_service.required_apis,
    google_service_networking_connection.private_service_access
  ]
}

# Private service access for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  name          = "google-managed-services-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = "projects/${var.project_id}/global/networks/default"
}

resource "google_service_networking_connection" "private_service_access" {
  network                 = "projects/${var.project_id}/global/networks/default"
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]

  depends_on = [google_project_service.required_apis]
}

# Database and user
resource "google_sql_database" "hub_database" {
  name     = "sevorix_hub"
  instance = google_sql_database_instance.hub_db.name
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_user" "hub_user" {
  name     = "sevorix"
  instance = google_sql_database_instance.hub_db.name
  password = random_password.db_password.result
}

# Secret Manager secrets
resource "google_secret_manager_secret" "database_url" {
  secret_id = "sevorix-hub-database-url"

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret      = google_secret_manager_secret.database_url.id
  secret_data = "postgresql://${google_sql_user.hub_user.name}:${random_password.db_password.result}@localhost/${google_sql_database.hub_database.name}?host=/cloudsql/${var.project_id}:${var.region}:${google_sql_database_instance.hub_db.name}"
}

resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "sevorix-hub-jwt-secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret_version" "jwt_secret" {
  secret      = google_secret_manager_secret.jwt_secret.id
  secret_data = random_password.jwt_secret.result
}

# Service account for Cloud Run
resource "google_service_account" "hub_sa" {
  account_id   = "sevorix-hub"
  display_name = "Sevorix Hub Service Account"
}

# Grant service account access to secrets
resource "google_secret_manager_secret_iam_member" "hub_db_url_access" {
  secret_id = google_secret_manager_secret.database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.hub_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "hub_jwt_access" {
  secret_id = google_secret_manager_secret.jwt_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.hub_sa.email}"
}

# Grant service account access to GCS bucket
resource "google_storage_bucket_iam_member" "hub_gcs_access" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.hub_sa.email}"
}

# Grant service account Cloud SQL client access
resource "google_project_iam_member" "hub_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.hub_sa.email}"
}

# Artifact Registry repository
resource "google_artifact_registry_repository" "hub_repo" {
  location      = var.region
  repository_id = "sevorix-hub"
  description   = "Docker repository for sevorix-hub"
  format        = "DOCKER"

  depends_on = [google_project_service.required_apis]
}

# Cloud Build trigger created manually in console after GitHub connection
# Create at: https://console.cloud.google.com/cloud-build/triggers
# Settings:
#   - Name: sevorix-hub-deploy
#   - Event: Push to branch
#   - Source: sevorix/sevorix-watchtower (GitHub)
#   - Branch: ^main$
#   - Configuration: cloudbuild.yaml
#   - Substitutions: _REGION=us-central1

# Output values
output "cloud_run_service_url" {
  description = "URL of the Cloud Run service"
  value       = data.google_cloud_run_service.hub_service.status[0].url
}

output "database_connection_name" {
  description = "Cloud SQL connection name"
  value       = google_sql_database_instance.hub_db.connection_name
}

output "artifacts_bucket" {
  description = "GCS bucket for artifacts"
  value       = google_storage_bucket.artifacts.name
}


# Data source for Cloud Run service (deployed via Cloud Build)
data "google_cloud_run_service" "hub_service" {
  name     = "sevorix-hub"
  location = var.region

  depends_on = [google_project_service.required_apis]
}

# Public access is configured via --allow-unauthenticated in cloudbuild.yaml
# If organization policy blocks allUsers, the deployment will handle it there
