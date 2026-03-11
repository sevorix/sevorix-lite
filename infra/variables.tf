# Variables for sevorix-hub GCP infrastructure

variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "sevorix"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "db_tier" {
  description = "Cloud SQL instance tier"
  type        = string
  default     = "db-f1-micro"
}

variable "db_availability_type" {
  description = "Cloud SQL availability type (REGIONAL for HA, ZONAL for single zone)"
  type        = string
  default     = "ZONAL"
}

variable "github_owner" {
  description = "GitHub repository owner"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "sevorix"
}
