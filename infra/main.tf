# Terraform configuration for sevorix-hub Azure infrastructure

terraform {
  required_version = ">= 1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # Backend configuration - update with your Azure Storage Account
  # backend "azurerm" {
  #   resource_group_name  = "sevorix-terraform-state-rg"
  #   storage_account_name = "sevorixterraformstate"
  #   container_name       = "tfstate"
  #   key                  = "sevorix-hub.tfstate"
  # }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
  subscription_id = var.subscription_id
}

data "azurerm_client_config" "current" {}

# Resource group
resource "azurerm_resource_group" "hub" {
  name     = var.resource_group_name
  location = var.location
}

# User-assigned managed identity for the Container App
resource "azurerm_user_assigned_identity" "hub" {
  name                = "${var.project_name}-identity"
  resource_group_name = azurerm_resource_group.hub.name
  location            = azurerm_resource_group.hub.location
}

# Azure Container Registry
resource "azurerm_container_registry" "hub" {
  name                = "${var.project_name}acr"
  resource_group_name = azurerm_resource_group.hub.name
  location            = azurerm_resource_group.hub.location
  sku                 = "Standard"
  admin_enabled       = false
}

# Grant the managed identity AcrPull on the registry
resource "azurerm_role_assignment" "hub_acr_pull" {
  scope                = azurerm_container_registry.hub.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.hub.principal_id
}

# Grant the GitHub Actions service principal AcrPush so CI can push images
resource "azurerm_role_assignment" "ci_acr_push" {
  scope                = azurerm_container_registry.hub.id
  role_definition_name = "AcrPush"
  principal_id         = "7b267806-f0ee-43ab-80d7-79a402d8fb0b"
}

# Storage account for artifacts (equivalent to GCS bucket)
resource "azurerm_storage_account" "hub" {
  name                     = "${var.project_name}storage"
  resource_group_name      = azurerm_resource_group.hub.name
  location                 = azurerm_resource_group.hub.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 7
    }
  }
}

# Blob container for artifacts
resource "azurerm_storage_container" "artifacts" {
  name                  = "artifacts"
  storage_account_name  = azurerm_storage_account.hub.name
  container_access_type = "private"
}

# Grant the managed identity Storage Blob Data Contributor on the storage account
resource "azurerm_role_assignment" "hub_storage_contributor" {
  scope                = azurerm_storage_account.hub.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.hub.principal_id
}

# Random passwords
resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

# PostgreSQL Flexible Server (equivalent to Cloud SQL)
resource "azurerm_postgresql_flexible_server" "hub" {
  name                   = "${var.project_name}-db"
  resource_group_name    = azurerm_resource_group.hub.name
  location               = var.db_location
  version                = "15"
  administrator_login    = "sevorix"
  administrator_password = random_password.db_password.result
  storage_mb             = var.db_storage_mb
  sku_name               = var.db_sku_name

  zone = "1"

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
}

resource "azurerm_postgresql_flexible_server_database" "hub" {
  name      = "sevorix_hub"
  server_id = azurerm_postgresql_flexible_server.hub.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# Allow the Container Apps environment to reach Postgres
# (public access with firewall; use VNet integration for stricter environments)
resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure_services" {
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.hub.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Key Vault for secrets (equivalent to GCP Secret Manager)
resource "azurerm_key_vault" "hub" {
  name                        = "${var.project_name}-kv"
  resource_group_name         = azurerm_resource_group.hub.name
  location                    = azurerm_resource_group.hub.location
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 30
  purge_protection_enabled    = true
}

# Allow the Terraform principal full admin access (for provisioning)
resource "azurerm_key_vault_access_policy" "terraform_admin" {
  key_vault_id = azurerm_key_vault.hub.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = ["Get", "List", "Set", "Delete", "Purge", "Recover"]
}

# Allow the managed identity to read secrets at runtime
resource "azurerm_key_vault_access_policy" "hub_identity" {
  key_vault_id = azurerm_key_vault.hub.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.hub.principal_id

  secret_permissions = ["Get", "List"]
}

# Secrets
resource "azurerm_key_vault_secret" "database_url" {
  name         = "database-url"
  value        = "postgresql://sevorix:${random_password.db_password.result}@${azurerm_postgresql_flexible_server.hub.fqdn}/sevorix_hub?sslmode=require"
  key_vault_id = azurerm_key_vault.hub.id

  depends_on = [azurerm_key_vault_access_policy.terraform_admin]
}

resource "azurerm_key_vault_secret" "jwt_secret" {
  name         = "jwt-secret"
  value        = random_password.jwt_secret.result
  key_vault_id = azurerm_key_vault.hub.id

  depends_on = [azurerm_key_vault_access_policy.terraform_admin]
}

# Container Apps Environment
resource "azurerm_container_app_environment" "hub" {
  name                = "${var.project_name}-env"
  resource_group_name = azurerm_resource_group.hub.name
  location            = azurerm_resource_group.hub.location
}

# Container App (equivalent to Cloud Run service)
resource "azurerm_container_app" "hub" {
  name                         = "${var.project_name}-hub"
  resource_group_name          = azurerm_resource_group.hub.name
  container_app_environment_id = azurerm_container_app_environment.hub.id
  revision_mode                = "Single"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.hub.id]
  }

  registry {
    server   = azurerm_container_registry.hub.login_server
    identity = azurerm_user_assigned_identity.hub.id
  }

  secret {
    name                = "database-url"
    key_vault_secret_id = azurerm_key_vault_secret.database_url.id
    identity            = azurerm_user_assigned_identity.hub.id
  }

  secret {
    name                = "jwt-secret"
    key_vault_secret_id = azurerm_key_vault_secret.jwt_secret.id
    identity            = azurerm_user_assigned_identity.hub.id
  }

  template {
    container {
      name   = "sevorix-hub"
      # Placeholder until CI/CD pushes the first real image to ACR
      image  = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name  = "STORAGE_BACKEND"
        value = "azure-blob"
      }

      env {
        name  = "AZURE_STORAGE_ACCOUNT"
        value = azurerm_storage_account.hub.name
      }

      env {
        name  = "AZURE_STORAGE_CONTAINER"
        value = azurerm_storage_container.artifacts.name
      }

      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }

      env {
        name        = "JWT_SECRET"
        secret_name = "jwt-secret"
      }
    }

    min_replicas = 0
    max_replicas = 3
  }

  ingress {
    external_enabled = true
    target_port      = 8080

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [
    azurerm_key_vault_access_policy.hub_identity,
    azurerm_role_assignment.hub_acr_pull,
    azurerm_role_assignment.hub_storage_contributor,
  ]
}

# Outputs
output "container_app_url" {
  description = "FQDN of the Container App (configure CNAME hub.sevorix.io -> this)"
  value       = azurerm_container_app.hub.ingress[0].fqdn
}

output "postgres_fqdn" {
  description = "PostgreSQL Flexible Server FQDN"
  value       = azurerm_postgresql_flexible_server.hub.fqdn
}

output "storage_account_name" {
  description = "Azure Storage Account name"
  value       = azurerm_storage_account.hub.name
}

output "acr_login_server" {
  description = "ACR login server (set as ACR_REGISTRY GitHub secret)"
  value       = azurerm_container_registry.hub.login_server
}
