# Variables for sevorix-hub Azure infrastructure

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = "sevorix-hub-rg"
}

variable "location" {
  description = "Azure region for all resources except PostgreSQL"
  type        = string
  default     = "swedencentral"
}

variable "db_location" {
  description = "Azure region for PostgreSQL Flexible Server (denmarkeast is the only region with B-family capacity on this subscription)"
  type        = string
  default     = "denmarkeast"
}

variable "project_name" {
  description = "Short project name used as a prefix for resource names (lowercase, no hyphens for storage/ACR)"
  type        = string
  default     = "sevorixhub"
}

variable "db_sku_name" {
  description = "PostgreSQL Flexible Server SKU"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "db_storage_mb" {
  description = "PostgreSQL storage size in MB"
  type        = number
  default     = 32768
}
