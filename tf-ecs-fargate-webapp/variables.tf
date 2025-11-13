variable "app_name" {
  description = "A name for the application, used to tag resources."
  type        = string
}

variable "docker_image" {
  description = "The full URL of the Docker image to deploy."
  type        = string
}

variable "container_port" {
  description = "The port exposed by the container."
  type        = number
}

variable "cpu" {
  description = "The number of CPU units to allocate to the container."
  type        = number
  default     = 256
}

variable "memory" {
  description = "The amount of memory (in MiB) to allocate to the container."
  type        = number
  default     = 512
}

variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
}
