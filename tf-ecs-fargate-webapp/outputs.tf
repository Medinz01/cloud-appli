output "app_url" {
  description = "The public URL of the application load balancer."
  value       = "http://${aws_lb.main.dns_name}"
}
