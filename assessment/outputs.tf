# outputs.tf - Terraform Outputs

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

output "nat_gateway_id" {
  description = "ID of the NAT Gateway"
  value       = aws_nat_gateway.main.id
}

output "nat_gateway_public_ip" {
  description = "Public IP of the NAT Gateway"
  value       = aws_eip.nat.public_ip
}

output "wazuh_instance_id" {
  description = "ID of the Wazuh EC2 instance"
  value       = aws_instance.wazuh.id
}

output "wazuh_instance_private_ip" {
  description = "Private IP address of the Wazuh instance"
  value       = aws_instance.wazuh.private_ip
}

output "wazuh_security_group_id" {
  description = "ID of the Wazuh security group"
  value       = aws_security_group.wazuh_instance.id
}

output "terraform_state_bucket" {
  description = "Name of the S3 bucket for Terraform state"
  value       = aws_s3_bucket.terraform_state.bucket
}

output "wazuh_data_bucket" {
  description = "Name of the S3 bucket for Wazuh data"
  value       = aws_s3_bucket.wazuh_data.bucket
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Wazuh logs"
  value       = aws_cloudwatch_log_group.wazuh_logs.name
}

output "iam_role_arn" {
  description = "ARN of the IAM role for the EC2 instance"
  value       = aws_iam_role.ec2_ssm_role.arn
}

output "ssm_session_manager_url" {
  description = "URL to access the instance via Session Manager"
  value       = "https://${var.aws_region}.console.aws.amazon.com/systems-manager/session-manager/sessions"
}

output "wazuh_dashboard_url" {
  description = "URL to access Wazuh dashboard (after setup)"
  value       = "https://${aws_instance.wazuh.private_ip}"
  sensitive   = false
}

output "setup_commands" {
  description = "Commands to run after Terraform deployment"
  value = [
    "1. Connect to instance via Session Manager:",
    "   aws ssm start-session --target ${aws_instance.wazuh.id}",
    "",
    "2. Check setup progress:",
    "   sudo tail -f /var/log/setup.log",
    "",
    "3. Access Wazuh dashboard:",
    "   https://${aws_instance.wazuh.private_ip}",
    "   Default credentials: admin/SecretPassword",
    "",
    "4. Check Docker status:",
    "   sudo docker ps",
    "",
    "5. View Wazuh logs:",
    "   sudo docker logs wazuh-manager"
  ]
}