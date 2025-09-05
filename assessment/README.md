# Wazuh Security Monitoring Infrastructure

This repository contains Terraform code and scripts to deploy a comprehensive security monitoring infrastructure using Wazuh on AWS. The solution follows security best practices and AWS Well-Architected Framework guidelines.

## 🏗️ Architecture Overview

The infrastructure includes:

- **VPC** with public and private subnets across 2 availability zones
- **NAT Gateway** for secure outbound internet access from private subnets
- **EC2 instance** (t3.xlarge) in private subnet running Wazuh via Docker
- **Security Groups** with minimal required access
- **IAM roles** with least privilege principles
- **S3 buckets** for state management and data backup
- **CloudWatch** integration for logging and monitoring
- **VPC Flow Logs** for network security monitoring

## 📋 Prerequisites

Before deploying, ensure you have:

- AWS CLI configured with appropriate permissions