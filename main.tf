terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  alias  = "default"
  region = "ap-northeast-1"
}

data "aws_caller_identity" "current" {
  provider = aws.default
}

data "aws_region" "current" {
  provider = aws.default
}

resource "aws_vpc" "default" {
  provider             = aws.default
  cidr_block           = var.cidr_block_vpc
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "internet_facing" {
  provider   = aws.default
  vpc_id     = aws_vpc.default.id
  cidr_block = var.cidr_block_vpc_subnet_internet_facing
}

resource "aws_subnet" "internal" {
  provider   = aws.default
  vpc_id     = aws_vpc.default.id
  cidr_block = var.cidr_block_vpc_subnet_internal
}

resource "aws_internet_gateway" "default" {
  provider = aws.default
  vpc_id   = aws_vpc.default.id
}

resource "aws_eip" "nat_gateway_default" {
  provider = aws.default
  domain   = "vpc"
}

resource "aws_nat_gateway" "default" {
  provider      = aws.default
  allocation_id = aws_eip.nat_gateway_default.id
  subnet_id     = aws_subnet.internet_facing.id
  depends_on    = [aws_internet_gateway.default]
}

resource "aws_route_table" "internet_facing" {
  provider = aws.default
  vpc_id   = aws_vpc.default.id
}

resource "aws_route" "internet_facing_default" {
  provider               = aws.default
  route_table_id         = aws_route_table.internet_facing.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.default.id
}

resource "aws_route_table" "internal" {
  provider = aws.default
  vpc_id   = aws_vpc.default.id
}

resource "aws_route" "internal_default" {
  provider               = aws.default
  route_table_id         = aws_route_table.internal.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.default.id
}

resource "aws_route_table_association" "internet_facing" {
  provider = aws.default
  subnet_id = aws_subnet.internet_facing.id
  route_table_id = aws_route_table.internet_facing.id
}

resource "aws_route_table_association" "internal" {
  provider = aws.default
  subnet_id = aws_subnet.internal.id
  route_table_id = aws_route_table.internal.id
}

resource "aws_vpc_endpoint" "s3" {
  provider          = aws.default
  vpc_id            = aws_vpc.default.id
  vpc_endpoint_type = "Gateway"

  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"
}

resource "aws_vpc_endpoint" "ecr" {
  provider            = aws.default
  vpc_id              = aws_vpc.default.id
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.internal.id]
  private_dns_enabled = true
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.dkr"
  security_group_ids = [aws_security_group.internal_vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "logs" {
  provider            = aws.default
  vpc_id              = aws_vpc.default.id
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.internal.id]
  private_dns_enabled = true
  service_name        = "com.amazonaws.${data.aws_region.current.name}.logs"
  security_group_ids = [aws_security_group.internal_vpc_endpoint.id]
}

resource "aws_security_group" "internal_vpc_endpoint" {
  provider = aws.default
  vpc_id   = aws_vpc.default.id
  name     = "internal-vpc-endpoint"
}

resource "aws_security_group_rule" "internal_vpc_endpoint_ingress" {
  provider          = aws.default
  security_group_id = aws_security_group.internal_vpc_endpoint.id
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = [aws_subnet.internal.cidr_block]
}

resource "aws_security_group" "internal_default" {
  provider = aws.default
  vpc_id   = aws_vpc.default.id
  name     = "internal-default"
}

resource "aws_security_group_rule" "internal_default_egress" {
  provider          = aws.default
  security_group_id = aws_security_group.internal_default.id
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_cloudwatch_log_group" "ecs_cluster_main_execute_command" {
  provider = aws.default
  name     = "/ecs/provisional-sshable-container-test/exec"
}

resource "aws_cloudwatch_log_group" "ecs_cluster_main_provisional_sshable_container_test" {
  provider = aws.default
  name     = "/ecs/provisional-sshable-container-test/provisional-sshable-container-test"
}

resource "aws_ecr_repository" "provisional_sshable_container_test" {
  provider = aws.default
  name     = var.ecs_repository_name_provisional_sshable_container_test
}

resource "aws_iam_service_linked_role" "ecs" {
  provider         = aws.default
  aws_service_name = "ecs.amazonaws.com"
}

data "aws_iam_policy_document" "assume_role_ecs_task" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}


data "aws_iam_policy_document" "ecs_task_execution_role_main_provisional_sshable_container_test" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
    ]
    resources = ["${aws_cloudwatch_log_group.ecs_cluster_main_provisional_sshable_container_test.arn}:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.ecs_cluster_main_provisional_sshable_container_test.arn}:*:log-stream:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = [aws_ecr_repository.provisional_sshable_container_test.arn]
  }
}

resource "aws_iam_role" "ecs_task_execution_role_main_provisional_sshable_container_test" {
  provider           = aws.default
  name               = "ecs-task-execution-role-provisional-sshable-container-test"
  assume_role_policy = data.aws_iam_policy_document.assume_role_ecs_task.json
}

resource "aws_iam_role_policy" "ecs_task_execution_role_main_provisional_sshable_container_test" {
  role     = aws_iam_role.ecs_task_execution_role_main_provisional_sshable_container_test.name
  policy = data.aws_iam_policy_document.ecs_task_execution_role_main_provisional_sshable_container_test.json
}

resource "aws_iam_role" "ecs_task_role_main_provisional_sshable_container_test" {
  provider           = aws.default
  name               = "ecs-task-role-provisional-sshable-container-test"
  assume_role_policy = data.aws_iam_policy_document.assume_role_ecs_task.json
}

data "aws_iam_policy_document" "ecs_task_role_main_provisional_sshable_container_test" {
  statement {
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
    ]
    resources = ["${aws_cloudwatch_log_group.ecs_cluster_main_provisional_sshable_container_test.arn}:*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:DescribeLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.ecs_cluster_main_provisional_sshable_container_test.arn}:*:log-stream:*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ecs_task_role_main_provisional_sshable_container_test" {
  role     = aws_iam_role.ecs_task_role_main_provisional_sshable_container_test.name
  provider = aws.default
  policy   = data.aws_iam_policy_document.ecs_task_role_main_provisional_sshable_container_test.json
}

resource "aws_ecs_cluster" "main" {
  provider = aws.default
  name     = var.ecs_cluster_name_main

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs_cluster_main_execute_command.name
      }
    }
  }
}

variable "cidr_block_vpc" {
  type    = string
  default = "172.16.254.0/24"
}

variable "cidr_block_vpc_subnet_internet_facing" {
  type    = string
  default = "172.16.254.128/25"
}

variable "cidr_block_vpc_subnet_internal" {
  type    = string
  default = "172.16.254.0/25"
}

variable "ecs_cluster_name_main" {
  type    = string
  default = "provisional-sshable-container-test"
}

variable "ecs_repository_name_provisional_sshable_container_test" {
  type    = string
  default = "provisional-sshable-container-test"
}
