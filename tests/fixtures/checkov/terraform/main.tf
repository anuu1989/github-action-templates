# Checkov custom-check scenarios. Each resource is a pass_* or fail_* scenario; the exact expected
# result per check lives in tests/fixtures/checkov/expected.json. Not meant to be applied.

# --- CKV_ORG_1 instance family / CKV2_ORG_10 SG attached ---------------------------------------
resource "aws_security_group" "pass_attached" {
  name = "attached"
}

resource "aws_security_group" "fail_unattached" {
  name = "orphan"
}

resource "aws_instance" "pass_instance_family" {
  ami                    = "ami-12345678"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.pass_attached.id]
}

resource "aws_instance" "fail_instance_family" {
  ami           = "ami-12345678"
  instance_type = "p4d.24xlarge"
}

# --- CKV_ORG_2 Lambda runtime / CKV2_ORG_7 Lambda log group ------------------------------------
resource "aws_lambda_function" "pass_runtime" {
  function_name = "pass-runtime"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "app.zip"
}

resource "aws_cloudwatch_log_group" "pass_lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.pass_runtime.function_name}"
  retention_in_days = 90
}

resource "aws_lambda_function" "fail_runtime" {
  function_name = "fail-runtime"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.8"
  handler       = "app.handler"
  filename      = "app.zip"
}

# --- CKV_ORG_3 IAM wildcards ------------------------------------------------------------------
resource "aws_iam_policy" "pass_scoped" {
  name = "scoped"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::acme-data/*" }]
  })
}

resource "aws_iam_policy" "fail_admin" {
  name = "admin"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_role_policy" "fail_iam_star" {
  name   = "iam-star"
  role   = "app"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:*\"],\"Resource\":\"*\"}]}"
}

# --- CKV_ORG_4 HTTP listeners -----------------------------------------------------------------
resource "aws_lb_listener" "pass_http_redirect" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/x/1"
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "fail_http_forward" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/x/1"
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/x/1"
  }
}

# --- CKV_ORG_5 ECR ------------------------------------------------------------------------------
resource "aws_ecr_repository" "pass_ecr" {
  name                 = "pass"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "fail_ecr" {
  name                 = "fail"
  image_tag_mutability = "MUTABLE"
}

# --- CKV_ORG_6 log retention -----------------------------------------------------------------
resource "aws_cloudwatch_log_group" "fail_no_retention" {
  name = "/app/forever"
}

# --- CKV2_ORG_1 tags / CKV2_ORG_2 public access block / CKV2_ORG_11 SSE-KMS ---------------------
resource "aws_s3_bucket" "pass_bucket" {
  bucket = "acme-pass-bucket"
  tags = {
    Owner              = "data"
    DataClassification = "internal"
  }
}

resource "aws_s3_bucket_public_access_block" "pass_bucket" {
  bucket                  = aws_s3_bucket.pass_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pass_bucket" {
  bucket = aws_s3_bucket.pass_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pass_rotation.arn
    }
  }
}

resource "aws_s3_bucket" "fail_bucket" {
  bucket = "acme-fail-bucket"
  tags = {
    DataClassification = "top-secret"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "fail_bucket" {
  bucket = aws_s3_bucket.fail_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- CKV2_ORG_3 KMS rotation ----------------------------------------------------------------
resource "aws_kms_key" "pass_rotation" {
  description         = "rotating"
  enable_key_rotation = true
}

resource "aws_kms_key" "pass_asymmetric" {
  description              = "signing"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "fail_no_rotation" {
  description = "static"
}

# --- CKV2_ORG_4 DynamoDB PITR -----------------------------------------------------------------
resource "aws_dynamodb_table" "pass_pitr" {
  name         = "pass"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_dynamodb_table" "fail_pitr" {
  name         = "fail"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
}

# --- CKV2_ORG_5 EKS endpoint ------------------------------------------------------------------
resource "aws_eks_cluster" "pass_private_endpoint" {
  name     = "private"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  vpc_config {
    subnet_ids              = ["subnet-1", "subnet-2"]
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}

resource "aws_eks_cluster" "pass_restricted_endpoint" {
  name     = "restricted"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  vpc_config {
    subnet_ids          = ["subnet-1", "subnet-2"]
    public_access_cidrs = ["203.0.113.0/24"]
  }
}

resource "aws_eks_cluster" "fail_open_endpoint" {
  name     = "open"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  vpc_config {
    subnet_ids = ["subnet-1", "subnet-2"]
  }
}

# --- CKV2_ORG_6 RDS subnet group ------------------------------------------------------------
resource "aws_db_subnet_group" "pass_subnets" {
  name       = "private"
  subnet_ids = ["subnet-1", "subnet-2"]
}

resource "aws_db_instance" "pass_rds" {
  identifier           = "pass"
  engine               = "postgres"
  instance_class       = "db.t4g.micro"
  allocated_storage    = 20
  db_subnet_group_name = aws_db_subnet_group.pass_subnets.name
}

resource "aws_db_instance" "fail_rds" {
  identifier        = "fail"
  engine            = "postgres"
  instance_class    = "db.t4g.micro"
  allocated_storage = 20
}

# --- CKV2_ORG_8 ALB + WAF -------------------------------------------------------------------
resource "aws_lb" "pass_internal_alb" {
  name     = "internal"
  internal = true
}

resource "aws_lb" "pass_nlb" {
  name               = "nlb"
  load_balancer_type = "network"
}

resource "aws_lb" "pass_alb_with_waf" {
  name = "with-waf"
}

resource "aws_wafv2_web_acl_association" "pass_alb_with_waf" {
  resource_arn = aws_lb.pass_alb_with_waf.arn
  web_acl_arn  = "arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/x/1"
}

resource "aws_lb" "fail_public_alb" {
  name = "public"
}

# --- CKV2_ORG_9 SQS DLQ ---------------------------------------------------------------------
resource "aws_sqs_queue" "pass_orders_dlq" {
  name = "orders-dlq"
}

resource "aws_sqs_queue" "pass_orders" {
  name = "orders"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.pass_orders_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue" "fail_no_dlq" {
  name = "events"
}
