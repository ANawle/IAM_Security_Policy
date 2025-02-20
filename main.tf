terraform {
  required_providers {
    spacelift = {
      source  = "spacelift-io/spacelift"
      version = "~> 1.0"  # Use the latest version
    }
  }
}

provider "spacelift" {
  # Spacelift API credentials (configure via environment variables)
}

resource "spacelift_policy" "iam_policy_approval" {
  name = "require_security_approval_for_iam_policy1"
  type = "PLAN"
  body = file("iam_policy_approval.rego")
}

# Attach policy to a specific stack
resource "spacelift_policy_attachment" "iam_policy_attachment" {
  stack_id  = "avinash_prompt_3"  # Replace with the actual stack ID
  policy_id = spacelift_policy.iam_policy_approval.id
}
