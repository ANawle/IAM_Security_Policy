resource "spacelift_policy" "iam_policy_approval" {
  name = "require_security_approval_for_iam_policy"
  type = "APPROVAL"
  body = file("iam_policy_approval.rego")
  
  labels = ["security", "iam"]
}

package spacelift

import future.keywords

default deny[msg] = false

# Define the IAM policy change rule
deny[msg] {
    some change in input.changes
    change.type == "update"
    change.resource.type == "aws_iam_policy"
    not is_approved(change)
    msg := sprintf("IAM policy change (%s) blocked: Security team approval required.", [change.resource.id]), [change.resource.id])
}

# Check if the security team has approved the change
is_approved(change) {
    some approval in input.metadata.approvals
    approval.role == "security_team"
    approval.status == "approved"
}
