package spacelift

import future.keywords

default allow = true

# Define the IAM policy change rule
deny[msg] {
    some change in input.changes
    change.type == "update"
    change.resource.type == "aws_iam_policy"
    not is_approved(change)
    msg := sprintf("Change to IAM policy %s requires security team approval.", [change.resource.id])
}

# Check if the security team has approved the change
is_approved(change) {
    some approval in input.metadata.approvals
    approval.role == "security_team"
    approval.status == "approved"
}
