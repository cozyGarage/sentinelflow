# Policy-as-Code with Rego

SentinelFlow lets you define custom security requirements using the **Rego** policy language and the embedded Open Policy Agent (OPA) engine.

## What is OPA/Rego?

Open Policy Agent (OPA) is a general-purpose policy engine. Rego is its declarative language for expressing rules like "deny if this resource is misconfigured."

## Built-in policies

Shipped and embedded in the binary (`policies.builtin`):

- `no-public-s3-buckets` — S3 public ACL and access-block checks
- `no-privileged-containers` — Kubernetes privileged/root containers
- `require-https` — TLS on ingress and endpoints
- `enforce-encryption` — Encryption at rest for cloud storage

They load from the embedded registry even when the scan target has no local `policies/` directory. Project `.rego` files with the same name override the embedded copy.

List them:

```bash
sentinelflow policy list
```

## Anatomy of a policy

Kubernetes policies receive parsed manifest YAML as `input`:

```rego
package sentinelflow.kubernetes

deny_privileged[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}
```

Terraform policies receive `input.resource_changes[]` built from `.tf` files:

```rego
package sentinelflow.s3

deny_public_buckets[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
    msg := sprintf("S3 bucket '%s' has public-read ACL", [resource.name])
}
```

## Authoring custom policies

1. Create a `.rego` file in `policies/` or `.sentinelflow/policies/`.
2. Use the `sentinelflow.*` package namespace.
3. Define rules that produce violation messages (strings or `{msg, resource}` objects).
4. Add `# severity: critical|high|medium|low` in METADATA comments for finding severity.
5. Policies use Rego v0 syntax by default. To write v1 syntax (`deny contains msg if { … }`), add `import rego.v1` to the policy.

Generate a starter template:

```bash
sentinelflow policy generate my-rule
```

## Validate and test

```bash
# Syntax check
sentinelflow policy validate policies/my-rule.rego

# Evaluate against sample input (positional args: policy file, then input JSON)
sentinelflow policy test policies/my-rule.rego test/fixtures/policy/k8s-privileged-pod.json
```

The CI **Policy Validation** job runs `policy validate` on all shipped policies.

## Configuration

```yaml
policies:
  enabled: true
  files:
    - policies/*.rego
    - .sentinelflow/policies/*.rego
```

Enable policy failure gates:

```yaml
fail_on:
  policy_violations: true
```

## Best practices

- One concern per policy file for easier testing and ownership.
- Use METADATA comments for title and severity.
- Keep input shapes aligned with how SentinelFlow collects K8s YAML and Terraform resources.
- Test policies with `policy test` before enabling in CI.
