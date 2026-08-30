package iac

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestTerraformPublicS3(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewTerraformScanner(cfg)

	dir := t.TempDir()
	content := `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`
	filePath := writeTempFile(t, dir, "test.tf", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	if len(findings) == 0 {
		t.Fatal("Expected to find public S3 bucket violation")
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "aws-s3-public-acl" {
			found = true
			if f.Severity != api.SeverityCritical {
				t.Errorf("Expected critical severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Error("Did not detect public S3 ACL")
	}
}

func TestTerraformUnencryptedRDS(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewTerraformScanner(cfg)

	dir := t.TempDir()
	content := `
resource "aws_db_instance" "default" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               ="mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  storage_encrypted    = false
}
`
	filePath := writeTempFile(t, dir, "test.tf", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "aws-rds-no-encryption" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect unencrypted RDS instance")
	}
}

func TestKubernetesPrivilegedContainer(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewKubernetesScanner(cfg)

	dir := t.TempDir()
	manifest := `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`
	filePath := writeTempFile(t, dir, "test.yaml", manifest)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	if len(findings) == 0 {
		t.Fatal("Expected to find privileged container")
	}

	found := false
	for _, f := range findings {
		if f.Title == "Privileged Container Detected" {
			found = true
			if f.Severity != api.SeverityCritical {
				t.Errorf("Expected critical severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Error("Did not detect privileged container")
	}
}

func TestKubernetesRunAsRoot(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewKubernetesScanner(cfg)

	dir := t.TempDir()
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          runAsUser: 0
`
	filePath := writeTempFile(t, dir, "deployment.yaml", manifest)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.Title == "Container Running as Root" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect container running as root")
	}
}

func TestDockerfileLatestTag(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewDockerfileScanner(cfg)

	dir := t.TempDir()
	content := `FROM nginx:latest
RUN apt-get update
`
	filePath := writeTempFile(t, dir, "Dockerfile", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "latest-tag" {
			found = true
			if f.Severity != api.SeverityMedium {
				t.Errorf("Expected medium severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Error("Did not detect 'latest' tag usage")
	}
}

func TestDockerfileMissingUser(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewDockerfileScanner(cfg)

	dir := t.TempDir()
	content := `FROM nginx:1.21
RUN apt-get update
COPY . /app
`
	filePath := writeTempFile(t, dir, "Dockerfile", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "missing-user" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect missing USER instruction")
	}
}

func TestDockerfileExposedPort(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewDockerfileScanner(cfg)

	dir := t.TempDir()
	content := `FROM nginx:1.21
EXPOSE 22
`
	filePath := writeTempFile(t, dir, "Dockerfile", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "exposed-port-22" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect exposed sensitive port (SSH)")
	}
}

func TestIaCFrameworkAndSkipRules(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "main.tf", `resource "aws_s3_bucket" "b" { acl = "public-read" }`)
	writeTempFile(t, dir, "Dockerfile", "FROM nginx:latest\n")

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			IaC: config.IaCConfig{
				Enabled:    true,
				Frameworks: []string{"dockerfile"},
				SkipRules:  []string{"latest-tag"},
				Severity:   "high",
			},
		},
	}
	result, err := NewScanner(cfg).Scan(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "aws-s3-public-acl" {
			t.Fatal("terraform framework should be disabled")
		}
		if f.RuleID == "latest-tag" {
			t.Fatal("latest-tag should be skipped")
		}
	}
}

func TestSupportsDockerfileSuffix(t *testing.T) {
	cfg := config.Default()
	s := NewScanner(cfg)
	if !s.Supports("app.dockerfile") {
		t.Fatal("expected *.dockerfile to be supported")
	}
	if !s.Supports("Dockerfile") {
		t.Fatal("expected Dockerfile to be supported")
	}
	if !s.Supports("Dockerfile.prod") {
		t.Fatal("expected Dockerfile.* to be supported")
	}
}


func TestKubernetesMultiDocAndInitContainer(t *testing.T) {
	dir := t.TempDir()
	manifest := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
data:
  x: y
---
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  securityContext:
    runAsNonRoot: true
  initContainers:
  - name: init
    image: busybox:1.36
    securityContext:
      privileged: true
  containers:
  - name: app
    image: nginx:1.25
    securityContext:
      runAsNonRoot: true
`
	filePath := writeTempFile(t, dir, "multi.yaml", manifest)
	findings := NewKubernetesScanner(&config.Config{}).ScanFile(context.Background(), filePath, dir)

	foundPriv := false
	for _, f := range findings {
		if f.RuleID == "k8s-privileged" {
			foundPriv = true
		}
	}
	if !foundPriv {
		t.Fatal("expected privileged initContainer finding")
	}
}

func TestKubernetesBoolishPrivileged(t *testing.T) {
	dir := t.TempDir()
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
  - name: app
    image: nginx:1.25
    securityContext:
      privileged: "true"
      runAsNonRoot: true
`
	filePath := writeTempFile(t, dir, "boolish.yaml", manifest)
	findings := NewKubernetesScanner(&config.Config{}).ScanFile(context.Background(), filePath, dir)
	for _, f := range findings {
		if f.RuleID == "k8s-privileged" {
			return
		}
	}
	t.Fatal("expected privileged finding when privileged: \"true\" (string)")
}

func TestDockerfileFinalStageUser(t *testing.T) {
	dir := t.TempDir()

	// Explicit USER in final stage should clear missing-user
	content2 := `FROM alpine:3.19 AS build
RUN echo hi
FROM alpine:3.19
RUN adduser -D app
USER app
`
	filePath2 := writeTempFile(t, dir, "Dockerfile.user", content2)
	findings := NewDockerfileScanner(&config.Config{}).ScanFile(context.Background(), filePath2, dir)
	for _, f := range findings {
		if f.RuleID == "missing-user" {
			t.Fatal("final stage USER app should satisfy missing-user")
		}
	}

	// USER only in build stage should still flag
	content3 := `FROM alpine:3.19 AS build
USER nobody
FROM alpine:3.19
CMD ["/bin/sh"]

# trailing blank/comment should not hide file-level checks
`
	filePath3 := writeTempFile(t, dir, "Dockerfile.builduser", content3)
	findings = NewDockerfileScanner(&config.Config{}).ScanFile(context.Background(), filePath3, dir)
	found := false
	for _, f := range findings {
		if f.RuleID == "missing-user" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected missing-user when only build stage sets USER")
	}
}

func TestTerraformPerResourceAndMultilineSG(t *testing.T) {
	dir := t.TempDir()
	content := `
resource "aws_s3_bucket" "safe" {
  bucket = "safe"
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "safe" {
  bucket = aws_s3_bucket.safe.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "safe" {
  bucket = aws_s3_bucket.safe.id
  block_public_acls = true
}

resource "aws_s3_bucket" "bad" {
  bucket = "bad"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	filePath := writeTempFile(t, dir, "main.tf", content)
	findings := NewTerraformScanner(&config.Config{}).ScanFile(context.Background(), filePath, dir)

	var publicACL, noEnc, sshOpen bool
	for _, f := range findings {
		switch f.RuleID {
		case "aws-s3-public-acl":
			if strings.Contains(f.Description, "bad") {
				publicACL = true
			}
			if strings.Contains(f.Description, "safe") {
				t.Fatal("safe bucket should not be public")
			}
		case "aws-s3-no-encryption":
			if strings.Contains(f.Description, "safe") {
				t.Fatal("safe bucket should not lack encryption")
			}
			if strings.Contains(f.Description, "bad") {
				noEnc = true
			}
		case "aws-sg-ssh-open":
			sshOpen = true
		}
	}
	if !publicACL || !noEnc || !sshOpen {
		t.Fatalf("expected per-resource findings, publicACL=%v noEnc=%v sshOpen=%v findings=%+v", publicACL, noEnc, sshOpen, findings)
	}
}

