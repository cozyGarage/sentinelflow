package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestBuiltinPoliciesLoadWithoutLocalFiles(t *testing.T) {
	root := t.TempDir()

	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
`
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(&config.Config{
		Policies: config.PoliciesConfig{
			Enabled: true,
			Builtin: []string{"no-privileged-containers"},
			Files:   nil,
		},
	})
	result, err := scanner.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected built-in policy to produce findings without local policies/")
	}
}

func TestBuiltinPoliciesCanBeDisabled(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(`apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      image: nginx
      securityContext: {privileged: true}
`), 0644)

	scanner := NewScanner(&config.Config{
		Policies: config.PoliciesConfig{
			Enabled: true,
			Builtin: []string{},
			Files:   nil,
		},
	})
	result, err := scanner.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings with builtins disabled, got %d", len(result.Findings))
	}
}

func TestCollectKubernetesMultiDoc(t *testing.T) {
	root := t.TempDir()
	content := `apiVersion: v1
kind: Pod
metadata:
  name: one
spec:
  containers:
    - name: a
      image: nginx
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
spec:
  rules:
    - host: example.com
`
	if err := os.WriteFile(filepath.Join(root, "multi.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := walkFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := collectKubernetesInputs(context.Background(), root, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(inputs))
	}
}

func TestParseTerraformResourceRefsAndLists(t *testing.T) {
	content := `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
	changes := parseTerraformResources(content, "main.tf")
	if len(changes) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(changes))
	}

	var block map[string]interface{}
	var sg map[string]interface{}
	for _, c := range changes {
		switch c["type"] {
		case "aws_s3_bucket_public_access_block":
			block = c["change"].(map[string]interface{})["after"].(map[string]interface{})
		case "aws_security_group":
			sg = c["change"].(map[string]interface{})["after"].(map[string]interface{})
		}
	}

	if block["bucket"] != "example" {
		t.Fatalf("expected bucket ref resolved to example, got %#v", block["bucket"])
	}
	ingress, ok := sg["ingress"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested ingress block, got %#v", sg["ingress"])
	}
	cidrs, ok := ingress["cidr_blocks"].([]interface{})
	if !ok || len(cidrs) != 1 || cidrs[0] != "0.0.0.0/0" {
		t.Fatalf("expected cidr list, got %#v", ingress["cidr_blocks"])
	}
}

func TestBuiltinS3PolicyWithResolvedRefs(t *testing.T) {
	root := t.TempDir()
	tf := `
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte(tf), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(&config.Config{
		Policies: config.PoliciesConfig{
			Enabled: true,
			Builtin: []string{"no-public-s3-buckets", "enforce-encryption"},
		},
	})
	result, err := scanner.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range result.Findings {
		if strings.Contains(f.Description, "missing public access block") ||
			strings.Contains(f.Description, "does not have encryption") {
			t.Fatalf("unexpected finding for secured bucket: %+v", f)
		}
		if f.Type != api.FindingTypePolicyViolation {
			continue
		}
	}
}
