package tfparse

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	src := `
variable "env" {}

resource "aws_security_group" "web" {
  name = "web-${var.env}"
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 443
  }
  tags = { Team = "core" }
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket = aws_s3_bucket.logs[0].id
  policy = <<EOT
{"Version": "2012-10-17"}
EOT
  ratio  = 0.5
}
`
	got := Parse([]byte(src), "main.tf")
	if len(got) != 2 {
		t.Fatalf("want 2 resources, got %d", len(got))
	}
	sg, pab := got[0], got[1]
	if sg.Type != "aws_security_group" || sg.Name != "web" || sg.Line != 4 {
		t.Fatalf("header: %+v", sg)
	}
	if sg.Attrs["name"] != `"web-${var.env}"` {
		t.Errorf("interpolation keeps source: %#v", sg.Attrs["name"])
	}
	ingress, ok := sg.Attrs["ingress"].([]any)
	if !ok || len(ingress) != 2 {
		t.Fatalf("repeated blocks become a list: %#v", sg.Attrs["ingress"])
	}
	first := ingress[0].(map[string]any)
	if first["from_port"] != 22 || !reflect.DeepEqual(first["cidr_blocks"], []any{"0.0.0.0/0"}) {
		t.Errorf("first ingress: %#v", first)
	}
	if !reflect.DeepEqual(sg.Attrs["tags"], map[string]any{"Team": "core"}) {
		t.Errorf("tags: %#v", sg.Attrs["tags"])
	}
	if pab.Attrs["bucket"] != (Ref{Type: "aws_s3_bucket", Name: "logs"}) {
		t.Errorf("indexed ref: %#v", pab.Attrs["bucket"])
	}
	if pab.Attrs["policy"] != "{\"Version\": \"2012-10-17\"}\n" || pab.Attrs["ratio"] != 0.5 {
		t.Errorf("heredoc/float: %#v %#v", pab.Attrs["policy"], pab.Attrs["ratio"])
	}

	resolved := Resolve(pab.Attrs, func(r Ref) any { return r.Name })
	if resolved["bucket"] != "logs" {
		t.Errorf("Resolve: %#v", resolved["bucket"])
	}
}

func TestParseToleratesSyntaxErrors(t *testing.T) {
	src := `
resource "aws_s3_bucket" "ok" {
  acl = "private"
}

resource "aws_s3_bucket" "broken" {
  acl = 
`
	got := Parse([]byte(src), "main.tf")
	if len(got) == 0 || got[0].Name != "ok" || got[0].Attrs["acl"] != "private" {
		t.Fatalf("want the valid resource recovered, got %+v", got)
	}
}
