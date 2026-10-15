// Package tfparse extracts Terraform resource blocks with a real HCL parser.
// Shared by the IaC rules and the OPA policy input so both see the same data.
package tfparse

import (
	"math/big"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Ref is a reference to another resource, e.g. aws_s3_bucket.logs.id -> {aws_s3_bucket, logs}.
type Ref struct {
	Type string
	Name string
}

// Resource is one `resource "type" "name" { ... }` block.
type Resource struct {
	Type string
	Name string
	Line int    // line of the `resource` keyword
	Body string // raw source between the braces
	// Attrs maps attribute names to bool, string, int, float64, nil, []any,
	// Ref, or map[string]any for a nested block ([]any of maps when repeated).
	// Expressions that are neither literals nor resource refs keep their source text.
	Attrs map[string]any
}

// Parse returns the resource blocks in src. Syntax errors are tolerated:
// whatever HCL could recover is returned, matching scanners' best-effort contract.
func Parse(src []byte, filename string) []Resource {
	file, _ := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if file == nil {
		return nil
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil
	}
	var out []Resource
	for _, b := range body.Blocks {
		if b.Type != "resource" || len(b.Labels) != 2 {
			continue
		}
		out = append(out, Resource{
			Type:  b.Labels[0],
			Name:  b.Labels[1],
			Line:  b.TypeRange.Start.Line,
			Body:  slice(src, b.OpenBraceRange.End.Byte, b.CloseBraceRange.Start.Byte),
			Attrs: attrs(b.Body, src),
		})
	}
	return out
}

func attrs(body *hclsyntax.Body, src []byte) map[string]any {
	out := make(map[string]any, len(body.Attributes)+len(body.Blocks))
	for name, a := range body.Attributes {
		out[name] = value(a.Expr, src)
	}
	for _, b := range body.Blocks {
		nested := attrs(b.Body, src)
		switch cur := out[b.Type].(type) {
		case nil:
			out[b.Type] = nested
		case []any:
			out[b.Type] = append(cur, nested)
		default:
			out[b.Type] = []any{cur, nested}
		}
	}
	return out
}

func value(expr hclsyntax.Expression, src []byte) any {
	switch e := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		list := make([]any, 0, len(e.Exprs))
		for _, el := range e.Exprs {
			list = append(list, value(el, src))
		}
		return list
	case *hclsyntax.ScopeTraversalExpr:
		if ref, ok := resourceRef(e.Traversal); ok {
			return ref
		}
	case *hclsyntax.TemplateWrapExpr: // "${aws_s3_bucket.x.id}"
		return value(e.Wrapped, src)
	}
	if v, diags := expr.Value(nil); !diags.HasErrors() {
		return fromCty(v)
	}
	return strings.TrimSpace(slice(src, expr.Range().Start.Byte, expr.Range().End.Byte))
}

// resourceRef recognises type.name[...].attr traversals; var., local., data., module. etc. are not resources.
func resourceRef(t hcl.Traversal) (Ref, bool) {
	if len(t) < 2 {
		return Ref{}, false
	}
	root := t.RootName()
	switch root {
	case "var", "local", "data", "module", "each", "count", "path", "self", "terraform":
		return Ref{}, false
	}
	attr, ok := t[1].(hcl.TraverseAttr)
	if !ok {
		return Ref{}, false
	}
	return Ref{Type: root, Name: attr.Name}, true
}

func fromCty(v cty.Value) any {
	if v.IsNull() || !v.IsKnown() {
		return nil
	}
	t := v.Type()
	switch {
	case t == cty.Bool:
		return v.True()
	case t == cty.String:
		return v.AsString()
	case t == cty.Number:
		f := v.AsBigFloat()
		if f.IsInt() {
			if i, acc := f.Int64(); acc == big.Exact {
				return int(i)
			}
		}
		n, _ := f.Float64()
		return n
	case t.IsListType() || t.IsTupleType() || t.IsSetType():
		var list []any
		for it := v.ElementIterator(); it.Next(); {
			_, el := it.Element()
			list = append(list, fromCty(el))
		}
		if list == nil {
			list = []any{}
		}
		return list
	case t.IsMapType() || t.IsObjectType():
		m := map[string]any{}
		for it := v.ElementIterator(); it.Next(); {
			k, el := it.Element()
			m[k.AsString()] = fromCty(el)
		}
		return m
	}
	return nil
}

// Resolve returns a copy of attrs with every Ref replaced by fn(ref).
func Resolve(attrs map[string]any, fn func(Ref) any) map[string]any {
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[k] = resolveValue(v, fn)
	}
	return out
}

func resolveValue(v any, fn func(Ref) any) any {
	switch t := v.(type) {
	case Ref:
		return fn(t)
	case map[string]any:
		return Resolve(t, fn)
	case []any:
		out := make([]any, len(t))
		for i, el := range t {
			out[i] = resolveValue(el, fn)
		}
		return out
	}
	return v
}

func slice(src []byte, start, end int) string {
	if start < 0 || end > len(src) || start > end {
		return ""
	}
	return string(src[start:end])
}
