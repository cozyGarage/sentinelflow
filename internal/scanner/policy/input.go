package policy

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"github.com/cozygarage/sentinelflow/internal/scanner/tfparse"
	"gopkg.in/yaml.v3"
)

type policyInput struct {
	Data     map[string]interface{}
	FilePath string
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".terraform": true,
	"__pycache__": true, ".venv": true, "dist": true, "build": true, ".cache": true,
	// Go convention for local test assets
	"testdata": true,
}

// walkFiles is the fallback file list when the engine did not provide one.
func walkFiles(root string) ([]string, error) {
	root = filepath.Clean(root)
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if filepath.Clean(path) != root && (skipDirs[info.Name()] || filter.IsBundledSampleDir(root, path)) {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

func collectPolicyInputs(ctx context.Context, root string, files []string) ([]policyInput, error) {
	inputs, err := collectKubernetesInputs(ctx, root, files)
	if err != nil {
		return nil, err
	}

	tfInput, err := collectTerraformInput(ctx, root, files)
	if err != nil {
		return nil, err
	}
	if tfInput != nil {
		inputs = append(inputs, *tfInput)
	}

	return inputs, nil
}

func collectKubernetesInputs(ctx context.Context, root string, files []string) ([]policyInput, error) {
	var inputs []policyInput
	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if !strings.Contains(string(content), "apiVersion:") {
			continue
		}

		rel, _ := filepath.Rel(root, path)
		docs, err := decodeYAMLDocuments(content)
		if err != nil {
			continue
		}

		for i, doc := range docs {
			if len(doc) == 0 {
				continue
			}
			if _, ok := doc["apiVersion"]; !ok {
				continue
			}
			doc["_file"] = rel
			filePath := rel
			if len(docs) > 1 {
				filePath = rel + "#" + strconv.Itoa(i+1)
			}
			inputs = append(inputs, policyInput{Data: doc, FilePath: filePath})
		}
	}
	return inputs, nil
}

func decodeYAMLDocuments(content []byte) ([]map[string]interface{}, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var docs []map[string]interface{}
	for {
		var doc map[string]interface{}
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if doc == nil {
			continue
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

func collectTerraformInput(ctx context.Context, root string, files []string) (*policyInput, error) {
	var changes []map[string]interface{}
	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if filepath.Ext(path) != ".tf" {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, path)
		changes = append(changes, parseTerraformResources(string(content), rel)...)
	}

	if len(changes) == 0 {
		return nil, nil
	}

	return &policyInput{
		Data: map[string]interface{}{
			"resource_changes": changes,
		},
		FilePath: ".", // spans every .tf file; violations carry their own resource
	}, nil
}

func parseTerraformResources(content, file string) []map[string]interface{} {
	var changes []map[string]interface{}
	for _, r := range tfparse.Parse([]byte(content), file) {
		changes = append(changes, map[string]interface{}{
			"type": r.Type,
			"name": r.Name,
			"file": file,
			"change": map[string]interface{}{
				// Policies compare references by resource name: aws_s3_bucket.example.id -> "example".
				"after": tfparse.Resolve(r.Attrs, func(ref tfparse.Ref) any { return ref.Name }),
			},
		})
	}
	return changes
}
