package iac

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"gopkg.in/yaml.v3"
)

// KubernetesScanner scans Kubernetes manifests for security issues
type KubernetesScanner struct {
	config *config.Config
}

// NewKubernetesScanner creates a new Kubernetes scanner
func NewKubernetesScanner(cfg *config.Config) *KubernetesScanner {
	return &KubernetesScanner{config: cfg}
}

// IsKubernetesManifest checks if a YAML file is a Kubernetes manifest
func (s *KubernetesScanner) IsKubernetesManifest(filePath string) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	text := string(content)
	return strings.Contains(text, "apiVersion:") && strings.Contains(text, "kind:")
}

// ScanFile scans a Kubernetes manifest file (supports multi-document YAML)
func (s *KubernetesScanner) ScanFile(ctx context.Context, filePath, basePath string) []api.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	relPath, _ := filepath.Rel(basePath, filePath)
	docs, err := decodeK8sDocuments(content)
	if err != nil || len(docs) == 0 {
		return nil
	}

	var findings []api.Finding
	for i, manifest := range docs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		kind, _ := manifest["kind"].(string)
		if kind == "" {
			continue
		}

		docPath := relPath
		if len(docs) > 1 {
			docPath = fmt.Sprintf("%s#%d", relPath, i+1)
		}

		switch kind {
		case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
			findings = append(findings, s.checkPodSecurity(manifest, docPath)...)
		case "Service":
			findings = append(findings, s.checkServiceSecurity(manifest, docPath)...)
		case "Role", "ClusterRole":
			findings = append(findings, s.checkRBAC(manifest, docPath)...)
		}
	}

	return findings
}

func decodeK8sDocuments(content []byte) ([]map[string]interface{}, error) {
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
		if _, ok := doc["apiVersion"]; !ok {
			continue
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

func (s *KubernetesScanner) checkPodSecurity(manifest map[string]interface{}, relPath string) []api.Finding {
	var findings []api.Finding

	spec := s.getPodSpec(manifest)
	if spec == nil {
		return findings
	}

	podSC, _ := spec["securityContext"].(map[string]interface{})

	if hostNetwork, ok := asBool(spec["hostNetwork"]); ok && hostNetwork {
		findings = append(findings, k8sFinding("IAC-K8S-host-network", "k8s-host-network",
			"Host Network Enabled", "Pod uses host network namespace",
			api.SeverityHigh, relPath, "hostNetwork: true",
			"Remove hostNetwork or set to false"))
	}
	if hostPID, ok := asBool(spec["hostPID"]); ok && hostPID {
		findings = append(findings, k8sFinding("IAC-K8S-host-pid", "k8s-host-pid",
			"Host PID Namespace Enabled", "Pod uses host PID namespace",
			api.SeverityHigh, relPath, "hostPID: true",
			"Remove hostPID or set to false"))
	}

	for _, container := range collectContainers(spec) {
		findings = append(findings, s.checkContainer(container, podSC, relPath)...)
	}

	return findings
}

func collectContainers(spec map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		list, ok := spec[key].([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			if c, ok := item.(map[string]interface{}); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

func (s *KubernetesScanner) checkContainer(container, podSC map[string]interface{}, relPath string) []api.Finding {
	var findings []api.Finding
	name, _ := container["name"].(string)
	secContext := mergeSecurityContext(podSC, container)

	if privileged, ok := asBool(secContext["privileged"]); ok && privileged {
		findings = append(findings, k8sFinding("IAC-K8S-privileged-container", "k8s-privileged",
			"Privileged Container Detected",
			fmt.Sprintf("Container %q is running in privileged mode, which grants all capabilities", name),
			api.SeverityCritical, relPath, "privileged: true",
			"Remove privileged flag or use specific capabilities instead"))
	}

	if runAsUser, ok := asInt(secContext["runAsUser"]); ok && runAsUser == 0 {
		findings = append(findings, k8sFinding("IAC-K8S-run-as-root", "k8s-run-as-root",
			"Container Running as Root",
			fmt.Sprintf("Container %q is configured to run as root user (UID 0)", name),
			api.SeverityHigh, relPath, "runAsUser: 0",
			"Set runAsUser to a non-root UID (e.g., 1000)"))
	}

	runAsNonRoot, hasRunAsNonRoot := asBool(secContext["runAsNonRoot"])
	if !hasRunAsNonRoot || !runAsNonRoot {
		findings = append(findings, k8sFinding("IAC-K8S-missing-run-as-non-root", "k8s-run-as-non-root",
			"runAsNonRoot Not Enforced",
			fmt.Sprintf("Container %q does not enforce running as non-root user", name),
			api.SeverityMedium, relPath, "securityContext",
			"Set runAsNonRoot: true in pod or container securityContext"))
	}

	if allowPrivEsc, ok := asBool(secContext["allowPrivilegeEscalation"]); ok && allowPrivEsc {
		findings = append(findings, k8sFinding("IAC-K8S-priv-escalation", "k8s-priv-escalation",
			"Privilege Escalation Allowed",
			fmt.Sprintf("Container %q allows privilege escalation", name),
			api.SeverityHigh, relPath, "allowPrivilegeEscalation: true",
			"Set allowPrivilegeEscalation: false"))
	}

	if _, hasResources := container["resources"]; !hasResources {
		findings = append(findings, k8sFinding("IAC-K8S-no-resource-limits", "k8s-resource-limits",
			"Missing Resource Limits",
			fmt.Sprintf("Container %q does not have CPU/memory limits defined", name),
			api.SeverityLow, relPath, fmt.Sprintf("container: %s", name),
			"Define resource requests and limits"))
	}

	if image, ok := container["image"].(string); ok {
		if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
			findings = append(findings, k8sFinding("IAC-K8S-latest-tag", "k8s-latest-tag",
				"Using 'latest' Image Tag",
				"Container uses 'latest' or no tag, which can lead to unpredictable deployments",
				api.SeverityMedium, relPath, fmt.Sprintf("image: %s", image),
				"Use specific image tags or digests"))
		}
	}

	return findings
}

func mergeSecurityContext(podSC, container map[string]interface{}) map[string]interface{} {
	merged := map[string]interface{}{}
	for k, v := range podSC {
		merged[k] = v
	}
	if csc, ok := container["securityContext"].(map[string]interface{}); ok {
		for k, v := range csc {
			merged[k] = v
		}
	}
	return merged
}

func (s *KubernetesScanner) checkServiceSecurity(manifest map[string]interface{}, relPath string) []api.Finding {
	spec, ok := manifest["spec"].(map[string]interface{})
	if !ok {
		return nil
	}
	if svcType, ok := spec["type"].(string); ok && svcType == "LoadBalancer" {
		return []api.Finding{k8sFinding("IAC-K8S-loadbalancer-service", "k8s-loadbalancer",
			"LoadBalancer Service Exposes Public IP",
			"Service type LoadBalancer may expose services publicly",
			api.SeverityMedium, relPath, "type: LoadBalancer",
			"Ensure LoadBalancer has appropriate firewall rules and consider using Ingress")}
	}
	return nil
}

func (s *KubernetesScanner) checkRBAC(manifest map[string]interface{}, relPath string) []api.Finding {
	var findings []api.Finding
	rules, ok := manifest["rules"].([]interface{})
	if !ok {
		return findings
	}
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if verbs, ok := rule["verbs"].([]interface{}); ok {
			for _, v := range verbs {
				if v == "*" {
					findings = append(findings, k8sFinding("IAC-K8S-rbac-wildcard-verbs", "k8s-rbac-wildcard",
						"RBAC Wildcard Verbs",
						"RBAC rule uses wildcard (*) for verbs",
						api.SeverityHigh, relPath, "verbs: ['*']",
						"Specify exact verbs needed instead of wildcard"))
					break
				}
			}
		}
	}
	return findings
}

func (s *KubernetesScanner) getPodSpec(manifest map[string]interface{}) map[string]interface{} {
	kind, _ := manifest["kind"].(string)
	spec, _ := manifest["spec"].(map[string]interface{})
	if spec == nil {
		return nil
	}

	if kind == "Pod" {
		return spec
	}

	if kind == "CronJob" {
		jobTemplate, _ := spec["jobTemplate"].(map[string]interface{})
		jobSpec, _ := jobTemplate["spec"].(map[string]interface{})
		template, _ := jobSpec["template"].(map[string]interface{})
		podSpec, _ := template["spec"].(map[string]interface{})
		return podSpec
	}

	template, _ := spec["template"].(map[string]interface{})
	podSpec, _ := template["spec"].(map[string]interface{})
	return podSpec
}

func k8sFinding(id, ruleID, title, desc string, sev api.Severity, file, snippet, remediation string) api.Finding {
	return api.Finding{
		ID:          fmt.Sprintf("%s-%s", id, pathToken(file)),
		Type:        api.FindingTypeMisconfiguration,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Location:    api.Location{File: file, Snippet: snippet},
		Remediation: remediation,
		Scanner:     "iac",
		RuleID:      ruleID,
		Confidence:  1.0,
	}
}

func asBool(v interface{}) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "true", "yes", "1", "on":
			return true, true
		case "false", "no", "0", "off":
			return false, true
		default:
			return false, false
		}
	case int:
		return b != 0, true
	case int64:
		return b != 0, true
	case float64:
		return b != 0, true
	default:
		return false, false
	}
}

func asInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}
