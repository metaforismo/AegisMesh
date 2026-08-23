// Guarded contract smoke test for the Helm chart in this directory.
//
// Shells out to `helm template` (offline, no cluster) and verifies the chart
// keeps rendering what this repository promises: exactly one
// ConfigMap/Deployment/Service, a dedicated token-free ServiceAccount (or a
// named external one), decoy-only exposure, hardened pod/container
// contexts, resource bounds, and a checksum annotation bound to the rendered
// mesh.yaml. A smoke check, not a second Kubernetes validator; deep config
// checking stays in internal/config.
//
// Hermetic by default (`go test ./...` skips it); run via `make helm-contract`.
// Missing helm or unexpected helm failures are infrastructure problems.
package aegismesh_test

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	guardEnv    = "AEGISMESH_HELM_CONTRACT_TEST"
	releaseName = "aegismesh-contract"
	adminListen = "127.0.0.1:9110" // validated loopback default (internal/config)
)

var chartDir = func() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("helm contract test: cannot resolve chart directory")
	}
	return filepath.Dir(file)
}()

type meshView struct {
	APIVersion string `yaml:"api_version"`
	Admin      struct {
		Listen string `yaml:"listen"`
	} `yaml:"admin"`
	Sensors []struct {
		Listen string `yaml:"listen"`
	} `yaml:"sensors"`
}

// probeTiming pins one kubelet exec probe's rendered scheduling knobs.
type probeTiming struct {
	initialDelaySeconds int
	periodSeconds       int
	timeoutSeconds      int
	failureThreshold    int
}

var (
	defaultLiveness  = probeTiming{initialDelaySeconds: 20, periodSeconds: 30, timeoutSeconds: 5, failureThreshold: 3}
	defaultReadiness = probeTiming{initialDelaySeconds: 5, periodSeconds: 10, timeoutSeconds: 3, failureThreshold: 3}
)

// probePair carries the expected liveness/readiness timing for a scenario.
type probePair struct {
	live  probeTiming
	ready probeTiming
}

type scenario struct {
	name       string
	valuesFile string
	wantType   string
	wantNetPol bool
	// Empty pdbKey asserts no PodDisruptionBudget renders; otherwise it
	// names the single threshold expected together with its value.
	pdbKey   string
	pdbValue any
	// wantSAs is the exact rendered ServiceAccount count (0 selects the
	// external-account mode); wantPodSA is the required Deployment
	// serviceAccountName in both modes.
	wantSAs   int
	wantPodSA string
	// wantProbes nil asserts NO liveness/readiness probe may render;
	// otherwise both must render with exactly this timing.
	wantProbes *probePair
}

func TestHelmChartContract(t *testing.T) {
	if os.Getenv(guardEnv) != "1" {
		t.Skipf("skipped: hermetic by default; set %s=1 (make helm-contract)", guardEnv)
	}
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Fatalf("INFRASTRUCTURE: helm binary not found in PATH (%v); install helm v4.x", err)
	}

	// Scratch lives under gitignored bin/ so aborted runs never dirty the tree.
	root := filepath.Clean(filepath.Join(chartDir, "..", "..", ".."))
	scratch := filepath.Join(root, "bin", "helm-contract")
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatalf("INFRASTRUCTURE: cannot reset scratch dir %s: %v", scratch, err)
	}
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		t.Fatalf("INFRASTRUCTURE: cannot create scratch dir %s: %v", scratch, err)
	}
	t.Cleanup(func() { os.RemoveAll(scratch) })

	files := map[string]string{
		// Meaningful overrides: 1) wider exposure model with the ingress
		// policy deliberately disabled (must render no NetworkPolicy) and
		// the external-account mode selected via a fixed pre-provisioned
		// ServiceAccount name; 2) immutable pin, resource bounds, and an
		// explicit PDB opt-in exercising the non-default threshold
		// (minAvailable).
		"nodeport.yaml": `service:
  type: NodePort
  ports:
    - {name: http, port: 8081, targetPort: 8081, protocol: TCP, nodePort: 30081}
    - {name: tcp, port: 6399, targetPort: 6399, protocol: TCP, nodePort: 30639}
networkPolicy:
  enabled: false
serviceAccount:
  create: false
  name: aegismesh-external-sa
`,
		"pinned.yaml": `image: {tag: "1.2.3", pullPolicy: Always}
resources:
  limits: {memory: 512Mi}
pdb:
  enabled: true
  maxUnavailable: null
  minAvailable: 1
probes:
  liveness: {initialDelaySeconds: 30, periodSeconds: 45, timeoutSeconds: 7, failureThreshold: 6}
  readiness: {initialDelaySeconds: 1, periodSeconds: 4, timeoutSeconds: 2, failureThreshold: 2}
`,
		"empty-sensors.yaml": "meshConfig:\n  sensors: []\n",
		"probes-off.yaml":    "probes:\n  enabled: false\n",
		"ssh-sensor.yaml": `meshConfig:
  sensors:
    - id: ssh-decoy
      kind: ssh
      listen: "0.0.0.0:2222"
      ssh:
        server_version: SSH-2.0-AegisMesh
        handshake_timeout_seconds: 10
        max_session_seconds: 30
        max_auth_attempts: 3
service:
  ports:
    - {name: ssh, port: 2222, targetPort: 2222, protocol: TCP}
`,
	}
	for name, content := range files {
		path := filepath.Join(scratch, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("INFRASTRUCTURE: cannot write override %s: %v", path, err)
		}
	}

	scenarios := []scenario{
		{name: "defaults", wantType: "ClusterIP", wantNetPol: true,
			wantSAs: 1, wantPodSA: releaseName,
			wantProbes: &probePair{live: defaultLiveness, ready: defaultReadiness}},
		{name: "nodeport-exposure-policy-off", valuesFile: "nodeport.yaml", wantType: "NodePort",
			wantSAs: 0, wantPodSA: "aegismesh-external-sa",
			wantProbes: &probePair{live: defaultLiveness, ready: defaultReadiness}},
		{name: "pinned-image-resources-pdb", valuesFile: "pinned.yaml", wantType: "ClusterIP", wantNetPol: true,
			pdbKey: "minAvailable", pdbValue: 1,
			wantSAs: 1, wantPodSA: releaseName,
			wantProbes: &probePair{
				live:  probeTiming{initialDelaySeconds: 30, periodSeconds: 45, timeoutSeconds: 7, failureThreshold: 6},
				ready: probeTiming{initialDelaySeconds: 1, periodSeconds: 4, timeoutSeconds: 2, failureThreshold: 2}}},
		{name: "probes-disabled-explicitly", valuesFile: "probes-off.yaml", wantType: "ClusterIP", wantNetPol: true,
			wantSAs: 1, wantPodSA: releaseName},
		{name: "ssh-sensor-schema", valuesFile: "ssh-sensor.yaml", wantType: "ClusterIP", wantNetPol: true,
			wantSAs: 1, wantPodSA: releaseName,
			wantProbes: &probePair{live: defaultLiveness, ready: defaultReadiness}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			var args []string
			if sc.valuesFile != "" {
				args = append(args, "--values", filepath.Join(scratch, sc.valuesFile))
			}
			rendered := mustRender(t, helm, scratch, args)
			if again := mustRender(t, helm, scratch, args); !bytes.Equal(rendered, again) {
				h1, h2 := sha256.Sum256(rendered), sha256.Sum256(again)
				t.Fatalf("non-deterministic render: %d vs %d bytes (%x… / %x…)",
					len(rendered), len(again), h1[:6], h2[:6])
			}
			checkContract(t, rendered, sc)
		})
	}

	// Every case must fail because values.schema.json names the offending path,
	// proving the machine-enforced contract rather than an incidental error.
	negatives := []struct {
		name, wantPath string
		set            []string
		valuesFile     string
	}{
		{"replica count below minimum", "/replicas", []string{"replicas=0"}, ""},
		{"invalid service type", "/service/type", []string{"service.type=Nonsense"}, ""},
		{"runAsNonRoot disabled", "/podSecurityContext/runAsNonRoot", []string{"podSecurityContext.runAsNonRoot=false"}, ""},
		{"capability added back", "/containerSecurityContext/capabilities/add", []string{"containerSecurityContext.capabilities.add[0]=NET_ADMIN"}, ""},
		{"wrong mesh api_version", "/meshConfig/api_version", []string{"meshConfig.api_version=aegismesh.io/v9"}, ""},
		{"nonsensical memory quantity", "/resources/limits/memory", []string{"resources.limits.memory=banana"}, ""},
		{"empty sensor set", "/meshConfig/sensors", nil, "empty-sensors.yaml"},
		{"non-boolean network policy flag", "/networkPolicy/enabled", []string{"networkPolicy.enabled=maybe"}, ""},
		{"non-boolean serviceaccount create flag", "/serviceAccount/create", []string{"serviceAccount.create=maybe"}, ""},
		{"empty external serviceaccount name", "/serviceAccount/name", []string{"serviceAccount.create=false"}, ""},
		{"boolean pdb threshold", "/pdb/minAvailable", []string{"pdb.enabled=true", "pdb.minAvailable=true"}, ""},
		{"malformed pdb percentage", "/pdb/maxUnavailable", []string{"pdb.maxUnavailable=%50"}, ""},
		{"non-boolean probes enabled flag", "/probes/enabled", []string{"probes.enabled=maybe"}, ""},
		{"zero liveness period", "/probes/liveness/periodSeconds", []string{"probes.liveness.periodSeconds=0"}, ""},
		{"negative readiness timeout", "/probes/readiness/timeoutSeconds", []string{"probes.readiness.timeoutSeconds=-2"}, ""},
		{"liveness timeout beyond CLI ceiling", "/probes/liveness/timeoutSeconds", []string{"probes.liveness.timeoutSeconds=11"}, ""},
		{"non-integer readiness failure threshold", "/probes/readiness/failureThreshold", []string{"probes.readiness.failureThreshold=three"}, ""},
		{"unknown probe command knob", "/probes/liveness", []string{"probes.liveness.command=sh"}, ""},
		{"unknown probe endpoint knob", "/probes/readiness", []string{"probes.readiness.httpGetPath=/readyz"}, ""},
	}
	for _, tc := range negatives {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			var args []string
			for _, s := range tc.set {
				args = append(args, "--set", s)
			}
			if tc.valuesFile != "" {
				args = append(args, "--values", filepath.Join(scratch, tc.valuesFile))
			}
			_, stderr, err := helmTemplate(t, helm, scratch, args)
			switch {
			case err == nil:
				t.Fatalf("helm rendered values violating schema path %s; expected rejection", tc.wantPath)
			case !strings.Contains(stderr, "schema"):
				t.Fatalf("failure was not a values.schema.json rejection: %.400s", stderr)
			case !strings.Contains(stderr, "at '"+tc.wantPath):
				t.Fatalf("rejection did not name expected path %s: %.400s", tc.wantPath, stderr)
			}
		})
	}

	// Ambiguous pdb thresholds must fail the render whether caught by the
	// schema layer or by the template guard: no invalid budget may ship.
	pdbNegatives := []struct {
		name string
		set  []string
	}{
		{"both pdb thresholds set", []string{"pdb.enabled=true", "pdb.minAvailable=1", "pdb.maxUnavailable=0"}},
		{"no pdb threshold set", []string{"pdb.enabled=true", "pdb.maxUnavailable=null"}},
	}
	for _, tc := range pdbNegatives {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			var args []string
			for _, s := range tc.set {
				args = append(args, "--set", s)
			}
			_, stderr, err := helmTemplate(t, helm, scratch, args)
			if err == nil {
				t.Fatal("helm rendered an ambiguous pdb configuration; expected rejection")
			}
			if !strings.Contains(stderr, "exactly one") && !strings.Contains(stderr, "/pdb") {
				t.Fatalf("failure lacks the exact-one reason or schema path /pdb: %.400s", stderr)
			}
		})
	}
}

func checkContract(t *testing.T, rendered []byte, sc scenario) {
	t.Helper()
	counts := map[string]int{}
	docsByKind := map[string]map[string]any{}
	for _, doc := range parseDocs(t, rendered) {
		k, _ := doc["kind"].(string)
		counts[k]++
		docsByKind[k] = doc
	}
	for _, k := range []string{"ConfigMap", "Deployment", "Service"} {
		if counts[k] != 1 {
			t.Errorf("want exactly one %s, got %d", k, counts[k])
		}
	}
	cmDoc, svcDoc, depDoc := docsByKind["ConfigMap"], docsByKind["Service"], docsByKind["Deployment"]
	if cmDoc == nil || svcDoc == nil || depDoc == nil {
		t.Fatal("required object(s) missing; skipping deeper checks")
	}

	meshData, ok := asMap(t, cmDoc["data"])["mesh.yaml"]
	if !ok {
		t.Fatal("ConfigMap carries no mesh.yaml key")
	}
	var mesh meshView
	if err := yaml.Unmarshal([]byte(meshData.(string)), &mesh); err != nil {
		t.Fatalf("embedded mesh.yaml is not valid YAML: %v", err)
	}
	if mesh.APIVersion != "aegismesh.io/v1alpha1" {
		t.Errorf("mesh api_version = %q, want aegismesh.io/v1alpha1", mesh.APIVersion)
	}
	if len(mesh.Sensors) == 0 {
		t.Error("mesh declares no sensors")
	}

	// Pod-template identity and integrity.
	depSpec := asMap(t, depDoc["spec"])
	podMeta := asMap(t, asMap(t, depSpec["template"])["metadata"])
	podSpec := asMap(t, asMap(t, depSpec["template"])["spec"])
	sel := asMap(t, asMap(t, depSpec["selector"])["matchLabels"])
	labels := asMap(t, podMeta["labels"])
	for k, v := range sel {
		if labels[k] != v {
			t.Errorf("pod labels do not satisfy selector %s=%v", k, v)
		}
	}
	sum := sha256.Sum256([]byte(strings.TrimSuffix(meshData.(string), "\n")))
	if got, _ := asMap(t, podMeta["annotations"])["checksum/config"]; got != hex.EncodeToString(sum[:]) {
		t.Errorf("checksum/config annotation does not match rendered mesh.yaml (got %.12v…)", got)
	}
	if am, ok := podSpec["automountServiceAccountToken"].(bool); !ok || am {
		t.Error("automountServiceAccountToken must be explicitly false")
	}
	if r, _ := depSpec["replicas"].(int); r < 1 {
		t.Error("replicas must be present and >= 1")
	}

	// Hardened pod and container context.
	psc := asMap(t, podSpec["securityContext"])
	if rn, ok := psc["runAsNonRoot"].(bool); !ok || !rn {
		t.Error("pod must pin runAsNonRoot=true")
	}
	switch st := asMap(t, psc["seccompProfile"])["type"].(string); st {
	case "RuntimeDefault", "Localhost":
	default:
		t.Errorf("pod seccomp profile must be RuntimeDefault or Localhost, got %q", st)
	}
	containers := asList(t, podSpec["containers"])
	if len(containers) != 1 {
		t.Fatalf("want exactly one container, got %d", len(containers))
	}
	c := asMap(t, containers[0])
	csc := asMap(t, c["securityContext"])
	if ap, ok := csc["allowPrivilegeEscalation"].(bool); !ok || ap {
		t.Error("container must pin allowPrivilegeEscalation=false")
	}
	if ro, ok := csc["readOnlyRootFilesystem"].(bool); !ok || !ro {
		t.Error("container must pin readOnlyRootFilesystem=true")
	}
	caps := asMap(t, csc["capabilities"])
	drop, _ := caps["drop"].([]any)
	add, _ := caps["add"].([]any)
	if !slices.Contains(drop, "ALL") || len(add) > 0 {
		t.Error("container capabilities must drop ALL and add nothing")
	}
	res := asMap(t, c["resources"])
	for _, section := range []struct {
		name string
		vals map[string]any
	}{{"requests", asMap(t, res["requests"])}, {"limits", asMap(t, res["limits"])}} {
		for _, r := range []string{"cpu", "memory"} {
			if v, ok := section.vals[r]; !ok || v == nil {
				t.Errorf("resource %s.%s missing or empty", section.name, r)
			}
		}
	}

	// Volume/mount contract: config stays read-only from the ConfigMap;
	// data and tmp stay writable/memory-backed emptyDirs. Probes must not
	// have disturbed any of it.
	mountPaths := make([]string, 0, 3)
	for _, m := range asList(t, c["volumeMounts"]) {
		mm := asMap(t, m)
		mountPaths = append(mountPaths, fmt.Sprint(mm["mountPath"]))
		if mm["name"] == "config" && mm["readOnly"] != true {
			t.Error("config mount must stay readOnly")
		}
	}
	slices.Sort(mountPaths)
	if !slices.Equal(mountPaths, []string{"/etc/aegismesh", "/tmp", "/workspace/data"}) {
		t.Errorf("container volumeMounts = %v, want [/etc/aegismesh /tmp /workspace/data]", mountPaths)
	}

	// Probe contract: enabled renders both probes as exec handlers running
	// exactly [/aegismesh healthcheck --config /etc/aegismesh/mesh.yaml
	// --live|--ready] — no shell, curl, wget, HTTP/tcpSocket handler, or
	// extra fields — with timing flowing from values verbatim. Disabled
	// renders neither key.
	if sc.wantProbes == nil {
		for _, k := range []string{"livenessProbe", "readinessProbe"} {
			if _, ok := c[k]; ok {
				t.Errorf("%s must not render when probes.enabled=false", k)
			}
		}
	} else {
		wants := map[string]struct {
			flag string
			time probeTiming
		}{
			"livenessProbe":  {"--live", sc.wantProbes.live},
			"readinessProbe": {"--ready", sc.wantProbes.ready},
		}
		for name, w := range wants {
			p, ok := c[name].(map[string]any)
			if !ok {
				t.Fatalf("%s missing or not a mapping", name)
			}
			keys := slices.Sorted(maps.Keys(p))
			if want := []string{"exec", "failureThreshold", "initialDelaySeconds", "periodSeconds", "timeoutSeconds"}; !slices.Equal(keys, want) {
				t.Errorf("%s fields = %v, want exactly %v (successThreshold stays at the API default)", name, keys, want)
			}
			argv, ok := asMap(t, p["exec"])["command"].([]any)
			if !ok {
				t.Fatalf("%s must carry an exec command list", name)
			}
			wantArgv := []any{"/aegismesh", "healthcheck", "--config", "/etc/aegismesh/mesh.yaml", w.flag}
			if !slices.Equal(argv, wantArgv) {
				t.Errorf("%s argv = %v, want exactly %v", name, argv, wantArgv)
			}
			for _, a := range argv {
				switch s := fmt.Sprint(a); s {
				case "sh", "bash", "/bin/sh", "/bin/bash", "curl", "wget":
					t.Errorf("%s must never shell out via %q", name, s)
				}
			}
			rendered := map[string]any{
				"initialDelaySeconds": p["initialDelaySeconds"],
				"periodSeconds":       p["periodSeconds"],
				"timeoutSeconds":      p["timeoutSeconds"],
				"failureThreshold":    p["failureThreshold"],
			}
			expected := map[string]int{
				"initialDelaySeconds": w.time.initialDelaySeconds,
				"periodSeconds":       w.time.periodSeconds,
				"timeoutSeconds":      w.time.timeoutSeconds,
				"failureThreshold":    w.time.failureThreshold,
			}
			for field, wantV := range expected {
				if v, ok := rendered[field].(int); !ok || v != wantV {
					t.Errorf("%s.%s = %v, want %d", name, field, rendered[field], wantV)
				}
			}
		}
	}

	// Exposure contract: Service routes decoy listeners only.
	svcSpec := asMap(t, svcDoc["spec"])
	if got := svcSpec["type"]; got != sc.wantType {
		t.Errorf("service type = %v, want %q", got, sc.wantType)
	}
	if !maps.Equal(asMap(t, svcSpec["selector"]), sel) {
		t.Error("service selector diverges from deployment matchLabels")
	}
	svcPorts := asList(t, svcSpec["ports"])
	targets := make([]string, 0, len(svcPorts))
	svcPairs := make([]string, 0, len(svcPorts))
	for _, p := range svcPorts {
		pm := asMap(t, p)
		targets = append(targets, fmt.Sprint(pm["targetPort"]))
		svcPairs = append(svcPairs, fmt.Sprint(pm["protocol"])+"/"+fmt.Sprint(pm["targetPort"]))
	}
	routable := []string{} // ports of non-loopback sensor listeners
	for _, s := range mesh.Sensors {
		port, exposed := listenerPort(s.Listen)
		if !exposed {
			if slices.Contains(targets, port) {
				t.Errorf("loopback listener :%s must never be routed through the Service", port)
			}
			continue
		}
		routable = append(routable, port)
	}
	slices.Sort(targets)
	slices.Sort(routable)
	if !slices.Equal(targets, routable) {
		t.Errorf("service targetPorts %v != routable sensor listeners %v", targets, routable)
	}
	if admin, _ := listenerPort(cmp.Or(mesh.Admin.Listen, adminListen)); slices.Contains(targets, admin) {
		t.Errorf("admin listener :%s must never be routed through the Service", admin)
	}

	// Ingress isolation contract: the NetworkPolicy admits exactly the decoy
	// protocol/targetPort pairs the Service exposes and never constrains
	// egress (local inference, remote LLM providers, webhooks depend on it).
	switch {
	case sc.wantNetPol:
		if counts["NetworkPolicy"] != 1 {
			t.Fatalf("want exactly one NetworkPolicy in addition to core objects, got %d", counts["NetworkPolicy"])
		}
		npSpec := asMap(t, docsByKind["NetworkPolicy"]["spec"])
		if !maps.Equal(asMap(t, asMap(t, npSpec["podSelector"])["matchLabels"]), sel) {
			t.Error("networkpolicy podSelector diverges from deployment matchLabels")
		}
		ptypes, _ := npSpec["policyTypes"].([]any)
		var types []string
		for _, v := range ptypes {
			types = append(types, fmt.Sprint(v))
		}
		if !slices.Equal(types, []string{"Ingress"}) {
			t.Errorf("networkpolicy policyTypes = %v, want exactly [Ingress]", types)
		}
		if _, ok := npSpec["egress"]; ok {
			t.Error("networkpolicy must not define egress rules")
		}
		var allowed []string
		for _, rule := range asList(t, npSpec["ingress"]) {
			for _, p := range asList(t, asMap(t, rule)["ports"]) {
				pm := asMap(t, p)
				allowed = append(allowed, fmt.Sprint(pm["protocol"])+"/"+fmt.Sprint(pm["port"]))
			}
		}
		slices.Sort(allowed)
		slices.Sort(svcPairs)
		if !slices.Equal(allowed, svcPairs) {
			t.Errorf("networkpolicy ingress %v != service protocol/targetPort set %v", allowed, svcPairs)
		}
	default:
		if counts["NetworkPolicy"] != 0 {
			t.Errorf("networkPolicy disabled must render no NetworkPolicy, got %d", counts["NetworkPolicy"])
		}
	}

	// Voluntary-disruption contract: the PDB is absent by default (with one
	// replica on an ephemeral evidence store it could only stall drains),
	// and when opted into it must be a single policy/v1 object bound to the
	// Deployment selector declaring exactly the configured threshold.
	switch {
	case sc.pdbKey != "":
		if counts["PodDisruptionBudget"] != 1 {
			t.Fatalf("want exactly one PodDisruptionBudget in addition to core objects, got %d", counts["PodDisruptionBudget"])
		}
		pdbDoc := docsByKind["PodDisruptionBudget"]
		if v := fmt.Sprint(pdbDoc["apiVersion"]); v != "policy/v1" {
			t.Errorf("poddisruptionbudget apiVersion = %q, want policy/v1", v)
		}
		pdbSpec := asMap(t, pdbDoc["spec"])
		if !maps.Equal(asMap(t, asMap(t, pdbSpec["selector"])["matchLabels"]), sel) {
			t.Error("poddisruptionbudget selector diverges from deployment matchLabels")
		}
		thrown := map[string]any{}
		for _, k := range []string{"minAvailable", "maxUnavailable"} {
			if v, ok := pdbSpec[k]; ok && v != nil {
				thrown[k] = v
			}
		}
		if len(thrown) != 1 || thrown[sc.pdbKey] == nil || fmt.Sprint(thrown[sc.pdbKey]) != fmt.Sprint(sc.pdbValue) {
			t.Errorf("poddisruptionbudget thresholds %v, want exactly %s=%v", thrown, sc.pdbKey, sc.pdbValue)
		}
	default:
		if counts["PodDisruptionBudget"] != 0 {
			t.Errorf("pdb disabled must render no PodDisruptionBudget, got %d", counts["PodDisruptionBudget"])
		}
	}
	// Identity contract: default and pinned scenarios render exactly one
	// dedicated ServiceAccount (explicitly token-free; the chart creates no
	// RBAC objects of any kind), the external mode renders none, and the Pod
	// always references a named account explicitly on top of its own
	// automountServiceAccountToken=false.
	if counts["ServiceAccount"] != sc.wantSAs {
		t.Errorf("want %d ServiceAccount, got %d", sc.wantSAs, counts["ServiceAccount"])
	}
	if sc.wantSAs > 0 {
		saDoc := docsByKind["ServiceAccount"]
		if got := fmt.Sprint(asMap(t, saDoc["metadata"])["name"]); got != sc.wantPodSA {
			t.Errorf("serviceaccount name = %q, want %q", got, sc.wantPodSA)
		}
		if am, ok := saDoc["automountServiceAccountToken"].(bool); !ok || am {
			t.Error("serviceaccount automountServiceAccountToken must be explicitly false")
		}
	}
	if got := fmt.Sprint(podSpec["serviceAccountName"]); got != sc.wantPodSA {
		t.Errorf("deployment serviceAccountName = %q, want %q", got, sc.wantPodSA)
	}
	if sc.name == "pinned-image-resources-pdb" {
		if img := fmt.Sprint(c["image"]); !strings.HasSuffix(img, ":1.2.3") {
			t.Errorf("image override ignored: %q does not end in :1.2.3", img)
		}
		if pp := fmt.Sprint(c["imagePullPolicy"]); pp != "Always" {
			t.Errorf("pullPolicy override ignored: got %q, want Always", pp)
		}
		if mem := fmt.Sprint(asMap(t, res["limits"])["memory"]); mem != "512Mi" {
			t.Errorf("memory limit override ignored: got %q, want 512Mi", mem)
		}
	}
}

func parseDocs(t *testing.T, rendered []byte) []map[string]any {
	t.Helper()
	var docs []map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(rendered))
	for i := 0; ; i++ {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs
		}
		if err != nil || doc == nil {
			t.Fatalf("document %d: not parseable YAML: %v", i, err)
		}
		docs = append(docs, doc)
	}
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected mapping, got %T", v)
	}
	return m
}

func asList(t *testing.T, v any) []any {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("expected list, got %T", v)
	}
	return l
}

// helmTemplate runs `helm template` fully offline (plugins disabled, HELM homes in scratch).
func helmTemplate(t *testing.T, helm, scratch string, args []string) ([]byte, string, error) {
	t.Helper()
	cmd := exec.Command(helm, append([]string{"template", releaseName, ".", "--namespace", "contract"}, args...)...)
	cmd.Dir = chartDir
	cmd.Env = append(os.Environ(),
		"HELM_CACHE_HOME="+filepath.Join(scratch, "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(scratch, "config"),
		"HELM_DATA_HOME="+filepath.Join(scratch, "data"),
		"HELM_NO_PLUGINS=1",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.String(), err
}

func mustRender(t *testing.T, helm, scratch string, args []string) []byte {
	t.Helper()
	out, stderr, err := helmTemplate(t, helm, scratch, args)
	if err != nil {
		t.Fatalf("INFRASTRUCTURE: helm template failed: %v\nstderr (bounded): %.400s", err, stderr)
	}
	return out
}

// listenerPort splits a listen address; routable is false for loopback binds.
func listenerPort(listen string) (port string, routable bool) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return port, false
	}
	return port, !strings.EqualFold(host, "localhost")
}
