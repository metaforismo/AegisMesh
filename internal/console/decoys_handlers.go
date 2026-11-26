package console

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
)

// Decoy is a value-only description of a configured synthetic surface.
type Decoy struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Listen          string   `json:"listen"`
	SurfaceFamilies []string `json:"surface_families"`
	Rules           int      `json:"rules"`
	Tools           int      `json:"tools"`
	FakeFiles       int      `json:"fake_files"`
	HoneytokenIDs   []string `json:"honeytoken_ids"`
	Events          int      `json:"events"`
	LastActivity    string   `json:"last_activity"`
}

// Honeytoken describes planting and presentations without carrying the value.
type Honeytoken struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	SensorIDs []string `json:"sensor_ids"`
	Hits      int      `json:"hit_count"`
	LastHit   string   `json:"last_hit"`
	Sources   []string `json:"sources"`
}

// DecoyCatalog derives safe metadata once from the validated effective configuration.
// External body files are not read to infer planting.
func DecoyCatalog(cfg *config.Config) ([]Decoy, []Honeytoken) {
	decoys := []Decoy{}
	markers := []Honeytoken{}
	for _, token := range cfg.Honeytokens {
		markers = append(markers, Honeytoken{
			ID:        token.ID,
			Kind:      token.Kind,
			SensorIDs: []string{},
			Sources:   []string{},
		})
	}
	for _, sensor := range cfg.Sensors {
		item := Decoy{
			ID:              sensor.ID,
			Kind:            sensor.Kind,
			Listen:          sensor.Listen,
			SurfaceFamilies: []string{},
			Rules:           len(sensor.Rules) + len(sensor.TCPResponseRule),
			Tools:           len(sensor.Tools) + config.MCPEnvironmentToolCount(sensor.Environment),
			HoneytokenIDs:   []string{},
		}
		parts := []string{sensor.Banner, sensor.Instructions}
		for _, rule := range sensor.Rules {
			parts = append(parts, rule.Body)
			for _, value := range rule.Headers {
				parts = append(parts, value)
			}
			path := strings.TrimSuffix(strings.TrimPrefix(rule.PathRegex, "^"), "$")
			family := string(detect.SurfaceFamily(detect.Input{Path: path}))
			if strings.HasPrefix(rule.Name, "vllm-") {
				family = "vllm"
			}
			if family != "" && !slices.Contains(item.SurfaceFamilies, family) {
				item.SurfaceFamilies = append(item.SurfaceFamilies, family)
			}
		}
		for _, rule := range sensor.TCPResponseRule {
			parts = append(parts, rule.Response)
		}
		for _, tool := range sensor.Tools {
			parts = append(parts, tool.Description, tool.ResultJSON)
		}
		for _, resource := range sensor.Resources {
			parts = append(parts, resource.Text)
		}
		for _, prompt := range sensor.Prompts {
			parts = append(parts, prompt.Messages...)
		}
		if sensor.Environment != nil {
			item.FakeFiles = len(sensor.Environment.Files)
			item.SurfaceFamilies = append(item.SurfaceFamilies, "mcp_environment")
			for _, entry := range append(append([]config.MCPEntry{}, sensor.Environment.Files...), sensor.Environment.Env...) {
				parts = append(parts, entry.Content)
			}
			for _, content := range sensor.Environment.Queries {
				parts = append(parts, content)
			}
		}
		if len(item.SurfaceFamilies) == 0 {
			item.SurfaceFamilies = append(item.SurfaceFamilies, sensor.Kind)
		}
		sort.Strings(item.SurfaceFamilies)
		for i, token := range cfg.Honeytokens {
			found := false
			for _, part := range parts {
				if strings.Contains(part, token.Value) {
					found = true
					break
				}
			}
			if found {
				item.HoneytokenIDs = append(item.HoneytokenIDs, token.ID)
				markers[i].SensorIDs = append(markers[i].SensorIDs, sensor.ID)
			}
		}
		sort.Strings(item.HoneytokenIDs)
		decoys = append(decoys, item)
	}
	sort.Slice(decoys, func(i, j int) bool { return decoys[i].ID < decoys[j].ID })
	for i := range markers {
		sort.Strings(markers[i].SensorIDs)
	}
	sort.Slice(markers, func(i, j int) bool { return markers[i].ID < markers[j].ID })
	return decoys, markers
}

func (s *Server) catalogWindow(w http.ResponseWriter, r *http.Request) (evidenceindex.Snapshot, []evidenceindex.Summary, bool) {
	values, ok := query(w, r, "window")
	if !ok {
		return evidenceindex.Snapshot{}, nil, false
	}
	duration, _, err := evidenceindex.Window(values.Get("window"))
	if err != nil {
		invalid(w)
		return evidenceindex.Snapshot{}, nil, false
	}
	now := time.Now().UTC()
	snapshot := s.index.SharedAnalysis()
	// The sample is newest-first, so the window is normally one contiguous run
	// that can be returned as a read-only subslice; any other layout is copied.
	inWindow := func(e evidenceindex.Summary) bool {
		t := evidenceview.Time(e)
		return !t.Before(now.Add(-duration)) && t.Before(now)
	}
	first, last, contiguous := -1, -1, true
	for i, e := range snapshot.Events {
		if !inWindow(e) {
			continue
		}
		if last >= 0 && last != i-1 {
			contiguous = false
			break
		}
		if first < 0 {
			first = i
		}
		last = i
	}
	if first < 0 {
		return snapshot, []evidenceindex.Summary{}, true
	}
	if contiguous {
		return snapshot, snapshot.Events[first : last+1 : last+1], true
	}
	events := []evidenceindex.Summary{}
	for _, e := range snapshot.Events {
		if inWindow(e) {
			events = append(events, e)
		}
	}
	return snapshot, events, true
}

func (s *Server) decoys(w http.ResponseWriter, r *http.Request, _ caller) {
	snapshot, events, ok := s.catalogWindow(w, r)
	if !ok {
		return
	}
	out := append([]Decoy{}, s.decoyCatalog...)
	for i := range out {
		for _, e := range events {
			if e.Node == nil && e.Sensor.ID == out[i].ID {
				out[i].Events++
				if e.Time > out[i].LastActivity {
					out[i].LastActivity = e.Time
				}
			}
		}
	}
	boundedJSON(w, map[string]any{"decoys": out, "bounds": snapshot})
}

func (s *Server) honeytokens(w http.ResponseWriter, r *http.Request, _ caller) {
	snapshot, events, ok := s.catalogWindow(w, r)
	if !ok {
		return
	}
	out := append([]Honeytoken{}, s.tokenCatalog...)
	for i := range out {
		out[i].Sources = []string{}
		for _, e := range events {
			if e.Node != nil || !slices.Contains(e.TokenIDs, out[i].ID) {
				continue
			}
			out[i].Hits++
			if e.Time > out[i].LastHit {
				out[i].LastHit = e.Time
			}
			if e.Source != "" && !slices.Contains(out[i].Sources, e.Source) {
				out[i].Sources = append(out[i].Sources, e.Source)
			}
		}
		sort.Strings(out[i].Sources)
	}
	boundedJSON(w, map[string]any{"honeytokens": out, "bounds": snapshot})
}
