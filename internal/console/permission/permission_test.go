package permission

import (
	"slices"
	"testing"
)

func TestCatalogueAndBuiltins(t *testing.T) {
	ids := map[string]bool{}
	for _, info := range Catalogue() {
		if ids[info.ID] || info.Label == "" || info.Group == "" ||
			(info.Risk != RiskLow && info.Risk != RiskElevated && info.Risk != RiskHigh) {
			t.Fatalf("catalogue entry %+v", info)
		}
		ids[info.ID] = true
	}
	if len(ids) != 18 {
		t.Fatalf("catalogue has %d ids", len(ids))
	}
	for _, high := range []string{AccountsManage, RolesManage, SettingsManage, FleetManage, SessionsManage} {
		if !HighRisk(high) {
			t.Errorf("%s should be high risk", high)
		}
	}
	for _, testCase := range []struct {
		role string
		want []string
	}{
		{Viewer, []string{AnalysisRead, EvidenceRead, FleetRead, InvestigationsRead, KeysSelf}},
		{Analyst, []string{AnalysisRead, EvidenceExport, EvidenceRead, FleetRead, InvestigationsRead, InvestigationsWrite, KeysSelf, ReportsDownload}},
	} {
		if got := Builtin(testCase.role); !slices.Equal(got, testCase.want) {
			t.Errorf("%s = %v; want %v", testCase.role, got, testCase.want)
		}
	}
	if len(Builtin(Admin)) != 18 || !Coherent(Builtin(Admin)) || !Administers(Builtin(Admin)) || Builtin("root") != nil {
		t.Fatal("admin must hold the whole coherent catalogue")
	}
	if Administers(Builtin(Analyst)) || !Coherent(Builtin(Viewer)) || !Coherent(Builtin(Analyst)) {
		t.Fatal("built-in coherence")
	}
}

func TestCoherent(t *testing.T) {
	for _, testCase := range []struct {
		ids  []string
		want bool
	}{
		{[]string{}, true},
		{[]string{RolesManage}, false},
		{[]string{SettingsManage, SettingsRead}, false},
		{[]string{AccountsManage}, false},
		{[]string{SessionsManage}, false},
		{[]string{AccountsManage, AccountsRead, RolesManage}, true},
		{[]string{AccountsManage, AccountsRead, SettingsManage}, false},
		{[]string{AccountsManage, AccountsRead, SettingsManage, SettingsRead}, true},
	} {
		if got := Coherent(testCase.ids); got != testCase.want {
			t.Errorf("Coherent(%v) = %v", testCase.ids, got)
		}
	}
}
