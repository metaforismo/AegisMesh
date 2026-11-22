package rulecatalog

import (
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/detect"
)

func TestEveryRuleHasStaticOperatorProse(t *testing.T) {
	if len(prose) != len(All()) {
		t.Fatal("prose must cover exactly the rule catalog")
	}
	for _, rule := range All() {
		if rule.Summary == "" || rule.Description == "" || rule.Guidance == "" || !strings.HasSuffix(rule.Description, ".") {
			t.Fatalf("missing operator text: %s", rule.ID)
		}
		if rule.ObserveOnly != (rule.Family == FamilyCorrelation || detect.ObserveOnly(detect.RuleID(rule.ID))) {
			t.Fatalf("observe-only drift: %s", rule.ID)
		}
	}
}
