package console

import (
	"net/http"
	"regexp"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
)

var campaignIDPattern = regexp.MustCompile(`^cmp_[0-9a-f]{12}$`)

// campaignSampleLimit caps event_ids_sample in campaign detail (newest per session first).
const campaignSampleLimit = 50

// CampaignList is the GET /api/v1/campaigns response.
type CampaignList struct {
	Items           []evidenceview.Campaign `json:"items"`
	ScannedSessions int                     `json:"scanned_sessions"`
	Truncated       bool                    `json:"truncated"`
	SessionLimit    int                     `json:"session_limit"`
	CampaignLimit   int                     `json:"campaign_limit"`
	TotalCampaigns  int                     `json:"total_campaigns"`
	GeneratedAt     string                  `json:"generated_at"`
	Bounds          evidenceindex.Snapshot  `json:"bounds"`
}

// ListCampaigns applies the list cap to one deterministic grouping.
func ListCampaigns(set evidenceview.CampaignSet, bounds evidenceindex.Snapshot, now time.Time) CampaignList {
	items := set.Campaigns[:min(len(set.Campaigns), evidenceview.CampaignListLimit)]
	return CampaignList{
		Items:           append([]evidenceview.Campaign{}, items...),
		ScannedSessions: set.ScannedSessions,
		Truncated:       set.SessionsTruncated || len(set.Campaigns) > evidenceview.CampaignListLimit,
		SessionLimit:    evidenceview.CampaignSessionLimit,
		CampaignLimit:   evidenceview.CampaignListLimit,
		TotalCampaigns:  len(set.Campaigns),
		GeneratedAt:     now.UTC().Format(time.RFC3339Nano),
		Bounds:          bounds,
	}
}

func (s *Server) campaignSet() (evidenceview.CampaignSet, evidenceindex.Snapshot) {
	analysis := s.analysis()
	return analysis.Campaigns(), analysis.snapshot
}

func (s *Server) campaigns(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	set, snapshot := s.campaignSet()
	boundedJSON(w, ListCampaigns(set, snapshot, time.Now()))
}

func (s *Server) campaign(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if !campaignIDPattern.MatchString(id) {
		invalid(w)
		return
	}
	set, snapshot := s.campaignSet()
	for _, campaign := range set.Campaigns {
		if campaign.ID == id {
			sample := []string{}
			for _, e := range campaign.EventSample(campaignSampleLimit, nil) {
				sample = append(sample, e.ID)
			}
			boundedJSON(w, struct {
				evidenceview.CampaignDetail
				EventIDsSample []string               `json:"event_ids_sample"`
				GeneratedAt    string                 `json:"generated_at"`
				Bounds         evidenceindex.Snapshot `json:"bounds"`
			}{campaign.Detail(), sample, time.Now().UTC().Format(time.RFC3339Nano), snapshot})
			return
		}
	}
	fail(w, 404, "not_found", "campaign is not present in the retained analysis sample")
}
