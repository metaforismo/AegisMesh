package console

import "testing"

func TestCompactDurationsAndCSVCells(t *testing.T) {
	for seconds, want := range map[int]string{0: "off", 60: "1m", 1800: "30m", 3600: "1h", 5400: "1h30m", 28800: "8h", 90: "1m30s", 86400: "24h"} {
		if got := duration(seconds); got != want {
			t.Errorf("duration(%d) = %q; want %q", seconds, got, want)
		}
	}
	for value, want := range map[string]string{
		"=1+1": "'=1+1", "+cmd": "'+cmd", "-2": "'-2", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx", "\rx": "'\rx",
		"alice": "alice", "": "", "a=b": "a=b",
	} {
		if got := csvCell(value); got != want {
			t.Errorf("csvCell(%q) = %q; want %q", value, got, want)
		}
	}
	for value, want := range map[string]string{"ab": "ab", "ééé": "é", "abcdef": "abc"} {
		if got := truncate(value, 3); got != want {
			t.Errorf("truncate(%q) = %q; want %q", value, got, want)
		}
	}
}
