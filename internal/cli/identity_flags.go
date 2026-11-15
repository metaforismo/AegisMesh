package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/metaforismo/aegismesh/internal/agekey"
	"github.com/metaforismo/aegismesh/internal/storage"
)

type identityFilesFlag struct {
	values []string
}

func (f *identityFilesFlag) String() string {
	if len(f.values) == 0 {
		return ""
	}
	return f.values[len(f.values)-1]
}

func (f *identityFilesFlag) Set(value string) error {
	if len(f.values) >= agekey.MaxIdentityFiles {
		return fmt.Errorf("may be given at most %d times", agekey.MaxIdentityFiles)
	}
	if value == "" || strings.TrimSpace(value) != value || strings.HasPrefix(value, "-") || strings.ContainsAny(value, ",\r\n\x00") {
		return fmt.Errorf("must be one unpadded file path without commas or a leading '-'")
	}
	f.values = append(f.values, value)
	return nil
}

func (f identityFilesFlag) openReader(dataDir string, requireSealed bool) (*storage.Reader, error) {
	return storage.NewReaderWithOptions(dataDir, storage.ReaderOptions{
		IdentityFiles: append([]string(nil), f.values...),
		RequireSealed: requireSealed,
	})
}

// flag includes the raw value in Set errors, so never return it for identities.
func parseIdentityFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if strings.Contains(err.Error(), "-identity") {
			return fmt.Errorf("invalid --identity: use at most 8 unpadded file references without commas")
		}
		return err
	}
	return nil
}

func reportOpenSegments(w io.Writer, notices []storage.OpenSegmentError) {
	for i := range notices {
		fmt.Fprintln(w, notices[i].Error())
	}
}
