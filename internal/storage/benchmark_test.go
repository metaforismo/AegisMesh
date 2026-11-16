package storage

import (
	"context"
	"testing"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/testutil/benchfixture"
)

func BenchmarkStorageAppend(b *testing.B) {
	for _, mode := range []string{"Plain", "Encrypted", "EncryptedCheckpoint"} {
		b.Run(mode, func(b *testing.B) {
			opts := Options{Dir: b.TempDir(), MaxFileBytes: 16 << 20}
			if mode != "Plain" {
				id, err := age.GenerateX25519Identity()
				if err != nil {
					b.Fatal(err)
				}
				opts.Encryption = &EncryptionOptions{Recipient: id.Recipient().String()}
			}
			s, err := New(opts)
			if err != nil {
				b.Fatal(err)
			}
			defer func() {
				if err := s.Close(); err != nil {
					b.Fatal(err)
				}
			}()
			e := benchfixture.Envelope(49999)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.Append(ctx, e); err != nil {
					b.Fatal(err)
				}
				if mode == "EncryptedCheckpoint" {
					if err := s.Flush(); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.StopTimer()
		})
	}
}
