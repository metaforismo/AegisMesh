package event

// OriginEnvelope preserves authenticated fleet origin outside native evidence bytes.
type OriginEnvelope struct {
	Envelope Envelope
	NodeID   string
}
