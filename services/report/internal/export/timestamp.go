package export

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// parseTimestamp converts an RFC3339 string to a protobuf timestamp.
//
// ⚠ RFC3339 WITH A LITERAL Z, and it comes from the scan record — never from a
// clock read here. A `time.Now()` in this path would make the same canonical
// model serialize to different bytes on every run, which breaks replay and
// makes every golden test flap.
func parseTimestamp(value string) (*timestamppb.Timestamp, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	return timestamppb.New(t.UTC()), nil
}
