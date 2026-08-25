package handler

import (
	"reflect"
	"testing"
)

func TestParseMentions(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"no mentions", "just a plain comment", []string{}},
		{"one mention", "cc @alice please review", []string{"alice"}},
		{"leading mention", "@bob take a look", []string{"bob"}},
		{"several mentions", "@alice and @bob, thoughts?", []string{"alice", "bob"}},
		{"duplicate mention kept once", "@alice @alice again", []string{"alice"}},
		{"dotted and hyphenated handles", "@alice.smith @bob-jones", []string{"alice.smith", "bob-jones"}},
		{"email is not a mention of the domain", "reach me at a@example.com", []string{}},
		{"bare at sign is not a mention", "the cost is @ $5 each", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseMentions(tt.body)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseMentions(%q) = %#v, want %#v", tt.body, got, tt.want)
			}
		})
	}
}
