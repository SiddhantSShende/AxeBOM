package discover

import "testing"

// TestParseHosts is a regression guard for a real bug found by actually
// running subfinder inside its sandbox: Policy()'s read-only rootfs blocks
// subfinder's first-run config write, and the resulting error —
// "open /.config/subfinder/config.yaml: no such file or directory" — reached
// stdout despite -silent, where every previous version of parseHosts
// accepted it as a discovered host indistinguishable from a real one.
func TestParseHosts(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		domain string
		want   []string
	}{
		{
			name:   "real hostnames pass",
			stdout: "www.example.com\napi.example.com\n",
			domain: "example.com",
			want:   []string{"www.example.com", "api.example.com"},
		},
		{
			name: "subfinder's own read-only-rootfs config error is rejected, not treated as a host",
			stdout: "www.example.com\n" +
				"open /.config/subfinder/config.yaml: no such file or directory\n",
			domain: "example.com",
			want:   []string{"www.example.com"},
		},
		{
			name:   "the root domain itself is never re-added",
			stdout: "example.com\nwww.example.com\n",
			domain: "example.com",
			want:   []string{"www.example.com"},
		},
		{
			name:   "blank lines and whitespace-only lines are dropped",
			stdout: "www.example.com\n\n   \n",
			domain: "example.com",
			want:   []string{"www.example.com"},
		},
		{
			name:   "a duplicate line is deduplicated",
			stdout: "www.example.com\nwww.example.com\n",
			domain: "example.com",
			want:   []string{"www.example.com"},
		},
		{
			name:   "mixed case is normalized",
			stdout: "WWW.Example.COM\n",
			domain: "example.com",
			want:   []string{"www.example.com"},
		},
		{
			name:   "a bare word with no dot is not a hostname",
			stdout: "notahost\n",
			domain: "example.com",
			want:   nil,
		},
		{
			name:   "a URL-shaped line is rejected, not truncated into a host",
			stdout: "https://www.example.com/path\n",
			domain: "example.com",
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseHosts(tc.stdout, tc.domain)
			if len(got) != len(tc.want) {
				t.Fatalf("parseHosts() = %v, want %v", got, tc.want)
			}
			for i, h := range got {
				if h != tc.want[i] {
					t.Errorf("parseHosts()[%d] = %q, want %q", i, h, tc.want[i])
				}
			}
		})
	}
}

func TestLooksLikeHostname(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		{"simple subdomain", "www.example.com", true},
		{"hyphenated label", "my-app.example.com", true},
		{"numeric label", "1.example.com", true},
		{"no dot", "example", false},
		{"empty", "", false},
		{"contains a space", "not a host", false},
		{"contains a slash", "path/segment.com", false},
		{"contains a colon", "host:8080.com", false},
		{"subfinder's config error", "open /.config/subfinder/config.yaml: no such file or directory", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeHostname(tc.host); got != tc.want {
				t.Errorf("looksLikeHostname(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}
