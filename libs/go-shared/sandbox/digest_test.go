package sandbox

import "testing"

// ⚠ THE DAEMON DOES NOT ECHO BACK THE NAME YOU GAVE IT.
//
// Every engine in OSINT/tools.manifest.yaml is written with a `docker.io/`
// prefix, and Docker returns RepoDigests without one. A literal comparison
// therefore matched nothing, and `invocation.image_digest` came back empty for
// every real engine while passing a test that used the short form `busybox:1.37`.
//
// Found in a live run, by the ENGINE_IMAGE_DIGEST_UNKNOWN diagnostic added in
// the same change — which is the argument for the diagnostic existing.
func TestRepoDigestFor(t *testing.T) {
	const d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const d2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	tests := []struct {
		name        string
		repoDigests []string
		ref         string
		want        string
	}{
		{
			name:        "the manifest's docker.io prefix against the daemon's short form",
			repoDigests: []string{"anchore/syft@" + d1},
			ref:         "docker.io/anchore/syft:v1.51.0",
			want:        d1,
		},
		{
			name:        "an official image, whose library/ namespace is implicit",
			repoDigests: []string{"busybox@" + d1},
			ref:         "docker.io/library/busybox:1.37",
			want:        d1,
		},
		{
			name:        "the short form both sides",
			repoDigests: []string{"busybox@" + d1},
			ref:         "busybox:1.37",
			want:        d1,
		},
		{
			name:        "a digest-pinned reference",
			repoDigests: []string{"anchore/syft@" + d1},
			ref:         "docker.io/anchore/syft@" + d1,
			want:        d1,
		},
		{
			name:        "index.docker.io, which the daemon also elides",
			repoDigests: []string{"anchore/grype@" + d1},
			ref:         "index.docker.io/anchore/grype:0.87.0",
			want:        d1,
		},
		{
			// ⚠ The reason this matches by name at all. Returning another
			// repository's digest would name a coordinate the scan never used.
			name:        "a retagged image carrying two repositories",
			repoDigests: []string{"someone-else/syft@" + d2, "anchore/syft@" + d1},
			ref:         "docker.io/anchore/syft:v1.51.0",
			want:        d1,
		},
		{
			name:        "a private registry with a port, whose colon is not a tag",
			repoDigests: []string{"registry.internal:5000/engine@" + d1},
			ref:         "registry.internal:5000/engine:2.0",
			want:        d1,
		},
		{
			// A locally built image has no registry digest. Empty is honest;
			// the worker turns it into a stated diagnostic.
			name:        "no registry digest at all",
			repoDigests: nil,
			ref:         "docker.io/anchore/syft:v1.51.0",
			want:        "",
		},
		{
			name:        "a digest for a repository we did not ask for",
			repoDigests: []string{"someone-else/syft@" + d2},
			ref:         "docker.io/anchore/syft:v1.51.0",
			want:        "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := repoDigestFor(tc.repoDigests, tc.ref); got != tc.want {
				t.Errorf("repoDigestFor(%v, %q) = %q, want %q",
					tc.repoDigests, tc.ref, got, tc.want)
			}
		})
	}
}
