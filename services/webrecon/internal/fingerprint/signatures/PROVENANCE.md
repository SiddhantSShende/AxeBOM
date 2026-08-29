# retire-js-jsrepository.json — provenance

Vendored verbatim, not toolctl-managed: this is a single ~550 KB JSON data
file, not an executable release artifact, so it does not fit
`tools.manifest.yaml`'s binary/container/checksum-file pinning machinery
(built around goreleaser-style multi-platform releases — see
`libs/go-shared/toolctl/manifest.go`'s own doc comment, ADR-0002). Checked
into git instead: the file's own history in this repository is the audit
trail, and re-vendoring is a one-line `curl` + a commit, reviewed like any
other change. Referenced in `OSINT/tools.manifest.yaml`'s `libraries:`
section (`id: retire-js-signatures`) so it still appears in the OSINT roster.

| Field | Value |
|---|---|
| Source | `github.com/RetireJS/retire.js`, `repository/jsrepository.json` |
| Fetch URL | `https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json` |
| Upstream commit | `db79fa77c86e24d91c9ce1934ad9f2a640242774` (2026-08-20) |
| Fetched | 2026-08-29 |
| License | Apache-2.0 |
| SHA-256 | `574f68690a6f5031ac7602936196a3f4531407bc79fafec0f49278241fda857a` |
| Libraries covered | 76 |

## RE2 compatibility — spiked, not assumed

Go's `regexp` package (RE2) cannot execute two constructs this file's
`extractors.filecontent`/`filecontentreplace` regexes use. Verified by
compiling all 76 `uri` + 208 `filecontent` + 8 `filecontentreplace` patterns
against Go's `regexp.Compile` (with `§§version§§` substituted for a plain
capture group, same as retire.js's own tooling does):

`services/webrecon/internal/fingerprint` does not load `filecontentreplace`
(8 patterns) or `hashes` (18 entries) at all — a deliberate scope cut, not
part of the spike's failure count below. Of the 76 `uri` + 208 `filecontent`
= **284 patterns it does load**:

- **Backreferences** (`\1`, `\2`, `\3` inside the pattern, not just a
  replacement string) — 1 pattern: one of jQuery's several `filecontent`
  variants (its `filecontentreplace` entry also uses one, but that field is
  never loaded regardless). RE2 has no backreference support at all; not a
  bug, a design tradeoff (linear-time matching).
- **Lookbehind** (`(?<=...)`) — 1 pattern, in lodash's `filecontent`. Also
  fundamentally unsupported by RE2.
- **Repeat counts above RE2's hardcoded 1000 cap** (`{0,8000}`, `{1,5000}`,
  etc.) — 7 patterns: tinyMCE, underscore.js, Vue (×2), Next.js (×2) and
  select2. `regexp/syntax/parse.go`'s `maxRepeat = 1000` is a literal
  constant, not configurable via any public Go API.

`services/webrecon/internal/fingerprint/retire.go` handles this HONESTLY, not
silently: a backreference or lookbehind pattern is skipped entirely (counted
in `LoadStats`, not logged per-match); an oversized repeat bound is CAPPED at
1000 rather than dropped — a real precision loss (a real gap between two
anchors in a minified bundle can exceed 1000 characters, producing a false
negative on that one variant), but every affected library still has other
matching signatures (jQuery: 10 of 11 `filecontent` patterns unaffected;
lodash: 5 of 6; Vue: 9 of 11; the rest have 1–2 patterns each, so losing one
is a real, documented reduction in detection precision for those specific
signatures, not a silent one). Net: 282 of 284 patterns compile and run
(2 skipped, 7 of those 282 capped). See `retire_test.go`'s golden-fixture
test, which pins these exact counts as a regression guard.
