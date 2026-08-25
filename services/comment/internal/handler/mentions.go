package handler

import "regexp"

// mentionPattern finds "@handle" tokens in comment text.
//
// ⚠ SCOPE: THIS IS TEXT PARSING ONLY. THERE IS NO MEMBER DIRECTORY LOOKUP.
//
// Phase 13 lists "mentions" as a deliverable, but no schema column exists for
// it (docs/01-DATA-MODEL.md §8 names only id, tenant_id, report_id, user_id,
// parent_id, body, edited_at, deleted_at, created_at) and there is no existing
// "look up a tenant member by handle" endpoint anywhere in this codebase to
// resolve one against — auth.users is keyed by UUID and has no short handle,
// and inventing a members-lookup service call for this alone would be a wider
// change than a comment thread justifies.
//
// So mentions are computed at READ TIME from the raw body text, never stored:
// a `@word` token is extracted verbatim and returned in the API response's
// `mentions` field, exactly as the caller typed it. The frontend renders it as
// highlighted text. It is NOT resolved to a user id, does NOT verify the
// handle refers to a real tenant member, and does NOT drive a notification —
// that would need the member directory this codebase does not yet expose.
// A future phase that adds one can make this a real resolution without
// changing the wire shape: `mentions` already exists as a []string.
var mentionPattern = regexp.MustCompile(`(?:^|\s)@([A-Za-z0-9][A-Za-z0-9._-]*)`)

// ParseMentions extracts every "@handle" token from body, in the order they
// appear, without duplicates. A pure function — no I/O, nothing to mock —
// deliberately, so a store or a service layer is never needed just to render
// this field.
func ParseMentions(body string) []string {
	matches := mentionPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return []string{}
	}

	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		handle := m[1]
		if seen[handle] {
			continue
		}
		seen[handle] = true
		out = append(out, handle)
	}
	return out
}
