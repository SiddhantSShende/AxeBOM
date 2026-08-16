# golang-incompatible

WARNING: GO MODULE PATHS ARE CASE-PRESERVING, AND "+incompatible" IS PART OF THE
VERSION.

Three traps in one fixture:

1. **github.com/Masterminds/semver/v3** — the capital M is significant. The Go
   module proxy encodes it as "!masterminds" on the wire, and a normalizer that
   decodes proxy escaping incorrectly produces "masterminds", which is a
   different module.

2. **v24.0.5+incompatible** — the suffix is part of the version string, not
   metadata to strip. Stripping it produces v24.0.5, which does not exist as a
   published version of that module.

3. **gopkg.in/yaml.v3** — the ".v3" is part of the module PATH, not a version.
   "gopkg.in/yaml" alone is a different, nonexistent module.

**What it proves:** that Go identity is preserved verbatim rather than
normalized like npm. Every one of these produces a plausible-looking wrong
answer when handled generically, which is why they are together in one fixture.
