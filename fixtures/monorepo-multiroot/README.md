# monorepo-multiroot

Four ecosystems in one repository, at four different depths, plus a vendored
tree.

    services/api/        npm
    services/worker/     pypi
    libs/shared/         golang
    tools/build/         maven
    vendor/legacy/       npm, VENDORED

**What it proves, in order of how easily each is got wrong:**

1. **Multiple roots per ecosystem.** services/api and vendor/legacy are both
   npm. An engine that stops at the first manifest reports one and misses the
   other — and reports a smaller, cleaner-looking component count.

2. **Depth.** A scanner that only looks at the repository root finds nothing at
   all here, and "nothing" renders as a clean report.

3. **The vendored tree is a real dependency.** lodash@3.10.1 under vendor/ is
   shipped code with known vulnerabilities. Excluding vendored paths by
   convention would hide it.

4. **Per-ecosystem coverage.** Not every engine supports all four, so this is
   the fixture where ecosystems_covered and the Engine Coverage gaps become
   visible rather than theoretical.
