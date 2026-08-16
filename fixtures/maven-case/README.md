# maven-case

WARNING: MAVEN COORDINATES ARE CASE-SENSITIVE.

npm lowercases. PyPI normalizes per PEP 503. Maven does NEITHER: commons-lang3
and Commons-Lang3 are different artifacts, and org.apache.commons is not
org.Apache.Commons.

**What it proves:** that normalization is PER-ECOSYSTEM, not one lowercase pass
applied everywhere. A normalizer that lowercases uniformly will merge Maven
artifacts that are genuinely distinct — producing a component count that is too
LOW, which is the more dangerous direction: a missing component is a missing
vulnerability, and nothing in the report says anything is absent.

The project's own artifactId (MavenCase) is mixed-case on purpose, so the root
component exercises the same rule.
