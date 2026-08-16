# npm-simple

The baseline fixture. Two direct npm dependencies, a lockfile, nothing unusual.

**What it proves:** the happy path. Every engine that claims npm support should
find exactly two components with correct PURLs. An engine that finds a different
number here has a parsing problem that would be invisible in a more complicated
fixture — which is the whole point of having a boring one.

lodash@4.17.21 and express@4.18.2 are pinned deliberately: both are widely
mirrored, and their PURLs are unambiguous across every tool.
