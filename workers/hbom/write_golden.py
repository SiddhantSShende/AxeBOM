"""Write the HBOM golden.

⚠ RUN DELIBERATELY, AND JUSTIFY THE RESULT IN THE COMMIT MESSAGE.

A golden exists to make an unintended change in canonical output impossible to
miss. Regenerating it because a test went red defeats that entirely — the red
test WAS the signal. Regenerate only when the change to the output is the thing
you meant to make, and say in the commit what changed and why.

    python -m workers.hbom.write_golden
"""

from __future__ import annotations

import json

from .test_golden import EXPECTED, canonical


def main() -> None:
    payload = canonical()
    # sort_keys and a trailing newline: the file is diffed by humans and by CI,
    # and a golden whose key order depends on dict insertion is a golden that
    # produces spurious diffs.
    EXPECTED.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {EXPECTED}")
    print(f"  {payload['component_count']} components, {payload['max_depth'] + 1} levels")
    print(
        f"  completeness {payload['coverage']['completeness_pct']}% · "
        f"declaration {payload['coverage']['declaration_pct']}%"
    )
    print("\nJustify this change in the commit message.")


if __name__ == "__main__":
    main()
