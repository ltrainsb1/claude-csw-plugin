"""Pin PATH_ALIASES in bin/csw_api.py to the path/verb rows in the
'API surface variants' catalog of skills/csw/SKILL.md. Either source
of truth changing without the other is a bug."""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import csw_api  # noqa: E402

SKILL_MD = os.path.join(
    os.path.dirname(__file__), "..", "skills", "csw", "SKILL.md"
)

# Match the catalog rows. Format:
# | `POST /openapi/v1/<canonical>` | `<alt_method> /openapi/v1/<alt>` ... | <note> |
# We capture the canonical method/path and alt method/path.
ROW_RE = re.compile(
    r"^\|\s*`(GET|POST|PUT|DELETE)\s+(/openapi/v1/[^\s`]+)`"
    r"\s*\|\s*`(GET|POST|PUT|DELETE)\s+(/openapi/v1/[^\s`]+)`"
)


def _parse_catalog_rows():
    """Return list of (canonical_method, canonical_path, alt_method, alt_path)
    for each path/verb-rename row in the SKILL.md catalog.

    No section-walking state machine — ROW_RE is specific enough on its
    own that it ONLY matches catalog rows. Pre-flight WARN #2 verified
    this: the HIGH/MEDIUM/LOW write-tier tables in 'Mutating endpoints
    by risk tier' have backtick-wrapped METHOD/path in cell 1 but PLAIN
    DESCRIPTIVE TEXT in cell 2, so the second `(GET|POST|PUT|DELETE)
    /openapi/v1/...` group in ROW_RE never matches them. The catalog
    rows are the only lines in SKILL.md where BOTH cells are
    backtick-wrapped METHOD/path."""
    rows = []
    with open(SKILL_MD, "r") as f:
        for line in f:
            m = ROW_RE.match(line.strip())
            if m:
                rows.append((m.group(1), m.group(2), m.group(3), m.group(4)))
    return rows


class TestAliasCatalogSync(unittest.TestCase):
    def test_catalog_has_at_least_one_path_verb_row(self):
        rows = _parse_catalog_rows()
        self.assertTrue(
            len(rows) > 0,
            "expected at least one path/verb-rename row in the catalog "
            f"(parsed from {SKILL_MD})",
        )

    def test_every_catalog_row_appears_in_path_aliases(self):
        catalog = _parse_catalog_rows()
        alias_set = {tuple(row) for row in csw_api.PATH_ALIASES}
        for row in catalog:
            self.assertIn(
                row,
                alias_set,
                f"catalog row {row} missing from PATH_ALIASES",
            )

    def test_every_path_aliases_row_appears_in_catalog(self):
        catalog_set = set(_parse_catalog_rows())
        for row in csw_api.PATH_ALIASES:
            self.assertIn(
                tuple(row),
                catalog_set,
                f"PATH_ALIASES row {row} missing from SKILL.md catalog",
            )

    def test_counts_match(self):
        catalog = _parse_catalog_rows()
        self.assertEqual(
            len(catalog),
            len(csw_api.PATH_ALIASES),
            "catalog and PATH_ALIASES have different row counts — out of sync",
        )


if __name__ == "__main__":
    unittest.main()
