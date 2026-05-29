"""Pin the ENDPOINT_MATRIX in bin/csw_api.py to the Deploy column
in skills/csw/api-reference.md. Either source of truth changing without
the other is a bug."""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import csw_api  # noqa: E402

API_REF = os.path.join(
    os.path.dirname(__file__), "..", "skills", "csw", "api-reference.md"
)

# Match rows like: | METHOD | `/path` | desc | S |
ROW_RE = re.compile(
    r"^\|\s*(GET|POST|PUT|DELETE)\s*\|\s*`([^`]+)`\s*\|[^|]*\|\s*([BSH])\s*\|"
)


def _parse_doc_rows():
    with open(API_REF, "r") as f:
        rows = []
        for line in f:
            m = ROW_RE.match(line.strip())
            if not m:
                continue
            method, path, deploy = m.group(1), m.group(2), m.group(3)
            # Doc paths are relative to /openapi/v1; matrix is full.
            if path.startswith("/openapi/v1"):
                full = path
            else:
                full = "/openapi/v1" + path
            rows.append((method, full, deploy))
        return rows


class TestMatrixSync(unittest.TestCase):
    def test_doc_non_both_rows_match_matrix(self):
        doc_rows = _parse_doc_rows()
        self.assertTrue(len(doc_rows) > 0, "no parseable rows in api-reference.md")

        # Doc rows marked S => matrix should have {'saas'}.
        # Doc rows marked H => matrix should have {'selfhosted'}.
        # Doc rows marked B should NOT appear in matrix.
        for method, path, deploy in doc_rows:
            matrix_row = csw_api._match_endpoint(method, path)
            if deploy == "B":
                self.assertIsNone(
                    matrix_row,
                    f"{method} {path} is B in doc but appears in matrix",
                )
            elif deploy == "S":
                self.assertIsNotNone(
                    matrix_row, f"{method} {path} is S in doc but missing from matrix"
                )
                self.assertEqual(matrix_row[2], frozenset({"saas"}))
            elif deploy == "H":
                self.assertIsNotNone(
                    matrix_row, f"{method} {path} is H in doc but missing from matrix"
                )
                self.assertEqual(matrix_row[2], frozenset({"selfhosted"}))

    def test_matrix_rows_appear_in_doc(self):
        doc_paths = {(m, p) for (m, p, _) in _parse_doc_rows()}
        for method, path, _ in csw_api.ENDPOINT_MATRIX:
            self.assertIn(
                (method, path),
                doc_paths,
                f"{method} {path} in matrix but missing from api-reference.md",
            )


if __name__ == "__main__":
    unittest.main()
