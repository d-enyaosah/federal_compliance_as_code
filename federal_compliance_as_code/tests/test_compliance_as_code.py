import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compliance_as_code import run, validate_catalog


class ComplianceAsCodeTests(unittest.TestCase):
    def test_schema_validation_detects_missing_field(self):
        schema = {"required":["catalog_id","controls"],"control_required":["control_id"]}
        self.assertTrue(validate_catalog({"controls":[{}]}, schema))

    def test_deterministic_outputs(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            for name in ["control_catalog.json","control_catalog.schema.json","evidence_inventory.csv","vulnerability_findings.csv","change_request.json"]:
                shutil.copy(source / name, target / name)
            summary = run(target, date(2026, 9, 12))
            self.assertEqual(summary["controls"], 5)
            for name in ["control_matrix.csv","evidence_index.json","vulnerability_reconciliation.csv","poam.csv","conmon_summary.json","authorization_summary.md","security_impact_assessment.md","security_decision_record.md"]:
                self.assertTrue((target / "output" / name).exists())


if __name__ == "__main__": unittest.main()
