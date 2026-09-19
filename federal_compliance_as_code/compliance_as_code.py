import argparse
import csv
import json
from datetime import date, datetime, timedelta
from pathlib import Path


SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}


def parse_date(value):
    return datetime.strptime(value, "%Y-%m-%d").date() if value else None


def validate_catalog(catalog, schema):
    errors = [f"Missing catalog field: {key}" for key in schema["required"] if key not in catalog]
    if not isinstance(catalog.get("controls", []), list):
        errors.append("controls must be a list")
        return errors
    for index, control in enumerate(catalog["controls"]):
        for key in schema["control_required"]:
            if key not in control:
                errors.append(f"controls[{index}] missing {key}")
    return errors


def load_csv(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def run(project_dir, as_of):
    output = project_dir / "output"; output.mkdir(exist_ok=True)
    catalog = json.loads((project_dir / "control_catalog.json").read_text())
    schema = json.loads((project_dir / "control_catalog.schema.json").read_text())
    errors = validate_catalog(catalog, schema)
    if errors:
        raise ValueError("; ".join(errors))

    evidence = load_csv(project_dir / "evidence_inventory.csv")
    evidence_by_control = {}
    for item in evidence:
        next_review = parse_date(item["next_review_date"])
        normalized = item["status"]
        if next_review and next_review < as_of and normalized == "Current": normalized = "Stale"
        item["normalized_status"] = normalized
        evidence_by_control.setdefault(item["control_id"], []).append(item)

    matrix = []
    for control in catalog["controls"]:
        items = evidence_by_control.get(control["control_id"], [])
        statuses = {i["normalized_status"] for i in items}
        readiness = "Gap" if not items or "Missing" in statuses else "Needs Review" if statuses & {"Partial", "Stale"} else "Ready"
        matrix.append({"control_id":control["control_id"],"framework":control["framework"],"owner":control["owner"],"implementation":control["implementation"],"evidence_count":len(items),"readiness":readiness})
    write_csv(output / "control_matrix.csv", matrix, list(matrix[0]))
    (output / "evidence_index.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    findings = load_csv(project_dir / "vulnerability_findings.csv")
    poam = []
    for finding in findings:
        due = parse_date(finding["first_seen"]) + timedelta(days=SLA_DAYS[finding["severity"]])
        finding["sla_due"] = due.isoformat()
        finding["sla_status"] = "Closed" if finding["status"] in {"Remediated", "Accepted"} else "Overdue" if due < as_of else "Open"
        finding["closure_validated"] = "Yes" if finding["status"] == "Remediated" and finding["validation_evidence"] else "No"
        if finding["status"] not in {"Remediated", "Accepted"}:
            poam.append({"finding_id":finding["finding_id"],"source":finding["source"],"asset":finding["asset"],"severity":finding["severity"],"jira_ticket":finding["jira_ticket"],"owner":finding["owner"],"sla_due":finding["sla_due"],"sla_status":finding["sla_status"],"planned_action":"Remediate, validate closure, and retain audit evidence"})
    write_csv(output / "vulnerability_reconciliation.csv", findings, list(findings[0]))
    write_csv(output / "poam.csv", poam, list(poam[0]))

    change = json.loads((project_dir / "change_request.json").read_text())
    affected = ", ".join(change["controls_affected"])
    actions = "\n".join(f"- [ ] {x}" for x in change["required_actions"])
    sia = f"# Security Impact Assessment\n\n**Change:** {change['change_id']} - {change['title']}\n\n**Decision:** {change['decision']}\n\n## Security and compliance impact\n\nAffected controls: {affected}\n\n" + "\n".join(f"- {x}" for x in change["security_impacts"]) + f"\n\n## Required actions\n\n{actions}\n"
    (output / "security_impact_assessment.md").write_text(sia, encoding="utf-8")
    sdr = f"# Security Decision Record\n\n**Decision ID:** SDR-{change['change_id']}\n\n**Status:** Pending\n\n**Decision:** Do not approve production implementation until required security evidence is complete and reviewed.\n\n**Rationale:** The change affects {affected} and introduces identity, logging, vulnerability, and boundary-documentation dependencies.\n"
    (output / "security_decision_record.md").write_text(sdr, encoding="utf-8")
    summary = {"as_of":as_of.isoformat(),"system":catalog["system"],"controls":len(matrix),"control_gaps":sum(x["readiness"]!="Ready" for x in matrix),"open_vulnerabilities":len(poam),"overdue_vulnerabilities":sum(x["sla_status"]=="Overdue" for x in poam),"change_decision":change["decision"]}
    (output / "conmon_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (output / "authorization_summary.md").write_text("# Federal Compliance Authorization Summary\n\n" + "\n".join(f"- **{k.replace('_',' ').title()}:** {v}" for k,v in summary.items()) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-dir", type=Path, default=Path("."))
    parser.add_argument("--as-of", type=parse_date, default=date.today())
    args = parser.parse_args(); print(json.dumps(run(args.project_dir, args.as_of), indent=2))
