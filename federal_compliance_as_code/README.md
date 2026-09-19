# Federal Compliance as Code Portfolio

Personal portfolio project by Damian Probity Enyaosah.

This Python prototype demonstrates structured federal compliance operations using synthetic data. It validates a machine-readable JSON control catalog, indexes evidence, reconciles vulnerability findings from illustrative Wiz, Nessus, and Burp exports, tracks Jira routing and SLA status, generates POA&M-ready records, and produces deterministic Markdown authorization and security-impact artifacts.

## Demonstrated workflow

1. Validate required fields and types in the JSON control catalog.
2. Link FedRAMP and NIST SP 800-53 controls to owners, implementation narratives, evidence, and review cadence.
3. Flag missing, stale, or incomplete evidence.
4. Reconcile vulnerability findings, assign risk-based SLAs, preserve Jira references, and track validation status.
5. Generate an evidence index, control matrix, POA&M, continuous-monitoring summary, Security Decision Record, and Security Impact Assessment.

## Run

```bash
python compliance_as_code.py --project-dir . --as-of 2026-09-12
python -m unittest discover -s tests -v
```

## Scope boundary

All records are synthetic. The project does not represent production FedRAMP authorization work, a 3PAO assessment, AWS GovCloud access, live integrations with Wiz, Jira, Splunk, Okta, GitLab, or Burp, or validation against the official OSCAL schemas. Framework references are illustrative and require authoritative source review and assessor confirmation.
