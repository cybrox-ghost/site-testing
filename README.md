# SiteSentinel SOC

A SOC analyst dashboard for reviewing common website security controls. It checks
public HTTP response metadata and provides severity-based findings, durable triage,
assessment history, score trends, and JSON/CSV exports.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run soc.py
```

Open the local URL printed by Streamlit, enter a site you are authorized to
assess, and select **Run passive assessment**. The target is intentionally blank
until you enter it.

## Assessment scope

- Requests the target homepage and follows at most five redirects.
- Reviews transport security, browser security headers, selected information
	disclosure headers, and `Set-Cookie` security attributes.
- Does not crawl, download page bodies, submit forms, send exploit payloads, or
	run port scans. Requests have an 8-second timeout.
- Blocks loopback, private, and non-public destinations, including redirect
	targets. TLS certificate verification remains enabled.
- The exposure score is a triage aid, not a penetration test or certification.
- Assessments and triage states are stored locally in `sitesentinel.db`; the file
	is excluded from Git. Back it up if you need to preserve local history.

Only assess systems for which you have authorization. A passive header review
cannot establish that a site is free of vulnerabilities.