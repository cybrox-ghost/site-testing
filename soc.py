from __future__ import annotations

import csv
import ipaddress
import io
import json
import socket
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
import streamlit as st

import storage


APP_VERSION = "1.1.0"
USER_AGENT = f"SiteSentinel-SOC/{APP_VERSION} (passive security assessment)"
REQUEST_TIMEOUT = 8
MAX_REDIRECTS = 5
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


@dataclass(frozen=True)
class Finding:
	title: str
	severity: str
	category: str
	evidence: str
	remediation: str


def normalize_url(value: str) -> str:
	"""Normalize a web URL and reject schemes or authority forms we do not scan."""
	candidate = value.strip()
	if not candidate:
		raise ValueError("Enter a website URL to assess.")
	if "://" not in candidate:
		candidate = f"https://{candidate}"

	parsed = urlsplit(candidate)
	if parsed.scheme.lower() not in {"http", "https"}:
		raise ValueError("Only HTTP and HTTPS website URLs are supported.")
	if not parsed.hostname or parsed.username or parsed.password:
		raise ValueError("Enter a valid URL without embedded credentials.")
	try:
		port = parsed.port
	except ValueError as error:
		raise ValueError("The URL contains an invalid port.") from error
	if port is not None and not 1 <= port <= 65535:
		raise ValueError("The URL contains an invalid port.")

	path = parsed.path or "/"
	return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, parsed.query, ""))


def validate_public_destination(url: str) -> None:
	"""Prevent requests to loopback, private, or otherwise non-public IP addresses."""
	parsed = urlsplit(url)
	hostname = parsed.hostname
	if not hostname:
		raise ValueError("The destination URL has no hostname.")

	try:
		addresses = [ipaddress.ip_address(hostname)]
	except ValueError:
		try:
			resolved = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
		except socket.gaierror as error:
			raise ValueError(f"Could not resolve {hostname}: {error}") from error
		addresses = list({ipaddress.ip_address(result[4][0]) for result in resolved})

	if not addresses or any(not address.is_global for address in addresses):
		raise ValueError("Private, local, and non-public network destinations are blocked.")


def analyze_response_headers(headers: Any, final_url: str) -> list[Finding]:
	"""Return passive findings from response headers only; no page content is read."""
	findings: list[Finding] = []
	is_https = urlsplit(final_url).scheme == "https"
	header_names = {name.lower() for name in headers}
	csp = headers.get("Content-Security-Policy", "")

	if not is_https:
		findings.append(Finding(
			"Website is served over HTTP", "High", "Transport security",
			"The final response URL uses HTTP, so traffic can be read or modified in transit.",
			"Enable HTTPS with a valid certificate and redirect all HTTP requests to HTTPS.",
		))
	elif "strict-transport-security" not in header_names:
		findings.append(Finding(
			"HSTS header is missing", "Medium", "Transport security",
			"The HTTPS response does not include Strict-Transport-Security.",
			"Set a suitable Strict-Transport-Security max-age after confirming all subdomains support HTTPS.",
		))

	if "content-security-policy" not in header_names:
		findings.append(Finding(
			"Content Security Policy is missing", "Medium", "Browser protections",
			"No Content-Security-Policy header was present in the response.",
			"Define a restrictive Content-Security-Policy and test it in report-only mode before enforcement.",
		))
	if "x-content-type-options" not in header_names:
		findings.append(Finding(
			"MIME-sniffing protection is missing", "Low", "Browser protections",
			"X-Content-Type-Options was not present.",
			"Add X-Content-Type-Options: nosniff to responses.",
		))
	if "referrer-policy" not in header_names:
		findings.append(Finding(
			"Referrer policy is missing", "Low", "Privacy",
			"Referrer-Policy was not present.",
			"Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin.",
		))
	if "permissions-policy" not in header_names:
		findings.append(Finding(
			"Permissions Policy is missing", "Low", "Browser protections",
			"Permissions-Policy was not present.",
			"Explicitly disable browser features the site does not use with a Permissions-Policy header.",
		))
	if "x-frame-options" not in header_names and "frame-ancestors" not in csp.lower():
		findings.append(Finding(
			"Clickjacking protection is missing", "Medium", "Browser protections",
			"Neither X-Frame-Options nor a frame-ancestors CSP directive was present.",
			"Set X-Frame-Options or define frame-ancestors in Content-Security-Policy.",
		))
	if "server" in header_names:
		findings.append(Finding(
			"Web server header is exposed", "Info", "Information disclosure",
			f"Server: {headers.get('Server', 'present')}.",
			"Remove or generalize the Server response header where practical.",
		))
	if "x-powered-by" in header_names:
		findings.append(Finding(
			"Technology header is exposed", "Low", "Information disclosure",
			f"X-Powered-By: {headers.get('X-Powered-By', 'present')}.",
			"Remove the X-Powered-By response header to reduce technology fingerprinting.",
		))
	return findings


def inspect_cookies(response: requests.Response) -> list[Finding]:
	cookie_headers = response.raw.headers.getlist("Set-Cookie")
	missing_flags: set[str] = set()
	for cookie in cookie_headers:
		parts = cookie.lower().split(";")[1:]
		attributes = {part.strip().split("=", 1)[0] for part in parts}
		if "secure" not in attributes:
			missing_flags.add("Secure")
		if "httponly" not in attributes:
			missing_flags.add("HttpOnly")
		if not any(part.strip().startswith("samesite=") for part in parts):
			missing_flags.add("SameSite")

	if not missing_flags:
		return []
	severity = "Medium" if "Secure" in missing_flags else "Low"
	return [Finding(
		"Cookie security attributes are incomplete", severity, "Session security",
		"At least one Set-Cookie response is missing: " + ", ".join(sorted(missing_flags)) + ".",
		"Set Secure, HttpOnly, and an appropriate SameSite attribute on session cookies.",
	)]


def assess_site(raw_url: str) -> dict[str, Any]:
	start_url = normalize_url(raw_url)
	current_url = start_url
	started = time.perf_counter()
	redirect_count = 0
	session = requests.Session()
	session.trust_env = False
	response: requests.Response | None = None

	try:
		while True:
			validate_public_destination(current_url)
			response = session.get(
				current_url,
				headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
				timeout=REQUEST_TIMEOUT,
				allow_redirects=False,
				stream=True,
			)
			location = response.headers.get("Location")
			if response.status_code not in {301, 302, 303, 307, 308} or not location:
				break
			if redirect_count >= MAX_REDIRECTS:
				raise ValueError(f"The site exceeded the {MAX_REDIRECTS}-redirect limit.")
			next_url = normalize_url(urljoin(current_url, location))
			response.close()
			response = None
			current_url = next_url
			redirect_count += 1

		findings = analyze_response_headers(response.headers, current_url)
		findings.extend(inspect_cookies(response))
		counts = {severity: sum(item.severity == severity for item in findings) for severity in SEVERITIES}
		score = max(
			0,
			100 - counts["Critical"] * 35 - counts["High"] * 25
			- counts["Medium"] * 12 - counts["Low"] * 4 - counts["Info"],
		)
		return {
			"target": start_url,
			"final_url": current_url,
			"status_code": response.status_code,
			"elapsed_ms": round((time.perf_counter() - started) * 1000),
			"redirects": redirect_count,
			"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
			"score": score,
			"findings": findings,
		}
	finally:
		if response is not None:
			response.close()
		session.close()


def _finding_record(finding: Finding | dict[str, Any], target: str) -> dict[str, Any]:
	record = dict(finding) if isinstance(finding, dict) else asdict(finding)
	record["fingerprint"] = record.get("fingerprint") or storage.finding_fingerprint(
		target, record["category"], record["title"]
	)
	record["triage_status"] = storage.get_triage_status(record["fingerprint"])
	return record


def _save_triage(fingerprint: str, widget_key: str) -> None:
	storage.update_triage(fingerprint, st.session_state[widget_key])


def _assessment_export(assessment: dict[str, Any]) -> dict[str, Any]:
	finding_records = []
	for finding in assessment["findings"]:
		record = _finding_record(finding, assessment["target"])
		finding_records.append({
			key: value for key, value in record.items()
			if key not in {"id", "assessment_id", "fingerprint"}
		})
	return {
		**{key: value for key, value in assessment.items() if key != "findings"},
		"findings": finding_records,
	}


def _render_findings(assessment: dict[str, Any]) -> None:
	severity_order = {severity: index for index, severity in enumerate(SEVERITIES)}
	records = [_finding_record(item, assessment["target"]) for item in assessment["findings"]]
	selected_severities = st.multiselect(
		"Severity", SEVERITIES, default=list(SEVERITIES), key="finding_severity_filter"
	)
	selected_states = st.multiselect(
		"Triage state", storage.TRIAGE_STATES, default=list(storage.TRIAGE_STATES),
		key="finding_state_filter",
	)
	sort_order = st.selectbox("Sort findings", ["Severity", "Title"], key="finding_sort")
	filtered = [
		item for item in records
		if item["severity"] in selected_severities and item["triage_status"] in selected_states
	]
	if sort_order == "Title":
		filtered.sort(key=lambda item: item["title"].lower())
	else:
		filtered.sort(key=lambda item: (severity_order.get(item["severity"], 5), item["title"].lower()))

	if not filtered:
		st.info("No findings match the selected filters.")
		return

	for finding in filtered:
		with st.container(border=True):
			st.write(f"{finding['severity']} · {finding['title']}")
			st.caption(f"{finding['category']} · {finding['triage_status']}")
			st.write(f"Evidence: {finding['evidence']}")
			with st.expander("Remediation"):
				st.write(finding["remediation"])
			widget_key = f"triage_{finding['fingerprint']}"
			current_status = storage.get_triage_status(finding["fingerprint"])
			st.selectbox(
				"Workflow state", storage.TRIAGE_STATES,
				index=storage.TRIAGE_STATES.index(current_status),
				key=widget_key, on_change=_save_triage,
				args=(finding["fingerprint"], widget_key),
			)

	csv_buffer = io.StringIO()
	csv_fields = ("severity", "title", "category", "triage_status", "evidence", "remediation")
	csv_writer = csv.DictWriter(csv_buffer, fieldnames=csv_fields)
	csv_writer.writeheader()
	csv_writer.writerows({field: item[field] for field in csv_fields} for item in filtered)
	with st.container(horizontal=True):
		st.download_button(
			"Export assessment JSON", json.dumps(_assessment_export(assessment), indent=2),
			file_name="sitesentinel-assessment.json", mime="application/json",
			icon=":material/download:",
		)
		st.download_button(
			"Export filtered findings CSV", csv_buffer.getvalue(),
			file_name="sitesentinel-findings.csv", mime="text/csv",
			icon=":material/table_chart:",
		)


def render_app() -> None:
	st.set_page_config(page_title="SiteSentinel | SOC", page_icon=":material/security:", layout="wide")
	storage.initialize_db()
	st.session_state.setdefault("assessment", None)
	st.session_state.setdefault("assessment_id", None)
	st.session_state.setdefault("scan_error", None)

	with st.sidebar:
		st.title("SiteSentinel", icon=":material/security:")
		st.caption("SOC / web exposure")
		with st.form("assessment_form", border=False):
			target = st.text_input(
				"Assessment target", value="",
				placeholder="https://your-authorized-site.com",
			)
			run_scan = st.form_submit_button(
				"Run passive assessment", type="primary", icon=":material/search:",
			)
		st.subheader("Scope")
		st.caption("Public HTTP response metadata only")
		st.caption("No crawling, payloads, or page-body downloads")
		st.caption("Only assess systems you are authorized to test.")
		st.caption(f"SiteSentinel {APP_VERSION}")

	if run_scan:
		with st.status("Assessing the authorized public endpoint", expanded=True) as status:
			try:
				assessment = assess_site(target)
				assessment_id = storage.save_assessment(assessment)
				st.session_state.assessment = assessment
				st.session_state.assessment_id = assessment_id
				st.session_state.scan_error = None
				status.update(label="Assessment complete", state="complete", expanded=False)
			except (ValueError, requests.RequestException) as error:
				st.session_state.assessment = None
				st.session_state.assessment_id = None
				st.session_state.scan_error = str(error)
				status.update(label="Assessment failed", state="error")

	history = storage.list_assessments(limit=100)
	if st.session_state.assessment is None and history:
		st.session_state.assessment = storage.get_assessment(history[0]["id"])
		st.session_state.assessment_id = history[0]["id"]
	assessment = st.session_state.assessment
	if st.session_state.scan_error:
		st.error(st.session_state.scan_error)

	st.title("Web surface assessment", icon=":material/monitoring:")
	st.caption("Passive review of transport, browser protections, and analyst workflow state.")
	overview_tab, findings_tab, history_tab = st.tabs(
		["Overview", "Findings and triage", "Scan history"]
	)

	with overview_tab:
		if assessment is None:
			st.info("Run a passive assessment to start your site exposure review.")
			if history:
				st.caption(f"{len(history)} saved assessments are available in scan history.")
		else:
			records = [_finding_record(item, assessment["target"]) for item in assessment["findings"]]
			counts = {severity: sum(item["severity"] == severity for item in records)
					  for severity in SEVERITIES}
			open_count = sum(item["triage_status"] == "Open" for item in records)
			acknowledged_count = sum(item["triage_status"] == "Acknowledged" for item in records)
			col1, col2, col3, col4 = st.columns(4)
			col1.metric("Exposure score", f"{assessment['score']} / 100")
			col2.metric("Open findings", open_count, f"{counts['High']} high · {counts['Critical']} critical")
			col3.metric("Acknowledged", acknowledged_count)
			col4.metric("HTTP response", assessment["status_code"], f"{assessment['elapsed_ms']} ms")
			st.subheader("Severity profile")
			st.bar_chart(
				{"Severity": list(counts), "Findings": list(counts.values())},
				x="Severity", y="Findings", horizontal=True,
				alt="Finding counts grouped by severity",
			)
			st.caption(
				f"Target: {assessment['target']} · Last checked: {assessment['checked_at']} · "
				f"{assessment['redirects']} redirects followed"
			)
			origin = urlsplit(assessment["target"]).netloc.lower()
			trend = [
				item for item in history
				if urlsplit(item["target"]).netloc.lower() == origin
			][:20]
			trend.reverse()
			if len(trend) > 1:
				st.subheader("Exposure score trend")
				st.line_chart(
					{"Checked": [item["checked_at"] for item in trend],
					 "Exposure score": [item["score"] for item in trend]},
					x="Checked", y="Exposure score",
					alt="Exposure scores across previous assessments of this host",
				)

	with findings_tab:
		if assessment is None:
			st.info("No findings to triage yet. Run an assessment or load one from history.")
		else:
			_render_findings(assessment)

	with history_tab:
		st.subheader("Assessment history")
		if not history:
			st.info("Saved assessments will appear here after your first scan.")
		else:
			history_rows = [
				{
					"Checked": item["checked_at"], "Target": item["target"],
					"Status": item["status_code"], "Score": item["score"],
					"Findings": item["finding_count"], "Open": item["open_count"],
				}
				for item in history
			]
			st.dataframe(
				history_rows, hide_index=True,
				alt="Saved website assessments with scores and triage counts",
			)
			if len(history) > 1:
				oldest_first = list(reversed(history))
				st.line_chart(
					{"Checked": [item["checked_at"] for item in oldest_first],
					 "Exposure score": [item["score"] for item in oldest_first]},
					x="Checked", y="Exposure score",
					alt="Exposure score trend across saved assessments",
				)
			history_by_id = {item["id"]: item for item in history}
			selected_id = st.selectbox(
				"Load a saved assessment", list(history_by_id),
				format_func=lambda item_id: (
					f"{history_by_id[item_id]['checked_at']} · {history_by_id[item_id]['target']} "
					f"· score {history_by_id[item_id]['score']}"
				),
				key="history_selection",
			)
			if st.button("Load selected assessment", icon=":material/restore:"):
				st.session_state.assessment = storage.get_assessment(selected_id)
				st.session_state.assessment_id = selected_id
				st.rerun()
			st.download_button(
				"Export scan history JSON", json.dumps(history, indent=2),
				file_name="sitesentinel-history.json", mime="application/json",
				icon=":material/download:",
			)


if __name__ == "__main__":
	render_app()