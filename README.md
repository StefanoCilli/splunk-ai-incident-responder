# Splunk AI Incident Responder

**1. Executive Summary**

In this project, I engineered an automated incident response (SOAR) playbook that bridges the gap between static SIEM logs and active threat analysis. The script programmatically connects to a local Splunk instance via API, extracts historical SSH brute-force logs, uses the Gemini AI engine to generate tactical context, and dispatches an automated triage report to the analyst's inbox.

---

**2. Project Ecosystem**

This automation layer functions as Part 2 of my modular home lab security architecture.

* **Part 1: Splunk-BruteForce-Detection** — Focused on building the underlying logging infrastructure, configuring an active Linux Ubuntu forwarder to collect raw authentication data (auth.log), and parsing it into a centralized Splunk index.
* **Part 2: (This Repository)** — Focuses on automated orchestration and response, leveraging programmatic API integration to turn static detection data into rapid, intelligent triage.

---

**3. Environment & Pipeline Architecture**

* **Data Ingestion:** A local Python orchestration script queries the Splunk management port (8089) using the splunklib SDK framework.
* **Threat Intelligence:** Raw log payloads are parsed and delivered securely to the Google Gemini AI interface via the google-genai library.
* **Alert Dispatch:** Validated security intelligence summaries are formatted into an automated payload and routed to a dedicated inbox using a secure Gmail SMTP SSL channel.

---

**4. Core Technical Implementations**

* **A. Production-Grade API Integration:** To match enterprise deployment standards, all sensitive operational details—including API credentials, access tokens, and mail handles were completely decoupled from the source code. The script dynamically binds to volatile environment variables during execution, ensuring zero risk of credential exposure within public version control logs.
* **B. Resilient Infrastructure Pacing:** To handle remote API infrastructure stress and network latency, I implemented an automated retry loop using an exponential backoff pacing mechanism. If the script encounters a temporary 503 Service Unavailable spike from the AI engine, it halts execution, sleeps for a variable delay, and incrementally scales the wait time across multiple attempts to ensure delivery without crashing the workflow.
* **C. Licensing Workaround Layer:** Working within the constraints of the Splunk Free Tier required bypassing typical enterprise credential blocks on management interfaces. I structured the connection method to explicitly pass an unauthenticated administrative map (username="admin", password=""), which allows the script to successfully pull data over the local network stack while keeping the database restricted from open access.

---

**5. Local Configuration & Usage**

* **Prerequisite Software Setup:** Before executing the script, install the required automation and platform packages:
  `pip install google-genai splunk-sdk`

* **Shell Initialization Sequence:** Load the required deployment keys and email paths into your active terminal process space using the following commands:
  `$env:GEMINI_API_KEY="your_actual_gemini_api_key"`
  `$env:GMAIL_ALERT_PASS="your_16_character_gmail_app_password"`
  `$env:ALERT_SENDER="soc-alert-sender@example.com"`
  `$env:ALERT_RECEIVER="soc-analyst@example.com"`

* **Playbook Execution:** Launch the automation pipeline:
  `python soc_alert.py`

---

**6. Cybersecurity Skills Demonstrated**

* **SOAR Engineering:** Designed an end-to-end automated orchestration pipeline to reduce incident triage turnaround time.
* **Defensive Scripting:** Built robust error-handling, retry intervals, and file fallback validation logic in Python.
* **Secure Configuration Management:** Followed strict access control principles by keeping API tokens and addresses entirely out of static repositories.
