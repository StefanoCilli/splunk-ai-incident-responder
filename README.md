# splunk-ai-incident-responder
An automated incident response (SOAR) playbook that connects to a local Splunk SIEM instance, extracts live SSH brute-force telemetry via the Splunk API, uses the Gemini AI engine for high-context threat analysis, and dispatches a prioritized alert report via Gmail SMTP.
