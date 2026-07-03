import os
import sys
import smtplib
from email.message import EmailMessage
from google import genai
import splunklib.client as client 

def query_splunk_logs():
    
    # Connects to Splunk API and fetches historical brute force telemetry across All Time. #

    try:
        # Pull Splunk connection settings from OS environment variables safely
        host = os.environ.get("SPLUNK_HOST", "localhost")
        port = int(os.environ.get("SPLUNK_PORT", "8089"))
        # Not needed for free tier Splunk
        #token = os.environ.get("SPLUNK_TOKEN")
        
        #1 Establish authenticated connection to the Splunk Management Port
        service = client.connect(
            host=host, 
            port=port,
            username="admin",
            password="")

        #2 Define SPL query
        spl_query = "search index=main source=\"/var/log/auth.log\" \"Failed password\" | head 10"

        print("Querying Splunk instance for historical auth failures (All Time)...")

        # Look from the oldest logs
        search_job = service.jobs.oneshot(spl_query, earliest_time="0", latest_time="now", output_mode="json")

        import splunklib.results as results
        reader = results.JSONResultsReader(search_job)

        splunk_logs = ""
        for result in reader:
            if isinstance(result, dict):
                # Extract raw log string
                splunk_logs += result.get('_raw', '') + "\n"

        return splunk_logs if splunk_logs.strip() else None
    
    except Exception as e:
        print(f"Splunk Connection Error: {e}")
        return None
    

def analyze_and_alert():

    #1 Setting main variables:

    gemini_key = os.environ.get("GEMINI_API_KEY")
    gmail_app_pass = os.environ.get("GMAIL_ALERT_PASS")

    sender_email = os.environ.get("ALERT_SENDER","soc-alert-sender@example.com")
    receiver_email = os.environ.get("ALERT_RECEIVER","soc-analyst@example.com")

    if not gemini_key or not gmail_app_pass:
        print("Error: Missing system environment variables! Set your keys first.")
        return

    #2 Setting the logs in a variable, either from a source or the hardcoded example logs:

    print("Gathering security telemetry...")
    splunk_data = query_splunk_logs()


    if splunk_data:
        log_payload = splunk_data
        print("Successfully pulled historical event telemetry from Splunk.")
    elif len(sys.argv) > 1:
        log_payload = sys.argv[1]
        print("Using manual log payload provided via terminal arguments.")
    else:
        log_payload = (
            "Jul 02 16:10:01 server1 sshd[4012]: Failed password for root from 185.220.101.5 port 49152 ssh2\n"
            "Jul 02 16:10:12 server1 sshd[4015]: Failed password for root from 185.220.101.5 port 49210 ssh2\n"
            "Jul 02 16:10:25 server1 sshd[4019]: Failed password for root from 185.220.101.5 port 49302 ssh2\n"
            "Jul 02 16:10:38 server1 sshd[4022]: Failed password for root from 185.220.101.5 port 49398 ssh2\n"
            "Jul 02 16:10:51 server1 sshd[4025]: Failed password for root from 185.220.101.5 port 49450 ssh2"
        )
    #3 Connecting to Gemini and prompting it while adding a retry loop in case of busy servers:

    import time

    max_retries = 3
    retry_delay = 4 # seconds to wait before retry

    print("Analyzing raw logs with Gemini...")
    for attempt in range(max_retries):
        try:
            client = genai.Client(api_key=gemini_key)
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=f"""
                You are a senior SOC Analyst. Analyze the following rapid authentication failure logs.
                Provide a strict 3-sentence summary highlighting:
                1. The targeted user profile and attack behavior pattern.
                2. The malicious source IP.
                3. A technical mitigation step (e.g., specific iptables or UFW ban rule).

                Logs:
                {log_payload}
                """
            )
            ai_analysis = response.text
            break

        except Exception as e:
            if "503" in str(e) and attempt < max_retries - 1:
                print(f"Google API is busy (Attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay *= 2 # doubling the wait time for the next attempt
            else:
                print(f"AI Generation Failed: {e}")
                return
    
    #4 Drafting email alert:

    msg = EmailMessage()
    msg['Subject'] = 'CRITICAL ALERT: SSH Brute Force Threshold Exceeded'
    msg['From'] = sender_email
    msg['To'] = receiver_email

    email_body = f"""SIEM TRIGGER: 5+ Authentication Failures in under 1 Minute.

=== AUTOMATED INCIDENT RESPONSE SUMMARY ===
{ai_analysis}

=== RAW SECURITY TELEMETRY DATA ===
{log_payload}
"""

    msg.set_content(email_body)

    #5 Sending email alert:

    print("Dispatching priority threat report to inbox...")
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, gmail_app_pass)
            server.send_message(msg)
        print("Success! Incident analysis report sent successfully.")
    except Exception as e:
        print(f"SMTP Mail Dispatch Failed: {e}")

#0 Checking if script is running from original source

if __name__ == "__main__":
    analyze_and_alert()