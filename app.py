from flask import Flask, render_template, request, jsonify
from markupsafe import Markup
import imaplib
import email
from email.header import decode_header
import chardet
import logging
import joblib
import shap
import pandas as pd
import re
import requests
import socket
import pyclamd
import base64
import time

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

model = joblib.load('model/email_classifier.pkl')

df_sample = pd.DataFrame({
    'text': ["sample email text here"],
    'label': [0]
})

# Vectorize the sample text
vectorizer = model.named_steps['tfidfvectorizer']
X_sample = vectorizer.transform(df_sample['text'])

# Initialize SHAP KernelExplainer
explainer = shap.KernelExplainer(
    model.named_steps['multinomialnb'].predict_proba, X_sample)

VIRUSTOTAL_API_KEY = '49d02db367a9801a6286f7f01c214b43fe875c75fb2fa9e3742c767425d84e99'


def decode_subject(subject):
    decoded_bytes, encoding = decode_header(subject)[0]
    if isinstance(decoded_bytes, bytes):
        return decoded_bytes.decode(encoding or 'utf-8')
    return decoded_bytes


def decode_body(body):
    try:
        return body.decode('utf-8')
    except UnicodeDecodeError:
        encoding = chardet.detect(body)['encoding']
        return body.decode(encoding)


def extract_ip_address(email_message):
    """
    Extract the IP address from the email's 'Received' headers.
    """
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    received_headers = email_message.get_all('Received')
    if received_headers:
        for header in received_headers:
            ips = ip_pattern.findall(header)
            if ips:
                return ips[0]  # Return the first found IP address
    return "No IP found"


def reverse_ip(ip):
    """Reverse the IP address to prepare it for a DNSBL query."""
    return '.'.join(reversed(ip.split('.')))


def check_ip_blacklist(ip):
    """Check if an IP address is blacklisted using common DNSBLs."""
    dnsbls = [
        'zen.spamhaus.org',
        'bl.spamcop.net',
        'b.barracudacentral.org',
        'dnsbl.sorbs.net'
    ]

    reversed_ip = reverse_ip(ip)
    blacklisted_in = []

    for dnsbl in dnsbls:
        query = f"{reversed_ip}.{dnsbl}"
        try:
            # Perform DNS query
            socket.gethostbyname(query)
            blacklisted_in.append(dnsbl)
        except socket.gaierror:
            # If the DNS query fails, the IP is not listed in this DNSBL
            continue

    if blacklisted_in:
        return True, blacklisted_in
    else:
        return False, []


def get_isp_from_iplocation(ip):
    """Get the ISP information of an IP address using iplocation.net."""
    iplocation_url = f'https://api.iplocation.net/?ip={ip}'
    try:
        response = requests.get(iplocation_url)
        data = response.json()
        # Extract only the ISP information
        return {'isp': data.get('isp')}
    except Exception as e:
        logging.error(
            f"Error retrieving ISP from iplocation.net for IP {ip}: {e}")
        return {}


def get_ip_location(ip):
    """Get the geolocation of an IP address using the original API."""
    API_KEY = '2fb305d2aab87077719a5df189ef6594'
    original_api_url = f'http://api.ipapi.com/{ip}?access_key={API_KEY}'
    try:
        response = requests.get(original_api_url)
        original_data = response.json()
    except Exception as e:
        logging.error(
            f"Error retrieving location from original API for IP {ip}: {e}")
        original_data = {}
    # Fetch ISP information from iplocation.net
    isp_data = get_isp_from_iplocation(ip)
    threat_data = check_ip_threat_level(ip)
    # Combine the two sets of data
    combined_data = {**original_data, **isp_data, **threat_data}
    return combined_data


def extract_attachments(msg):
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            attachment_data = {
                "filename": filename,
                "content_type": part.get_content_type(),
                "payload": part.get_payload(decode=True),
                "is_malicious": False,
                "virus_name": None
            }
            attachments.append(attachment_data)
    return attachments


def scan_attachment_for_viruses(attachment_data):
    try:
        cd = pyclamd.ClamdAgnostic()
        scan_result = cd.scan_stream(attachment_data["payload"])
        if scan_result:
            attachment_data["is_malicious"] = True
            attachment_data["virus_name"] = scan_result.get(
                'stream', {}).get('engine')
    except Exception as e:
        logging.error(f"Error scanning attachment for viruses: {e}")


def extract_links_from_text(text):
    # Regular expression to match URLs
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.findall(text)


def check_url_with_virustotal(url):
    vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    try:
        response = requests.get(vt_url, params=params)
        result = response.json()
        # Handle rate limiting
        if response.status_code == 204:
            logging.error(
                "Rate limit exceeded. Waiting for a minute before retrying.")
            time.sleep(60)
            response = requests.get(vt_url, params=params)
            result = response.json()
        if result['response_code'] == 1:
            positives = result.get('positives', 0)
            total = result.get('total', 0)
            return f"Detected by {positives}/{total} scans"
        else:
            return "No data available"
    except Exception as e:
        logging.error(f"Error checking URL with VirusTotal: {e}")
        return "Error checking URL"


def scan_url_with_virustotal(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    # Encoding the URL
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    scan_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        response = requests.get(scan_url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            last_analysis_stats = result['data']['attributes']['last_analysis_stats']
            reputation = result['data']['attributes']['reputation']
            categories = result['data']['attributes']['categories']
            return {
                "reputation": reputation,
                "categories": categories,
                "malicious": last_analysis_stats['malicious'],
                "suspicious": last_analysis_stats['suspicious'],
                "harmless": last_analysis_stats['harmless']
            }
        elif response.status_code == 204:
            return {"error": "No content available for this URL, or rate limit exceeded."}
        else:
            return {"error": f"Failed to scan URL. Status code: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking URL with VirusTotal: {e}")
        return {"error": "An error occurred while contacting VirusTotal."}


def fetch_emails(username, app_password, imap_server, mailbox='INBOX', start=0, num_emails=10):
    emails = []
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, app_password)
        mail.select(mailbox)
        status, messages = mail.search(None, 'ALL')
        email_ids = messages[0].split()
        logging.debug(f"Found {len(email_ids)} emails")
        # Fetch a subset of emails
        latest_email_ids = email_ids[-(start + num_emails)                                     : -start] if start > 0 else email_ids[-num_emails:]
        for email_id in reversed(latest_email_ids):
            status, msg_data = mail.fetch(email_id, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = decode_subject(msg['Subject'])
                    from_ = decode_subject(msg.get('From'))
                    date = msg['Date']
                    email_content = {
                        "id": email_id.decode(),
                        "subject": subject,
                        "from": from_,
                        "body": "",
                        "date": date
                    }
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            try:
                                body = part.get_payload(decode=True)
                                if body:
                                    email_content["body"] += decode_body(body)
                            except Exception as e:
                                logging.error(f"Error decoding part: {e}")
                    else:
                        content_type = msg.get_content_type()
                        body = msg.get_payload(decode=True)
                        if body:
                            email_content["body"] = decode_body(body)
                    # Get the phishing probability and classification
                    phishing_proba, classification = classify_email(
                        email_content['body'])
                    email_content['phishing_probability'] = phishing_proba
                    email_content['classification'] = classification
                    email_content["snippet"] = email_content["body"][:100] + \
                        '...' if len(
                            email_content["body"]) > 100 else email_content["body"]
                    emails.append(email_content)
        mail.close()
        mail.logout()
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    return emails


def classify_email(text):
    proba = model.predict_proba([text])[0]
    phishing_proba = round(proba[1] * 100)
    if phishing_proba <= 40:
        classification = "safe"
    elif 40 < phishing_proba <= 70:
        classification = "suspicious"
    else:
        classification = "phishing"
    return phishing_proba, classification


def check_ip_threat_level(ip):
    """Check the security threat level of an IP address using AbuseIPDB."""
    api_key = 'bf80bd4c7daee2a88675972ac2d08318e1e8a99a699199c3eba88fd38ddd138cb9114297418faaa9'
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key,
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90  # Check reports within the last 90 days
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        if response.status_code == 200:
            threat_score = data.get('data', {}).get('abuseConfidenceScore')
            return {
                'threat_level': threat_score,
                'reports': data.get('data', {}).get('totalReports'),
                'categories': data.get('data', {}).get('categories')
            }
        else:
            logging.error(f"Error checking threat level for IP {ip}: {data}")
            return {}
    except Exception as e:
        logging.error(
            f"Error retrieving threat level from AbuseIPDB for IP {ip}: {e}")
        return {}


@app.route('/api/ip-threat/<ip_address>')
def api_ip_threat(ip_address):
    # Check the security threat level of the IP address
    threat_info = check_ip_threat_level(ip_address)
    return jsonify(threat_info)


def highlight_phishing_areas(text):
    # Vectorize the text
    vectorized_text = vectorizer.transform([text])
    # Use SHAP to explain the prediction
    shap_values = explainer.shap_values(vectorized_text, nsamples=100)
    # Get the SHAP values for the words
    words = text.split()
    # Assuming '1' is the label for phishing
    shap_values_for_text = shap_values[1][0]
    # Highlight words with high SHAP values
    highlighted_text = ""
    for i, word in enumerate(words):
        if i < len(shap_values_for_text) and shap_values_for_text[i] > 0:
            highlighted_text += f'<mark>{word}</mark> '
        else:
            highlighted_text += word + ' '
    return highlighted_text


def fetch_email_by_id(username, app_password, imap_server, email_id, mailbox='INBOX'):
    email_content = {}
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, app_password)
        mail.select(mailbox)
        status, msg_data = mail.fetch(email_id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject = decode_subject(msg['Subject'])
                from_ = decode_subject(msg.get('From'))
                date = msg['Date']
                # Extract the IP address
                ip_address = extract_ip_address(msg)
                # Check if the IP address is blacklisted
                is_blacklisted, blacklisted_in = check_ip_blacklist(ip_address)
                # Extract and prepare attachments
                attachments = extract_attachments(msg)
                # Initialize reasons for marking an email as suspicious
                suspicious_reasons = []
                email_content = {
                    "subject": subject,
                    "from": from_,
                    "body": "",
                    "date": date,
                    "ip_address": ip_address,
                    "is_blacklisted": is_blacklisted,
                    "blacklisted_in": blacklisted_in,  # List of DNSBLs where the IP is blacklisted
                    "attachments": attachments,
                    "links": [],  # Placeholder for extracted links
                    "reply_status": "Safe",  # Default reply status
                    "suspicious_reasons": suspicious_reasons
                }
                # Check if this is a reply and if it's to the same person
                to_addresses = msg.get_all('To', [])
                if 'In-Reply-To' in msg or 'References' in msg:
                    if any(from_ in to_address for to_address in to_addresses):
                        email_content['reply_status'] = "Safe"
                    else:
                        email_content['reply_status'] = "Suspicious"
                        suspicious_reasons.append(
                            "The reply is not addressed to the original sender.")
                else:
                    email_content['reply_status'] = "Suspicious"
                    suspicious_reasons.append(
                        "The email does not appear to be a reply, or the reply does not include references to the original conversation.")
                if is_blacklisted:
                    email_content['reply_status'] = "Suspicious"
                    suspicious_reasons.append(
                        f"The sender's IP address is blacklisted in the following DNSBL(s): {', '.join(blacklisted_in)}")
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        try:
                            body = part.get_payload(decode=True)
                            if body:
                                decoded_body = decode_body(body)
                                email_content["body"] += decoded_body
                                # Extract links from the body, but do not scan them yet
                                links = extract_links_from_text(decoded_body)
                                for link in links:
                                    email_content["links"].append(
                                        {"url": link, "vt_result": "Not yet scanned"})
                        except Exception as e:
                            logging.error(f"Error decoding part: {e}")
                else:
                    content_type = msg.get_content_type()
                    body = msg.get_payload(decode=True)
                    if body:
                        decoded_body = decode_body(body)
                        # Extract links from the body, but do not scan them yet
                        links = extract_links_from_text(decoded_body)
                        for link in links:
                            email_content["links"].append(
                                {"url": link, "vt_result": "Not yet scanned"})
                # Get phishing probability and highlight areas
                phishing_proba, classification = classify_email(
                    email_content['body'])
                email_content['phishing_probability'] = phishing_proba
                email_content['body'] = Markup(
                    highlight_phishing_areas(email_content['body']))
        mail.close()
        mail.logout()
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    return email_content


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/fetch-emails', methods=['POST'])
def fetch_emails_route():
    username = request.form.get('username')
    app_password = request.form.get('app_password')
    imap_server = request.form.get('imap_server')
    start = int(request.form.get('start', 0))  # Get the 'start' parameter
    # Input validation (basic example)
    if not all([username, app_password, imap_server]):
        logging.error("Missing credentials or server information.")
        return jsonify({'error': 'Missing necessary parameters'}), 400
    logging.debug(
        f"Fetching emails for user: {username} with server: {imap_server} starting from {start}")
    try:
        emails = fetch_emails(username, app_password, imap_server, start=start)
        logging.debug(f"Fetched {len(emails)} emails")
        return render_template('emails.html', emails=emails, username=username, app_password=app_password, imap_server=imap_server, start=start)
    except Exception as e:
        logging.error(f"Failed to fetch emails: {e}")
        return jsonify({'error': 'Failed to fetch emails'}), 500


@app.route('/email/<email_id>')
def email_detail(email_id):
    username = request.args.get('username')
    app_password = request.args.get('app_password')
    imap_server = request.args.get('imap_server')
    if not username or not app_password or not imap_server:
        logging.error("Missing parameters for fetching email details.")
        return "Missing parameters", 400
    email_content = fetch_email_by_id(
        username, app_password, imap_server, email_id)
    return render_template('email_detail.html', email=email_content)


@app.route('/api/ip-details/<ip_address>')
def api_ip_details(ip_address):
    # Fetch the detailed information for the IP address using both APIs
    ip_info = get_ip_location(ip_address)
    return jsonify(ip_info)


@app.route('/api/detect-link', methods=['POST'])
def detect_link():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    vt_result = check_url_with_virustotal(url)
    return jsonify({'vt_result': vt_result})


@app.route('/api/scan-link', methods=['POST'])
def scan_link():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    vt_result = scan_url_with_virustotal(url)
    return jsonify(vt_result)


@app.route('/login')
def login():
    return render_template('login.html')


if __name__ == '__main__':
    app.run(host='localhost', port=5002, debug=True)
