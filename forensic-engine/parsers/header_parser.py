"""
header_parser.py — RFC 822 Email Header Forensic Parser

Extracts all forensically relevant headers from a raw .eml file:
- Sender identity (From, Reply-To, Return-Path, Sender)
- Recipient chain (To, Cc, Bcc)
- Routing chain (all Received: headers in chronological order)
- Authentication results (Authentication-Results, ARC headers)
- Message metadata (Subject, Date, Message-ID, X-Mailer)
- All IPs from the Received: hop chain
"""

import email
from email import policy
from email.utils import parsedate_to_datetime
import re
import ipaddress
from typing import Optional


# Regex to match IPv4 addresses in Received headers
IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP address string is valid and routable on the public internet."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_link_local or
            ip_obj.is_unspecified
        )
    except ValueError:
        return False

# Regex to extract domain from email addresses
EMAIL_DOMAIN_PATTERN = re.compile(r'@([\w.-]+)')

# Regex to extract "from <hostname>" in Received headers
RECEIVED_FROM_PATTERN = re.compile(
    r'from\s+([\w.-]+)\s*\(?([\w.-]*)\s*\[?([\d.]*)\]?\)?',
    re.IGNORECASE
)

# Regex to extract "by <hostname>" in Received headers
RECEIVED_BY_PATTERN = re.compile(
    r'by\s+([\w.-]+)',
    re.IGNORECASE
)

# Regex to extract timestamp from Received headers
RECEIVED_DATE_PATTERN = re.compile(
    r';\s*(.+)$',
    re.MULTILINE
)


def parse_email_from_bytes(raw_bytes: bytes) -> email.message.EmailMessage:
    """Parse raw email bytes into an EmailMessage object."""
    return email.message_from_bytes(raw_bytes, policy=policy.default)


def parse_email_from_string(raw_string: str) -> email.message.EmailMessage:
    """Parse raw email string into an EmailMessage object."""
    return email.message_from_string(raw_string, policy=policy.default)


def extract_domain(address: str) -> Optional[str]:
    """Extract domain from an email address string."""
    if not address:
        return None
    match = EMAIL_DOMAIN_PATTERN.search(address)
    return match.group(1).lower() if match else None


def extract_display_name(address: str) -> Optional[str]:
    """Extract display name from a formatted email address like 'John Doe <john@example.com>'."""
    if not address:
        return None
    # Check for "Name <email>" format
    match = re.match(r'^"?([^"<]+)"?\s*<', address)
    if match:
        return match.group(1).strip()
    return None


def parse_received_header(header_text: str) -> dict:
    """
    Parse a single Received: header into structured data.
    
    Returns dict with:
        - from_hostname: claimed sending hostname
        - from_ip: IP address of sending server
        - by_hostname: receiving server hostname
        - timestamp_raw: raw timestamp string
        - timestamp: parsed datetime (if possible)
        - raw: original header text
    """
    result = {
        "from_hostname": None,
        "from_ip": None,
        "by_hostname": None,
        "timestamp_raw": None,
        "timestamp": None,
        "raw": header_text.strip()
    }

    # Extract "from" information
    from_match = RECEIVED_FROM_PATTERN.search(header_text)
    if from_match:
        result["from_hostname"] = from_match.group(1)
        # IP might be in group 3 (inside brackets) or group 2
        if from_match.group(3):
            result["from_ip"] = from_match.group(3)

    # If no IP found in "from" pattern, try to find any IP in the header
    if not result["from_ip"]:
        ips = IPV4_PATTERN.findall(header_text)
        if ips:
            result["from_ip"] = ips[0]

    # Extract "by" information
    by_match = RECEIVED_BY_PATTERN.search(header_text)
    if by_match:
        result["by_hostname"] = by_match.group(1)

    # Extract timestamp (after the semicolon)
    date_match = RECEIVED_DATE_PATTERN.search(header_text)
    if date_match:
        raw_date = date_match.group(1).strip()
        result["timestamp_raw"] = raw_date
        try:
            result["timestamp"] = parsedate_to_datetime(raw_date).isoformat()
        except Exception:
            result["timestamp"] = None

    return result


def extract_all_headers(msg: email.message.EmailMessage) -> dict:
    """
    Extract all forensically relevant headers from an EmailMessage.
    
    Returns a comprehensive dictionary containing:
        - sender: From address details
        - reply_to: Reply-To address details
        - return_path: Return-Path address
        - to: recipient list
        - subject: email subject
        - date: email date
        - message_id: Message-ID header
        - x_mailer: X-Mailer / User-Agent
        - authentication_results: raw auth results header
        - received_hops: list of parsed Received headers (chronological, oldest first)
        - all_ips: list of all IPs found across all Received headers
        - spoofing_indicators: detected identity mismatches
    """
    
    # --- Core Identity Headers ---
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    sender_header = msg.get("Sender", "")
    to_header = msg.get("To", "")
    cc_header = msg.get("Cc", "")
    subject = msg.get("Subject", "")
    date_header = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    auth_results = msg.get("Authentication-Results", "")
    
    # --- Extract domains for comparison ---
    from_domain = extract_domain(from_header)
    reply_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)
    from_display_name = extract_display_name(from_header)
    
    # --- Parse Received headers (bottom-to-top = oldest-to-newest) ---
    received_headers = msg.get_all("Received", [])
    # Reverse to get chronological order (oldest hop first)
    received_headers_reversed = list(reversed(received_headers))
    
    received_hops = []
    all_ips = []
    
    for idx, header in enumerate(received_headers_reversed):
        hop = parse_received_header(header)
        hop["hop_index"] = idx + 1
        received_hops.append(hop)
        
        if hop["from_ip"]:
            all_ips.append(hop["from_ip"])
    
    # --- Detect Spoofing Indicators ---
    spoofing_indicators = []
    
    # Check From vs Reply-To domain mismatch
    if from_domain and reply_domain and from_domain.lower() != reply_domain.lower():
        spoofing_indicators.append({
            "type": "REPLY_TO_MISMATCH",
            "severity": "high",
            "detail": f"From domain ({from_domain}) differs from Reply-To domain ({reply_domain})"
        })
    
    # Check From vs Return-Path domain mismatch
    if from_domain and return_path_domain and from_domain.lower() != return_path_domain.lower():
        spoofing_indicators.append({
            "type": "RETURN_PATH_MISMATCH",
            "severity": "medium",
            "detail": f"From domain ({from_domain}) differs from Return-Path domain ({return_path_domain})"
        })
    
    # Check for suspicious display name (looks like a domain or organization)
    if from_display_name:
        # Check if display name impersonates known brands
        impersonation_keywords = [
            "bank", "security", "admin", "support", "helpdesk", "paypal",
            "microsoft", "google", "apple", "amazon", "netflix", "facebook",
            "instagram", "state bank", "sbi", "hdfc", "icici", "rbi",
            "director", "ceo", "cfo", "executive", "president", "manager"
        ]
        display_lower = from_display_name.lower()
        for keyword in impersonation_keywords:
            if keyword in display_lower:
                spoofing_indicators.append({
                    "type": "DISPLAY_NAME_IMPERSONATION",
                    "severity": "high",
                    "detail": f"Display name '{from_display_name}' contains impersonation keyword: '{keyword}'"
                })
                break
    
    # --- Parse Date ---
    parsed_date = None
    if date_header:
        try:
            parsed_date = parsedate_to_datetime(date_header).isoformat()
        except Exception:
            parsed_date = date_header
    
    # --- Extract Best Candidate Public Sender IP ---
    explicit_client_ip = None
    detection_source = None
    is_explicit = False

    explicit_headers = [
        'X-Originating-IP',
        'X-Sender-IP',
        'X-Remote-IP',
        'X-Client-IP'
    ]
    for h_name in explicit_headers:
        val = msg.get(h_name)
        if val:
            clean_ip = re.sub(r'[\[\]\s]', '', val)
            if is_public_ip(clean_ip):
                explicit_client_ip = clean_ip
                detection_source = f"Explicit Header ({h_name})"
                is_explicit = True
                break

    if not explicit_client_ip and auth_results:
        spf_match = IPV4_PATTERN.findall(auth_results)
        for ip in spf_match:
            if is_public_ip(ip):
                explicit_client_ip = ip
                detection_source = "Authentication-Results (SPF)"
                break

    # Public IP chain from Received headers (bottom to top / oldest to newest)
    public_ip_chain = []
    for hop in received_hops:
        ip = hop.get("from_ip")
        if ip and is_public_ip(ip) and ip not in public_ip_chain:
            public_ip_chain.append(ip)

    if not explicit_client_ip and public_ip_chain:
        explicit_client_ip = public_ip_chain[0]  # Earliest public relay
        detection_source = "Received (Earliest Public Hop)"

    return {
        "sender": {
            "full": from_header,
            "domain": from_domain,
            "display_name": from_display_name
        },
        "reply_to": {
            "full": reply_to,
            "domain": reply_domain
        },
        "return_path": {
            "full": return_path,
            "domain": return_path_domain
        },
        "origin_ip_analysis": {
            "origin_ip": explicit_client_ip,
            "detection_source": detection_source or "None (No public IP detected)",
            "ip_chain": public_ip_chain,
            "is_explicit_client_ip": is_explicit
        },
        "to": to_header,
        "cc": cc_header,
        "subject": subject,
        "date": {
            "raw": date_header,
            "parsed": parsed_date
        },
        "message_id": message_id,
        "x_mailer": x_mailer,
        "authentication_results_raw": auth_results,
        "received_hops": received_hops,
        "all_ips": all_ips,
        "spoofing_indicators": spoofing_indicators,
        "total_hops": len(received_hops)
    }
