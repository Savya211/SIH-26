"""
body_parser.py — Email Body & Content Parser

Extracts and analyzes the email body:
- Decodes MIME parts (text/plain, text/html)
- Extracts all URLs from HTML with anchor text comparison
- Lists attachments with filenames, MIME types, and size
- Detects dangerous file extensions
- Detects embedded scripts and active content
"""

import re
from typing import Optional
from email.message import EmailMessage


# Dangerous file extensions commonly used in phishing/malware delivery
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.ps1', '.bat', '.cmd', '.com', '.msi', '.dll', '.pif',
    '.iso', '.img', '.hta', '.cpl', '.inf', '.reg',
    '.docm', '.xlsm', '.pptm',  # Macro-enabled Office
    '.jar', '.py', '.rb', '.sh',
}

# Double extension patterns (e.g., file.pdf.exe)
DOUBLE_EXTENSION_PATTERN = re.compile(
    r'\.\w{2,5}\.(exe|scr|vbs|bat|cmd|com|js|pif|ps1|msi)$',
    re.IGNORECASE
)

# Common tunnel/phishing infrastructure domains
TUNNEL_DOMAINS = [
    'ngrok.io', 'ngrok-free.app', 'serveo.net', 'loclx.io',
    'trycloudflare.com', 'localxpose.io', 'bohr.io',
    'pagekite.me', 'localhost.run'
]


def extract_body(msg: EmailMessage) -> dict:
    """
    Extract plain text and HTML body from an email message.
    
    Returns:
        {
            "plain_text": str,
            "html": str,
            "has_html": bool,
            "content_type": str (primary content type)
        }
    """
    plain_text = ""
    html_body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            # Skip attachments
            if part.get_content_disposition() == 'attachment':
                continue
            
            try:
                payload = part.get_content()
            except Exception:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Try common encodings
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            payload = payload.decode(charset)
                        except (UnicodeDecodeError, LookupError):
                            payload = payload.decode('utf-8', errors='replace')
                except Exception:
                    continue
            
            if not isinstance(payload, str):
                continue
                
            if content_type == 'text/plain':
                plain_text += payload
            elif content_type == 'text/html':
                html_body += payload
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    try:
                        payload = payload.decode(charset)
                    except (UnicodeDecodeError, LookupError):
                        payload = payload.decode('utf-8', errors='replace')
            except Exception:
                payload = ""
        
        if isinstance(payload, str):
            if content_type == 'text/html':
                html_body = payload
            else:
                plain_text = payload
    
    return {
        "plain_text": plain_text.strip(),
        "html": html_body.strip(),
        "has_html": bool(html_body.strip()),
        "content_type": msg.get_content_type()
    }


def extract_urls_from_html(html_content: str) -> list:
    """
    Extract all URLs from HTML content, comparing anchor text with actual href.
    
    Returns list of:
        {
            "href": str,
            "display_text": str,
            "anchor_mismatch": bool,
            "is_raw_ip": bool,
            "uses_non_standard_port": bool,
            "port": str or None,
            "is_tunnel_domain": bool,
            "tunnel_service": str or None
        }
    """
    urls = []
    
    if not html_content:
        return urls
    
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
    except ImportError:
        # Fallback: regex extraction
        href_pattern = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html_content):
            urls.append({
                "href": match.group(1),
                "display_text": "",
                "anchor_mismatch": False,
                "is_raw_ip": False,
                "uses_non_standard_port": False,
                "port": None,
                "is_tunnel_domain": False,
                "tunnel_service": None
            })
        return urls
    
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        display_text = a_tag.get_text(strip=True)
        
        # Skip mailto: and tel: links
        if href.startswith('mailto:') or href.startswith('tel:'):
            continue
        
        url_info = {
            "href": href,
            "display_text": display_text,
            "anchor_mismatch": False,
            "is_raw_ip": False,
            "uses_non_standard_port": False,
            "port": None,
            "is_tunnel_domain": False,
            "tunnel_service": None
        }
        
        # Check for anchor text / href mismatch
        # If display text looks like a URL but points elsewhere
        if display_text and re.match(r'https?://', display_text):
            try:
                from urllib.parse import urlparse
                display_parsed = urlparse(display_text)
                href_parsed = urlparse(href)
                if (display_parsed.hostname and href_parsed.hostname and
                    display_parsed.hostname.lower() != href_parsed.hostname.lower()):
                    url_info["anchor_mismatch"] = True
            except Exception:
                pass
        
        # Check for raw IP address as host
        try:
            from urllib.parse import urlparse
            parsed = urlparse(href)
            hostname = parsed.hostname or ""
            
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
                url_info["is_raw_ip"] = True
            
            # Check for non-standard port
            if parsed.port and parsed.port not in (80, 443):
                url_info["uses_non_standard_port"] = True
                url_info["port"] = str(parsed.port)
            
            # Check for tunnel domains
            for tunnel in TUNNEL_DOMAINS:
                if hostname.endswith(tunnel):
                    url_info["is_tunnel_domain"] = True
                    url_info["tunnel_service"] = tunnel
                    break
                    
        except Exception:
            pass
        
        urls.append(url_info)
    
    return urls


def detect_embedded_scripts(html_content: str) -> list:
    """
    Detect embedded scripts, iframes, and active content in HTML email body.
    
    Returns list of findings:
        {"type": str, "detail": str, "severity": str}
    """
    findings = []
    
    if not html_content:
        return findings
    
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
    except ImportError:
        return findings
    
    # Check for <script> tags (should NEVER be in email)
    scripts = soup.find_all('script')
    for script in scripts:
        src = script.get('src', '')
        finding = {
            "type": "EMBEDDED_SCRIPT",
            "severity": "critical",
            "detail": "Active <script> tag detected in email body"
        }
        
        # Check for known exploitation frameworks
        if 'hook.js' in src:
            finding["detail"] = f"BeEF Browser Exploitation Framework hook detected: {src}"
            finding["type"] = "BEEF_HOOK"
        elif src:
            finding["detail"] = f"External script loaded: {src}"
        
        # Check for exploitation ports
        if re.search(r':3000\b|:8080\b|:4444\b|:1337\b', src):
            finding["detail"] += f" (suspicious port in URL: {src})"
        
        findings.append(finding)
    
    # Check for <iframe> tags
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        src = iframe.get('src', 'no source')
        findings.append({
            "type": "HIDDEN_IFRAME",
            "severity": "high",
            "detail": f"Embedded iframe detected: {src}"
        })
    
    # Check for event handlers (onload, onerror, onclick with JS)
    event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus']
    for tag in soup.find_all(True):
        for handler in event_handlers:
            if tag.get(handler):
                findings.append({
                    "type": "EVENT_HANDLER",
                    "severity": "high",
                    "detail": f"JavaScript event handler '{handler}' found on <{tag.name}> element"
                })
                break  # One finding per tag is enough
    
    # Check for <form> tags with external action URLs
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '')
        if action and not action.startswith('#'):
            findings.append({
                "type": "FORM_ACTION",
                "severity": "medium",
                "detail": f"Form with external action URL: {action}"
            })
    
    return findings


def extract_attachments(msg: EmailMessage) -> list:
    """
    Extract attachment metadata from an email message.
    
    Returns list of:
        {
            "filename": str,
            "content_type": str,
            "size_bytes": int,
            "is_dangerous": bool,
            "has_double_extension": bool,
            "extension": str
        }
    """
    attachments = []
    
    if not msg.is_multipart():
        return attachments
    
    for part in msg.walk():
        disposition = part.get_content_disposition()
        if disposition != 'attachment':
            # Also check for inline images with filenames
            filename = part.get_filename()
            if not filename:
                continue
        
        filename = part.get_filename() or "unnamed"
        content_type = part.get_content_type()
        
        # Get size
        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0
        
        # Check extension
        ext_match = re.search(r'(\.\w+)$', filename.lower())
        extension = ext_match.group(1) if ext_match else ""
        
        is_dangerous = extension.lower() in DANGEROUS_EXTENSIONS
        has_double_ext = bool(DOUBLE_EXTENSION_PATTERN.search(filename))
        
        if has_double_ext:
            is_dangerous = True
        
        attachments.append({
            "filename": filename,
            "content_type": content_type,
            "size_bytes": size,
            "is_dangerous": is_dangerous,
            "has_double_extension": has_double_ext,
            "extension": extension
        })
    
    return attachments


def parse_body(msg: EmailMessage) -> dict:
    """
    Complete body analysis pipeline.
    
    Returns:
        {
            "body": {...},           # Plain text and HTML content
            "urls": [...],           # Extracted URLs with analysis
            "scripts": [...],        # Detected scripts and active content
            "attachments": [...],    # Attachment metadata
            "url_count": int,
            "dangerous_attachment_count": int,
            "has_scripts": bool,
            "has_anchor_mismatch": bool
        }
    """
    body = extract_body(msg)
    urls = extract_urls_from_html(body["html"])
    scripts = detect_embedded_scripts(body["html"])
    attachments = extract_attachments(msg)
    
    return {
        "body": body,
        "urls": urls,
        "scripts": scripts,
        "attachments": attachments,
        "url_count": len(urls),
        "dangerous_attachment_count": sum(1 for a in attachments if a["is_dangerous"]),
        "has_scripts": len(scripts) > 0,
        "has_anchor_mismatch": any(u["anchor_mismatch"] for u in urls)
    }
