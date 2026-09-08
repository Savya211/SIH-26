/**
 * routes/send-report.js
 * POST /api/send-report - Sends investigation report via backend SMTP
 */

import nodemailer from 'nodemailer';

export default function sendReportRoute(app) {
    app.post('/api/send-report', async (req, res) => {
        const { to, subject, body, message, reportHtml } = req.body;

        if (!to || typeof to !== 'string' || !to.includes('@')) {
            return res.status(400).json({
                success: false,
                error: 'Valid recipient email address is required.'
            });
        }

        const host = process.env.SMTP_HOST || 'smtp.gmail.com';
        const port = parseInt(process.env.SMTP_PORT || '587', 10);
        const secure = process.env.SMTP_SECURE === 'true'; // true for port 465, false for 587
        const user = process.env.SMTP_USER;
        const pass = process.env.SMTP_PASS;
        const from = process.env.SMTP_FROM || (user ? `CyberShield <${user}>` : 'CyberShield <noreply@cybershield.local>');

        if (!user || !pass) {
            console.error('[Send Report] SMTP credentials missing in .env');
            return res.status(500).json({
                success: false,
                error: 'SMTP credentials not configured on backend. Please configure SMTP_USER and SMTP_PASS in backend .env file.'
            });
        }

        try {
            const transporter = nodemailer.createTransport({
                host,
                port,
                secure,
                auth: { user, pass }
            });

            const rawReportContent = reportHtml || body || '';
            const analystMessage = message && message !== rawReportContent ? message.trim() : '';

            let analystNoteHtml = '';
            if (analystMessage) {
                const safeNote = analystMessage
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/\n/g, '<br>');
                analystNoteHtml = `
                    <div style="background-color: #f0f9ff; border-left: 4px solid #0284c7; border-radius: 6px; padding: 14px 16px; margin-bottom: 24px;">
                        <div style="font-weight: 700; font-size: 12px; color: #0369a1; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">Analyst Note</div>
                        <div style="color: #1e293b; font-size: 14px; line-height: 1.5;">${safeNote}</div>
                    </div>
                `;
            }

            const isHtml = /<[a-z][\s\S]*>/i.test(rawReportContent);
            let formattedReportBody = '';

            if (isHtml) {
                formattedReportBody = rawReportContent;
            } else if (rawReportContent) {
                const safeText = rawReportContent
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/\n/g, '<br>');
                formattedReportBody = `<div style="white-space: pre-wrap; font-size: 14px; color: #334155;">${safeText}</div>`;
            } else {
                formattedReportBody = `<div style="color: #64748b; font-style: italic;">No report content provided.</div>`;
            }

            const formattedHtml = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #f1f5f9;
            color: #0f172a;
            margin: 0;
            padding: 20px;
            -webkit-font-smoothing: antialiased;
        }
        .email-wrapper {
            max-width: 720px;
            margin: 0 auto;
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
        }
        .email-banner {
            background-color: #0f172a;
            padding: 20px 24px;
            border-bottom: 3px solid #0284c7;
        }
        .email-banner-title {
            color: #38bdf8;
            font-size: 20px;
            font-weight: 700;
            margin: 0 0 4px 0;
        }
        .email-banner-sub {
            color: #94a3b8;
            font-size: 12px;
            margin: 0;
        }
        .email-body {
            padding: 24px;
            font-size: 14px;
            line-height: 1.6;
            color: #334155;
        }

        /* Report Component Styles for Email Clients */
        .fr-header {
            padding-bottom: 16px;
            border-bottom: 2px solid #e2e8f0;
            margin-bottom: 24px;
        }
        .fr-header-title {
            font-size: 22px;
            font-weight: 800;
            color: #0f172a;
            letter-spacing: -0.5px;
        }
        .fr-header-subtitle {
            font-size: 12px;
            color: #64748b;
            margin-top: 2px;
        }
        .fr-header-meta {
            font-size: 12px;
            color: #475569;
            margin-top: 10px;
            padding: 8px 12px;
            background-color: #f8fafc;
            border-radius: 4px;
            border: 1px solid #f1f5f9;
        }
        .fr-header-meta span {
            display: inline-block;
            margin-right: 16px;
        }
        .fr-section {
            margin-bottom: 28px;
        }
        .fr-section-title {
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #0284c7;
            border-left: 4px solid #0284c7;
            padding-left: 10px;
            margin-bottom: 14px;
        }
        .fr-subsection-title {
            font-size: 12px;
            font-weight: 700;
            color: #475569;
            margin-top: 12px;
            margin-bottom: 6px;
            text-transform: uppercase;
        }
        .fr-overview-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 12px;
        }
        .fr-overview-item {
            flex: 1 1 140px;
            min-width: 130px;
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 10px 12px;
            box-sizing: border-box;
        }
        .fr-overview-label {
            display: block;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            color: #64748b;
            margin-bottom: 4px;
        }
        .fr-overview-value {
            font-size: 14px;
            font-weight: 700;
            color: #0f172a;
            word-break: break-all;
        }
        .fr-mono {
            font-family: SFMono-Regular, Consolas, Monaco, monospace;
            font-size: 12px;
        }
        .fr-score-badge, .fr-verdict-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        .fr-verdict-safe, .fr-auth-pass {
            background-color: #dcfce7 !important;
            color: #15803d !important;
            border: 1px solid #bbf7d0 !important;
        }
        .fr-verdict-suspicious, .fr-auth-unknown {
            background-color: #fef3c7 !important;
            color: #b45309 !important;
            border: 1px solid #fde68a !important;
        }
        .fr-verdict-malicious, .fr-auth-fail {
            background-color: #fee2e2 !important;
            color: #b91c1c !important;
            border: 1px solid #fca5a5 !important;
        }
        .fr-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            margin-bottom: 12px;
            font-size: 13px;
        }
        .fr-table th {
            background-color: #f1f5f9;
            color: #334155;
            font-weight: 700;
            text-align: left;
            padding: 10px 12px;
            border: 1px solid #e2e8f0;
        }
        .fr-table td {
            padding: 10px 12px;
            border: 1px solid #e2e8f0;
            color: #1e293b;
            vertical-align: top;
        }
        .fr-table-label {
            font-weight: 600;
            width: 140px;
            background-color: #f8fafc;
            color: #475569;
        }
        .fr-url-cell {
            word-break: break-all;
            font-family: SFMono-Regular, Consolas, monospace;
            font-size: 12px;
        }
        .fr-auth-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
        }
        .fr-auth-card {
            flex: 1 1 180px;
            min-width: 160px;
            padding: 12px 14px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
            box-sizing: border-box;
        }
        .fr-auth-name {
            font-weight: 800;
            font-size: 14px;
            color: #0f172a;
            margin-bottom: 4px;
        }
        .fr-auth-status {
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
        }
        .fr-auth-detail {
            font-size: 11px;
            color: #64748b;
            margin-top: 6px;
        }
        .fr-timeline {
            border-left: 2px solid #cbd5e1;
            margin-left: 8px;
            padding-left: 16px;
        }
        .fr-timeline-item {
            margin-bottom: 14px;
            position: relative;
        }
        .fr-timeline-dot {
            width: 8px;
            height: 8px;
            background-color: #0284c7;
            border-radius: 50%;
            position: absolute;
            left: -21px;
            top: 5px;
        }
        .fr-timeline-time {
            font-size: 11px;
            font-weight: 700;
            color: #64748b;
        }
        .fr-timeline-desc {
            font-size: 13px;
            color: #1e293b;
        }
        .fr-timeline-ip {
            font-size: 12px;
            color: #475569;
        }
        .fr-keyword-list {
            margin-top: 6px;
        }
        .fr-keyword {
            display: inline-block;
            background-color: #fee2e2;
            color: #991b1b;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            margin: 2px 4px 2px 0;
            font-family: SFMono-Regular, Consolas, monospace;
        }
        .fr-empty {
            color: #94a3b8;
            font-style: italic;
            font-size: 13px;
            margin: 6px 0;
        }
        .fr-footer {
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid #e2e8f0;
            font-size: 11px;
            color: #94a3b8;
            text-align: center;
        }
        code {
            font-family: SFMono-Regular, Consolas, Monaco, monospace;
            font-size: 12px;
            background-color: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            color: #0f172a;
        }
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="email-banner">
            <h1 class="email-banner-title">CyberShield Investigation Report</h1>
            <p class="email-banner-sub">Email Forensic Intelligence Platform</p>
        </div>
        <div class="email-body">
            ${analystNoteHtml}
            ${formattedReportBody}
            <div class="fr-footer">
                Sent automatically by CyberShield Forensic Dashboard.
            </div>
        </div>
    </div>
</body>
</html>`;

            // Clean plain-text fallback
            let plainText = '';
            if (analystMessage) {
                plainText += `ANALYST NOTE:\n${analystMessage}\n\n========================================\n\n`;
            }
            if (isHtml) {
                plainText += rawReportContent
                    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                    .replace(/<tr[^>]*>/gi, '\n')
                    .replace(/<div[^>]*>/gi, '\n')
                    .replace(/<p[^>]*>/gi, '\n')
                    .replace(/<br\s*\/?>/gi, '\n')
                    .replace(/<[^>]+>/g, ' ')
                    .replace(/&nbsp;/gi, ' ')
                    .replace(/&lt;/gi, '<')
                    .replace(/&gt;/gi, '>')
                    .replace(/&amp;/gi, '&')
                    .replace(/[ \t]+/g, ' ')
                    .replace(/\n\s*\n/g, '\n\n')
                    .trim();
            } else {
                plainText += rawReportContent;
            }

            const mailOptions = {
                from,
                to,
                subject: subject || 'CyberShield Investigation Report',
                text: plainText || 'CyberShield Investigation Report',
                html: formattedHtml
            };

            const info = await transporter.sendMail(mailOptions);
            console.log(`[Send Report] Email sent to ${to}: ${info.messageId}`);
            return res.json({ success: true, messageId: info.messageId });
        } catch (err) {
            console.error('[Send Report] SMTP Error:', err);
            return res.status(500).json({
                success: false,
                error: err.message || 'Failed to send email via SMTP server.'
            });
        }
    });
}
