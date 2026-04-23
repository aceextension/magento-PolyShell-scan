import json
import smtplib
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from utils import Colors, section_header, log_info, log_warning

class ReportGenerator:
    def __init__(self, scanner):
        self.scanner = scanner

    def generate_report(self):
        duration = (self.scanner.scan_end - self.scanner.scan_start).total_seconds()
        
        # Determine severity
        total_threats = len(self.scanner.malicious_files) + len(self.scanner.misplaced_php)
        severity = 'CRITICAL' if self.scanner.malicious_files else ('WARNING' if self.scanner.misplaced_php else 'CLEAN')
        
        print(f"\n{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    SCAN RESULTS SUMMARY                      ║")
        print(f"╠══════════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"  Scan Duration:        {duration:.1f} seconds")
        print(f"  Files Scanned:        {self.scanner.total_scanned}")
        print(f"  Overall Severity:     {Colors.RED if severity == 'CRITICAL' else Colors.YELLOW if severity == 'WARNING' else Colors.GREEN}{severity}{Colors.RESET}\n")
        
        print(f"  {Colors.RED}Malicious Files:      {len(self.scanner.malicious_files)}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Misplaced PHP:        {len(self.scanner.misplaced_php)}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Modified Core Files:  {len(self.scanner.modified_core)}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Suspicious Files:     {len(self.scanner.suspicious_files)}{Colors.RESET}")
        print(f"  {Colors.RED}Log Evidence Entries:  {len(self.scanner.log_evidence)}{Colors.RESET}")
        print(f"{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
        
        # Save JSON
        # Use project name as prefix for the report files so they don't overwrite each other in a central directory
        project_name = self.scanner.project_root.name
        report_path = self.scanner.report_dir / f'{project_name}_security_report.json'
        report_data = {
            'scan_time': self.scanner.scan_start.isoformat(),
            'scan_duration_seconds': duration,
            'project_root': str(self.scanner.project_root),
            'severity': severity,
            'summary': {
                'files_scanned': self.scanner.total_scanned,
                'malicious_count': len(self.scanner.malicious_files),
                'misplaced_php_count': len(self.scanner.misplaced_php),
                'modified_core_count': len(self.scanner.modified_core),
                'suspicious_count': len(self.scanner.suspicious_files),
                'log_evidence_count': len(self.scanner.log_evidence),
            },
            'malicious_files': self.scanner.malicious_files,
            'misplaced_php_files': self.scanner.misplaced_php,
            'modified_core_files': self.scanner.modified_core,
            'suspicious_files': self.scanner.suspicious_files[:50],
            'log_evidence': self.scanner.log_evidence[:100],
            'remediation_checklist': self._get_remediation_checklist(),
        }
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            log_info(f"Full JSON report saved: {report_path}")
        except Exception as e:
            log_warning(f"Could not save JSON report: {e}")
            
        html_content = self.generate_html_report(project_name)
        if self.scanner.smtp_config and self.scanner.smtp_config.get('to_email'):
            self.send_email_notification(html_content)

        section_header("MANDATORY REMEDIATION CHECKLIST")
        for i, item in enumerate(self._get_remediation_checklist(), 1):
            priority = item.get('priority', 'MEDIUM')
            color = Colors.RED if priority == 'CRITICAL' else Colors.YELLOW
            status = '☐'
            print(f"  {color}{status} {i}. [{priority}]{Colors.RESET} {item['action']}")
            if item.get('command'):
                print(f"     {Colors.CYAN}$ {item['command']}{Colors.RESET}")
                
        section_header("NGINX HARDENING — ADD TO SERVER BLOCK")
        print(f"""{Colors.CYAN}
    # Block PHP execution in media directories
    location ~* ^/pub/media/.*\\.php$ {{
        deny all;
        return 403;
    }}
    location ~* ^/media/.*\\.php$ {{
        deny all;
        return 403;
    }}
    location ~* ^/pub/static/.*\\.php$ {{
        deny all;
        return 403;
    }}
    location ~* ^/var/ {{
        deny all;
        return 403;
    }}
{Colors.RESET}""")

    def _get_remediation_checklist(self):
        checklist = []
        if self.scanner.malicious_files:
            checklist.append({
                'priority': 'CRITICAL',
                'action': 'Remove all malicious PHP files (webshells)',
                'command': f'find {self.scanner.project_root}/pub/media -name "*.php" -delete',
            })
        if self.scanner.modified_core:
            checklist.append({
                'priority': 'CRITICAL',
                'action': 'Restore modified core files from git',
                'command': f'cd {self.scanner.project_root} && git checkout HEAD -- pub/get.php',
            })
        checklist.extend([
            {'priority': 'CRITICAL', 'action': 'Rotate ALL database credentials in app/etc/env.php'},
            {'priority': 'CRITICAL', 'action': 'Rotate Magento crypt_key (invalidates all encrypted data)'},
            {'priority': 'CRITICAL', 'action': 'Change ALL Magento admin user passwords'},
            {'priority': 'CRITICAL', 'action': 'Rotate AWS IAM access keys and secrets'},
            {'priority': 'CRITICAL', 'action': 'Add Nginx rules to block PHP execution in media/static dirs'},
            {'priority': 'CRITICAL', 'action': 'Flush all Magento sessions (force all users to re-login)',
             'command': f'rm -rf {self.scanner.project_root}/var/session/*'},
            {'priority': 'HIGH', 'action': 'Check and disable Magento custom options file upload if not needed'},
            {'priority': 'HIGH', 'action': 'Review and restrict Magento admin user accounts'},
            {'priority': 'HIGH', 'action': 'Enable Magento 2FA for all admin accounts'},
            {'priority': 'HIGH', 'action': 'Run full Magento security scan: bin/magento security:scan'},
            {'priority': 'MEDIUM', 'action': 'Set up file integrity monitoring (AIDE/OSSEC/Wazuh)'},
            {'priority': 'MEDIUM', 'action': 'Review all Magento API integration tokens and revoke unknown ones'},
            {'priority': 'MEDIUM', 'action': 'Check for skimmer/card-stealer JS in checkout templates'},
        ])
        return checklist

    def generate_html_report(self, project_name):
        html_report_file = str(self.scanner.report_dir / f"{project_name}_security_report.html")
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Magento Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; border-bottom: 2px solid #3498db; padding-bottom: 8px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }}
        .summary-box {{ padding: 20px; border-radius: 8px; text-align: center; }}
        .critical {{ background: #ffebee; border-left: 4px solid #e74c3c; }}
        .warning {{ background: #fff3e0; border-left: 4px solid #f39c12; }}
        .info {{ background: #e3f2fd; border-left: 4px solid #3498db; }}
        .success {{ background: #e8f5e9; border-left: 4px solid #27ae60; }}
        .count {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        .label {{ font-size: 14px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #3498db; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #e74c3c; color: white; }}
        .badge-warning {{ background: #f39c12; color: white; }}
        .badge-info {{ background: #3498db; color: white; }}
        .timestamp {{ color: #888; font-size: 14px; }}
        .finding-section {{ margin: 30px 0; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Magento Security Scan Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Scanned Directory:</strong> <code>{self.scanner.project_root}</code></p>
        
        <div class="summary">
            <div class="summary-box critical">
                <div class="count">{self.scanner.critical_issues}</div>
                <div class="label">Critical Issues</div>
            </div>
            <div class="summary-box warning">
                <div class="count">{self.scanner.warnings}</div>
                <div class="label">Warnings</div>
            </div>
            <div class="summary-box info">
                <div class="count">{self.scanner.info_items}</div>
                <div class="label">Info Items</div>
            </div>
            <div class="summary-box success">
                <div class="count">{len(self.scanner.findings)}</div>
                <div class="label">Categories Scanned</div>
            </div>
        </div>
"""
        if self.scanner.findings.get('web_shells'):
            html += self._generate_finding_section('Web Shells Detected', self.scanner.findings['web_shells'], ['file', 'modified', 'size', 'permissions'], 'CRITICAL')
        if self.scanner.findings.get('malicious_sessions'):
            html += self._generate_finding_section('Malicious Session Files', self.scanner.findings['malicious_sessions'], ['file', 'modified', 'size'], 'CRITICAL')
        if self.scanner.findings.get('suspicious_pub'):
            html += self._generate_finding_section('Suspicious Files in pub/', self.scanner.findings['suspicious_pub'], ['file', 'modified', 'size', 'permissions'], 'CRITICAL')
        if self.scanner.findings.get('malicious_domains'):
            html += self._generate_finding_section('Malicious Domains Found', self.scanner.findings['malicious_domains'], ['file', 'domain', 'modified'], 'CRITICAL')
        if self.scanner.findings.get('permission_issues'):
            html += self._generate_finding_section('File Permission Issues', self.scanner.findings['permission_issues'], ['file', 'current', 'recommended'], 'CRITICAL')
        if self.scanner.findings.get('recent_modifications'):
            html += self._generate_finding_section('Recently Modified PHP Files', self.scanner.findings['recent_modifications'], ['file', 'modified', 'size'], 'WARNING')
        if self.scanner.findings.get('backdoor_functions'):
            html += self._generate_finding_section('Potential Backdoor Functions', self.scanner.findings['backdoor_functions'], ['file', 'modified'], 'WARNING')
        if self.scanner.findings.get('writable_directories'):
            html += self._generate_finding_section('World-Writable Directories', self.scanner.findings['writable_directories'], ['directory', 'permissions'], 'WARNING')
        
        if self.scanner.findings.get('cron_jobs'):
            html += """
        <div class="finding-section">
            <h2>Cron Jobs <span class="badge badge-info">{} found</span></h2>
            <table><tr><th>Type</th><th>Entry</th></tr>
""".format(len(self.scanner.findings['cron_jobs']))
            for cron in self.scanner.findings['cron_jobs'][:50]:
                if isinstance(cron, dict):
                    html += f"<tr><td>{{cron.get('type', 'N/A')}}</td><td><code>{{cron.get('entry', 'N/A')}}</code></td></tr>\n"
            html += "</table></div>\n"
            
        html += """
        <h2>📋 Recommended Actions</h2>
        <ol>
            <li><strong>Immediate:</strong> Review all CRITICAL issues above</li>
            <li><strong>Immediate:</strong> Take site offline if web shells are detected</li>
            <li><strong>Immediate:</strong> Clear all sessions: <code>rm -rf var/session/*</code></li>
            <li><strong>High Priority:</strong> Delete identified malicious files</li>
            <li><strong>High Priority:</strong> Change all passwords (database, admin, SSH)</li>
            <li><strong>High Priority:</strong> Update Magento to latest version</li>
        </ol>
    </div>
</body>
</html>
"""
        try:
            with open(html_report_file, 'w') as f:
                f.write(html)
            log_info(f"HTML report saved: {html_report_file}")
        except Exception as e:
            log_warning(f"Failed to generate HTML report: {e}")
        return html

    def _generate_finding_section(self, title, findings, columns, severity):
        badge_class = f"badge-{severity.lower()}"
        html = f"\n<div class='finding-section'>\n<h2>{title} <span class='badge {badge_class}'>{len(findings)} found</span></h2>\n<table><tr>"
        for col in columns:
            html += f"<th>{col.replace('_', ' ').title()}</th>"
        html += "</tr>\n"
        for item in findings[:50]:
            if isinstance(item, dict):
                html += "<tr>"
                for col in columns:
                    value = item.get(col, 'N/A')
                    if col == 'size' and isinstance(value, int): value = f"{value:,} bytes"
                    html += f"<td>{value}</td>"
                html += "</tr>\n"
            else:
                html += f"<tr><td colspan='{len(columns)}'>{str(item)}</td></tr>\n"
        html += "</table></div>\n"
        return html

    def send_email_notification(self, html_content=None):
        try:
            config = self.scanner.smtp_config
            project_name = self.scanner.project_root.name
            msg = MIMEMultipart()
            msg['Subject'] = f"🚨 Magento Security Scan Alert [{project_name}] - {self.scanner.critical_issues} Critical Issues"
            msg['From'] = 'security-scan@localhost'
            msg['To'] = config.get('to_email')

            text = f"Magento Scan Completed for {project_name}. Critical: {self.scanner.critical_issues}, Warnings: {self.scanner.warnings}"
            
            # Use the full HTML report as the email body if available
            html = html_content if html_content else f"<html><body><h2>Magento Security Scan - {project_name}</h2><p>Critical: {self.scanner.critical_issues}</p><p>Please find the detailed reports attached.</p></body></html>"
            
            msg.attach(MIMEText(text, 'plain'))
            msg.attach(MIMEText(html, 'html'))

            # Attach HTML Report as a file as well
            html_path = self.scanner.report_dir / f"{project_name}_security_report.html"
            if html_path.exists():
                with open(html_path, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={html_path.name}")
                msg.attach(part)

            # Attach JSON Report
            json_path = self.scanner.report_dir / f"{project_name}_security_report.json"
            if json_path.exists():
                with open(json_path, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={json_path.name}")
                msg.attach(part)
            
            host = config.get('host', 'localhost')
            port = config.get('port', 25)
            user = config.get('user')
            password = config.get('pass')

            with smtplib.SMTP(host, port) as server:
                if user and password:
                    server.starttls()
                    server.login(user, password)
                server.send_message(msg)
            log_info(f"Email notification with embedded report and attachments sent to {config.get('to_email')}")
        except Exception as e:
            log_warning(f"Could not send email: {e}")
