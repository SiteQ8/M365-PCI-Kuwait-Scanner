# M365 PCI Kuwait Scanner - Deployment Guide

## Overview
This guide provides step-by-step instructions for deploying the M365 PCI Kuwait Scanner in Kuwait financial sector environments. The scanner is designed specifically for PCI DSS compliance assessment of Microsoft 365 environments with Central Bank of Kuwait (CBK) regulatory considerations.

**Target Audience**: IT Security Teams, Compliance Officers, System Administrators  
**Prerequisites**: Microsoft 365 E3/E5 license, Azure AD Global Administrator access  
**Deployment Time**: 2-4 hours (initial setup)  

---

## 🏦 Pre-Deployment Requirements

### Microsoft 365 Requirements
- **License**: Microsoft 365 E3 or E5 with compliance features
- **Permissions**: Global Administrator or Compliance Administrator role
- **Services**: SharePoint Online, Exchange Online, OneDrive for Business, Teams
- **Compliance Center**: Microsoft Purview or Security & Compliance Center access

### System Requirements
- **Operating System**: Windows 10/11, Linux, or macOS
- **Python**: Version 3.8 or higher
- **Memory**: Minimum 8GB RAM (16GB recommended for large environments)
- **Storage**: 10GB free space for reports and logs
- **Network**: Internet connectivity and access to Microsoft Graph APIs

### Azure AD App Registration Requirements
- **API Permissions**: Microsoft Graph API access
- **Authentication**: Client credentials flow support
- **Tenant**: Same tenant as target Microsoft 365 environment

---

## 🚀 Phase 1: Environment Setup

### Step 1: Azure AD App Registration

1. **Sign in to Azure Portal**
   ```
   https://portal.azure.com
   ```

2. **Create App Registration**
   - Navigate to Azure Active Directory → App registrations
   - Click "New registration"
   - Name: "M365 PCI Scanner"
   - Supported account types: "Accounts in this organizational directory only"
   - Redirect URI: Not required for this application

3. **Configure API Permissions**
   ```
   Microsoft Graph Application Permissions:
   ✅ SecurityEvents.Read.All
   ✅ Directory.Read.All
   ✅ InformationProtectionPolicy.Read.All
   ✅ Policy.Read.All
   ✅ Reports.Read.All
   ✅ AuditLog.Read.All
   ✅ Organization.Read.All
   ✅ User.Read.All
   ✅ GroupMember.Read.All
   ✅ Files.Read.All
   ✅ Sites.Read.All
   ✅ Mail.Read
   ```

4. **Grant Admin Consent**
   - Click "Grant admin consent for [Organization]"
   - Confirm consent for all permissions

5. **Create Client Secret**
   - Go to "Certificates & secrets"
   - Click "New client secret"
   - Description: "PCI Scanner Secret"
   - Expires: 24 months (maximum recommended)
   - **Save the secret value immediately** (you won't see it again)

6. **Record Configuration Values**
   ```
   Tenant ID: [Copy from Overview page]
   Client ID: [Copy from Overview page]  
   Client Secret: [Copy the value you just created]
   ```

### Step 2: System Preparation

1. **Install Python 3.8+**
   ```bash
   # Windows (using Chocolatey)
   choco install python
   
   # Ubuntu/Debian
   sudo apt update && sudo apt install python3 python3-pip
   
   # CentOS/RHEL
   sudo yum install python3 python3-pip
   
   # macOS (using Homebrew)
   brew install python3
   ```

2. **Verify Python Installation**
   ```bash
   python3 --version
   pip3 --version
   ```

3. **Create Project Directory**
   ```bash
   mkdir /opt/m365-pci-scanner
   cd /opt/m365-pci-scanner
   ```

---

## 📦 Phase 2: Scanner Installation

### Step 1: Download and Setup

1. **Clone Repository**
   ```bash
   git clone https://github.com/SiteQ8/M365-PCI-Kuwait-Scanner.git
   cd M365-PCI-Kuwait-Scanner
   ```

2. **Create Virtual Environment**
   ```bash
   python3 -m venv venv
   
   # Activate virtual environment
   # Windows
   venv\Scripts\activate
   
   # Linux/macOS
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify Installation**
   ```bash
   python scanner.py --help
   ```

### Step 2: Configuration Setup

1. **Copy Configuration Template**
   ```bash
   cp config/pci_config.yaml config/pci_config_production.yaml
   ```

2. **Edit Configuration File**
   ```bash
   nano config/pci_config_production.yaml
   ```

3. **Update Azure AD Settings**
   ```yaml
   azure_ad:
     tenant_id: "your-tenant-id-here"
     client_id: "your-app-registration-id"
     client_secret: "your-client-secret"
   ```

4. **Configure Organization Details**
   ```yaml
   organization:
     name: "Your Bank Name"
     type: "commercial_bank"
     cbk_license: "BANK###"
     primary_regulator: "CBK"
     contact_email: "compliance@yourbank.com.kw"
   ```

5. **Validate Configuration**
   ```bash
   python scanner.py --config config/pci_config_production.yaml --validate-config
   ```

---

## 🔒 Phase 3: Security Hardening

### Step 1: File Permissions

1. **Set Secure Permissions**
   ```bash
   # Linux/macOS
   chmod 600 config/pci_config_production.yaml
   chmod 700 logs/
   chmod 700 reports/
   
   # Windows (PowerShell as Administrator)
   icacls config\pci_config_production.yaml /inheritance:d
   icacls config\pci_config_production.yaml /remove Users
   ```

2. **Create Service Account (Linux)**
   ```bash
   sudo useradd -r -s /bin/false pciscanner
   sudo chown -R pciscanner:pciscanner /opt/m365-pci-scanner
   ```

### Step 2: Network Security

1. **Firewall Configuration**
   ```bash
   # Allow outbound HTTPS to Microsoft Graph
   # Windows Firewall
   netsh advfirewall firewall add rule name="M365 Scanner HTTPS Out" dir=out action=allow protocol=TCP remoteport=443
   
   # Linux UFW
   sudo ufw allow out 443/tcp comment "Microsoft Graph API access"
   ```

2. **DNS Configuration**
   ```
   Ensure DNS resolution for:
   ✅ graph.microsoft.com
   ✅ login.microsoftonline.com
   ✅ graph.microsoft.us (if using US Government cloud)
   ```

### Step 3: Logging and Monitoring

1. **Configure Log Rotation**
   ```bash
   # Linux - create logrotate configuration
   sudo nano /etc/logrotate.d/pciscanner
   ```
   
   ```
   /opt/m365-pci-scanner/logs/*.log {
     daily
     rotate 30
     compress
     delaycompress
     missingok
     notifempty
     create 640 pciscanner pciscanner
   }
   ```

2. **Setup Monitoring (Optional)**
   ```bash
   # Create monitoring script
   nano scripts/health_check.sh
   ```

---

## 🧪 Phase 4: Testing and Validation

### Step 1: Connectivity Testing

1. **Test Azure AD Authentication**
   ```bash
   python -c "
   from utils.m365_connector import M365Connector
   import asyncio
   import yaml
   
   with open('config/pci_config_production.yaml') as f:
       config = yaml.safe_load(f)
   
   async def test_auth():
       connector = M365Connector(config['azure_ad'])
       await connector.authenticate()
       print('✅ Authentication successful')
   
   asyncio.run(test_auth())
   "
   ```

2. **Test Microsoft Graph Access**
   ```bash
   python scanner.py --config config/pci_config_production.yaml --test-connection
   ```

### Step 2: Limited Scope Testing

1. **Quick Test Scan**
   ```bash
   python scanner.py \
     --config config/pci_config_production.yaml \
     --scan-type quick \
     --test-mode
   ```

2. **Validate Report Generation**
   ```bash
   python scanner.py \
     --config config/pci_config_production.yaml \
     --scan-type quick \
     --generate-report \
     --format json
   ```

3. **Review Test Results**
   ```bash
   ls -la reports/
   cat reports/scan_*.json | jq .summary
   ```

---

## 🏭 Phase 5: Production Deployment

### Step 1: Initial Production Scan

1. **Comprehensive Assessment**
   ```bash
   python scanner.py \
     --config config/pci_config_production.yaml \
     --scan-type comprehensive \
     --org-type commercial_bank \
     --include-cbk \
     --generate-report \
     --format all
   ```

2. **Monitor Scan Progress**
   ```bash
   tail -f logs/pci_scanner.log
   ```

### Step 2: Automated Scheduling

1. **Create Scan Script**
   ```bash
   nano scripts/daily_scan.sh
   ```
   
   ```bash
   #!/bin/bash
   cd /opt/m365-pci-scanner
   source venv/bin/activate
   
   python scanner.py \
     --config config/pci_config_production.yaml \
     --scan-type quick \
     --generate-report \
     --format json \
     --output-dir reports/daily/
   ```

2. **Setup Cron Job (Linux)**
   ```bash
   sudo crontab -e
   
   # Daily scan at 2 AM
   0 2 * * * /opt/m365-pci-scanner/scripts/daily_scan.sh
   
   # Weekly comprehensive scan on Sundays at 3 AM
   0 3 * * 0 /opt/m365-pci-scanner/scripts/weekly_comprehensive_scan.sh
   ```

3. **Setup Windows Task Scheduler**
   ```powershell
   $action = New-ScheduledTaskAction -Execute "C:\path\to\python.exe" -Argument "C:\path\to\scanner.py --config config\pci_config_production.yaml --scan-type quick"
   $trigger = New-ScheduledTaskTrigger -Daily -At 2am
   Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "M365 PCI Daily Scan"
   ```

---

## 📊 Phase 6: Integration and Reporting

### Step 1: Email Notification Setup

1. **Configure SMTP Settings**
   ```yaml
   email_notifications:
     enabled: true
     smtp_server: "smtp.yourbank.com.kw"
     smtp_port: 587
     smtp_username: "pciscanner@yourbank.com.kw"
     smtp_password: "your-smtp-password"
   ```

2. **Test Email Notifications**
   ```bash
   python -c "
   from utils.email_notifier import EmailNotifier
   import yaml
   
   with open('config/pci_config_production.yaml') as f:
       config = yaml.safe_load(f)
   
   notifier = EmailNotifier(config)
   notifier.send_test_notification()
   "
   ```

### Step 2: SIEM Integration (Optional)

1. **Configure Splunk Integration**
   ```yaml
   integrations:
     siem:
       enabled: true
       platform: "Splunk"
       endpoint: "https://splunk.yourbank.com.kw:8088"
       api_key: "your-splunk-hec-token"
   ```

2. **Test SIEM Connectivity**
   ```bash
   python scripts/test_siem_integration.py
   ```

---

## 🔍 Phase 7: Compliance Validation

### Step 1: Internal Validation

1. **Review Initial Scan Results**
   - Executive Summary Report
   - Technical Findings Detail
   - PCI DSS Compliance Scorecard
   - CBK Regulatory Compliance Status

2. **Validate Findings Accuracy**
   ```bash
   # Generate detailed evidence report
   python scanner.py \
     --config config/pci_config_production.yaml \
     --scan-type comprehensive \
     --evidence-collection \
     --detailed-analysis
   ```

3. **False Positive Analysis**
   - Review flagged locations manually
   - Update exclusion patterns if necessary
   - Document justified exclusions

### Step 2: Regulatory Preparation

1. **CBK Compliance Report**
   ```bash
   python scanner.py \
     --config config/pci_config_production.yaml \
     --scan-type banking \
     --kuwait-focus \
     --cbk-report \
     --format pdf
   ```

2. **PCI DSS Documentation**
   - Self-Assessment Questionnaire (SAQ) preparation
   - Evidence collection for QSA assessment
   - Remediation plan development

---

## 🛠️ Ongoing Maintenance

### Daily Operations

1. **Monitor Scan Results**
   ```bash
   # Check latest scan status
   python scripts/scan_status.py
   
   # Review critical findings
   grep "CRITICAL" logs/pci_scanner.log | tail -20
   ```

2. **Update Threat Intelligence**
   ```bash
   # Update card patterns (monthly)
   python scripts/update_patterns.py
   ```

### Weekly Tasks

1. **Compliance Trend Analysis**
   ```bash
   python scripts/compliance_trends.py --period 7days
   ```

2. **Report Distribution**
   ```bash
   python scripts/distribute_reports.py --weekly-summary
   ```

### Monthly Tasks

1. **Configuration Review**
   ```bash
   python scripts/config_audit.py
   ```

2. **Performance Optimization**
   ```bash
   python scripts/performance_review.py
   ```

### Quarterly Tasks

1. **CBK Regulatory Report**
   ```bash
   python scanner.py \
     --config config/pci_config_production.yaml \
     --scan-type comprehensive \
     --kuwait-focus \
     --cbk-quarterly-report
   ```

2. **PCI DSS Assessment Preparation**
   ```bash
   python scripts/pci_assessment_prep.py --quarter Q1
   ```

---

## 🚨 Troubleshooting Guide

### Common Issues

#### Authentication Failures
```bash
# Check token cache
ls -la .token_cache

# Clear token cache
rm -rf .token_cache
python scanner.py --config config/pci_config_production.yaml --test-connection
```

#### Performance Issues
```bash
# Reduce scan scope
# Edit config to limit file size or services
max_file_size_mb: 50
max_concurrent_scans: 5
```

#### False Positives
```bash
# Update exclusion patterns
# Edit card_detection section in config
exclude_test_cards: true
confidence_threshold: 0.90
```

### Error Resolution

#### "Permission Denied" Errors
1. Verify API permissions in Azure AD
2. Check admin consent status
3. Validate client secret expiration

#### "Quota Exceeded" Errors
1. Implement rate limiting
2. Reduce concurrent requests
3. Schedule scans during off-peak hours

#### "Network Timeout" Errors
1. Increase timeout values
2. Check firewall configuration
3. Verify DNS resolution

---

## 📞 Support and Maintenance

### Internal Support Team Setup
1. **Primary Administrator**: IT Security Manager
2. **Secondary Administrator**: Compliance Officer  
3. **Technical Support**: System Administrator
4. **Business Owner**: CISO or Risk Manager

### Escalation Procedures
1. **Critical Findings**: Immediate notification to CISO
2. **System Issues**: IT Security team response within 4 hours
3. **Compliance Questions**: Compliance officer consultation
4. **Regulatory Issues**: Legal and compliance team involvement

### Documentation Requirements
1. **Installation Documentation**: This deployment guide
2. **Configuration Management**: Change control procedures
3. **Incident Response**: Security event handling procedures
4. **Audit Documentation**: Compliance evidence collection

---

## 📋 Compliance Checklist

### Pre-Production Checklist
- [ ] Azure AD app registration completed
- [ ] API permissions granted and consented
- [ ] Configuration file secured and validated
- [ ] Test scans completed successfully
- [ ] Email notifications tested
- [ ] Log rotation configured
- [ ] Access controls implemented
- [ ] Network security configured
- [ ] Documentation completed

### Post-Production Checklist
- [ ] Initial comprehensive scan completed
- [ ] Results reviewed and validated
- [ ] False positives analyzed and resolved
- [ ] Automated scheduling configured
- [ ] Integration testing completed
- [ ] Team training conducted
- [ ] Incident response procedures defined
- [ ] Maintenance schedule established

### Ongoing Compliance Checklist
- [ ] Daily scan monitoring
- [ ] Weekly trend analysis
- [ ] Monthly configuration reviews
- [ ] Quarterly regulatory reporting
- [ ] Annual security assessment
- [ ] Continuous staff training
- [ ] Regular backup verification
- [ ] Disaster recovery testing

---

**✅ Deployment Complete**

Your M365 PCI Kuwait Scanner is now ready for production use. Regular monitoring and maintenance will ensure ongoing compliance with PCI DSS and CBK regulatory requirements.

For technical support or questions about this deployment, contact the development team or refer to the project documentation on GitHub.

---

*This deployment guide is specifically designed for Kuwait financial sector organizations and includes considerations for local regulatory requirements and banking industry best practices.*