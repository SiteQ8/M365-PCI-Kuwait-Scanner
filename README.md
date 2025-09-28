# M365 PCI Kuwait Scanner 🏦

## Microsoft 365 PCI DSS Compliance Scanner for Kuwait Financial Sector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Kuwait Banking](https://img.shields.io/badge/Kuwait-Banking%20Compliant-green.svg)](https://www.cbk.gov.kw/)

> **Comprehensive security scanning tool designed specifically for Kuwait's banking and financial services sector to ensure PCI DSS compliance and card data protection within Microsoft 365 environments.**

---

## 👨‍💻 About the Author

**Ali AlEnezi**  
🔒 Kuwait  
🎓 SANS/GIAC Certified Security Professional  
🏦 Financial Services Security Specialist  

- 📧 Email: [site@hotmail.com](mailto:site@hotmail.com)
- 💼 LinkedIn: [linkedin.com/in/alenizi](https://www.linkedin.com/in/alenizi/)
- 🌍 Location: Kuwait
- 🏢 Expertise: PCI DSS, Banking Cybersecurity, Microsoft 365 Security

---

## 🏦 Key Features

### 🔍 Card Data Detection Engine
- **Primary Account Number (PAN) Detection** - Advanced pattern recognition for all major card brands
- **CVV/CVC Pattern Recognition** - Secure code identification and classification
- **Track Data Analysis** - Magnetic stripe data detection and validation
- **Cardholder Information Classification** - Name, address, and personal data protection
- **Kuwait-Specific Card Patterns** - Local banking card formats and structures

### 🛡️ PCI DSS Compliance Scanning
- **Complete PCI DSS v4.0 Coverage** - All 12 requirements with 300+ validation points
- **Microsoft 365 Deep Integration** - SharePoint, OneDrive, Exchange, Teams, Power Platform
- **Data Location Mapping** - Comprehensive cardholder data environment (CDE) discovery
- **Access Control Validation** - Role-based access and privilege analysis
- **Encryption Assessment** - Data-at-rest and in-transit protection verification

### 🇰🇼 Kuwait Financial Regulation Compliance
- **Central Bank of Kuwait (CBK) Framework** - Complete cybersecurity requirement coverage
- **Kuwait Banking Law Compliance** - Local regulatory requirement validation
- **Anti-Money Laundering (AML) Checks** - Transaction monitoring and reporting compliance
- **Consumer Protection Guidelines** - Customer data protection and privacy validation
- **Sharia Compliance Considerations** - Islamic banking regulatory requirements

### 📊 Professional Reporting & Analytics
- **Executive Dashboards** - Board-ready compliance scorecards and risk metrics
- **CBK Audit Reports** - Regulator-compliant documentation and evidence
- **PCI QSA Documentation** - Qualified Security Assessor report generation
- **Risk Heat Maps** - Visual representation of compliance gaps and priorities
- **Trend Analysis** - Historical compliance tracking and improvement metrics

---

## 🚀 Quick Start Guide

### Prerequisites
- Microsoft 365 E3/E5 license with compliance features
- Azure AD Global Administrator or Compliance Administrator role
- Python 3.8+ environment
- Network connectivity to Microsoft Graph APIs

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/SiteQ8/M365-PCI-Kuwait-Scanner.git
   cd M365-PCI-Kuwait-Scanner
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Authentication**
   ```bash
   # Set up Azure AD App Registration
   cp config/sample_config.yaml config/pci_config.yaml
   # Edit config/pci_config.yaml with your tenant details
   ```

4. **Run Initial Scan**
   ```bash
   # Quick PCI assessment
   python scanner.py --scan-type quick --org-type bank
   
   # Comprehensive compliance scan
   python scanner.py --scan-type comprehensive --org-type bank --include-cbk
   ```

### Configuration Example
```yaml
# config/pci_config.yaml
azure_ad:
  tenant_id: "your-tenant-id"
  client_id: "your-app-registration-id"
  client_secret: "your-client-secret"

organization:
  type: "commercial_bank"  # commercial_bank, investment_company, payment_processor
  cbk_license: "BANK001"
  primary_regulator: "CBK"

scan_settings:
  include_teams: true
  include_sharepoint: true
  include_exchange: true
  include_onedrive: true
  deep_content_scan: true
```

---

## 🎯 Scan Types and Use Cases

### 📋 Quick Assessment (15-30 minutes)
```bash
python scanner.py --scan-type quick --org-type bank
```
- **Use Case**: Monthly compliance monitoring
- **Coverage**: Critical PCI requirements and card data exposure
- **Output**: Executive summary and high-priority findings

### 🔍 Comprehensive Audit (2-4 hours)
```bash
python scanner.py --scan-type comprehensive --include-cbk --generate-report
```
- **Use Case**: Annual PCI assessment or regulatory audit
- **Coverage**: Complete PCI DSS v4.0 + CBK cybersecurity framework
- **Output**: Full audit documentation and evidence collection

### 🏦 Banking-Specific Scan
```bash
python scanner.py --scan-type banking --kuwait-focus --aml-check
```
- **Use Case**: Kuwait banking regulatory compliance
- **Coverage**: CBK requirements, AML compliance, consumer protection
- **Output**: Regulator-ready compliance reports

### 💳 Card Data Discovery
```bash
python scanner.py --scan-type card-discovery --sensitivity-high
```
- **Use Case**: Data discovery for PCI scope reduction
- **Coverage**: All M365 locations for cardholder data
- **Output**: Data flow diagrams and storage locations

---

## 📊 Sample Reports and Outputs

### Executive Dashboard
```
╔══════════════════════════════════════════════════════════════╗
║                   PCI COMPLIANCE SCORECARD                  ║
║                     Al-Kuwait Bank                          ║
╠══════════════════════════════════════════════════════════════╣
║ Overall Compliance Score: 87% (Target: 95%)                 ║
║ Critical Issues: 3                                          ║
║ High Priority: 12                                           ║
║ CBK Regulatory Status: COMPLIANT                            ║
║ Last Assessment: 2025-09-28                                 ║
╚══════════════════════════════════════════════════════════════╝

PCI DSS Requirements Status:
✅ Build and maintain secure networks (Req 1-2)      95%
⚠️  Protect cardholder data (Req 3-4)                78%
✅ Maintain vulnerability management (Req 5-6)        92%
⚠️  Implement strong access control (Req 7-8)        83%
✅ Regularly monitor networks (Req 9-10)              90%
✅ Maintain information security policy (Req 11-12)   88%
```

### Card Data Discovery Results
```json
{
  "scan_summary": {
    "total_locations_scanned": 15420,
    "card_data_found": 23,
    "high_risk_exposures": 3,
    "encryption_status": "partially_protected"
  },
  "findings": [
    {
      "location": "SharePoint/HR/Employee_Records",
      "data_type": "Credit Application Forms",
      "pan_count": 12,
      "risk_level": "HIGH",
      "cbk_violation": true,
      "remediation": "Immediate data removal required"
    }
  ]
}
```

---

## 🏗️ Architecture and Components

### Core Scanning Modules

| Module | Purpose | PCI Requirements |
|--------|---------|------------------|
| `card_data_detector.py` | PAN, CVV, track data detection | Req 3, 4 |
| `access_control_scanner.py` | User permissions and roles | Req 7, 8 |
| `encryption_validator.py` | Data protection verification | Req 3, 4 |
| `network_security_checker.py` | Firewall and segmentation | Req 1, 2 |
| `vulnerability_scanner.py` | Security updates and patches | Req 5, 6 |
| `monitoring_analyzer.py` | Logging and monitoring | Req 9, 10 |

### Kuwait-Specific Modules

| Module | Purpose | Regulation |
|--------|---------|------------|
| `cbk_compliance_checker.py` | CBK cybersecurity framework | CBK-CS-001 |
| `aml_data_scanner.py` | Anti-money laundering compliance | Kuwait AML Law |
| `consumer_protection_validator.py` | Customer data protection | Consumer Protection Law |
| `sharia_compliance_checker.py` | Islamic banking requirements | Sharia Board Guidelines |

### Reporting Engines

| Report Type | Audience | Format |
|-------------|----------|--------|
| Executive Summary | Board of Directors | PDF, PowerBI |
| Technical Assessment | IT Security Team | JSON, HTML |
| CBK Audit Report | Regulatory Authorities | PDF, Word |
| Remediation Plan | Implementation Teams | Excel, CSV |

---

## 🔧 Advanced Configuration

### Custom Card Patterns
```yaml
# config/kuwait_card_patterns.yml
kuwait_cards:
  knet_cards:
    pattern: "^(627780|440621)\\d{10}$"
    issuer: "K-Net"
    validation: luhn_algorithm
  
  cbk_regulated:
    - pattern: "^4\\d{15}$"  # Visa
      local_issuer: true
    - pattern: "^5[1-5]\\d{14}$"  # MasterCard
      local_issuer: true
```

### Risk Scoring Configuration
```yaml
# config/risk_scoring.yml
risk_factors:
  card_data_exposure:
    unencrypted_pan: 10.0
    cvv_storage: 9.5
    track_data: 9.0
    expired_cards: 5.0
  
  access_control:
    admin_access: 8.0
    shared_accounts: 7.5
    weak_passwords: 6.0
    
  kuwait_specific:
    cbk_violation: 10.0
    aml_non_compliance: 9.0
    consumer_data_breach: 8.5
```

### Integration Settings
```yaml
# config/integrations.yml
siem_integration:
  enabled: true
  platform: "Splunk"
  endpoint: "https://siem.bank.com.kw:8088"
  
email_notifications:
  enabled: true
  critical_alerts: ["ciso@bank.com.kw", "compliance@bank.com.kw"]
  cbk_reports: ["regulatory@bank.com.kw"]
  
compliance_tools:
  microsoft_purview: true
  azure_sentinel: true
  defender_for_cloud: true
```

---

## 📋 Compliance Frameworks Coverage

### PCI DSS v4.0 Requirements
- ✅ **Requirement 1**: Install and maintain network security controls
- ✅ **Requirement 2**: Apply secure configurations to all system components
- ✅ **Requirement 3**: Protect stored cardholder data
- ✅ **Requirement 4**: Protect cardholder data with strong cryptography during transmission
- ✅ **Requirement 5**: Protect all systems and networks from malicious software
- ✅ **Requirement 6**: Develop and maintain secure systems and software
- ✅ **Requirement 7**: Restrict access to cardholder data by business need to know
- ✅ **Requirement 8**: Identify users and authenticate access to system components
- ✅ **Requirement 9**: Restrict physical access to cardholder data
- ✅ **Requirement 10**: Log and monitor all access to network resources and cardholder data
- ✅ **Requirement 11**: Test security of systems and networks regularly
- ✅ **Requirement 12**: Support information security with organizational policies and programs

### Central Bank of Kuwait (CBK) Framework
- ✅ **Information Security Governance**
- ✅ **Risk Management**
- ✅ **Information Asset Management**
- ✅ **Access Control**
- ✅ **Cryptography**
- ✅ **Systems Security**
- ✅ **Network Security Management**
- ✅ **Application Security**
- ✅ **Vulnerability Management**
- ✅ **Information Security Incident Management**
- ✅ **Business Continuity Management**
- ✅ **Supplier Relationship Management**

---

## 🎯 Target Organizations

### Primary Target Sectors
- **Commercial Banks** - All CBK-licensed commercial banking institutions
- **Investment Companies** - Kuwait Investment Company (KIC) members
- **Payment Service Providers** - Local and international payment processors
- **FinTech Companies** - Digital banking and payment solution providers
- **Insurance Companies** - Organizations processing payment card data
- **Government Financial Agencies** - Public sector financial institutions

### Regulatory Bodies
- **Central Bank of Kuwait (CBK)** - Primary banking regulator
- **Capital Markets Authority (CMA)** - Investment services oversight
- **Kuwait Payment System Company (KNET)** - National payment system
- **Ministry of Commerce and Industry** - Consumer protection enforcement

---

## 🚨 Security and Privacy Considerations

### Data Protection Measures
- **No Sensitive Data Storage** - Scanner never stores actual card data
- **Encrypted Communication** - All API calls use TLS 1.3 encryption
- **Audit Logging** - Complete activity logs for regulatory compliance
- **Access Controls** - Role-based access with MFA requirements
- **Data Retention** - Configurable retention policies for scan results

### Privacy Compliance
- **Kuwait Data Protection Law** - Full compliance with local privacy regulations
- **GDPR Considerations** - For international banking operations
- **Employee Privacy** - Respect for staff personal information
- **Customer Confidentiality** - Banking secrecy law compliance

---

## 🔗 Integration Capabilities

### Microsoft 365 Services
- **Microsoft Graph API** - Core data access and analysis
- **Compliance Center** - Native integration with M365 compliance tools
- **Azure Information Protection** - Label and sensitivity analysis
- **Microsoft Purview** - Data governance and classification
- **Power Platform** - Custom apps and automated workflows

### Third-Party Security Tools
- **SIEM Platforms** - Splunk, Azure Sentinel, QRadar integration
- **Vulnerability Scanners** - Qualys, Rapid7, Tenable connectivity
- **GRC Platforms** - ServiceNow, MetricStream, LogicGate integration
- **Ticketing Systems** - Jira, ServiceDesk, BMC Remedy workflow

### Banking Core Systems
- **Core Banking Platforms** - Integration APIs for transaction analysis
- **Card Management Systems** - Real-time card status verification
- **Risk Management Platforms** - Risk scoring and alert integration
- **Regulatory Reporting** - Automated CBK report generation

---

## 📞 Support and Professional Services

### Community Support
- **GitHub Issues** - Bug reports and feature requests
- **Documentation Wiki** - Comprehensive implementation guides
- **Email Support** - [site@hotmail.com](mailto:site@hotmail.com)
- **LinkedIn** - [Ali AlEnezi](https://linkedin.com/in/alenizi/) for professional networking

### Professional Services Available
- **Implementation Consulting** - Expert deployment and configuration
- **Custom Development** - Organization-specific feature development
- **Compliance Training** - PCI DSS and CBK framework education
- **Regulatory Liaison** - CBK examination preparation and support

### Enterprise Support
- **24/7 Technical Support** - Critical issue resolution
- **Dedicated Implementation Manager** - Project oversight and guidance
- **Regulatory Updates** - Automatic compliance requirement updates
- **Custom Reporting** - Tailored executive and regulatory reports

---

## ⚖️ Legal and Compliance Disclaimers

### Usage Authorization
- ✅ **Authorized Use Only** - Only scan Microsoft 365 environments you own or have permission to assess
- ✅ **Regulatory Compliance** - Ensure compliance with all applicable local and international regulations
- ✅ **Professional Guidance** - Consult with qualified security assessors for official PCI DSS compliance
- ✅ **Legal Requirements** - Maintain compliance with Kuwait banking laws and CBK regulations

### Limitation of Liability
- **Assessment Tool Only** - This scanner provides assessment capabilities but does not guarantee compliance
- **Professional Validation Required** - Results should be validated by qualified security professionals
- **No Warranty** - Software provided as-is without warranty of any kind
- **Regulatory Responsibility** - Organizations remain responsible for actual regulatory compliance

---

## 📄 License and Attribution

### Licensing
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Attribution
- **Microsoft Graph APIs** - For comprehensive M365 data access capabilities
- **PCI Security Standards Council** - For PCI DSS framework and requirements
- **Central Bank of Kuwait** - For cybersecurity framework guidance
- **Open Source Security Community** - For threat intelligence and best practices

---

**🛡️ Securing Kuwait's Financial Sector Through Advanced Compliance Technology**

*M365 PCI Kuwait Scanner - Where regulatory compliance meets technological innovation*

**Built with expertise in Kuwait's financial sector | Maintained by Ali AlEnezi**

---

*Last Updated: September 2025*  
*Version: 1.0.0*  
*Regulatory Framework: PCI DSS v4.0 + CBK Cybersecurity Framework*  
*Supported Languages: English, Arabic (planned)*