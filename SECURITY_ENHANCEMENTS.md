# Email Security Scanner - Enhanced Security Features

This document outlines the security enhancements added to the Email Security Scanner project.

## 🔒 New Security Features

### 1. **Email Header Analysis** (SPF, DKIM, DMARC)

The enhanced header analyzer performs deep inspection of email authentication protocols:

#### Features:
- **SPF (Sender Policy Framework)**: Validates SPF records to verify legitimate senders
- **DKIM (DomainKeys Identified Mail)**: Detects DKIM signatures and validates domain authenticity
- **DMARC (Domain-based Message Authentication, Reporting & Conformance)**: Checks DMARC policies for additional sender validation
- **Sender Spoofing Detection**: Identifies mismatches between From, Return-Path, and Reply-To headers
- **Authentication Results**: Parses and evaluates authentication headers

#### How it Works:
```python
from header_analyzer import HeaderAnalyzer

analyzer = HeaderAnalyzer()
reasons, risk_score = analyzer.analyze_headers(email_text)

# Returns:
# - reasons: List of security analysis findings
# - risk_score: 0-100 risk score based on header analysis
```

#### Example Output:
```
✅ SPF record found: v=spf1 include:_spf.google.com ~all
⚠️ No DKIM signature found
✅ DMARC policy: reject
⚠️ Domain mismatch: From (attacker.com) ≠ Return-Path (legit.com)
```

---

### 2. **URL Reputation Checking**

Integrated URL reputation checks using VirusTotal and Google Safe Browsing APIs:

#### Features:
- **VirusTotal Integration**: Check URLs against 90+ antivirus engines
- **Google Safe Browsing**: Check URLs against Google's malware and phishing databases
- **Automatic URL Extraction**: Finds all URLs in email content
- **Risk Scoring**: Calculates URL reputation risk score (0-100)
- **Caching**: Reduces API calls with intelligent caching

#### How it Works:
```python
from url_reputation_checker import URLReputationChecker

checker = URLReputationChecker(
    virustotal_api_key='your_vt_key',
    google_api_key='your_google_key'
)

results = checker.check_email_urls(email_text)
```

#### Example Output:
```
URLs found: 3
- https://example.com: ✅ SAFE
- https://suspicious.tk: 🚨 MALICIOUS (5/90 vendors flagged)
- https://bit.ly/xyz: ⚠️ SUSPICIOUS (2/90 vendors flagged)

Risk Score: 65
Recommendations:
- 🚨 1 URL(s) detected as malicious - DO NOT CLICK
```

---

### 3. **Sender Spoofing Detection**

Advanced detection of email spoofing attacks:

#### Checks:
- Domain mismatches between From and Return-Path
- Reply-To redirection to different domains
- Generic greetings that lack personalization
- Missing authentication headers

#### Risk Indicators:
- ⚠️ Domain mismatch: Different domains in From vs Return-Path
- ⚠️ No SPF record: Domain lacks SPF validation
- ⚠️ No DMARC record: Domain lacks DMARC policy
- ⚠️ No DKIM signature: Email not digitally signed

---

## 📋 Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Key dependencies:
- `dnspython`: For DNS lookups (SPF, DKIM, DMARC records)
- `requests`: For API calls (VirusTotal, Google Safe Browsing)
- `Flask`, `scikit-learn`: Core dependencies

### 2. Configure API Keys (Optional but Recommended)

#### VirusTotal API:
1. Sign up at: https://www.virustotal.com
2. Get your API key from your profile
3. Set environment variable:

**Windows (PowerShell):**
```powershell
$env:VT_API_KEY = "your-virustotal-api-key"
```

**Windows (Command Prompt):**
```cmd
set VT_API_KEY=your-virustotal-api-key
```

**Linux/Mac:**
```bash
export VT_API_KEY="your-virustotal-api-key"
```

#### Google Safe Browsing API:
1. Go to: https://console.cloud.google.com
2. Create a new project
3. Enable "Safe Browsing API"
4. Create an API key
5. Set environment variable:

**Windows (PowerShell):**
```powershell
$env:GOOGLE_API_KEY = "your-google-api-key"
```

**Linux/Mac:**
```bash
export GOOGLE_API_KEY="your-google-api-key"
```

### 3. Verify Configuration

```bash
python -c "
from config import VT_API_KEY, GOOGLE_API_KEY
print(f'VirusTotal API configured: {bool(VT_API_KEY)}')
print(f'Google API configured: {bool(GOOGLE_API_KEY)}')
"
```

---

## 🚀 Usage

### Via Web Interface
1. Start the Flask app: `python app.py`
2. Navigate to `/scan`
3. Submit an email
4. Review the enhanced security analysis results

### Via Python Code

```python
from header_analyzer import HeaderAnalyzer
from url_reputation_checker import URLReputationChecker
from phishing_analyzer import analyze_email

# Analyze headers
analyzer = HeaderAnalyzer()
header_reasons, header_score = analyzer.analyze_headers(email_text)

# Check URLs
checker = URLReputationChecker()
url_results = checker.check_email_urls(email_text)

# Full analysis
phishing_score, reasons, risk_level = analyze_email(email_text)
```

---

## 📊 Integration with Existing System

The enhancements are automatically integrated into:

1. **app.py**: 
   - Header analysis runs during email scan
   - URL reputation checks are included in phishing analysis
   - Results contribute to final risk score

2. **phishing_analyzer.py**:
   - URL reputation findings boost phishing score
   - Malicious URLs +40 points
   - High-risk URLs +20 points

3. **pdf_report.py** (if updated):
   - Include header analysis findings in PDF reports
   - Include URL reputation details

---

## ⚙️ Configuration

See [config.py](config.py) for detailed settings:

```python
# Feature Flags
ENABLE_URL_REPUTATION_CHECK = True
ENABLE_HEADER_ANALYSIS = True

# Security Thresholds
VT_MALICIOUS_THRESHOLD = 5  # Flag if 5+ vendors flag as malicious
URL_RISK_THRESHOLD = 40     # Flag if risk score >= 40
HEADER_RISK_THRESHOLD = 30  # Flag if risk score >= 30

# API Timeouts
VT_API_TIMEOUT = 5          # seconds
GSB_API_TIMEOUT = 5         # seconds
DNS_TIMEOUT = 3             # seconds
```

---

## 🔍 Troubleshooting

### Header Analysis Errors

**Issue**: "DNS query timeout"
- **Solution**: Check internet connectivity, increase `DNS_TIMEOUT` in config.py

**Issue**: "Domain not found (NXDOMAIN)"
- **Solution**: This is normal for non-existent domains; indicates potential spoofing

### URL Reputation Errors

**Issue**: "VirusTotal API key not configured"
- **Solution**: Set `VT_API_KEY` environment variable or pass API key to `URLReputationChecker()`

**Issue**: "API error: 403"
- **Solution**: Check API key validity, verify rate limits haven't been exceeded

### Integration Issues

**Issue**: "header_analyzer module not found"
- **Solution**: Ensure `header_analyzer.py` is in the project root

**Issue**: "dnspython not installed"
- **Solution**: Run `pip install dnspython`

---

## 🎯 Security Best Practices

1. **Never commit API keys**: Use environment variables only
2. **Cache results**: URL reputation checks are cached to reduce API calls
3. **Monitor API usage**: Track VirusTotal/Google Safe Browsing API quotas
4. **Test in sandbox**: Validate email samples in a test environment first
5. **Update regularly**: Keep dependencies updated for security patches

---

## 📈 Performance Impact

- **Header Analysis**: ~100-500ms per email (DNS lookups)
- **URL Reputation**: ~200-2000ms per URL (API calls)
- **Caching**: Reduces subsequent URL checks to <10ms

**Optimization tip**: Disable DNS checks or cache results for high-volume scanning

---

## 🔗 Resources

- **SPF Documentation**: https://www.rfc-editor.org/rfc/rfc7208
- **DKIM Documentation**: https://www.rfc-editor.org/rfc/rfc6376
- **DMARC Documentation**: https://www.rfc-editor.org/rfc/rfc7489
- **VirusTotal API**: https://developers.virustotal.com/reference
- **Google Safe Browsing**: https://developers.google.com/safe-browsing

---

## 📝 License

Same as parent project
