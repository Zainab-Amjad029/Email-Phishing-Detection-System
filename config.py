# Email Security Scanner - Configuration File
# 
# This file contains configuration settings for the email security scanner.
# For security: DO NOT commit API keys to version control!
# Instead, use environment variables:
#   - VT_API_KEY: VirusTotal API key
#   - GOOGLE_API_KEY: Google Safe Browsing API key

import os

# ============================================
# API KEYS (from environment variables)
# ============================================

# VirusTotal API Key
# Get from: https://www.virustotal.com/gui/home/upload
# Free tier available
VT_API_KEY = os.getenv('VT_API_KEY', '')

# Google Safe Browsing API Key
# Get from: https://developers.google.com/safe-browsing/v4/get-started
# Requires Google Cloud project
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')

# ============================================
# FEATURE FLAGS
# ============================================

# Enable/disable URL reputation checks
ENABLE_URL_REPUTATION_CHECK = True

# Enable/disable header analysis
ENABLE_HEADER_ANALYSIS = True

# Enable/disable AI detection
ENABLE_AI_DETECTION = os.getenv('AI_ENABLED', 'false').lower() == 'true'

# ============================================
# DNS SETTINGS
# ============================================

# Timeout for DNS queries (seconds)
DNS_TIMEOUT = 3

# Retry count for DNS queries
DNS_RETRY_COUNT = 1

# ============================================
# API SETTINGS
# ============================================

# VirusTotal API timeout (seconds)
VT_API_TIMEOUT = 5

# Google Safe Browsing API timeout (seconds)
GSB_API_TIMEOUT = 5

# Cache URL reputation checks for this duration (seconds)
# Set to 0 to disable caching
URL_CACHE_DURATION = 3600  # 1 hour

# ============================================
# SECURITY THRESHOLDS
# ============================================

# VirusTotal malicious score threshold (0-100)
VT_MALICIOUS_THRESHOLD = 5  # Flag if 5+ vendors flag as malicious

# URL reputation risk score threshold (0-100)
URL_RISK_THRESHOLD = 40  # Flag if risk score >= 40

# Header analysis risk score threshold (0-100)
HEADER_RISK_THRESHOLD = 30  # Flag if risk score >= 30

# ============================================
# LOGGING
# ============================================

# Enable debug logging
DEBUG = False

# Log file path
LOG_FILE = 'logs/email_security.log'

# ============================================
# SETUP INSTRUCTIONS
# ============================================
"""
To use the enhanced security features:

1. VIRUSTOTAL API:
   - Sign up at: https://www.virustotal.com
   - Get API key from your profile
   - Set environment variable: VT_API_KEY=your_key
   
   Example (Windows PowerShell):
   $env:VT_API_KEY = "your-virustotal-api-key"
   
   Example (Windows CMD):
   set VT_API_KEY=your-virustotal-api-key
   
   Example (Linux/Mac):
   export VT_API_KEY="your-virustotal-api-key"

2. GOOGLE SAFE BROWSING API:
   - Go to: https://console.cloud.google.com
   - Create new project
   - Enable Safe Browsing API
   - Create API key
   - Set environment variable: GOOGLE_API_KEY=your_key
   
   Example (Windows PowerShell):
   $env:GOOGLE_API_KEY = "your-google-api-key"
   
   Example (Windows CMD):
   set GOOGLE_API_KEY=your-google-api-key
   
   Example (Linux/Mac):
   export GOOGLE_API_KEY="your-google-api-key"

3. Test the configuration:
   python -c "
   from config import VT_API_KEY, GOOGLE_API_KEY
   print(f'VT API configured: {bool(VT_API_KEY)}')
   print(f'Google API configured: {bool(GOOGLE_API_KEY)}')
   "
"""
