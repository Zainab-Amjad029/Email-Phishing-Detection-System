import re
import requests
import time
from urllib.parse import urlparse
import os


class URLReputationChecker:
    """Check URL reputation using VirusTotal and Google Safe Browsing APIs."""
    
    def __init__(self, virustotal_api_key=None, google_api_key=None):
        """
        Initialize URL reputation checker.
        
        Args:
            virustotal_api_key: VirusTotal API key (or set VT_API_KEY env var)
            google_api_key: Google Safe Browsing API key (or set GOOGLE_API_KEY env var)
        """
        self.vt_api_key = virustotal_api_key or os.getenv('VT_API_KEY')
        self.google_api_key = google_api_key or os.getenv('GOOGLE_API_KEY')
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.google_base_url = "https://safebrowsing.googleapis.com/v4"
        self.cache = {}  # Simple in-memory cache
    
    def extract_urls(self, text):
        """Extract all URLs from text."""
        url_pattern = r'https?://[^\s"\)<>\[\]{}|\\^`]+'
        return re.findall(url_pattern, text)
    
    def normalize_url(self, url):
        """Normalize URL for comparison."""
        try:
            parsed = urlparse(url.lower())
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except:
            return url.lower()
    
    def check_virustotal(self, url):
        """
        Check URL reputation on VirusTotal.
        
        Returns:
            {
                'malicious': int,
                'suspicious': int,
                'safe': int,
                'undetected': int,
                'details': str,
                'available': bool
            }
        """
        if not self.vt_api_key:
            return {
                'malicious': 0,
                'suspicious': 0,
                'safe': 0,
                'undetected': 0,
                'details': 'VirusTotal API key not configured',
                'available': False
            }
        
        # Check cache
        url_key = self.normalize_url(url)
        if url_key in self.cache:
            return self.cache[url_key]
        
        try:
            headers = {
                'x-apikey': self.vt_api_key,
                'User-Agent': 'Email-Security-Scanner/1.0'
            }
            
            # URL encode the URL for VirusTotal
            encoded_url = url.encode().hex()
            endpoint = f"{self.vt_base_url}/urls/{encoded_url}"
            
            response = requests.get(endpoint, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'safe': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'available': True
                }
                
                # Generate details
                total = sum([result['malicious'], result['suspicious'], result['safe'], result['undetected']])
                if result['malicious'] > 0:
                    result['details'] = f"🚨 MALICIOUS: {result['malicious']}/{total} vendors flagged this URL"
                elif result['suspicious'] > 0:
                    result['details'] = f"⚠️ SUSPICIOUS: {result['suspicious']}/{total} vendors marked as suspicious"
                else:
                    result['details'] = f"✅ SAFE: {result['safe']}/{total} vendors marked safe"
                
                # Cache result
                self.cache[url_key] = result
                return result
            
            elif response.status_code == 404:
                return {
                    'malicious': 0,
                    'suspicious': 0,
                    'safe': 0,
                    'undetected': 0,
                    'details': 'URL not yet analyzed on VirusTotal',
                    'available': True
                }
            
            else:
                return {
                    'malicious': 0,
                    'suspicious': 0,
                    'safe': 0,
                    'undetected': 0,
                    'details': f'VirusTotal API error: {response.status_code}',
                    'available': False
                }
        
        except requests.exceptions.Timeout:
            return {
                'malicious': 0,
                'suspicious': 0,
                'safe': 0,
                'undetected': 0,
                'details': 'VirusTotal API timeout',
                'available': False
            }
        except Exception as e:
            return {
                'malicious': 0,
                'suspicious': 0,
                'safe': 0,
                'undetected': 0,
                'details': f'VirusTotal check failed: {str(e)}',
                'available': False
            }
    
    def check_google_safe_browsing(self, url):
        """
        Check URL using Google Safe Browsing API.
        
        Returns:
            {
                'is_safe': bool,
                'threats': list,
                'details': str,
                'available': bool
            }
        """
        if not self.google_api_key:
            return {
                'is_safe': True,
                'threats': [],
                'details': 'Google Safe Browsing API key not configured',
                'available': False
            }
        
        try:
            endpoint = f"{self.google_base_url}/threatMatches:find"
            
            payload = {
                'client': {
                    'clientId': 'email-security-scanner',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = requests.post(
                endpoint,
                params={'key': self.google_api_key},
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'matches' in data and len(data['matches']) > 0:
                    threats = []
                    for match in data['matches']:
                        threat_type = match.get('threatType', 'UNKNOWN')
                        threats.append(threat_type)
                    
                    return {
                        'is_safe': False,
                        'threats': threats,
                        'details': f"🚨 DANGEROUS: Detected threats: {', '.join(set(threats))}",
                        'available': True
                    }
                else:
                    return {
                        'is_safe': True,
                        'threats': [],
                        'details': '✅ URL not found in Google Safe Browsing database',
                        'available': True
                    }
            else:
                return {
                    'is_safe': True,
                    'threats': [],
                    'details': f'Google Safe Browsing API error: {response.status_code}',
                    'available': False
                }
        
        except requests.exceptions.Timeout:
            return {
                'is_safe': True,
                'threats': [],
                'details': 'Google Safe Browsing API timeout',
                'available': False
            }
        except Exception as e:
            return {
                'is_safe': True,
                'threats': [],
                'details': f'Google Safe Browsing check failed: {str(e)}',
                'available': False
            }
    
    def check_url(self, url, check_vt=True, check_gsb=True):
        """
        Check URL reputation on both APIs.
        
        Returns:
            {
                'url': str,
                'virustotal': dict,
                'google_safe_browsing': dict,
                'risk_score': int,
                'summary': str
            }
        """
        vt_result = self.check_virustotal(url) if check_vt else None
        gsb_result = self.check_google_safe_browsing(url) if check_gsb else None
        
        # Calculate risk score (0-100)
        risk_score = 0
        
        if vt_result and vt_result.get('available'):
            if vt_result['malicious'] > 0:
                risk_score = min(100, 50 + (vt_result['malicious'] * 5))
            elif vt_result['suspicious'] > 0:
                risk_score = max(risk_score, 30)
        
        if gsb_result and gsb_result.get('available'):
            if not gsb_result['is_safe']:
                risk_score = min(100, risk_score + 30)
        
        # Generate summary
        summary_parts = []
        if vt_result and vt_result.get('available'):
            summary_parts.append(vt_result['details'])
        if gsb_result and gsb_result.get('available'):
            summary_parts.append(gsb_result['details'])
        
        if not summary_parts:
            summary_parts.append("⚠️ Could not verify URL reputation (API keys may not be configured)")
        
        return {
            'url': url,
            'virustotal': vt_result,
            'google_safe_browsing': gsb_result,
            'risk_score': risk_score,
            'summary': ' | '.join(summary_parts)
        }
    
    def check_email_urls(self, email_text):
        """
        Check all URLs found in email text.
        
        Returns:
            {
                'urls_found': int,
                'urls': [dict],
                'malicious_count': int,
                'risk_score': int,
                'recommendations': list
            }
        """
        urls = self.extract_urls(email_text)
        results = []
        malicious_count = 0
        total_risk = 0
        
        for url in urls:
            result = self.check_url(url)
            results.append(result)
            
            if result['virustotal'] and result['virustotal'].get('malicious', 0) > 0:
                malicious_count += 1
            
            total_risk = max(total_risk, result['risk_score'])
        
        recommendations = []
        if malicious_count > 0:
            recommendations.append(f"🚨 {malicious_count} URL(s) detected as malicious - DO NOT CLICK")
        
        if total_risk > 70:
            recommendations.append("⚠️ High risk detected - Do not interact with this email")
        elif total_risk > 40:
            recommendations.append("⚠️ Moderate risk detected - Exercise caution")
        
        if not urls:
            recommendations.append("✅ No URLs found in email")
        
        return {
            'urls_found': len(urls),
            'urls': results,
            'malicious_count': malicious_count,
            'risk_score': total_risk,
            'recommendations': recommendations
        }


# Standalone functions for backward compatibility
def check_urls_in_email(email_text, vt_api_key=None, google_api_key=None):
    """Check all URLs in email text."""
    checker = URLReputationChecker(vt_api_key, google_api_key)
    return checker.check_email_urls(email_text)


def check_url_reputation(url, vt_api_key=None, google_api_key=None):
    """Check single URL reputation."""
    checker = URLReputationChecker(vt_api_key, google_api_key)
    return checker.check_url(url)
