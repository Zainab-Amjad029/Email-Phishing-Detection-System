import re
import dns.resolver
import dns.rdatatype
from email.utils import parseaddr


class HeaderAnalyzer:
    """Enhanced email header analyzer with SPF, DKIM, DMARC checks."""
    
    def __init__(self):
        self.dns_timeout = 3  # seconds
        self.risk_score = 0
        self.reasons = []
    
    def extract_domain(self, email_address):
        """Extract domain from email address."""
        if not email_address or '@' not in email_address:
            return None
        return email_address.split('@')[1].lower()
    
    def extract_from_header(self, headers):
        """Extract From address from headers."""
        from_match = re.search(r'^From:\s*(.+?)(?:\r?\n[^\s]|\r?\n$)', headers, re.MULTILINE | re.IGNORECASE)
        if from_match:
            from_str = from_match.group(1).strip()
            # Parse email address from "Name <email@domain.com>" format
            name, email = parseaddr(from_str)
            return email.lower() if email else None
        return None
    
    def extract_return_path(self, headers):
        """Extract Return-Path from headers."""
        return_path_match = re.search(r'^Return-Path:\s*[<]?(.+?)[>]?\s*(?:\r?\n|$)', headers, re.MULTILINE | re.IGNORECASE)
        if return_path_match:
            return return_path_match.group(1).strip().lower()
        return None
    
    def extract_dkim_signature(self, headers):
        """Check for DKIM-Signature header."""
        dkim_match = re.search(r'^DKIM-Signature:', headers, re.MULTILINE | re.IGNORECASE)
        return dkim_match is not None
    
    def extract_authentication_results(self, headers):
        """Extract Authentication-Results header."""
        auth_match = re.search(r'^Authentication-Results:\s*(.+?)(?:\r?\n[^\s]|\r?\n$)', headers, re.MULTILINE | re.IGNORECASE)
        return auth_match.group(1).strip() if auth_match else None
    
    def check_spf(self, domain):
        """Check SPF record for domain."""
        if not domain:
            return False, "No domain to check"
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=self.dns_timeout)
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    return True, f"SPF record found: {txt_record[:50]}..."
            return False, "No SPF record found for domain"
        except dns.resolver.NXDOMAIN:
            return False, f"Domain {domain} not found (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            return False, "No SPF record (No Answer)"
        except Exception as e:
            return False, f"SPF check unavailable: {str(e)}"
    
    def check_dmarc(self, domain):
        """Check DMARC policy for domain."""
        if not domain:
            return False, "No domain to check"
        
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.dns_timeout)
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    # Extract policy
                    policy_match = re.search(r'p=(\w+)', txt_record)
                    policy = policy_match.group(1) if policy_match else "unknown"
                    return True, f"DMARC policy: {policy}"
            return False, "No DMARC record found"
        except dns.resolver.NXDOMAIN:
            return False, "No DMARC record (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            return False, "No DMARC record (No Answer)"
        except Exception as e:
            return False, f"DMARC check unavailable: {str(e)}"
    
    def detect_sender_spoofing(self, headers):
        """Detect potential sender spoofing attacks."""
        issues = []
        
        from_email = self.extract_from_header(headers)
        return_path = self.extract_return_path(headers)
        
        if not from_email:
            issues.append("⚠️ No From header found")
            return issues
        
        from_domain = self.extract_domain(from_email)
        return_domain = self.extract_domain(return_path) if return_path else None
        
        # Check if From and Return-Path domains mismatch
        if return_path and from_domain != return_domain:
            issues.append(f"⚠️ Domain mismatch: From ({from_domain}) ≠ Return-Path ({return_domain})")
            self.risk_score += 25
        
        # Check for generic Reply-To divergence
        reply_to_match = re.search(r'^Reply-To:\s*(.+?)(?:\r?\n[^\s]|\r?\n$)', headers, re.MULTILINE | re.IGNORECASE)
        if reply_to_match:
            reply_to_str = reply_to_match.group(1).strip()
            name, reply_email = parseaddr(reply_to_str)
            if reply_email:
                reply_domain = self.extract_domain(reply_email.lower())
                if from_domain != reply_domain:
                    issues.append(f"⚠️ Reply-To domain ({reply_domain}) differs from From ({from_domain})")
                    self.risk_score += 15
        
        # Check for suspicious Reply-To when no From exists
        if reply_to_match and not from_email:
            issues.append("⚠️ Has Reply-To but no valid From header (suspicious)")
            self.risk_score += 20
        
        return issues
    
    def analyze_headers(self, headers):
        """Comprehensive header analysis."""
        self.risk_score = 0
        self.reasons = []
        
        # Extract key information
        from_email = self.extract_from_header(headers)
        return_path = self.extract_return_path(headers)
        has_dkim = self.extract_dkim_signature(headers)
        auth_results = self.extract_authentication_results(headers)
        
        # Add basic header info with explanation
        if from_email:
            self.reasons.append(f"Sender email: {from_email}")
            from_domain = self.extract_domain(from_email)
        else:
            self.reasons.append("WARNING: No valid sender email found in From header - This is a red flag for spoofing")
            self.risk_score += 10
            from_domain = None
        
        if return_path:
            self.reasons.append(f"Return-Path: {return_path} (where bounced emails go)")
        
        # Check SPF
        if from_domain:
            spf_valid, spf_msg = self.check_spf(from_domain)
            if spf_valid:
                self.reasons.append(f"GOOD: SPF record found - helps prevent sender spoofing")
            else:
                self.reasons.append(f"WARNING: No SPF record for {from_domain} - anyone could pretend to be this sender")
                self.risk_score += 15
        
        # Check DMARC
        if from_domain:
            dmarc_valid, dmarc_msg = self.check_dmarc(from_domain)
            if dmarc_valid:
                self.reasons.append(f"GOOD: DMARC policy is configured - provides extra sender verification")
            else:
                self.reasons.append(f"WARNING: No DMARC policy for {from_domain} - domain has no anti-spoofing protection")
                self.risk_score += 10
        
        # Check DKIM
        if has_dkim:
            self.reasons.append("GOOD: DKIM digital signature found - email is cryptographically signed")
        else:
            self.reasons.append("WARNING: No DKIM signature - email is not digitally signed, could be forged")
            self.risk_score += 10
        
        # Check Authentication-Results
        if auth_results:
            self.reasons.append(f"Server authentication results received: {auth_results[:50]}...")
            if 'pass' in auth_results.lower():
                self.reasons.append("GOOD: Server authentication checks PASSED")
            elif 'fail' in auth_results.lower():
                self.reasons.append("CRITICAL: Server authentication checks FAILED - this is likely a phishing email")
                self.risk_score += 30
        else:
            self.reasons.append("WARNING: No Authentication-Results header - this email passed through a mail system without proper verification")
            self.risk_score += 5
        
        # Sender spoofing detection
        spoofing_issues = self.detect_sender_spoofing(headers)
        for issue in spoofing_issues:
            # Make spoofing issues more readable
            if "Domain mismatch" in issue:
                self.reasons.append(f"ALERT: {issue} - This indicates possible email spoofing")
            elif "Reply-To domain" in issue:
                self.reasons.append(f"WARNING: {issue} - Replies may go to a different sender")
            else:
                self.reasons.append(issue)
        
        # Check for suspicious reply-to redirection
        if return_path and from_email and return_path.lower() != from_email.lower():
            self.reasons.append("INFO: Return-Path is different from From address (this is normal for forwarded emails)")
        
        return self.reasons, self.risk_score


# Backward compatibility - keep the simple function
def analyze_headers(headers):
    """Simple header analysis for backward compatibility."""
    analyzer = HeaderAnalyzer()
    reasons, score = analyzer.analyze_headers(headers)
    return reasons