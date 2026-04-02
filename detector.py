"""
Phishing Detection Engine
Rule-based analysis for identifying phishing indicators in emails
"""

import re
from urllib.parse import urlparse
from datetime import datetime
import json
import os

# Configuration for detection rules
DETECTION_RULES = {
    'urgent_keywords': {
        'keywords': [
            'urgent', 'act now', 'immediate action', 'limited time',
            'expires today', 'suspended', 'account locked',
            'verify immediately', 'confirm your identity',
            'unusual activity', 'security alert', 'verify now'
        ],
        'score': 20,
        'description': 'Urgent/pressuring language detected'
    },
    'suspicious_cta': {
        'keywords': [
            'click here', 'click now', 'click below', 'open attachment',
            'download now', 'update your info', 'confirm your account',
            'verify your details', 'log in to', 'enter your password'
        ],
        'score': 15,
        'description': 'Suspicious call-to-action phrase detected'
    },
    'financial_request': {
        'keywords': [
            'bank account', 'credit card', 'social security', 'ssn',
            'wire transfer', 'payment', 'billing', 'invoice',
            'refund', 'prize', 'winner', 'lottery'
        ],
        'score': 25,
        'description': 'Financial or sensitive information request'
    },
    'poor_grammar': {
        'patterns': [
            r'\b(dear|customer|user|account holder)\b',
            r'\b(kindly|plz|recieve|acount)\b',
            r'(?i)\b(free money|guaranteed|win)\b'
        ],
        'score': 10,
        'description': 'Poor grammar or suspicious phrasing detected'
    },
    'threat_language': {
        'keywords': [
            'terminate', 'suspend', 'close your account',
            'legal action', 'lawsuit', 'arrest', 'prosecute',
            'failure to comply', 'penalties', 'final notice'
        ],
        'score': 20,
        'description': 'Threatening or intimidating language detected'
    }
}

# Legitimate domains for comparison (typosquatting detection)
KNOWN_LEGITIMATE_DOMAINS = [
    'google.com', 'microsoft.com', 'amazon.com', 'apple.com',
    'paypal.com', 'netflix.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'instagram.com', 'yahoo.com', 'outlook.com',
    'dropbox.com', 'adobe.com', 'bankofamerica.com', 'chase.com',
    'wellsfargo.com', 'citibank.com', 'usbank.com', 'capitalone.com'
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link']


class PhishingDetector:
    """Main class for phishing detection analysis"""
    
    def __init__(self):
        self.flags = []
        self.total_score = 0
    
    def reset(self):
        """Reset the detector state"""
        self.flags = []
        self.total_score = 0
    
    def analyze(self, sender: str, subject: str, body: str, links: list = None) -> dict:
        """
        Analyze an email for phishing indicators
        
        Args:
            sender: Email sender address
            subject: Email subject line
            body: Email body content
            links: List of URLs found in the email
        
        Returns:
            dict: Analysis result with score, risk level, and flags
        """
        self.reset()
        
        # Convert all text to lowercase for analysis
        body_lower = body.lower()
        subject_lower = subject.lower()
        
        # Run all detection checks
        self._check_urgent_language(body_lower, subject_lower)
        self._check_suspicious_cta(body_lower)
        self._check_financial_requests(body_lower)
        self._check_threat_language(body_lower)
        self._check_sender_domain(sender)
        self._check_poor_grammar(body_lower)
        
        # Analyze links if provided
        if links:
            for link in links:
                self._analyze_link(link, body_lower)
        
        # Check for typosquatting in sender domain
        self._check_typosquatting(sender)
        
        # Check for mismatched display text vs actual URL
        self._check_mismatched_urls(body)
        
        # Calculate risk level
        risk_level = self._calculate_risk_level()
        
        return {
            'score': min(self.total_score, 100),  # Cap at 100
            'risk': risk_level,
            'flags': self.flags,
            'timestamp': datetime.now().isoformat()
        }
    
    def _add_flag(self, flag_type: str, description: str, score: int):
        """Add a detection flag to the results"""
        self.flags.append({
            'type': flag_type,
            'description': description,
            'score': score
        })
        self.total_score += score
    
    def _check_urgent_language(self, body: str, subject: str):
        """Check for urgent/pressuring language"""
        text = body + ' ' + subject
        for keyword in DETECTION_RULES['urgent_keywords']['keywords']:
            if keyword in text:
                self._add_flag(
                    'urgent_language',
                    f"Urgent language detected: '{keyword}'",
                    DETECTION_RULES['urgent_keywords']['score']
                )
                break  # Only flag once for this category
    
    def _check_suspicious_cta(self, body: str):
        """Check for suspicious call-to-action phrases"""
        for keyword in DETECTION_RULES['suspicious_cta']['keywords']:
            if keyword in body:
                self._add_flag(
                    'suspicious_cta',
                    f"Suspicious call-to-action: '{keyword}'",
                    DETECTION_RULES['suspicious_cta']['score']
                )
                break
    
    def _check_financial_requests(self, body: str):
        """Check for requests involving financial or sensitive information"""
        for keyword in DETECTION_RULES['financial_request']['keywords']:
            if keyword in body:
                self._add_flag(
                    'sensitive_info_request',
                    f"Request for sensitive data: '{keyword}'",
                    DETECTION_RULES['financial_request']['score']
                )
                break
    
    def _check_threat_language(self, body: str):
        """Check for threatening or intimidating language"""
        for keyword in DETECTION_RULES['threat_language']['keywords']:
            if keyword in body:
                self._add_flag(
                    'threat_language',
                    f"Threatening language: '{keyword}'",
                    DETECTION_RULES['threat_language']['score']
                )
                break
    
    def _check_sender_domain(self, sender: str):
        """Check sender email domain"""
        if not sender or '@' not in sender:
            self._add_flag(
                'unknown_sender',
                'Unverifiable sender address',
                15
            )
            return
        
        domain = sender.split('@')[-1].lower()
        
        # Check for free email domains that could be suspicious
        free_email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        legitimate_corporate = ['.com', '.org', '.edu', '.gov', '.net']
        
        # If sender uses free email but claims to be a company
        is_free_domain = any(domain == f for f in free_email_domains)
        
        if is_free_domain and len(domain) > 20:
            self._add_flag(
                'suspicious_sender',
                f'Unusual sender domain: {domain}',
                15
            )
        
        # Check for newly registered or suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                self._add_flag(
                    'suspicious_tld',
                    f'Suspicious domain extension: {domain}',
                    20
                )
                break
    
    def _check_typosquatting(self, sender: str):
        """Detect typosquatting attempts"""
        if not sender or '@' not in sender:
            return
        
        domain = sender.split('@')[-1].lower()
        
        for legitimate in KNOWN_LEGITIMATE_DOMAINS:
            # Check for common typosquatting patterns
            # 1. Character replacement (paypa1, g00gle)
            # 2. Missing character (googel)
            # 3. Extra character (googlee)
            # 4. Swapped characters (goolge)
            
            if self._is_typosquatting(domain, legitimate):
                self._add_flag(
                    'typosquatting',
                    f'Possible typosquatting: {domain} (similar to {legitimate})',
                    30
                )
                break
    
    def _is_typosquatting(self, domain: str, legitimate: str) -> bool:
        """Check if domain is a typosquatting variant of legitimate"""
        # Remove TLD for comparison
        domain_base = domain.split('.')[0] if '.' in domain else domain
        legit_base = legitimate.split('.')[0] if '.' in legitimate else legitimate
        
        if domain_base == legit_base:
            return False
        
        # Check for character substitution (l -> 1, o -> 0, i -> 1)
        substitutions = {'l': '1', 'o': '0', 'i': '1', 'e': '3', 'a': '4'}
        
        for char, replacement in substitutions.items():
            if char in legit_base:
                test_domain = domain_base.replace(replacement, char)
                if test_domain == legit_base:
                    return True
        
        # Check for missing character (1 character difference)
        if abs(len(domain_base) - len(legit_base)) == 1:
            shorter = domain_base if len(domain_base) < len(legit_base) else legit_base
            longer = domain_base if len(domain_base) > len(legit_base) else legit_base
            if sum(1 for i in range(len(shorter)) if shorter[i] != longer[i]) <= 1:
                return True
        
        return False
    
    def _check_poor_grammar(self, body: str):
        """Check for poor grammar patterns common in phishing"""
        for pattern in DETECTION_RULES['poor_grammar']['patterns']:
            if re.search(pattern, body, re.IGNORECASE):
                self._add_flag(
                    'poor_grammar',
                    'Poor grammar or suspicious phrasing detected',
                    DETECTION_RULES['poor_grammar']['score']
                )
                break
    
    def _analyze_link(self, url: str, body: str):
        """Analyze a URL for suspicious characteristics"""
        if not url:
            return
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for IP address instead of domain
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain):
                self._add_flag(
                    'ip_address_url',
                    f'URL uses IP address instead of domain: {domain}',
                    30
                )
            
            # Check for suspicious characters in domain
            suspicious_chars = ['@', '\\', '//', 'javascript:']
            for char in suspicious_chars:
                if char in url.lower():
                    self._add_flag(
                        'suspicious_url',
                        f'Suspicious URL format detected: {url}',
                        25
                    )
                    break
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
            if any(s in domain for s in shorteners):
                self._add_flag(
                    'url_shortener',
                    f'URL shortener used: {domain}',
                    15
                )
            
            # Check for excessive hyphens (common in phishing domains)
            if domain.count('-') >= 3:
                self._add_flag(
                    'suspicious_domain_structure',
                    f'Domain with excessive hyphens: {domain}',
                    20
                )
            
            # Check for data: URLs
            if url.lower().startswith('data:'):
                self._add_flag(
                    'data_url',
                    'Data URL detected (potential phishing)',
                    25
                )
            
        except Exception:
            pass
    
    def _check_mismatched_urls(self, body: str):
        """Check for HTML anchor text that doesn't match actual URL"""
        # Pattern to match <a href="...">Display Text</a>
        link_pattern = r'<a\s+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        matches = re.findall(link_pattern, body, re.IGNORECASE)
        
        for url, display_text in matches:
            display_lower = display_text.lower()
            url_lower = url.lower()
            
            # Check if display text mentions a known brand but URL doesn't
            brands = ['paypal', 'google', 'microsoft', 'amazon', 'apple', 'facebook', 'netflix', 'bank']
            for brand in brands:
                if brand in display_lower and brand not in url_lower:
                    self._add_flag(
                        'mismatched_url',
                        f'Display text mentions "{brand}" but URL does not',
                        25
                    )
                    break
    
    def _calculate_risk_level(self) -> str:
        """Calculate the risk level based on total score"""
        if self.total_score > 60:
            return 'HIGH'
        elif self.total_score > 30:
            return 'MEDIUM'
        else:
            return 'LOW'


# Standalone function for easy use
def analyze_email(sender: str, subject: str, body: str, links: list = None) -> dict:
    """
    Analyze an email for phishing indicators
    
    Args:
        sender: Email sender address
        subject: Email subject line
        body: Email body content
        links: List of URLs found in the email
    
    Returns:
        dict: Analysis result with score, risk level, and flags
    """
    detector = PhishingDetector()
    return detector.analyze(sender, subject, body, links)


# Demo function with sample phishing email
def demo_phishing_detection():
    """Demonstrate the detection engine with sample emails"""
    
    # Sample phishing email
    phishing_email = {
        'sender': 'security@paypa1.com',
        'subject': 'URGENT: Your Account Has Been Compromised!',
        'body': '''
        Dear Valued Customer,
        
        We have detected unusual activity on your PayPal account. 
        Your account has been LIMITED until you verify your information.
        
        Click here to verify your account: http://192.168.1.1/verify
        
        If you do not verify within 24 hours, your account will be permanently suspended.
        
        Act now to avoid legal action!
        
        Sincerely,
        PayPal Security Team
        ''',
        'links': ['http://192.168.1.1/verify', 'http://bit.ly/fake-link']
    }
    
    # Sample legitimate email
    legitimate_email = {
        'sender': 'newsletter@amazon.com',
        'subject': 'Your Order Has Shipped',
        'body': '''
        Hello,
        
        Good news! Your order #123-4567890 has shipped and is on its way.
        
        You can track your package in the Amazon app or on our website.
        
        Thank you for shopping with us!
        
        Amazon Customer Service
        ''',
        'links': ['https://amazon.com/track/123']
    }
    
    print("=" * 60)
    print("PHISHING EMAIL ANALYSIS")
    print("=" * 60)
    result = analyze_email(
        phishing_email['sender'],
        phishing_email['subject'],
        phishing_email['body'],
        phishing_email['links']
    )
    print(f"\nRisk Score: {result['score']}/100")
    print(f"Risk Level: {result['risk']}")
    print("\nDetection Flags:")
    for flag in result['flags']:
        print(f"  ⚠️  [{flag['score']} pts] {flag['description']}")
    
    print("\n" + "=" * 60)
    print("LEGITIMATE EMAIL ANALYSIS")
    print("=" * 60)
    result = analyze_email(
        legitimate_email['sender'],
        legitimate_email['subject'],
        legitimate_email['body'],
        legitimate_email['links']
    )
    print(f"\nRisk Score: {result['score']}/100")
    print(f"Risk Level: {result['risk']}")
    if result['flags']:
        print("\nDetection Flags:")
        for flag in result['flags']:
            print(f"  ⚠️  [{flag['score']} pts] {flag['description']}")
    else:
        print("\n✅ No suspicious indicators detected")


if __name__ == '__main__':
    demo_phishing_detection()
