"""
URL Detection Module
Analyzes URLs for phishing characteristics.
"""

import re
from urllib.parse import urlparse

from utils.helpers import TyposquatHelpers


class URLDetector:
    """
    Detects suspicious URLs and domain characteristics.
    """
    
    def __init__(self):
        """Initialize URL detection patterns."""
        self.shortener_services = [
            'bit.ly', 'tinyurl', 'short.link', 'ow.ly', 
            'goo.gl', 'is.gd', 'buff.ly', 't.co', 'adf.ly'
        ]
        
        self.suspicious_keywords = [
            'verify', 'confirm', 'secure', 'update', 'login',
            'signin', 'account', 'password', 'reset', 'urgent',
            'payroll', 'salary', 'banking', 'human-resources'
        ]
    
    def extract_urls(self, text):
        """
        Extract all URLs from text.
        
        Args:
            text (str): Text to scan
        
        Returns:
            list: List of unique URLs found
        """
        url_pattern = r'https?://[^\s\n<>"\)\]]+|www\.[^\s\n<>"\)\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls
    
    def is_url_shortened(self, url):
        """
        Check if URL uses a shortener service.
        
        Args:
            url (str): URL to check
        
        Returns:
            bool: True if URL is shortened
        """
        url_lower = url.lower()
        return any(service in url_lower for service in self.shortener_services)
    
    def is_ip_address(self, url):
        """
        Check if URL uses IP address instead of domain.
        
        Args:
            url (str): URL to check
        
        Returns:
            bool: True if URL contains IP address
        """
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        return bool(re.search(ip_pattern, url))
    
    def has_suspicious_subdomain(self, url):
        """
        Check for suspicious subdomains.
        
        Args:
            url (str): URL to check
        
        Returns:
            bool: True if subdomain looks suspicious
        """
        url_lower = url.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                return True
        
        return False
    
    def analyze_urls(self, text):
        """
        Complete URL analysis.
        
        Args:
            text (str): Text to analyze
        
        Returns:
            dict: Dictionary with URL findings
        """
        urls = self.extract_urls(text)
        
        suspicious_urls = []
        for url in urls:
            reasons = []
            
            if self.is_url_shortened(url):
                reasons.append('Shortened URL (hides destination)')
            
            if self.is_ip_address(url):
                reasons.append('Uses IP address instead of domain')
            
            if self.has_suspicious_subdomain(url):
                reasons.append('Contains suspicious keywords')
            
            if reasons:
                suspicious_urls.append({
                    'url': url,
                    'reasons': reasons
                })
        
        return {
            'total_urls': len(urls),
            'all_urls': urls,
            'suspicious_urls': suspicious_urls,
            'suspicion_count': len(suspicious_urls)
        }
    
    def get_url_risk_score(self, url_analysis):
        """
        Calculate risk score from URL analysis.
        
        Args:
            url_analysis (dict): Result from analyze_urls()
        
        Returns:
            float: Risk score contribution (0-25)
        """
        score = 0
        
        # Each suspicious URL: +5 points (max 25)
        score += min(url_analysis['suspicion_count'] * 5, 25)
        
        return score

    def analyze_standalone_url(self, url):
        """Analyze one normalized website URL using lexical phishing signals."""
        parsed = urlparse(url)
        domain = (parsed.hostname or '').lower()
        full_url = url.lower()
        findings = []

        def add(code, description, points):
            findings.append({
                'code': code,
                'description': description,
                'points': points
            })

        if parsed.scheme != 'https':
            add('no_https', 'The URL does not use HTTPS', 15)
        if self.is_ip_address(domain):
            add('ip_host', 'The URL uses an IP address instead of a domain name', 25)
        if self.is_url_shortened(url):
            add('shortener', 'The URL uses a shortening service that hides its destination', 25)
        if parsed.username or '@' in parsed.netloc:
            add('embedded_credentials', 'The URL contains embedded user information or an @ symbol', 25)
        if domain.startswith('xn--') or '.xn--' in domain:
            add('punycode', 'The domain uses punycode and may imitate another name', 20)
        if domain.count('.') >= 3:
            add('many_subdomains', 'The URL contains an unusually deep subdomain chain', 10)
        if parsed.port and parsed.port not in (80, 443):
            add('unusual_port', 'The URL uses a non-standard web port', 10)
        if len(url) > 120:
            add('long_url', 'The URL is unusually long and may hide its destination', 10)

        action_terms = [term for term in self.suspicious_keywords if term in full_url]
        if action_terms:
            add('action_terms', f"The URL contains account-action wording: {', '.join(action_terms[:4])}", 15)

        official_domains = {
            'amazon': ('amazon.com', 'amazon.co.uk'),
            'apple': ('apple.com', 'icloud.com'),
            'google': ('google.com', 'gmail.com'),
            'microsoft': ('microsoft.com', 'outlook.com'),
            'paypal': ('paypal.com',),
            'netflix': ('netflix.com',),
        }
        brand_matched = False
        for brand, legitimate_domains in official_domains.items():
            if brand in domain and not any(domain == item or domain.endswith(f'.{item}') for item in legitimate_domains):
                add('brand_impersonation', f'The domain mentions {brand} but is not an official {brand} domain', 35)
                brand_matched = True
                break

        # Fuzzy/typo check - catches lookalikes like "ntflx.com" or "amaz0n.com"
        # that don't literally contain the brand name, so the substring check above misses them
        if not brand_matched:
            domain_labels = [label for label in re.split(r'[.\-]', domain) if label and label != 'www']
            typo_match = TyposquatHelpers.find_typosquat_match(domain_labels, list(official_domains.keys()))
            if typo_match:
                add(
                    'typosquat_brand',
                    f"The domain \"{typo_match['candidate']}\" closely resembles the brand "
                    f"\"{typo_match['brand']}\" (possible typosquat)",
                    35
                )

        if '-' in domain and action_terms:
            add('hyphenated_action_domain', 'The domain combines hyphens with account-action wording', 15)

        score = min(sum(item['points'] for item in findings), 100)
        return {
            'url': url,
            'domain': domain,
            'findings': findings,
            'risk_score': score
        }

