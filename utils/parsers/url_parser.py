"""Normalize and parse website URLs for phishing analysis."""

import ipaddress
import re
from urllib.parse import parse_qs, urlparse


class URLParser:
    """Extract structural details from a website URL."""

    def __init__(self, url):
        self.raw_url = url.strip()
        self.normalized_url = self._normalize_url()
        self.parsed = urlparse(self.normalized_url)

    def _normalize_url(self):
        if not self.raw_url:
            return ""
        if not self.raw_url.lower().startswith(("http://", "https://")):
            return f"https://{self.raw_url}"
        return self.raw_url

    def get_extracted_info(self):
        return {
            "url": self.normalized_url,
            "scheme": self.parsed.scheme.lower(),
            "domain": (self.parsed.hostname or "").lower(),
            "port": self.parsed.port,
            "path": self.parsed.path or "/",
            "query_parameters": parse_qs(self.parsed.query),
            "uses_https": self.parsed.scheme.lower() == "https",
        }

    def is_valid(self):
        domain = (self.parsed.hostname or '').lower()
        if not domain or any(character.isspace() for character in domain):
            return False
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            pass
        if '.' not in domain or len(domain) > 253:
            return False
        return all(
            label and len(label) <= 63 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label)
            for label in domain.split('.')
        )
