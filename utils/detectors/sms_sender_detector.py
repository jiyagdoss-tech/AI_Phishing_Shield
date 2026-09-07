"""
SMS Sender Detection Module
Analyzes SMS sender numbers/IDs for smishing (SMS phishing) indicators.
"""

import re

from utils.helpers import TyposquatHelpers


class SMSSenderDetector:
    """
    Detects suspicious SMS sender numbers and alphanumeric sender IDs.
    Checks if the sender looks like a legitimate short code/brand ID or a spoofed number.
    """

    def __init__(self):
        """Initialize SMS sender detection patterns."""
        # Legitimate short codes are typically 5-6 digits
        self.short_code_length_range = (5, 6)

        # Known premium-rate style prefixes sometimes abused in smishing
        self.premium_prefixes = ('900', '976')

        # Brand names commonly impersonated in smishing messages/sender IDs
        self.impersonated_brands = [
            'bank', 'paypal', 'amazon', 'apple', 'google', 'microsoft',
            'fedex', 'ups', 'usps', 'dhl', 'netflix', 'irs', 'gov',
            'delivery', 'support', 'security', 'alert'
        ]

    def extract_sender_type(self, sender):
        """
        Classify sender as short_code, phone_number, alphanumeric_id, mixed, or unknown.

        Args:
            sender (str): Raw sender string (phone number or ID)

        Returns:
            dict: Sender classification info
        """
        if not sender or sender == 'Unknown':
            return {'type': 'unknown', 'digits': '', 'raw': sender}

        digits_only = re.sub(r'\D', '', sender)
        letters_only = re.sub(r'[^A-Za-z]', '', sender)

        if letters_only and not digits_only:
            return {'type': 'alphanumeric_id', 'digits': '', 'raw': sender}

        if digits_only and not letters_only:
            if self.short_code_length_range[0] <= len(digits_only) <= self.short_code_length_range[1]:
                return {'type': 'short_code', 'digits': digits_only, 'raw': sender}
            return {'type': 'phone_number', 'digits': digits_only, 'raw': sender}

        if digits_only and letters_only:
            return {'type': 'mixed', 'digits': digits_only, 'raw': sender}

        return {'type': 'unknown', 'digits': '', 'raw': sender}

    def detect_brand_impersonation(self, sender, message_body=''):
        """
        Detect a message/sender claiming to be a known brand from an ordinary phone number.

        Args:
            sender (str): Sender phone number or ID
            message_body (str): SMS message content

        Returns:
            list: List of impersonation findings
        """
        findings = []
        sender_lower = (sender or '').lower()
        body_lower = (message_body or '').lower()
        sender_type = self.extract_sender_type(sender)['type']

        brand_matched = False
        for brand in self.impersonated_brands:
            if brand in sender_lower or brand in body_lower:
                if sender_type == 'phone_number':
                    findings.append({
                        'type': 'brand_impersonation',
                        'brand': brand,
                        'description': f'Message references "{brand}" but is sent from an ordinary phone number, not an official short code'
                    })
                    brand_matched = True
                    break

        # Fuzzy/typo check on the sender ID itself - catches lookalikes like
        # "NTFLX-ALERT" or "AMZN-SUPPORT" that don't literally contain the
        # brand name. Only checked against the sender token (not the free-text
        # message body) to avoid false positives on ordinary words.
        if not brand_matched:
            sender_tokens = [token for token in re.split(r'[.\-\s]', sender_lower) if token]
            typo_match = TyposquatHelpers.find_typosquat_match(sender_tokens, self.impersonated_brands)
            if typo_match:
                findings.append({
                    'type': 'typosquat_sender_id',
                    'brand': typo_match['brand'],
                    'description': (
                        f"Sender ID \"{typo_match['candidate']}\" closely resembles the brand "
                        f"\"{typo_match['brand']}\" (possible spoofed sender ID)"
                    )
                })

        return findings

        return findings

    def detect_suspicious_patterns(self, sender):
        """
        Detect suspicious patterns in the SMS sender.

        Args:
            sender (str): Sender phone number or ID

        Returns:
            list: List of suspicious patterns found
        """
        suspicious = []

        if not sender or sender == 'Unknown':
            suspicious.append({
                'type': 'missing_sender',
                'description': 'No sender number/ID could be identified'
            })
            return suspicious

        digits_only = re.sub(r'\D', '', sender)
        stripped = sender.strip()

        # Pattern 1: International number pretending to be a familiar local sender
        if stripped.startswith('+') and not stripped.startswith('+1'):
            suspicious.append({
                'type': 'international_number',
                'description': 'Message originates from an international phone number'
            })

        # Pattern 2: Premium-rate style number prefixes
        if digits_only[:3] in self.premium_prefixes:
            suspicious.append({
                'type': 'premium_rate_number',
                'description': 'Sender number matches known premium-rate prefixes'
            })

        # Pattern 3: Unusually long numeric sender (spoofed/foreign format)
        if len(digits_only) > 11:
            suspicious.append({
                'type': 'excessive_length',
                'description': 'Sender number is unusually long for a standard phone number'
            })

        # Pattern 4: Alphanumeric sender ID with account-action wording (spoofed sender ID)
        action_terms = ['verify', 'update', 'secure', 'confirm', 'alert']
        if re.search(r'[A-Za-z]', sender) and any(term in sender.lower() for term in action_terms):
            suspicious.append({
                'type': 'lookalike_action_id',
                'description': 'Sender ID uses account-action wording often seen in spoofed IDs'
            })

        return suspicious

    def check_sender_reputation(self, sender, message_body=''):
        """
        Check overall SMS sender reputation.

        Args:
            sender (str): Sender phone number/ID
            message_body (str): SMS message body

        Returns:
            dict: Reputation assessment
        """
        sender_info = self.extract_sender_type(sender)

        reputation = {
            'sender': sender,
            'sender_type': sender_info['type'],
            'brand_impersonation': self.detect_brand_impersonation(sender, message_body),
            'suspicious_patterns': self.detect_suspicious_patterns(sender),
            'risk_level': 'Low'
        }

        if reputation['brand_impersonation'] or reputation['suspicious_patterns']:
            reputation['risk_level'] = 'High'
        elif sender_info['type'] == 'phone_number':
            reputation['risk_level'] = 'Moderate'

        return reputation

    def get_sender_risk_score(self, sender, message_body=''):
        """
        Calculate risk score for SMS sender (0-20 points).

        Args:
            sender (str): Sender phone number/ID
            message_body (str): SMS message body

        Returns:
            float: Risk score (0-20)
        """
        score = 0
        reputation = self.check_sender_reputation(sender, message_body)

        # Brand impersonation: +10 points each (very suspicious)
        score += len(reputation['brand_impersonation']) * 10

        # Suspicious patterns: +5 points each
        score += len(reputation['suspicious_patterns']) * 5

        # Ordinary phone number (rather than a verified short code): +2 points
        if reputation['sender_type'] == 'phone_number':
            score += 2

        return min(score, 20)  # Max 20 points
