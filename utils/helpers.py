"""
Helpers Module
Common utility functions used throughout the application.
"""

import re
from datetime import datetime


class TextHelpers:
    """Helper functions for text processing."""
    
    @staticmethod
    def truncate_text(text, length=100):
        """
        Truncate text to specified length.
        
        Args:
            text (str): Text to truncate
            length (int): Maximum length
        
        Returns:
            str: Truncated text with ellipsis
        """
        if not text:
            return ''
        if len(text) <= length:
            return text
        return text[:length] + '...'
    
    @staticmethod
    def clean_text(text):
        """
        Remove extra whitespace and normalize text.
        
        Args:
            text (str): Text to clean
        
        Returns:
            str: Cleaned text
        """
        # Remove extra whitespace
        cleaned = ' '.join(text.split())
        
        # Remove multiple consecutive newlines
        cleaned = re.sub(r'\n\n+', '\n\n', cleaned)
        
        return cleaned
    
    @staticmethod
    def escape_html(text):
        """
        Escape HTML special characters.
        
        Args:
            text (str): Text to escape
        
        Returns:
            str: Escaped text
        """
        replacements = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        
        return text
    
    @staticmethod
    def has_special_characters(text):
        """
        Check if text contains suspicious special characters.
        
        Args:
            text (str): Text to check
        
        Returns:
            bool: True if suspicious characters found
        """
        suspicious = ['<', '>', '{', '}', '[', ']', '\\', '|']
        return any(char in text for char in suspicious)


class EmailHelpers:
    """Helper functions for email processing."""
    
    @staticmethod
    def extract_sender_name(email_address):
        """
        Extract name part from email address.
        
        Args:
            email_address (str): Email address
        
        Returns:
            str: Name part before @
        """
        if '@' not in email_address:
            return email_address
        
        return email_address.split('@')[0]
    
    @staticmethod
    def extract_domain(email_address):
        """
        Extract domain from email address.
        
        Args:
            email_address (str): Email address
        
        Returns:
            str: Domain part after @
        """
        if '@' not in email_address:
            return ''
        
        return email_address.split('@')[1]
    
    @staticmethod
    def is_valid_email(email):
        """
        Validate email format.
        
        Args:
            email (str): Email to validate
        
        Returns:
            bool: True if valid format
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def looks_like_noreply(email):
        """
        Check if email looks like an automated noreply address.
        
        Args:
            email (str): Email address
        
        Returns:
            bool: True if looks like noreply
        """
        noreply_patterns = [
            'noreply', 'no-reply', 'no_reply',
            'donotreply', 'do-not-reply', 'do_not_reply',
            'automated', 'notification'
        ]
        
        email_lower = email.lower()
        return any(pattern in email_lower for pattern in noreply_patterns)


class ValidationHelpers:
    """Helper functions for data validation."""
    
    @staticmethod
    def is_valid_risk_score(score):
        """
        Validate risk score is in valid range.
        
        Args:
            score (float): Risk score to validate
        
        Returns:
            bool: True if valid
        """
        return isinstance(score, (int, float)) and 0 <= score <= 100
    
    @staticmethod
    def is_valid_risk_level(level):
        """
        Validate risk level.
        
        Args:
            level (str): Risk level to validate
        
        Returns:
            bool: True if valid
        """
        valid_levels = ['Low', 'Moderate', 'High', 'Critical']
        return level in valid_levels
    
    @staticmethod
    def validate_email_content(content):
        """
        Validate email content meets minimum requirements.
        
        Args:
            content (str): Email content
        
        Returns:
            tuple: (is_valid, error_message)
        """
        if not content:
            return False, 'Email content is empty'
        
        if len(content.strip()) < 10:
            return False, 'Email content too short (minimum 10 characters)'
        
        if len(content) > 1000000:  # 1MB
            return False, 'Email content too large'
        
        return True, 'Valid'


class DateTimeHelpers:
    """Helper functions for date/time operations."""
    
    @staticmethod
    def format_datetime(dt):
        """
        Format datetime for display.
        
        Args:
            dt (datetime): Datetime to format
        
        Returns:
            str: Formatted datetime string
        """
        if isinstance(dt, str):
            return dt
        
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    @staticmethod
    def get_current_timestamp():
        """
        Get current timestamp.
        
        Returns:
            str: Current datetime as string
        """
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    @staticmethod
    def time_ago(datetime_str):
        """
        Get human-readable time difference.
        
        Args:
            datetime_str (str): Datetime string
        
        Returns:
            str: Time ago description
        """
        # Simplified version - in production would use better parsing
        return f"Some time ago on {datetime_str.split()[0]}"


class RenderHelpers:
    """Helper functions for rendering results."""
    
    @staticmethod
    def get_risk_badge(risk_level):
        """
        Get emoji badge for risk level.
        
        Args:
            risk_level (str): Risk level
        
        Returns:
            str: Emoji badge
        """
        badges = {
            'Low': '✅',
            'Moderate': '⚠️',
            'High': '❌',
            'Critical': '🚨'
        }
        return badges.get(risk_level, '❓')
    
    @staticmethod
    def get_risk_color_class(risk_level):
        """
        Get CSS class for risk level color.
        
        Args:
            risk_level (str): Risk level
        
        Returns:
            str: CSS class name
        """
        classes = {
            'Low': 'risk-low',
            'Moderate': 'risk-moderate',
            'High': 'risk-high',
            'Critical': 'risk-critical'
        }
        return classes.get(risk_level, 'risk-unknown')


class TyposquatHelpers:
    """
    Helper functions for detecting typosquatted brand names, e.g. "ntflx"
    for "netflix" or "amzn" for "amazon". Plain substring checks (`if
    'netflix' in domain`) miss these because the full brand name never
    literally appears - this uses fuzzy (edit-distance) matching instead.
    """

    @staticmethod
    def levenshtein_distance(text_a, text_b):
        """
        Compute the Levenshtein (edit) distance between two strings: the
        minimum number of single-character insertions, deletions, or
        substitutions needed to turn one string into the other.

        Args:
            text_a (str): First string
            text_b (str): Second string

        Returns:
            int: Edit distance between the two strings
        """
        a, b = text_a.lower(), text_b.lower()
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)

        previous_row = list(range(len(b) + 1))
        for i, char_a in enumerate(a, start=1):
            current_row = [i]
            for j, char_b in enumerate(b, start=1):
                insert_cost = current_row[j - 1] + 1
                delete_cost = previous_row[j] + 1
                substitute_cost = previous_row[j - 1] + (0 if char_a == char_b else 1)
                current_row.append(min(insert_cost, delete_cost, substitute_cost))
            previous_row = current_row

        return previous_row[-1]

    @staticmethod
    def find_typosquat_match(tokens, brands, min_brand_length=4):
        """
        Check a list of short tokens (e.g. domain labels or a sender ID)
        against a list of known brand names for close-but-not-exact
        matches, catching character-dropping/substitution typosquats that
        plain substring matching misses.

        Args:
            tokens (list): Candidate strings to check (words/labels)
            brands (list): Known brand names to compare against
            min_brand_length (int): Skip brands shorter than this - very
                short brand names produce too many false positives when
                fuzzy-matched

        Returns:
            dict or None: {'brand', 'candidate', 'distance'} for the
                closest suspicious match found, or None if nothing is close
        """
        best_match = None

        for brand in brands:
            brand_lower = brand.lower()
            if len(brand_lower) < min_brand_length:
                continue

            # Allow more edits for longer brand names, fewer for short ones
            max_distance = 2 if len(brand_lower) > 5 else 1

            for token in tokens:
                token_lower = (token or '').lower()
                if not token_lower or len(token_lower) < 3 or token_lower == brand_lower:
                    continue
                # Skip tokens whose length is too different to plausibly be a typo
                if abs(len(token_lower) - len(brand_lower)) > max_distance:
                    continue

                distance = TyposquatHelpers.levenshtein_distance(token_lower, brand_lower)
                if distance <= max_distance and (best_match is None or distance < best_match['distance']):
                    best_match = {'brand': brand_lower, 'candidate': token_lower, 'distance': distance}

        return best_match
