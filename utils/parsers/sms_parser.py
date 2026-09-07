"""
SMS Parser Module
Extracts and cleans SMS/text message content for analysis.
"""

import re


class SMSParser:
    """
    Parses SMS content and extracts relevant information.
    Accepts either a raw SMS message body, or structured text with
    "From:"/"Sender:" and "Message:"/"Body:"/"Text:" fields.
    """

    def __init__(self, sms_content):
        """
        Initialize SMS parser with message content.

        Args:
            sms_content (str): Raw SMS text
        """
        self.raw_content = sms_content
        self.cleaned_content = self._clean_sms()
        self.extracted_info = self._extract_sms_info()

    def _clean_sms(self):
        """
        Remove extra whitespace and normalize SMS content.

        Returns:
            str: Cleaned SMS content
        """
        cleaned = self.raw_content.strip()
        cleaned = re.sub(r'\n\n+', '\n\n', cleaned)
        return cleaned

    def _extract_sms_info(self):
        """
        Extract key information from the SMS.

        Returns:
            dict: Dictionary with extracted SMS components
        """
        info = {
            'sender': self._extract_sender(),
            'body': self._extract_body(),
            'links': self._extract_links(),
            'phone_numbers': self._extract_phone_numbers()
        }
        return info

    def _extract_sender(self):
        """
        Extract sender phone number/ID from content.

        Returns:
            str: Sender phone number/ID, or 'Unknown' if not present
        """
        sender_pattern = r'(?:From|Sender)\s*:\s*([^\n]+)'
        match = re.search(sender_pattern, self.cleaned_content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return "Unknown"

    def _extract_body(self):
        """
        Extract the SMS message text.

        Returns:
            str: SMS message body
        """
        # Look for an explicit "Message:"/"Body:"/"Text:" field first
        body_pattern = r'(?:Message|Body|Text)\s*:\s*(.+)'
        match = re.search(body_pattern, self.cleaned_content, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()

        # No explicit body field - strip a leading sender line if present
        lines = self.cleaned_content.split('\n')
        if lines and re.match(r'^(From|Sender)\s*:', lines[0], re.IGNORECASE):
            return '\n'.join(lines[1:]).strip()

        return self.cleaned_content

    def _extract_links(self):
        """
        Extract all URLs/links from the SMS.

        Returns:
            list: List of unique URLs found
        """
        url_pattern = r'https?://[^\s\n<>"\)\]]+|www\.[^\s\n<>"\)\]]+'
        links = re.findall(url_pattern, self.cleaned_content, re.IGNORECASE)

        seen = set()
        unique_links = []
        for link in links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)

        return unique_links

    def _extract_phone_numbers(self):
        """
        Extract phone numbers referenced within the SMS body (e.g. callback numbers).

        Returns:
            list: List of unique phone numbers found
        """
        phone_pattern = r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        phones = re.findall(phone_pattern, self.cleaned_content)
        return list(set(phones))

    def get_extracted_info(self):
        """
        Get all extracted SMS information.

        Returns:
            dict: Dictionary with sender, body, links, phone numbers
        """
        return self.extracted_info

    def get_full_text(self):
        """
        Get cleaned SMS full text.

        Returns:
            str: Cleaned SMS content
        """
        return self.cleaned_content
