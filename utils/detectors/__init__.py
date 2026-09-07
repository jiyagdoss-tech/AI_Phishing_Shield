"""Detector modules for phishing pattern recognition."""

from .regex_detector import RegexDetector
from .keyword_detector import KeywordDetector
from .url_detector import URLDetector
from .sender_detector import SenderDetector
from .attachment_detector import AttachmentDetector
from .sms_sender_detector import SMSSenderDetector

__all__ = ['RegexDetector', 'KeywordDetector', 'URLDetector', 'SenderDetector', 'AttachmentDetector', 'SMSSenderDetector']
