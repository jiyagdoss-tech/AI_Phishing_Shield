"""
Phishing Detection Engine
Orchestrates all detection modules and produces final analysis.

Pipeline:
    Email Input → Parser → Keyword Detector → URL Detector → 
    Regex Detector → AI Analyzer → Risk Calculator → Save Results
"""

from utils.parsers import EmailParser, SMSParser, URLParser
from utils.detectors import RegexDetector, KeywordDetector, URLDetector, SenderDetector, AttachmentDetector, SMSSenderDetector
from utils.analyzers import RiskCalculator, AIAnalyzer
from utils.helpers import RenderHelpers


class PhishingDetectionEngine:
    """
    Main detection engine that combines rule-based and AI analysis.
    This orchestrates the entire detection workflow.
    """
    
    def __init__(self):
        """Initialize the detection engine with all modules."""
        self.regex_detector = RegexDetector()
        self.keyword_detector = KeywordDetector()
        self.url_detector = URLDetector()
        self.sender_detector = SenderDetector()
        self.attachment_detector = AttachmentDetector()
        self.sms_sender_detector = SMSSenderDetector()
        self.risk_calculator = RiskCalculator()
        self.ai_analyzer = AIAnalyzer()
    
    def analyze_email(self, email_content):
        """
        Complete analysis of email combining all detection methods.
        
        Pipeline Flow:
        1. Parse email
        2. Keyword detection
        3. URL detection
        4. Regex pattern detection
        5. AI analysis
        6. Calculate final risk score
        7. Generate recommendations
        
        Args:
            email_content (str): Raw email text
        
        Returns:
            dict: Complete analysis result with risk score, explanations, etc.
        """
        
        # Step 1: Parse email
        parser = EmailParser(email_content)
        extracted_info = parser.get_extracted_info()
        
        # Step 2: Keyword detection
        keywords_found = self.keyword_detector.analyze_keywords(email_content)
        keyword_score = self.keyword_detector.get_keyword_risk_score(keywords_found)
        
        # Step 3: URL detection
        url_analysis = self.url_detector.analyze_urls(email_content)
        url_score = self.url_detector.get_url_risk_score(url_analysis)
        
        # Step 4: Regex-based detection
        regex_indicators = self.regex_detector.detect_indicators(email_content)
        regex_risk_score = self.regex_detector.calculate_risk_score_from_indicators(regex_indicators)
        regex_summary = self.regex_detector.get_indicator_summary(regex_indicators)
        
        # Step 5: Sender reputation detection
        sender_email = extracted_info.get('sender', 'Unknown')
        sender_analysis = self.sender_detector.check_sender_reputation(sender_email)
        sender_risk_score = self.sender_detector.get_sender_risk_score(sender_email)
        
        # Step 6: Attachment scanning
        attachment_analysis = self.attachment_detector.analyze_attachments(email_content)
        attachment_risk_score = self.attachment_detector.get_attachment_risk_score(email_content)
        
        # Step 7: AI-based analysis
        ai_analysis = self.ai_analyzer.analyze_email(email_content, extracted_info)
        ai_risk_score = self._risk_level_to_score(ai_analysis.get('risk_level', 'Low'))
        
        # Step 8: Calculate combined risk score
        scores_dict = {
            'keyword_score': keyword_score,
            'url_score': url_score,
            'regex_score': regex_risk_score,
            'sender_score': sender_risk_score,
            'attachment_score': attachment_risk_score,
            'ai_score': ai_risk_score
        }
        
        final_risk_score = self.risk_calculator.calculate_combined_score(scores_dict)

        strong_signals = sum([
            keyword_score >= 12,
            url_analysis.get('suspicion_count', 0) > 0,
            regex_risk_score >= 30,
            sender_risk_score >= 10,
            bool(keywords_found.get('urgent')) and bool(keywords_found.get('credentials')),
        ])
        if strong_signals >= 4:
            final_risk_score = max(final_risk_score, 80)

        final_risk_level = self.risk_calculator.score_to_risk_level(final_risk_score)
        
        # Get confidence and summary
        confidence = self.risk_calculator.get_confidence_indicator(scores_dict)
        risk_summary = self.risk_calculator.generate_risk_summary(
            final_risk_score, final_risk_level, confidence
        )
        
        # Step 9: Compile all findings
        final_analysis = self._compile_final_analysis(
            final_risk_score,
            final_risk_level,
            regex_summary,
            ai_analysis,
            keywords_found,
            url_analysis,
            extracted_info,
            confidence,
            sender_analysis,
            attachment_analysis,
            scores_dict
        )
        
        return final_analysis
    
    def analyze_sms(self, sms_content):
        """
        Complete analysis of an SMS/text message combining all detection methods.
        
        Pipeline Flow:
        1. Parse SMS
        2. Keyword detection
        3. URL detection
        4. Regex pattern detection
        5. Sender (phone number/ID) reputation detection
        6. AI analysis
        7. Calculate final risk score
        8. Generate recommendations
        
        Args:
            sms_content (str): Raw SMS text
        
        Returns:
            dict: Complete analysis result with risk score, explanations, etc.
        """
        
        # Step 1: Parse SMS
        parser = SMSParser(sms_content)
        extracted_info = parser.get_extracted_info()
        message_body = extracted_info.get('body', sms_content)
        
        # Step 2: Keyword detection
        keywords_found = self.keyword_detector.analyze_keywords(sms_content)
        keyword_score = self.keyword_detector.get_keyword_risk_score(keywords_found)
        
        # Step 3: URL detection
        url_analysis = self.url_detector.analyze_urls(sms_content)
        url_score = self.url_detector.get_url_risk_score(url_analysis)
        
        # Step 4: Regex-based detection
        regex_indicators = self.regex_detector.detect_indicators(sms_content)
        regex_risk_score = self.regex_detector.calculate_risk_score_from_indicators(regex_indicators)
        regex_summary = self.regex_detector.get_indicator_summary(regex_indicators)
        
        # Step 5: SMS sender (phone number/ID) reputation detection
        sender = extracted_info.get('sender', 'Unknown')
        sender_analysis = self.sms_sender_detector.check_sender_reputation(sender, message_body)
        sender_risk_score = self.sms_sender_detector.get_sender_risk_score(sender, message_body)
        
        # Step 6: AI-based analysis
        ai_analysis = self.ai_analyzer.analyze_sms(sms_content, extracted_info)
        ai_risk_score = self._risk_level_to_score(ai_analysis.get('risk_level', 'Low'))
        
        # Step 7: Calculate combined risk score (no attachment detector for SMS)
        scores_dict = {
            'keyword_score': keyword_score,
            'url_score': url_score,
            'regex_score': regex_risk_score,
            'sender_score': sender_risk_score,
            'ai_score': ai_risk_score
        }
        
        final_risk_score = self.risk_calculator.calculate_combined_score_sms(scores_dict)

        strong_signals = sum([
            keyword_score >= 12,
            url_analysis.get('suspicion_count', 0) > 0,
            regex_risk_score >= 30,
            sender_risk_score >= 10,
            bool(keywords_found.get('urgent')) and bool(keywords_found.get('credentials')),
        ])
        if strong_signals >= 4:
            final_risk_score = max(final_risk_score, 80)

        final_risk_level = self.risk_calculator.score_to_risk_level(final_risk_score)
        
        # Get confidence
        confidence = self.risk_calculator.get_confidence_indicator_sms(scores_dict)
        
        # Step 8: Compile all findings
        final_analysis = self._compile_final_analysis_sms(
            final_risk_score,
            final_risk_level,
            regex_summary,
            ai_analysis,
            keywords_found,
            url_analysis,
            extracted_info,
            confidence,
            sender_analysis,
            scores_dict
        )
        
        return final_analysis

    def analyze_url(self, url):
        """Analyze a standalone website URL for phishing indicators."""
        parser = URLParser(url)
        url_info = parser.get_extracted_info()
        normalized_url = url_info['url']
        if not parser.is_valid():
            raise ValueError('Please provide a valid website URL')

        url_analysis = self.url_detector.analyze_standalone_url(normalized_url)
        lexical_score = url_analysis['risk_score']
        ai_analysis = self.ai_analyzer.analyze_url(
            normalized_url,
            url_info,
            url_analysis['findings']
        )
        ai_score = self._risk_level_to_score(ai_analysis.get('risk_level', 'Low'))
        scores_dict = {'url_score': lexical_score, 'ai_score': ai_score}

        final_score = self.risk_calculator.calculate_combined_score_url(scores_dict)
        if lexical_score >= 80:
            final_score = max(final_score, 80)
        # A confirmed brand-impersonation/typosquat match (e.g. "ntflx.com" for
        # Netflix) is one of the most decisive phishing signals there is for a
        # standalone URL, so floor the score at Critical even if the AI's own
        # wording came out more measured than the lexical finding warrants.
        brand_flagged = any(
            finding['code'] in ('brand_impersonation', 'typosquat_brand')
            for finding in url_analysis['findings']
        )
        if brand_flagged:
            final_score = max(final_score, 80)
        final_level = self.risk_calculator.score_to_risk_level(final_score)
        confidence = self.risk_calculator.get_confidence_indicator_url(scores_dict)

        indicators = [item['description'] for item in url_analysis['findings']]
        indicators.extend(ai_analysis.get('key_concerns', []))
        recommendations = [
            'Do not open the URL or enter credentials until the domain is verified',
            'Navigate to the organization through its official website or app',
        ] if final_level in ('High', 'Critical') else [
            'Verify the domain and destination before opening the URL'
        ]

        return {
            'analysis_type': 'url',
            'input_content': normalized_url,
            'risk_score': round(final_score, 1),
            'risk_level': final_level,
            'detected_indicators': indicators,
            'ai_explanation': ai_analysis.get('ai_explanation', ''),
            'risk_level_text': ai_analysis.get('risk_level_text', ai_analysis.get('risk_level', 'Moderate')),
            'top_concerns': ai_analysis.get('top_concerns', ai_analysis.get('key_concerns', [])),
            'explanation': ai_analysis.get('explanation', ''),
            'recommendation_bullets': ai_analysis.get('recommendation_bullets', recommendations),
            'recommendations': recommendations,
            'scores': scores_dict,
            'email_details': {
                'sender': url_info['domain'],
                'subject': '(Website URL)',
                'links_found': 1,
                'emails_found': 0
            },
            'detection_confidence': confidence,
            'breakdown': {
                'url_info': url_info,
                'url_findings': url_analysis['findings']
            }
        }
    
    def _compile_final_analysis(self, risk_score, risk_level, regex_summary, 
                                ai_analysis, keywords, urls, email_info, confidence,
                                sender_analysis, attachment_analysis, scores_dict):
        """
        Compile all detection results into final analysis.
        
        Args:
            risk_score (float): Final calculated risk score
            risk_level (str): Risk level
            regex_summary (list): Regex findings
            ai_analysis (dict): AI analysis results
            keywords (dict): Keyword findings
            urls (dict): URL analysis results
            email_info (dict): Extracted email info
            confidence (dict): Confidence metrics
        
        Returns:
            dict: Complete analysis result
        """
        
        # Compile all indicators
        all_indicators = []
        
        # Add regex-based indicators
        all_indicators.extend(regex_summary)
        
        # Add keyword-based indicators
        if keywords.get('urgent'):
            all_indicators.append(f"🚨 Urgent language detected ({len(keywords['urgent'])} keywords)")
        if keywords.get('credentials'):
            all_indicators.append(f"🔐 Credential requests found ({len(keywords['credentials'])} keywords)")
        if keywords.get('fear_tactics'):
            all_indicators.append(f"😟 Fear tactics detected ({len(keywords['fear_tactics'])} phrases)")
        
        # Add URL-based indicators
        if urls.get('suspicious_urls'):
            all_indicators.append(f"🌐 Suspicious URLs found ({len(urls['suspicious_urls'])} URLs)")
        
        # Add sender reputation indicators
        if sender_analysis.get('homograph_attacks'):
            all_indicators.append(f"👤 Suspicious sender detected: {sender_analysis['homograph_attacks']}")
        if sender_analysis.get('suspicious_patterns'):
            all_indicators.append(f"⚠️ Sender email has suspicious patterns")
        
        # Add attachment indicators
        if attachment_analysis.get('has_critical_files'):
            all_indicators.append(f"🚫 CRITICAL: Dangerous file attachments detected!")
        elif attachment_analysis.get('has_macro_files'):
            all_indicators.append(f"⚠️ Suspicious macro-enabled files detected")
        elif attachment_analysis.get('attachment_count', 0) > 0:
            all_indicators.append(f"📎 {attachment_analysis['attachment_count']} attachment(s) found")
        
        # Add AI indicators
        all_indicators.extend(ai_analysis.get('key_concerns', []))
        
        # Compile recommendations
        recommendations = self._get_recommendations(risk_level, all_indicators)
        
        # Build final result
        result = {
            'analysis_type': 'email',
            'input_content': email_info.get('body', '')[:500],
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'detected_indicators': all_indicators,
            'ai_explanation': ai_analysis.get('ai_explanation', ''),
            'risk_level_text': ai_analysis.get('risk_level_text', ai_analysis.get('risk_level', 'Moderate')),
            'top_concerns': ai_analysis.get('top_concerns', ai_analysis.get('key_concerns', [])),
            'explanation': ai_analysis.get('explanation', ''),
            'recommendation_bullets': ai_analysis.get('recommendation_bullets', ai_analysis.get('recommendations', [])),
            'recommendations': recommendations,
            'scores': scores_dict,
            'email_details': {
                'sender': email_info.get('sender', 'Unknown'),
                'subject': email_info.get('subject', 'No subject'),
                'links_found': len(email_info.get('links', [])),
                'emails_found': len(email_info.get('emails', []))
            },
            'detection_confidence': confidence,
            'breakdown': {
                'keywords_found': keywords,
                'urls_analyzed': urls.get('total_urls'),
                'suspicious_urls': len(urls.get('suspicious_urls', [])),
                'sender_reputation': {
                    'risk_level': sender_analysis.get('risk_level'),
                    'is_free_email': sender_analysis.get('is_free_email')
                },
                'attachments': {
                    'count': attachment_analysis.get('attachment_count', 0),
                    'has_critical': attachment_analysis.get('has_critical_files', False),
                    'has_macros': attachment_analysis.get('has_macro_files', False)
                }
            }
        }
        
        return result
    
    def _compile_final_analysis_sms(self, risk_score, risk_level, regex_summary,
                                     ai_analysis, keywords, urls, sms_info, confidence,
                                     sender_analysis, scores_dict):
        """
        Compile all SMS detection results into final analysis.
        
        Args:
            risk_score (float): Final calculated risk score
            risk_level (str): Risk level
            regex_summary (list): Regex findings
            ai_analysis (dict): AI analysis results
            keywords (dict): Keyword findings
            urls (dict): URL analysis results
            sms_info (dict): Extracted SMS info
            confidence (dict): Confidence metrics
            sender_analysis (dict): Sender (phone number/ID) reputation findings
            scores_dict (dict): Individual detector scores
        
        Returns:
            dict: Complete analysis result
        """
        
        # Compile all indicators
        all_indicators = []
        
        # Add regex-based indicators
        all_indicators.extend(regex_summary)
        
        # Add keyword-based indicators
        if keywords.get('urgent'):
            all_indicators.append(f"🚨 Urgent language detected ({len(keywords['urgent'])} keywords)")
        if keywords.get('credentials'):
            all_indicators.append(f"🔐 Credential requests found ({len(keywords['credentials'])} keywords)")
        if keywords.get('fear_tactics'):
            all_indicators.append(f"😟 Fear tactics detected ({len(keywords['fear_tactics'])} phrases)")
        
        # Add URL-based indicators
        if urls.get('suspicious_urls'):
            all_indicators.append(f"🌐 Suspicious URLs found ({len(urls['suspicious_urls'])} URLs)")
        
        # Add sender reputation indicators
        if sender_analysis.get('brand_impersonation'):
            all_indicators.append(f"📱 Sender number/ID impersonates a known brand")
        if sender_analysis.get('suspicious_patterns'):
            all_indicators.append(f"⚠️ Sender number/ID has suspicious patterns")
        
        # Add AI indicators
        all_indicators.extend(ai_analysis.get('key_concerns', []))
        
        # Compile recommendations
        recommendations = self._get_recommendations(risk_level, all_indicators)
        
        # Build final result
        result = {
            'analysis_type': 'sms',
            'input_content': sms_info.get('body', '')[:500],
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'detected_indicators': all_indicators,
            'ai_explanation': ai_analysis.get('ai_explanation', ''),
            'risk_level_text': ai_analysis.get('risk_level_text', ai_analysis.get('risk_level', 'Moderate')),
            'top_concerns': ai_analysis.get('top_concerns', ai_analysis.get('key_concerns', [])),
            'explanation': ai_analysis.get('explanation', ''),
            'recommendation_bullets': ai_analysis.get('recommendation_bullets', ai_analysis.get('recommendations', [])),
            'recommendations': recommendations,
            'scores': scores_dict,
            'email_details': {
                'sender': sms_info.get('sender', 'Unknown'),
                'subject': '(SMS message)',
                'links_found': len(sms_info.get('links', [])),
                'emails_found': 0
            },
            'detection_confidence': confidence,
            'breakdown': {
                'keywords_found': keywords,
                'urls_analyzed': urls.get('total_urls'),
                'suspicious_urls': len(urls.get('suspicious_urls', [])),
                'sender_reputation': {
                    'risk_level': sender_analysis.get('risk_level'),
                    'sender_type': sender_analysis.get('sender_type')
                }
            }
        }
        
        return result
    
    def _risk_level_to_score(self, risk_level):
        """
        Convert risk level to numerical score.
        
        Args:
            risk_level (str): 'Low', 'Moderate', 'High', 'Critical'
        
        Returns:
            float: Score 0-100
        """
        mapping = {
            'Low': 20,
            'Moderate': 50,
            'High': 75,
            'Critical': 95
        }
        return mapping.get(risk_level, 50)
    
    def _score_to_risk_level(self, score):
        """
        Convert numerical score to risk level.
        
        Args:
            score (float): Score 0-100
        
        Returns:
            str: Risk level
        """
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Moderate'
        else:
            return 'Low'
    
    def _get_recommendations(self, risk_level, indicators):
        """
        Generate recommendations based on risk level and indicators.
        
        Args:
            risk_level (str): Final risk level
            indicators (list): List of detected indicators
        
        Returns:
            list: Actionable recommendations
        """
        recommendations = []
        
        # Base recommendations based on risk level
        if risk_level == 'Critical':
            recommendations.append("⛔ DO NOT click any links or download attachments")
            recommendations.append("⛔ DO NOT reply to this email")
            recommendations.append("⛔ DO NOT provide any personal information")
            recommendations.append("🚨 Report immediately to your email provider")
        elif risk_level == 'High':
            recommendations.append("❌ Be very cautious with links and attachments")
            recommendations.append("❌ Verify sender identity through official channels")
            recommendations.append("📧 Report this email as phishing to your email provider")
        elif risk_level == 'Moderate':
            recommendations.append("⚠️ Review email carefully before taking action")
            recommendations.append("⚠️ Check sender email address closely")
        elif risk_level == 'Low':
            recommendations.append("✅ This email appears legitimate")
            recommendations.append("💡 Always verify sender identity if you have any doubts")
        
        # Specific recommendations based on indicators
        has_urgency = any('urgent' in str(ind).lower() for ind in indicators)
        has_credentials = any('credential' in str(ind).lower() or 'password' in str(ind).lower() for ind in indicators)
        has_links = any('link' in str(ind).lower() or 'url' in str(ind).lower() for ind in indicators)
        
        if has_credentials:
            recommendations.append("🔐 Legitimate companies never ask for passwords via email")
            recommendations.append("🔐 If asked to verify credentials, go directly to the official website")
        
        if has_urgency:
            recommendations.append("⏰ Don't let urgency pressure you into clicking")
            recommendations.append("⏰ Real companies allow time for verification")
        
        if has_links:
            recommendations.append("🔗 Hover over links to see the real URL (don't click)")
            recommendations.append("🔗 If suspicious, visit the official website directly")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
        
