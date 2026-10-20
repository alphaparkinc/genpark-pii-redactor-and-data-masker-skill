"""PII Redactor & Data Masker.
100% Python Standard Library.
"""
import re

class PiiRedactorAndDataMasker:
    """Regex & Luhn heuristic PII redaction and tokenization engine."""

    EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    PHONE_REGEX = re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
    SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

    @staticmethod
    def _is_luhn_valid(card_str: str) -> bool:
        digits = [int(c) for c in card_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    @classmethod
    def redact(cls, text: str) -> dict:
        redacted_text = text
        token_map = {}
        redaction_counts = {"email": 0, "phone": 0, "credit_card": 0, "ssn": 0, "ipv4": 0}

        def mask_email(match):
            original = match.group(0)
            token = f"[EMAIL_{redaction_counts['email'] + 1}]"
            token_map[token] = original
            redaction_counts["email"] += 1
            return token
        redacted_text = cls.EMAIL_REGEX.sub(mask_email, redacted_text)

        def mask_ssn(match):
            original = match.group(0)
            token = f"[SSN_{redaction_counts['ssn'] + 1}]"
            token_map[token] = original
            redaction_counts["ssn"] += 1
            return token
        redacted_text = cls.SSN_REGEX.sub(mask_ssn, redacted_text)

        def mask_card(match):
            candidate = match.group(0)
            clean_digits = re.sub(r'[\s-]', '', candidate)
            if cls._is_luhn_valid(clean_digits):
                token = f"[CREDIT_CARD_{redaction_counts['credit_card'] + 1}]"
                token_map[token] = candidate
                redaction_counts["credit_card"] += 1
                return token
            return candidate
        redacted_text = cls.CARD_REGEX.sub(mask_card, redacted_text)

        def mask_phone(match):
            original = match.group(0)
            token = f"[PHONE_{redaction_counts['phone'] + 1}]"
            token_map[token] = original
            redaction_counts["phone"] += 1
            return token
        redacted_text = cls.PHONE_REGEX.sub(mask_phone, redacted_text)

        def mask_ip(match):
            original = match.group(0)
            token = f"[IP_{redaction_counts['ipv4'] + 1}]"
            token_map[token] = original
            redaction_counts["ipv4"] += 1
            return token
        redacted_text = cls.IPV4_REGEX.sub(mask_ip, redacted_text)

        return {
            "redacted_text": redacted_text,
            "token_map": token_map,
            "redaction_counts": redaction_counts,
            "total_redactions": sum(redaction_counts.values())
        }

    @staticmethod
    def restore(redacted_text: str, token_map: dict) -> str:
        restored = redacted_text
        for token, original in token_map.items():
            restored = restored.replace(token, original)
        return restored
