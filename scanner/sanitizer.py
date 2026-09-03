"""
Scanned Response Input Sanitizer & Validator.
Sanitizes raw HTTP header/body evidence before logging or JSON report generation.
Prevents log injection, XSS, and control character corruption.
"""

import html
import re
from typing import Any, Dict, Optional, Union


class ResponseSanitizer:
    """
    Sanitizes string inputs extracted from untrusted scan target HTTP responses.
    """

    # Strip ANSI escape codes, null bytes, and non-printable control characters
    CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]|\x1b\[[0-9;]*[a-zA-Z]')

    @classmethod
    def sanitize(cls, input_val: Optional[Union[str, Any]], max_len: int = 500) -> str:
        """
        Sanitizes untrusted target output:
        1. Converts non-string types safely.
        2. Strips dangerous control characters and ANSI color sequences.
        3. HTML-escapes special characters to prevent HTML/XSS injection.
        4. Truncates output to safe maximum length.
        """
        if input_val is None:
            return ""

        val_str = str(input_val)

        # 1. Strip control characters and terminal ANSI sequences
        clean_str = cls.CONTROL_CHAR_REGEX.sub("", val_str)

        # 2. Escape HTML entities
        escaped_str = html.escape(clean_str)

        # 3. Truncate if exceeding max length
        if len(escaped_str) > max_len:
            return escaped_str[:max_len] + "... [TRUNCATED]"

        return escaped_str

    @classmethod
    def sanitize_dict(cls, data_dict: Dict[str, Any]) -> Dict[str, str]:
        """
        Recursively sanitizes dictionary keys and values (e.g. response headers).
        """
        sanitized = {}
        for k, v in data_dict.items():
            clean_k = cls.sanitize(k, max_len=100)
            clean_v = cls.sanitize(v, max_len=300)
            sanitized[clean_k] = clean_v
        return sanitized
