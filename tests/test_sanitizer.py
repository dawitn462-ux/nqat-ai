"""
Unit tests for ResponseSanitizer evidence sanitization logic.
"""

from scanner.sanitizer import ResponseSanitizer


def test_sanitizer_html_escape():
    untrusted = "<script>alert('XSS')</script>"
    clean = ResponseSanitizer.sanitize(untrusted)
    assert "<script>" not in clean
    assert "&lt;script&gt;" in clean


def test_sanitizer_control_characters_stripped():
    untrusted = "Server: Apache\x00\x1b[31m\r\nHeader: Injection"
    clean = ResponseSanitizer.sanitize(untrusted)
    assert "\x00" not in clean
    assert "\x1b[31m" not in clean


def test_sanitizer_truncation():
    long_input = "A" * 1000
    clean = ResponseSanitizer.sanitize(long_input, max_len=100)
    assert len(clean) < 150
    assert "[TRUNCATED]" in clean


def test_sanitizer_dict():
    raw_dict = {
        "X-Powered-By": "<script>test</script>",
        "Server": "Express\x00Version",
    }
    clean_dict = ResponseSanitizer.sanitize_dict(raw_dict)
    assert clean_dict["X-Powered-By"] == "&lt;script&gt;test&lt;/script&gt;"
    assert "\x00" not in clean_dict["Server"]
