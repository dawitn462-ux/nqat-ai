import sys
import os
sys.path.insert(0, os.path.abspath('.'))

import logging
logging.basicConfig(level=logging.INFO)

from backend.services.email_service import send_verification_email

try:
    print("Testing send_verification_email...")
    res = send_verification_email(
        recipient_email="cybert378@gmail.com",
        username="testuser",
        verification_code="123456",
        verification_token="testtoken"
    )
    print("RESULT:", res)
except Exception as e:
    print("EXCEPTION:", e)
