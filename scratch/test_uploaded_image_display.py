"""
Uploaded Image & Media Display Test Script
-------------------------------------------
1. Uploads a sample image file to POST /api/v1/posts/upload-media.
2. Confirms file is saved in uploads/ folder on disk.
3. Tests GET request on HTTPS Dashboard (https://127.0.0.1:8443/uploads/...) to verify image is served cleanly with HTTP 200 OK and correct Content-Type.
"""

import os
import sys
import ssl
import json
import uuid
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BACKEND_URL = "http://127.0.0.1:8000"
DASHBOARD_URL = "https://127.0.0.1:8443"

# Minimal 1x1 valid PNG bytes
SAMPLE_PNG_BYTES = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
    0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
])


def run_media_test():
    print("=" * 75)
    print("UPLOADED IMAGE & MEDIA SERVING VERIFICATION")
    print("=" * 75)

    # 1. Prepare multipart form data payload
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    filename = f"test_cyber_screenshot_{uuid.uuid4().hex[:8]}.png"

    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
    body.extend(b"Content-Type: image/png\r\n\r\n")
    body.extend(SAMPLE_PNG_BYTES)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    # Upload to Backend API
    upload_endpoint = f"{BACKEND_URL}/api/v1/posts/upload-media"
    print(f"[STEP 1] Uploading image '{filename}' to POST {upload_endpoint}...")

    req = urllib.request.Request(
        upload_endpoint,
        data=bytes(body),
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-API-Key": "nkat_secret_api_key_2026"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print("  [PASS] Image Upload Endpoint Response:")
            print(f"    Status:     {data.get('status')}")
            print(f"    URL Path:   {data.get('url')}")
            print(f"    Filename:   {data.get('filename')}")
            print(f"    Media Type: {data.get('media_type')}\n")
            rel_url = data.get("url")
            saved_filename = data.get("filename")
    except Exception as exc:
        print(f"  [FAIL] Upload failed: {exc}")
        return

    # 2. Check Disk Storage
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    disk_path = os.path.join(project_root, "uploads", saved_filename)
    print(f"[STEP 2] Checking physical file on disk at '{disk_path}'...")
    if os.path.exists(disk_path):
        size = os.path.getsize(disk_path)
        print(f"  [PASS] File verified on disk! (Size: {size} bytes)\n")
        disk_ok = True
    else:
        print(f"  [FAIL] File missing from uploads folder.")
        disk_ok = False

    # 3. Test HTTPS Dashboard Static File Serving (https://127.0.0.1:8443/uploads/...)
    media_url = f"{DASHBOARD_URL}{rel_url}"
    print(f"[STEP 3] Fetching image from HTTPS Dashboard server: GET {media_url}...")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(media_url)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            content_type = resp.headers.get("Content-Type")
            served_bytes = resp.read()
            status_code = resp.status
            print("  [PASS] HTTPS Dashboard Image Serving Result:")
            print(f"    HTTP Status:   {status_code}")
            print(f"    Content-Type:  {content_type} (EXPECTED: image/png)")
            print(f"    Bytes Served:  {len(served_bytes)} bytes")
            dashboard_ok = (status_code == 200 and "image" in content_type and len(served_bytes) == len(SAMPLE_PNG_BYTES))
    except Exception as exc:
        print(f"  [FAIL] Failed to fetch image from HTTPS Dashboard: {exc}")
        dashboard_ok = False

    # 4. Test Post Creation & Media Attachment Rendering
    print(f"\n[STEP 4] Creating new Cyber Advisory Post with uploaded image...")
    post_endpoint = f"{BACKEND_URL}/api/v1/posts"
    post_payload = json.dumps({
        "title": f"Test Security Advisory #{uuid.uuid4().hex[:4]}",
        "tag": "ZERO-DAY ALERT",
        "tag_color": "#ef4444",
        "author": "Security Operations Team",
        "read_time": "3 min read",
        "image_url": rel_url,
        "snippet": "Vulnerability proof-of-concept screenshot attached to security advisory.",
        "content": "Detailed technical analysis with proof of concept image screenshot..."
    }).encode("utf-8")

    req = urllib.request.Request(
        post_endpoint,
        data=post_payload,
        headers={"Content-Type": "application/json", "X-API-Key": "nkat_secret_api_key_2026"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            post_res = json.loads(resp.read().decode("utf-8"))
            print(f"  [PASS] Post Created! ID: #{post_res.get('id')}, image_url: {post_res.get('image_url')}")
            post_ok = True
    except Exception as exc:
        print(f"  [FAIL] Post creation error: {exc}")
        post_ok = False

    all_pass = disk_ok and dashboard_ok and post_ok

    print("\n" + "=" * 75)
    print("UPLOADED MEDIA DISPLAY VERIFICATION SUMMARY")
    print("=" * 75)
    print(f"1. Media File Saved to Disk:        {'[PASS]' if disk_ok else '[FAIL]'}")
    print(f"2. HTTPS Server Returns Image 200: {'[PASS]' if dashboard_ok else '[FAIL]'}")
    print(f"3. Post Advisory Image Attached:  {'[PASS]' if post_ok else '[FAIL]'}")
    print(f"OVERALL MEDIA DISPLAY RESULT:        {'[PASS] ALL MEDIA SERVING CHECKS PASSED' if all_pass else '[FAIL] VERIFICATION FAILED'}")
    print("=" * 75)


if __name__ == "__main__":
    run_media_test()
