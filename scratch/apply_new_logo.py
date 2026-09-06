import os
import base64
from PIL import Image

def process_logo():
    uploaded_path = r"C:\Users\hp\.gemini\antigravity-ide\brain\4a9c0a98-4aa6-4589-b7ea-3c32867dd6aa\.user_uploaded\media_1788720605668.png"
    if not os.path.exists(uploaded_path):
        print(f"[-] Uploaded image not found at {uploaded_path}")
        return

    img = Image.open(uploaded_path)
    print(f"[+] Loaded original image size: {img.size}, mode: {img.mode}")

    # Prepare directories
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    public_dir = os.path.join(root, "frontend", "public")
    dist_dir = os.path.join(root, "frontend", "dist")
    dashboard_dir = os.path.join(root, "dashboard")
    data_dir = os.path.join(root, "data")

    for d in [public_dir, dist_dir, dashboard_dir, data_dir]:
        os.makedirs(d, exist_ok=True)

    # 1. Save logo.png
    png_img = img.convert("RGBA")
    png_img.save(os.path.join(public_dir, "logo.png"), "PNG")
    png_img.save(os.path.join(dist_dir, "logo.png"), "PNG")

    # 2. Save logo.jpg
    rgb_img = Image.new("RGB", img.size, (10, 2, 4))
    if img.mode in ("RGBA", "LA"):
        rgb_img.paste(img, (0, 0), img)
    else:
        rgb_img = img.convert("RGB")

    rgb_img.save(os.path.join(public_dir, "logo.jpg"), "JPEG", quality=95)
    rgb_img.save(os.path.join(dist_dir, "logo.jpg"), "JPEG", quality=95)
    rgb_img.save(os.path.join(dashboard_dir, "logo.jpg"), "JPEG", quality=95)
    rgb_img.save(os.path.join(data_dir, "logo.jpg"), "JPEG", quality=95)

    # 3. Save favicon.png
    fav_png = png_img.resize((256, 256), Image.Resampling.LANCZOS)
    fav_png.save(os.path.join(public_dir, "favicon.png"), "PNG")
    fav_png.save(os.path.join(dist_dir, "favicon.png"), "PNG")

    # 4. Save favicon.ico (multi-size ICO)
    fav_png.save(
        os.path.join(public_dir, "favicon.ico"),
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    )
    fav_png.save(
        os.path.join(dist_dir, "favicon.ico"),
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    )

    # 5. Save favicon.svg (embedded data URI SVG)
    with open(os.path.join(public_dir, "logo.png"), "rb") as f:
        b64_str = base64.b64encode(f.read()).decode("utf-8")

    w, h = img.size
    svg_content = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%" height="100%">
  <image href="data:image/png;base64,{b64_str}" width="{w}" height="{h}"/>
</svg>'''

    with open(os.path.join(public_dir, "favicon.svg"), "w", encoding="utf-8") as f:
        f.write(svg_content)
    with open(os.path.join(dist_dir, "favicon.svg"), "w", encoding="utf-8") as f:
        f.write(svg_content)

    print("[+] Successfully generated all logo and favicon assets across the platform!")

if __name__ == "__main__":
    process_logo()
