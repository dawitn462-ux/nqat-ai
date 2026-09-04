import sys
import os
from PIL import Image, ImageDraw

def generate_favicons():
    # Create 64x64 RGBA image
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Outer rounded square background (Black with white border)
    # Rounded rect from (2, 2) to (61, 61)
    rect_box = [2, 2, 61, 61]
    radius = 14
    draw.rounded_rectangle(rect_box, radius=radius, fill=(0, 0, 0, 255), outline=(255, 255, 255, 255), width=3)

    # 2. Outer White Triangle
    # Top: (32, 12), Bottom Right: (53, 50), Bottom Left: (11, 50)
    outer_triangle = [(32, 12), (53, 50), (11, 50)]
    draw.polygon(outer_triangle, fill=(255, 255, 255, 255))

    # 3. Inner Black Triangle Cutout
    # Top: (32, 26), Bottom Right: (43, 44), Bottom Left: (21, 44)
    inner_triangle = [(32, 26), (43, 44), (21, 44)]
    draw.polygon(inner_triangle, fill=(0, 0, 0, 255))

    # Paths
    public_dir = os.path.abspath("frontend/public")
    dist_dir = os.path.abspath("frontend/dist")
    os.makedirs(public_dir, exist_ok=True)
    os.makedirs(dist_dir, exist_ok=True)

    # Save PNG
    png_path_public = os.path.join(public_dir, "favicon.png")
    png_path_dist = os.path.join(dist_dir, "favicon.png")
    img.save(png_path_public, "PNG")
    img.save(png_path_dist, "PNG")
    print(f"[+] Saved PNG favicons: {png_path_public}")

    # Save ICO (sizes 16, 32, 48, 64)
    ico_path_public = os.path.join(public_dir, "favicon.ico")
    ico_path_dist = os.path.join(dist_dir, "favicon.ico")
    img.save(ico_path_public, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
    img.save(ico_path_dist, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
    print(f"[+] Saved ICO favicons: {ico_path_public}")

if __name__ == "__main__":
    generate_favicons()
