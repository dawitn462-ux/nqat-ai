from PIL import Image, ImageDraw

def create_favicon():
    size = (64, 64)
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Dark background rounded rectangle with red border
    # Fill: #090d16 -> (9, 13, 22, 255)
    # Stroke: #ef4444 -> (239, 68, 68, 255)
    draw.rounded_rectangle([2, 2, 61, 61], radius=14, fill=(9, 13, 22, 255), outline=(239, 68, 68, 255), width=3)

    # Outer Delta Triangle (white)
    draw.polygon([(32, 10), (52, 50), (12, 50)], fill=(255, 255, 255, 255), outline=(255, 255, 255, 255))

    # Inner Delta Cutout (dark)
    draw.polygon([(32, 23), (43, 45), (21, 45)], fill=(9, 13, 22, 255))

    # Red AI Core Node dot
    # Circle at (32, 38) radius 5 -> [27, 33, 37, 43]
    draw.ellipse([27, 33, 37, 43], fill=(239, 68, 68, 255))

    # Save PNG and ICO
    pub_dir = 'frontend/public'
    img.save(f'{pub_dir}/favicon.png', format='PNG')
    
    # Save multi-size ICO
    img_32 = img.resize((32, 32), Image.Resampling.LANCZOS)
    img_16 = img.resize((16, 16), Image.Resampling.LANCZOS)
    img.save(f'{pub_dir}/favicon.ico', format='ICO', sizes=[(64, 64), (32, 32), (16, 16)])
    print("Favicon PNG and ICO generated successfully!")

if __name__ == '__main__':
    create_favicon()
