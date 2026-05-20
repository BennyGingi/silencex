#!/usr/bin/env python3
"""Generate SilenceX application icon — purple/magenta theme."""

try:
    from PIL import Image, ImageDraw
except ImportError:
    import subprocess
    subprocess.check_call(["pip", "install", "Pillow", "--quiet"])
    from PIL import Image, ImageDraw

import os

def generate_icon():
    sizes = [256, 128, 64, 48, 32, 16]
    images = []

    for size in sizes:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Background circle — dark
        m = int(size * 0.05)
        draw.ellipse([m, m, size - m, size - m], fill=(14, 17, 23, 255),
                     outline=(192, 38, 211, 255), width=max(1, int(size * 0.04)))

        cx, cy = size // 2, size // 2

        # Sound wave lines (muted/crossed)
        lw = max(1, int(size * 0.03))
        # Wave 1
        w1 = int(size * 0.15)
        h1 = int(size * 0.20)
        draw.arc([cx - w1, cy - h1, cx + w1, cy + h1], 200, 340,
                 fill=(192, 38, 211, 180), width=lw)
        # Wave 2
        w2 = int(size * 0.25)
        h2 = int(size * 0.30)
        draw.arc([cx - w2, cy - h2, cx + w2, cy + h2], 210, 330,
                 fill=(192, 38, 211, 120), width=lw)
        # Wave 3
        w3 = int(size * 0.35)
        h3 = int(size * 0.40)
        draw.arc([cx - w3, cy - h3, cx + w3, cy + h3], 220, 320,
                 fill=(192, 38, 211, 60), width=lw)

        # Center dot
        r = int(size * 0.08)
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(192, 38, 211, 255))

        # X slash (silence)
        slash_w = max(2, int(size * 0.04))
        offset = int(size * 0.25)
        draw.line([cx - offset, cy - offset, cx + offset, cy + offset],
                  fill=(255, 59, 59, 200), width=slash_w)
        draw.line([cx - offset, cy + offset, cx + offset, cy - offset],
                  fill=(255, 59, 59, 200), width=slash_w)

        images.append(img)

    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "silencex.ico")
    images[0].save(icon_path, format="ICO", sizes=[(s, s) for s in sizes],
                   append_images=images[1:])

    # Also save PNG for Linux
    png_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "silencex.png")
    images[0].save(png_path, format="PNG")

    print(f"Icon saved: {icon_path}")
    print(f"PNG saved:  {png_path}")

if __name__ == "__main__":
    generate_icon()
