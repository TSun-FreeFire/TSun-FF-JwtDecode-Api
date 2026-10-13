#!/usr/bin/env python3
"""Generate the JWT Decoder favicon set.

The mark is the same 24x24 "layers" artwork that is used in the site header
(templates/index.html, .logo-icon), drawn in the brand colour
(--color-primary: #6366f1) on a rounded tile, so the browser tab icon and the
header logo are the same identity.

Every raster size is drawn on a 64x64 design grid, rendered at 8x and
downsampled with Lanczos, which keeps the 16/32 px versions crisp instead of
mushy. Output goes to static/.

Pillow is a build time dependency only:

    python -m pip install Pillow
    python tools/generate_favicons.py
"""

import io
import json
import struct
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "static"

# --- brand, taken from static/style.css ------------------------------------ #
BRAND = (99, 102, 241)  # --color-primary
BRAND_HEX = "#6366f1"
MARK = (255, 255, 255)

# --- geometry, on a 64x64 design grid (= favicon.svg viewBox) -------------- #
GRID = 64
RADIUS = 14  # tile corner radius, 22% of the grid
MARK_SCALE = 1.75  # the 24x24 logo box scaled to 42/64 of the tile
MARK_ORIGIN = 11  # (GRID - 24 * MARK_SCALE) / 2, centres the mark
STROKE = 2.6  # stroke-width inside the 24x24 logo box; the header logo uses 2,
#               a touch heavier so the three layers stay readable at 16 px
SUPERSAMPLE = 8

# Half pixel: the tile is centred on the pixel grid of the canvas, the mark has
# to be shifted by the same half pixel or it lands one pixel off centre (and
# the export is no longer mirror symmetric).
MARK_OFFSET = -0.5

# The 24x24 logo paths, copied verbatim from the header logo (Feather "layers").
LAYERS = (
    [(12, 2), (2, 7), (12, 12), (22, 7), (12, 2)],  # top layer (closed)
    [(2, 12), (12, 17), (22, 12)],  # middle layer
    [(2, 17), (12, 22), (22, 17)],  # bottom layer
)


def render(size: int, *, rounded: bool = True) -> Image.Image:
    """Draw the icon at ``size`` px, with or without the rounded tile.

    iOS applies its own mask to apple-touch-icon, so that one is full bleed.
    """
    canvas = size * SUPERSAMPLE
    scale = canvas / GRID
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # The tile fills the canvas: its box centre is the pixel centre grid, so it
    # is symmetric on its own.
    box = (0, 0, canvas - 1, canvas - 1)
    if rounded:
        draw.rounded_rectangle(box, radius=RADIUS * scale, fill=BRAND)
    else:
        draw.rectangle(box, fill=BRAND)

    stroke = max(1, round(STROKE * MARK_SCALE * scale))
    half = stroke / 2

    for layer in LAYERS:
        points = [
            (
                (MARK_ORIGIN + MARK_SCALE * x) * scale + MARK_OFFSET,
                (MARK_ORIGIN + MARK_SCALE * y) * scale + MARK_OFFSET,
            )
            for x, y in layer
        ]

        # Round joins come from joint="curve", round caps from the dots below.
        draw.line(points, fill=MARK, width=stroke, joint="curve")
        for x, y in points:
            draw.ellipse((x - half, y - half, x + half, y + half), fill=MARK)

    image = image.resize((size, size), Image.LANCZOS)

    # Mirror the left half onto the right half so the exported icon is exactly
    # symmetric, whatever rounding the rasteriser did on the way down.
    half = size // 2
    image.paste(image.crop((0, 0, half, size)).transpose(Image.FLIP_LEFT_RIGHT), (half, 0))

    return image


def write_svg(path: Path) -> None:
    """Write the vector version, same geometry as :func:`render`."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {g} {g}" '
        'role="img" aria-label="JWT Decoder">\n'
        "    <title>JWT Decoder</title>\n"
        '    <rect width="{g}" height="{g}" rx="{r}" fill="{c}"/>\n'
        "    <g fill=\"none\" stroke=\"#ffffff\" stroke-width=\"{w}\" "
        'stroke-linecap="round" stroke-linejoin="round" '
        'transform="translate({o} {o}) scale({s})">\n'
        '        <path d="M12 2L2 7L12 12L22 7L12 2Z"/>\n'
        '        <path d="M2 12L12 17L22 12"/>\n'
        '        <path d="M2 17L12 22L22 17"/>\n'
        "    </g>\n"
        "</svg>\n"
    ).format(
        g=GRID, r=RADIUS, c=BRAND_HEX, w=STROKE, o=MARK_ORIGIN, s=MARK_SCALE
    )
    path.write_text(svg, encoding="utf-8")


def write_ico(path: Path, images) -> None:
    """Write a PNG compressed .ico holding several sizes.

    Written by hand so every frame is downsampled here (Lanczos) instead of
    being re-scaled by the image library.
    """
    frames = []
    for image in images:
        buffer = io.BytesIO()
        image.save(buffer, format="PNG", optimize=True)
        frames.append((image.size[0], buffer.getvalue()))

    header = struct.pack("<HHH", 0, 1, len(frames))
    directory = b""
    offset = 6 + 16 * len(frames)
    payload = b""

    for size, data in frames:
        dimension = 0 if size >= 256 else size  # 0 means 256 in the ICO header
        directory += struct.pack(
            "<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)
        payload += data

    path.write_bytes(header + directory + payload)


def write_manifest(path: Path) -> None:
    """Minimal web app manifest so Android/desktop installs get the icon."""
    manifest = {
        "name": "JWT Decoder",
        "short_name": "JWT Decoder",
        "description": (
            "Decode FreeFire JSON Web Tokens instantly: header, payload, "
            "signature, claims and expiry."
        ),
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": BRAND_HEX,
        "icons": [
            {
                "src": "/static/android-chrome-192x192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any",
            },
            {
                "src": "/static/android-chrome-512x512.png",
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any",
            },
        ],
    }
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    write_svg(OUT / "favicon.svg")
    write_manifest(OUT / "site.webmanifest")

    # Browser tab / bookmarks, rounded tile on transparency.
    for size in (16, 32):
        render(size).save(OUT / f"favicon-{size}x{size}.png", optimize=True)

    # Legacy / pinned tabs: one .ico with the three classic sizes.
    write_ico(OUT / "favicon.ico", [render(s) for s in (16, 32, 48)])

    # iOS home screen: full bleed, iOS applies its own corner mask.
    render(180, rounded=False).save(OUT / "apple-touch-icon.png", optimize=True)

    # Android / PWA.
    for size in (192, 512):
        render(size).save(OUT / f"android-chrome-{size}x{size}.png", optimize=True)

    written = sorted(p.name for p in OUT.glob("favicon*"))
    written += sorted(p.name for p in OUT.glob("*icon*.png"))
    written += sorted(p.name for p in OUT.glob("android-chrome-*.png"))
    written += ["site.webmanifest"]

    for name in written:
        print(f"  {name:<28} {OUT.joinpath(name).stat().st_size:>7} bytes")


if __name__ == "__main__":
    main()
