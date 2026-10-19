"""Prépare les déclinaisons du logo ReconIA (fond transparent, recadrage, favicons).

Entrée : /in/1.png (symbole « R »), /in/2.png (logo complet avec slogan).
Sortie : /out/*.png, /out/favicon.ico

Seul le fond blanc RELIÉ AU BORD est rendu transparent (remplissage depuis
les coins) : les blancs intérieurs (blanc de l'œil, reflet) restent opaques.
Les pixels de bord anti-crénelés sont « dé-blanchis » (white-to-alpha).
"""
from PIL import Image, ImageDraw, ImageFilter

WHITE_T = 232  # seuil « quasi blanc » (min des canaux)


def transparent(img):
    if img.mode in ("RGBA", "LA", "P"):
        rgba = img.convert("RGBA")
        base = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        base.alpha_composite(rgba)
        img = base
    img = img.convert("RGB")
    w, h = img.size
    px = img.load()
    # Masque binaire quasi-blanc, puis remplissage depuis le bord
    mask = Image.new("L", (w, h), 0)
    mp = mask.load()
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            if min(r, g, b) >= WHITE_T:
                mp[x, y] = 255
    for seed in [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)]:
        if mp[seed] == 255:
            ImageDraw.floodfill(mask, seed, 128)
    bg = mask.point(lambda v: 255 if v == 128 else 0)
    band = bg.filter(ImageFilter.MaxFilter(5))
    bgp, bandp = bg.load(), band.load()
    out = Image.new("RGBA", (w, h))
    op = out.load()
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            if bgp[x, y]:
                op[x, y] = (r, g, b, 0)
            elif bandp[x, y]:
                a = 255 - min(r, g, b)
                a = max(0, min(255, int(a * 1.15)))
                if a == 0:
                    op[x, y] = (r, g, b, 0)
                else:
                    f = lambda c: max(0, min(255, int((c - (255 - a)) * 255 / a)))
                    op[x, y] = (f(r), f(g), f(b), a)
            else:
                op[x, y] = (r, g, b, 255)
    return out


def crop(img, pad_ratio=0.04):
    box = img.getchannel("A").point(lambda v: 255 if v > 8 else 0).getbbox()
    img = img.crop(box)
    w, h = img.size
    pad = int(max(w, h) * pad_ratio)
    canvas = Image.new("RGBA", (w + 2 * pad, h + 2 * pad), (0, 0, 0, 0))
    canvas.paste(img, (pad, pad))
    return canvas


def square(img, size, bg=None, inner=0.86):
    w, h = img.size
    s = max(w, h)
    canvas = Image.new("RGBA", (s, s), bg or (0, 0, 0, 0))
    canvas.alpha_composite(img, ((s - w) // 2, (s - h) // 2))
    if inner < 1:
        small = canvas.resize((int(size * inner),) * 2, Image.LANCZOS)
        final = Image.new("RGBA", (size, size), bg or (0, 0, 0, 0))
        final.alpha_composite(small, ((size - small.width) // 2, (size - small.height) // 2))
        return final
    return canvas.resize((size, size), Image.LANCZOS)


def fit_width(img, width):
    return img.resize((width, round(img.height * width / img.width)), Image.LANCZOS)


mark = crop(transparent(Image.open("/in/1.png")))
full = crop(transparent(Image.open("/in/2.png")), pad_ratio=0.02)

fit_width(mark, 512).save("/out/reconia-mark.png", optimize=True)
fit_width(mark, 160).save("/out/reconia-mark-160.png", optimize=True)
fit_width(full, 1000).save("/out/reconia-logo.png", optimize=True)
fit_width(full, 600).save("/out/reconia-logo-600.png", optimize=True)

# Favicons : symbole seul, centré
square(mark, 32, inner=1).save("/out/favicon-32.png", optimize=True)
square(mark, 192, inner=0.92).save("/out/icon-192.png", optimize=True)
square(mark, 512, inner=0.92).save("/out/icon-512.png", optimize=True)
# Icône Apple : fond blanc plein (iOS ne gère pas la transparence)
square(mark, 180, bg=(255, 255, 255, 255), inner=0.8).save("/out/apple-touch-icon.png", optimize=True)
square(mark, 256, inner=1).save("/out/favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
print("ok", mark.size, full.size)
