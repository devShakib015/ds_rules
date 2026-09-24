#!/usr/bin/env python3
"""icon.png / icon-512.png and preview.png for the Marketplace listing.

    python3 tool/art.py

The preview is drawn, not captured, but nothing in it is invented: the squiggles
and the Problems list come from running lib/lint.js over the sample below, so the
picture cannot claim a check the code does not make.
"""
import json
import pathlib
import re
import subprocess

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
FONTS = pathlib.Path.home() / "Library" / "Fonts"

GROUND = "#0D0D0F"
PANEL = "#141417"
CARD = "#1B1B1F"
EDGE = "#2C2C33"
MINT = "#3DDC97"
TEXT = "#E8E8E8"
DIM = "#8A8A92"
RED = "#F0625A"
AMBER = "#E2B25A"
BLUE = "#6FA8DC"

SEVERITY = {"error": RED, "warning": AMBER, "info": BLUE}

SAMPLE = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{postId} {
      allow read: if true;
      allow update: if request.auth != null;
    }
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2026, 12, 1);
    }
  }
}"""


def face(*candidates):
    for c in candidates:
        if pathlib.Path(c).exists():
            return str(c)
    raise SystemExit(f"  none of these fonts is installed: {[str(c) for c in candidates]}")


UI = face(FONTS / "Inter-Medium.ttf", "/System/Library/Fonts/Helvetica.ttc")
MONO = face(FONTS / "JetBrainsMono-Regular.ttf", FONTS / "VictorMono-Regular.ttf",
            "/System/Library/Fonts/Menlo.ttc")


def findings():
    """What the linter says about SAMPLE — the same code the extension runs."""
    script = ("const {lint}=require('./lib/lint');"
              "process.stdout.write(JSON.stringify(lint(require('fs').readFileSync(0,'utf8'),"
              "{today:new Date('2026-09-24')})))")
    out = subprocess.run(["node", "-e", script], input=SAMPLE, capture_output=True,
                         text=True, cwd=ROOT, check=True)
    return json.loads(out.stdout)


def shield(d, cx, top, w, h, colour, weight):
    """A heater shield: straight shoulders, sides that curve to a point."""
    left, right = cx - w / 2, cx + w / 2
    pts = [(left, top + h * .10), (cx, top), (right, top + h * .10)]
    steps = 24
    for i in range(1, steps + 1):          # right side down to the point
        t = i / steps
        pts.append((right - (w / 2) * t ** 1.8, top + h * .10 + (h * .90) * t))
    for i in range(steps - 1, 0, -1):      # and back up the left
        t = i / steps
        pts.append((left + (w / 2) * t ** 1.8, top + h * .10 + (h * .90) * t))
    pts.append(pts[0])
    d.line(pts, fill=colour, width=weight, joint="curve")


def squiggle(d, x0, x1, y, colour, weight, amp=6, period=16):
    pts = []
    x = x0
    up = True
    while x <= x1:
        pts.append((x, y - amp if up else y + amp))
        x += period / 2
        up = not up
    d.line(pts, fill=colour, width=weight, joint="curve")


def icon():
    s = 512
    img = Image.new("RGB", (s, s), GROUND)
    d = ImageDraw.Draw(img)
    shield(d, s / 2, 78, 300, 356, MINT, 24)
    # A rule, and the mistake in it.
    d.rounded_rectangle([176, 206, 336, 226], 10, fill=MINT)
    squiggle(d, 176, 336, 286, RED, 16, amp=11, period=40)
    img.save(ROOT / "icon-512.png", optimize=True)
    img.resize((128, 128), Image.LANCZOS).save(ROOT / "icon.png", optimize=True)
    print("  icon.png 128, icon-512.png 512")


def colour_of(word):
    if word in ("allow", "match", "if", "service", "rules_version"):
        return "#C792EA"
    if word in ("read", "write", "update", "create", "delete", "get", "list"):
        return AMBER
    if word in ("request", "resource", "database"):
        return "#82AAFF"
    if word in ("true", "false", "null"):
        return "#F78C6C"
    return TEXT


def preview():
    lines = SAMPLE.split("\n")
    found = findings()
    code = ImageFont.truetype(MONO, 21)
    ui = ImageFont.truetype(UI, 17)
    small = ImageFont.truetype(UI, 15)
    line_h, x0, y0 = 34, 96, 70
    problems = [f for f in found if f["severity"] != "hint"]
    w = 1400
    h = y0 + line_h * len(lines) + 70 + 44 * len(problems) + 40
    img = Image.new("RGB", (w, h), GROUND)
    d = ImageDraw.Draw(img)

    # Title bar and tab.
    d.rectangle([0, 0, w, 44], fill=PANEL)
    d.text((24, 12), "firestore.rules", font=ui, fill=TEXT)
    d.line([(20, 43), (160, 43)], fill=MINT, width=2)

    cw = d.textlength("m", font=code)
    offsets = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1

    def xy(offset):
        line = max(i for i, s in enumerate(offsets) if s <= offset)
        return line, x0 + (offset - offsets[line]) * cw

    for i, ln in enumerate(lines):
        y = y0 + i * line_h
        d.text((x0 - 56, y), f"{i + 1:>2}", font=code, fill="#4A4A52")
        x = x0
        for tok in re.findall(r"\s+|'[^']*'|[A-Za-z_]+|\d+|.", ln):
            fill = "#C3E88D" if tok.startswith("'") else "#F78C6C" if tok.isdigit() else colour_of(tok)
            d.text((x, y), tok, font=code, fill=fill)
            x += cw * len(tok)

    # Squiggles and hint dots where the linter put them — least severe first,
    # so where two share a range the worse one is on top, as in VS Code.
    rank = {"hint": 0, "info": 1, "warning": 2, "error": 3}
    for f in sorted(found, key=lambda f: rank[f["severity"]]):
        line, xa = xy(f["start"])
        _, xb = xy(f["end"])
        y = y0 + line * line_h + 29
        if f["severity"] == "hint":
            for k in range(3):
                d.ellipse([xa + k * 7, y - 1, xa + k * 7 + 3, y + 2], fill=DIM)
        else:
            squiggle(d, xa, xb, y, SEVERITY[f["severity"]], 2, amp=2.5, period=7)

    # The Problems panel, in VS Code's order: errors, then warnings, then info.
    top = y0 + line_h * len(lines) + 30
    d.rectangle([0, top, w, h], fill=PANEL)
    d.text((24, top + 14), "PROBLEMS", font=small, fill=TEXT)
    d.line([(20, top + 40), (110, top + 40)], fill=MINT, width=2)
    order = {"error": 0, "warning": 1, "info": 2}
    y = top + 60
    for f in sorted(problems, key=lambda f: (order[f["severity"]], f["start"])):
        line, _ = xy(f["start"])
        colour = SEVERITY[f["severity"]]
        d.ellipse([28, y + 5, 40, y + 17], fill=colour)
        words = f["message"].split(" ")
        room = w - 380
        msg = " ".join(words)
        while d.textlength(msg, font=ui) > room and len(words) > 1:
            words.pop()                      # drop a word, then re-add the ellipsis
            msg = " ".join(words).rstrip(",.;:—") + " …"
        d.text((54, y), msg, font=ui, fill=TEXT)
        tail = f'{f["id"]}   [Ln {line + 1}]'
        d.text((w - 24, y), tail, font=small, fill=DIM, anchor="ra")
        y += 44

    img.save(ROOT / "preview.png", optimize=True)
    print(f"  preview.png {w}x{h}  ({len(problems)} problems, "
          f"{len(found) - len(problems)} hint)")


if __name__ == "__main__":
    icon()
    preview()
