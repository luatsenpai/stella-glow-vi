# bffnt_dump_png_and_metrics.py
# pip install pillow
# python bffnt_dump_png_and_metrics.py font_common.bffnt

import os, sys, json, struct
from PIL import Image

def u16(b, off): return struct.unpack_from("<H", b, off)[0]
def u32(b, off): return struct.unpack_from("<I", b, off)[0]
def s8(b, off):  return struct.unpack_from("<b", b, off)[0]

def morton3(x, y):
    r = 0
    for i in range(3):
        r |= ((x >> i) & 1) << (2*i)
        r |= ((y >> i) & 1) << (2*i + 1)
    return r

def parse_blocks(b: bytes):
    if b[0:4] != b"FFNT":
        raise ValueError("Not FFNT/BFFNT")
    header_size = u16(b, 6)
    num_blocks = u16(b, 16)

    off = header_size
    blocks = []
    for _ in range(num_blocks):
        sig = b[off:off+4].decode("ascii")
        size = u32(b, off+4)
        blocks.append((sig, off, size))
        off += size
    return blocks

def parse_tglp_and_sheet(b: bytes, tglp_off: int, tglp_size: int):
    # Layout used by your file (works for the tested one):
    # base = tglp_off+8:
    # +0x00 u8 cellW, +0x01 u8 cellH, +0x04 u32 sheetSize
    # +0x0E u16 fmt, +0x10 u16 sheetW, +0x12 u16 sheetH, +0x14 u32 sheetDataOffset
    base = tglp_off + 8

    cell_w = b[base + 0]
    cell_h = b[base + 1]
    sheet_size = u32(b, base + 4)

    fmt = u16(b, base + 0x0E)
    sheet_w = u16(b, base + 0x10)
    sheet_h = u16(b, base + 0x12)
    sheet_off = u32(b, base + 0x14)

    # IMPORTANT FIX:
    # sheet_off may be absolute-file offset. Auto-detect:
    rel_abs = tglp_off + sheet_off
    tglp_end = tglp_off + tglp_size
    abs_off = sheet_off if (rel_abs + sheet_size) > tglp_end else rel_abs

    raw = b[abs_off:abs_off + sheet_size]

    return {
        "cellWidth": cell_w,
        "cellHeight": cell_h,
        "sheetSize": sheet_size,
        "formatId": fmt,
        "sheetWidth": sheet_w,
        "sheetHeight": sheet_h,
        "sheetDataOffset": sheet_off,
        "sheetDataAbs": abs_off,
        "rawSheet": raw,
    }

def unswizzle_a8_tile8_morton(raw: bytes, w: int, h: int) -> bytes:
    # 8x8 tiles; inside tile: Morton order, 1 byte per pixel
    tiles_x = w // 8
    out = bytearray(w * h)
    for y in range(h):
        ty, iy = divmod(y, 8)
        for x in range(w):
            tx, ix = divmod(x, 8)
            tile_base = (ty * tiles_x + tx) * 64
            si = tile_base + morton3(ix, iy)
            out[y*w + x] = raw[si] if si < len(raw) else 0
    return bytes(out)

def parse_cwdh_all(b: bytes, blocks):
    # CWDH may be one block or a chain; we dump every CWDH block found.
    all_entries = {}
    for sig, off, size in blocks:
        if sig != "CWDH":
            continue

        start = u16(b, off+0x08)
        end   = u16(b, off+0x0A)
        count = end - start + 1

        p = off + 0x10
        for i in range(count):
            q = p + i*3
            if q + 3 > off + size:
                break
            gi = start + i
            all_entries[gi] = {
                "glyphIndex": gi,
                "left": s8(b, q+0),
                "glyphWidth": b[q+1],
                "charWidth": b[q+2],
            }

    # Return as sorted list
    return [all_entries[k] for k in sorted(all_entries.keys())]

def make_transparent_png_from_a8(a8: bytes, w: int, h: int):
    # A8 -> RGBA with alpha=A8.
    # Use white RGB so it’s a clean alpha mask (still transparent background).
    alpha = Image.frombytes("L", (w, h), a8)
    rgba = Image.new("RGBA", (w, h), (255, 255, 255, 0))
    rgba.putalpha(alpha)
    return rgba

def main():
    if len(sys.argv) < 2:
        print("Usage: python bffnt_dump_png_and_metrics.py <file.bffnt>")
        sys.exit(1)

    in_path = sys.argv[1]
    b = open(in_path, "rb").read()
    blocks = parse_blocks(b)

    # Find TGLP
    tglp = next(((sig, off, size) for sig, off, size in blocks if sig == "TGLP"), None)
    if not tglp:
        raise RuntimeError("TGLP not found")
    _, tglp_off, tglp_size = tglp

    t = parse_tglp_and_sheet(b, tglp_off, tglp_size)

    w, h = t["sheetWidth"], t["sheetHeight"]
    raw = t["rawSheet"]

    # Decode A8
    if len(raw) != t["sheetSize"]:
        print(f"WARNING: raw size {len(raw)} != sheetSize {t['sheetSize']}")

    a8 = unswizzle_a8_tile8_morton(raw, w, h)
    png = make_transparent_png_from_a8(a8, w, h)

    # Dump CWDH metrics
    metrics = parse_cwdh_all(b, blocks)

    base = os.path.splitext(os.path.basename(in_path))[0]
    out_dir = os.path.join(os.path.dirname(in_path), base + "_out")
    os.makedirs(out_dir, exist_ok=True)

    out_png = os.path.join(out_dir, "sheet0.png")
    out_json = os.path.join(out_dir, "glyph_metrics.json")

    png.save(out_png)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    print("OK:", out_dir)
    print(" - sheet0.png (transparent)")
    print(" - glyph_metrics.json")

if __name__ == "__main__":
    main()