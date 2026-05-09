# BFFNT Glyph UI Editor v6 Standalone
# Requirements: pip install pillow
# Standalone version: does NOT depend on bffnttool_v3.py
# Usage: python bffnttool_ui_v6_standalone.py

import os
import sys
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk

APP_TITLE = "BFFNT Glyph UI Editor"

# bffnttool_v3.py
# Requirements: pip install pillow
# Usage:
#   python bffnttool_v3.py            (menu)
#   python bffnttool_v3.py export  path/to/font.bffnt
#   python bffnttool_v3.py import  path/to/font.bffnt  path/to/folder_out
#   python bffnttool_v3.py remap   path/to/font.bffnt  path/to/map.txt
#
# Features added per request:
# - Export ALL CMAP mappings (cmap_all.json + cmap_blocks.json)
# - Export glyph_table.json = metrics + list codepoints per glyphIndex (edit-friendly)
# - Apply CMAP from glyph_table.json (many codes can share one glyph)
# - Remap/extend CMAP by PREPENDING a new CMAP (scan method) so it overrides old mappings
# - "Increase CMAP size" by adding more entries via that new CMAP (no need to resize existing blocks)

import os, sys, json, struct, re
import traceback
from typing import Dict, List, Tuple, Optional
from PIL import Image, ImageDraw

# ------------------ helpers (endian-aware) ------------------

def detect_endian(b: bytes) -> str:
    # BOM at 0x04
    if len(b) < 6:
        return "<"
    le = struct.unpack_from("<H", b, 4)[0]
    be = struct.unpack_from(">H", b, 4)[0]
    if le == 0xFEFF:
        return "<"
    if be == 0xFEFF:
        return ">"
    # fallback: most CTR fonts are little-endian
    return "<"

def u16(b: bytes, off: int, e: str) -> int:
    return struct.unpack_from(e + "H", b, off)[0]

def u32(b: bytes, off: int, e: str) -> int:
    return struct.unpack_from(e + "I", b, off)[0]

def p16(v: int, e: str) -> bytes:
    return struct.pack(e + "H", v & 0xFFFF)

def p32(v: int, e: str) -> bytes:
    return struct.pack(e + "I", v & 0xFFFFFFFF)

def s8(b: bytes, off: int, e: str) -> int:
    # signed 8-bit does not depend on endianness
    return struct.unpack_from("<b", b, off)[0]

def align4(n: int) -> int:
    return (n + 3) & ~3

# ------------------ swizzle helpers (A8 tile 8 morton) ------------------

def morton3(x: int, y: int) -> int:
    r = 0
    for i in range(3):
        r |= ((x >> i) & 1) << (2*i)
        r |= ((y >> i) & 1) << (2*i + 1)
    return r

def unswizzle_a8_tile8_morton(raw: bytes, w: int, h: int) -> bytes:
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

def swizzle_a8_tile8_morton(a8_linear: bytes, w: int, h: int) -> bytes:
    tiles_x = w // 8
    out = bytearray(w * h)
    for y in range(h):
        ty, iy = divmod(y, 8)
        for x in range(w):
            tx, ix = divmod(x, 8)
            tile_base = (ty * tiles_x + tx) * 64
            di = tile_base + morton3(ix, iy)
            out[di] = a8_linear[y*w + x]
    return bytes(out)


def unswizzle_a4_tile8_morton(raw: bytes, w: int, h: int, high_nibble_first: bool = True) -> bytes:
    """
    formatId=11 (A4): 4-bit alpha, 8x8 tile order, morton within tile.
    Returns A8 linear bytes (expanded to 0..255).
    """
    tiles_x = w // 8
    out = bytearray(w * h)
    for y in range(h):
        ty, iy = divmod(y, 8)
        for x in range(w):
            tx, ix = divmod(x, 8)
            tile_index = ty * tiles_x + tx
            tile_base = tile_index * 32  # 64 pixels / 2 = 32 bytes
            pi = morton3(ix, iy)  # 0..63
            bi = tile_base + (pi >> 1)
            if bi >= len(raw):
                a = 0
            else:
                byte = raw[bi]
                if high_nibble_first:
                    nib = (byte >> 4) if ((pi & 1) == 0) else (byte & 0x0F)
                else:
                    nib = (byte & 0x0F) if ((pi & 1) == 0) else (byte >> 4)
                a = nib * 17
            out[y * w + x] = a
    return bytes(out)

def swizzle_a4_tile8_morton(a8_linear: bytes, w: int, h: int, high_nibble_first: bool = True) -> bytes:
    """
    formatId=11 (A4): take A8 linear alpha, quantize to 4-bit, pack 2 pixels/byte, swizzle tile8 morton.
    Returns raw A4 swizzled bytes length = w*h/2.
    """
    tiles_x = w // 8
    out = bytearray((w * h) // 2)
    for y in range(h):
        ty, iy = divmod(y, 8)
        for x in range(w):
            tx, ix = divmod(x, 8)
            tile_index = ty * tiles_x + tx
            tile_base = tile_index * 32
            pi = morton3(ix, iy)
            bi = tile_base + (pi >> 1)
            if bi >= len(out):
                continue
            a = a8_linear[y * w + x]
            nib = (a + 8) // 17  # round to 0..15
            if nib < 0: nib = 0
            if nib > 15: nib = 15
            cur = out[bi]
            if high_nibble_first:
                if (pi & 1) == 0:
                    cur = (cur & 0x0F) | (nib << 4)
                else:
                    cur = (cur & 0xF0) | nib
            else:
                if (pi & 1) == 0:
                    cur = (cur & 0xF0) | nib
                else:
                    cur = (cur & 0x0F) | (nib << 4)
            out[bi] = cur
    return bytes(out)


def _choose_a4_nibble_order(raw: bytes, w: int, h: int) -> bool:
    """
    Return high_nibble_first boolean.
    Better heuristic for "double layer/ghost": choose the nibble order that yields smoother alpha field
    (lower high-frequency / checkerboard artifacts).
    We compare total variation (sum abs diffs with right/bottom neighbors). Lower is better.
    """
    a_high = unswizzle_a4_tile8_morton(raw, w, h, True)
    a_low  = unswizzle_a4_tile8_morton(raw, w, h, False)

    def score(a: bytes) -> int:
        tv = 0
        # sample every 2 pixels to keep it fast on big sheets
        step = 2
        for y in range(0, h-1, step):
            row = y * w
            row2 = (y+1) * w
            for x in range(0, w-1, step):
                i = row + x
                tv += abs(a[i] - a[i+1])
                tv += abs(a[i] - a[row2 + x])
        return tv

    s_high = score(a_high)
    s_low  = score(a_low)
    return True if s_high <= s_low else False

def decode_sheet_to_png(raw: bytes, w: int, h: int, format_id: int) -> Image.Image:
    """
    Robust decoder for CTR BFFNT sheet formats.
    Common values seen in the wild:
      - 0x24 (36) : A8   (sheetSize == w*h)
      - 0x40 (64) : A4   (sheetSize == w*h/2)
    Also supports legacy ids: 8=A8, 11=A4.
    If format_id is unknown, we infer from raw length (sheetSize).
    """
    # Normalize known ids
    if format_id in (8, 0x24, 36):
        a8 = unswizzle_a8_tile8_morton(raw, w, h)
        return make_transparent_png_from_a8(a8, w, h)
    if format_id in (11, 0x40, 64):
        high = _choose_a4_nibble_order(raw, w, h)
        a8 = unswizzle_a4_tile8_morton(raw, w, h, high)
        img = make_transparent_png_from_a8(a8, w, h)
        try:
            img.info["a4_high_nibble_first"] = "1" if high else "0"
        except Exception:
            pass
        return img

    # Infer from sheet size
    if len(raw) == w * h:
        a8 = unswizzle_a8_tile8_morton(raw, w, h)
        return make_transparent_png_from_a8(a8, w, h)
    if len(raw) == (w * h) // 2:
        high = _choose_a4_nibble_order(raw, w, h)
        a8 = unswizzle_a4_tile8_morton(raw, w, h, high)
        img = make_transparent_png_from_a8(a8, w, h)
        try:
            img.info["a4_high_nibble_first"] = "1" if high else "0"
        except Exception:
            pass
        return img

    raise ValueError(f"Unsupported sheet formatId={format_id} and cannot infer from raw size={len(raw)} (w*h={w*h}).")

def encode_png_to_sheet_raw(png_path: str, w: int, h: int, format_id: int, expected_size: int = 0, a4_high_nibble_first: bool = True) -> bytes:
    """
    Convert PNG (alpha) -> swizzled raw bytes for TGLP.
    Supports A8 and A4 with robust id mapping and size inference.
    expected_size: if provided, will override inference (useful when format_id is unknown).
    """
    a8_linear = rgba_png_to_a8_linear(png_path, w, h)

    # Normalize known ids
    if format_id in (8, 0x24, 36):
        out = swizzle_a8_tile8_morton(a8_linear, w, h)
        if expected_size and len(out) != expected_size:
            # try A4 if mismatch
            out2 = swizzle_a4_tile8_morton(a8_linear, w, h, a4_high_nibble_first)
            if len(out2) == expected_size:
                return out2
        return out
    if format_id in (11, 0x40, 64):
        out = swizzle_a4_tile8_morton(a8_linear, w, h, a4_high_nibble_first)
        if expected_size and len(out) != expected_size:
            # try A8 if mismatch
            out2 = swizzle_a8_tile8_morton(a8_linear, w, h)
            if len(out2) == expected_size:
                return out2
        return out

    # Infer by expected size if provided
    if expected_size:
        if expected_size == w * h:
            return swizzle_a8_tile8_morton(a8_linear, w, h)
        if expected_size == (w * h) // 2:
            return swizzle_a4_tile8_morton(a8_linear, w, h, a4_high_nibble_first)

    # Fallback inference by common sizes
    # Default to A8 if ambiguous
    return swizzle_a8_tile8_morton(a8_linear, w, h)

def make_transparent_png_from_a8(a8: bytes, w: int, h: int) -> Image.Image:
    alpha = Image.frombytes("L", (w, h), a8)
    rgba = Image.new("RGBA", (w, h), (255, 255, 255, 0))
    rgba.putalpha(alpha)
    return rgba

def rgba_png_to_a8_linear(png_path: str, w: int, h: int) -> bytes:
    img = Image.open(png_path).convert("RGBA")
    if img.size != (w, h):
        raise ValueError(f"PNG size {img.size} != expected {(w,h)}")
    return img.split()[3].tobytes()



def alpha_to_grayscale_png(img: Image.Image) -> Image.Image:
    """Return L image of alpha channel (0..255) for easier editing."""
    im = img.convert("RGBA")
    return im.split()[3].convert("L")

def despeckle_alpha(img: Image.Image, min_alpha: int = 34, median: int = 3) -> Image.Image:
    """
    Reduce A4 'speckle' by:
      - zeroing very small alpha (<min_alpha)
      - optional median filter on alpha (median=3 recommended)
    Keeps antialias (unlike hard binary threshold).
    """
    from PIL import ImageFilter
    im = img.convert("RGBA")
    r,g,b,a = im.split()
    a2 = a.point(lambda v: 0 if v < min_alpha else v)
    if median and median >= 3:
        a2 = a2.filter(ImageFilter.MedianFilter(size=median))
    return Image.merge("RGBA", (r,g,b,a2))
def clean_alpha_binary(img: Image.Image, threshold: int = 128) -> Image.Image:
    """
    Make alpha strictly 0/255 to remove speckle / antialias noise (useful for A4 preview/edit).
    Returns new RGBA image.
    """
    im = img.convert("RGBA")
    r,g,b,a = im.split()
    a2 = a.point(lambda v: 255 if v >= threshold else 0)
    return Image.merge("RGBA", (r,g,b,a2))

def make_grid_png(w: int, h: int, cell_w: int, cell_h: int, line_alpha: int = 96) -> Image.Image:
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    x = 0
    while x <= w:
        d.line([(x, 0), (x, h)], fill=(255, 255, 255, line_alpha))
        x += cell_w
    y = 0
    while y <= h:
        d.line([(0, y), (w, y)], fill=(255, 255, 255, line_alpha))
        y += cell_h
    return img

# ------------------ parsing blocks ------------------

def parse_blocks(b: bytes) -> Tuple[str, int, int, List[Tuple[str,int,int]]]:
    if b[0:4] not in (b"FFNT", b"CFNT"):
        raise ValueError("Not FFNT/CFNT (BFFNT/BCFNT)")
    e = detect_endian(b)
    header_size = u16(b, 6, e)
    num_blocks  = u16(b, 16, e)
    off = header_size
    blocks = []
    for _ in range(num_blocks):
        sig = b[off:off+4].decode("ascii", errors="replace")
        size = u32(b, off+4, e)
        blocks.append((sig, off, size))
        off += size
    return e, header_size, num_blocks, blocks

def find_block(blocks, sig: str):
    for s, off, size in blocks:
        if s == sig:
            return (s, off, size)
    return None

# ------------------ TGLP sheet ------------------

def parse_tglp_and_sheet(b: bytes, tglp_off: int, tglp_size: int, e: str) -> dict:
    base = tglp_off + 8
    cell_w     = b[base + 0]
    cell_h     = b[base + 1]
    baseline   = b[base + 2]
    max_char_w = b[base + 3]
    sheet_size = u32(b, base + 4, e)
    field10    = u16(b, base + 0x08, e)
    field12    = u16(b, base + 0x0A, e)
    field14    = u16(b, base + 0x0C, e)
    fmt        = u16(b, base + 0x0E, e)
    sheet_w    = u16(b, base + 0x10, e)
    sheet_h    = u16(b, base + 0x12, e)
    sheet_off  = u32(b, base + 0x14, e)

    # sheet_off can be absolute or relative-to-TGLP; auto detect like old tool
    rel_abs = tglp_off + sheet_off
    tglp_end = tglp_off + tglp_size
    abs_off = sheet_off if (rel_abs + sheet_size) > tglp_end else rel_abs
    raw = b[abs_off:abs_off + sheet_size]

    return {
        "cellWidth": cell_w,
        "cellHeight": cell_h,
        "baselinePos": baseline,
        "maxCharWidth": max_char_w,
        "sheetSize": sheet_size,
        "field10": field10,
        "field12": field12,
        "field14": field14,
        "formatId": fmt,
        "sheetWidth": sheet_w,
        "sheetHeight": sheet_h,
        "sheetDataOffset": sheet_off,
        "sheetDataAbs": abs_off,
        "rawSheet": raw,
        "tglpOff": tglp_off,
        "tglpSize": tglp_size,
    }

# ------------------ CWDH metrics ------------------

def parse_cwdh_blocks(b: bytes, blocks, e: str):
    out = []
    for sig, off, size in blocks:
        if sig != "CWDH":
            continue
        start = u16(b, off+0x08, e)
        end   = u16(b, off+0x0A, e)
        count = end - start + 1
        entry_base = off + 0x10
        out.append({
            "off": off,
            "size": size,
            "start": start,
            "end": end,
            "count": count,
            "entryBase": entry_base
        })
    return out

def dump_metrics(b: bytes, cwdh_descs, e: str):
    all_entries = {}
    for d in cwdh_descs:
        start, count = d["start"], d["count"]
        p = d["entryBase"]
        for i in range(count):
            q = p + i*3
            if q + 3 > d["off"] + d["size"]:
                break
            gi = start + i
            all_entries[gi] = {
                "glyphIndex": gi,
                "left": s8(b, q+0, e),
                "glyphWidth": b[q+1],
                "charWidth": b[q+2],
            }
    return [all_entries[k] for k in sorted(all_entries.keys())]

def apply_metrics_patch(buf: bytearray, cwdh_descs, metrics_list, e: str):
    metrics_by_gi = {m["glyphIndex"]: m for m in metrics_list}
    max_gi_in_file = max((d["end"] for d in cwdh_descs), default=-1)
    max_gi_in_patch = max(metrics_by_gi.keys(), default=-1)
    if max_gi_in_patch > max_gi_in_file:
        raise ValueError(f"Patch glyphIndex max={max_gi_in_patch} > file max={max_gi_in_file} (tool này không resize CWDH)")

    for d in cwdh_descs:
        start = d["start"]
        count = d["count"]
        base = d["entryBase"]
        for i in range(count):
            gi = start + i
            m = metrics_by_gi.get(gi)
            if not m:
                continue
            q = base + i*3
            left = int(m["left"])
            left = -128 if left < -128 else (127 if left > 127 else left)
            gw = int(m["glyphWidth"])
            cw = int(m["charWidth"])
            gw = 0 if gw < 0 else (255 if gw > 255 else gw)
            cw = 0 if cw < 0 else (255 if cw > 255 else cw)
            buf[q+0] = struct.pack("<b", left)[0]
            buf[q+1] = gw & 0xFF
            buf[q+2] = cw & 0xFF

# ------------------ CMAP ------------------

def parse_cmap_at(b: bytes, cmap_off: int, e: str) -> dict:
    # cmap_off points to BLOCK START (signature 'CMAP')
    if b[cmap_off:cmap_off+4] != b"CMAP":
        raise ValueError(f"Bad CMAP signature at 0x{cmap_off:X}")
    size = u32(b, cmap_off+4, e)
    code_begin = u16(b, cmap_off+0x08, e)
    code_end   = u16(b, cmap_off+0x0A, e)
    method     = u16(b, cmap_off+0x0C, e)
    reserved   = u16(b, cmap_off+0x0E, e)
    next_base  = u32(b, cmap_off+0x10, e)  # NOTE: points to next CMAP's DATA BASE (offset+8), or 0
    payload = b[cmap_off+0x14:cmap_off+size]
    return {
        "off": cmap_off,
        "size": size,
        "codeBegin": code_begin,
        "codeEnd": code_end,
        "method": method,
        "reserved": reserved,
        "nextBase": next_base,
        "payload": payload,
    }

def _is_legacy_reserved_scan_cmap(cmap: dict, e: str) -> bool:
    """
    v4 UI accidentally wrote method=2 CMAP with an extra u16 reserved after numPairs.
    Real BFFNT/BCFNT scan CMAP is:
      u16 numPairs; repeated { u16 charCode, u16 glyphIndex }; padding to 4 bytes.
    This detects that old malformed block so the UI can still read/repair it.
    """
    if cmap.get("method") != 2:
        return False
    p = cmap.get("payload", b"")
    if len(p) < 4:
        return False
    num = struct.unpack_from(e + "H", p, 0)[0]
    # Old malformed size = header 0x14 + num(2) + fake reserved(2) + pairs(4*num)
    expected_old_size = 0x18 + 4 * num
    if int(cmap.get("size", 0)) != expected_old_size:
        return False
    fake_reserved = struct.unpack_from(e + "H", p, 2)[0]
    if fake_reserved != 0:
        return False
    # If parsed correctly without the fake reserved, first glyphIndex would often be a char code
    # and many pairs become shifted. Treat as legacy only when the +4 parse looks sane.
    if len(p) < 4 + 4 * num:
        return False
    return True


def cmap_block_to_mapping(cmap: dict, e: str) -> Dict[int,int]:
    m: Dict[int,int] = {}
    cb, ce, method = cmap["codeBegin"], cmap["codeEnd"], cmap["method"]
    p = cmap["payload"]
    if method == 0:
        # direct: glyphIndex = glyphIndexOffset + (code - cb)
        if len(p) < 4:
            return m
        glyph_index_offset = struct.unpack_from(e+"H", p, 0)[0]
        for code in range(cb, ce+1):
            m[code] = (glyph_index_offset + (code - cb)) & 0xFFFF
    elif method == 1:
        # table: u16 index[ce-cb+1]
        count = ce - cb + 1
        for i in range(count):
            if 2*i+2 > len(p):
                break
            gi = struct.unpack_from(e+"H", p, 2*i)[0]
            if gi != 0xFFFF:
                m[cb+i] = gi
    elif method == 2:
        # scan: u16 numPairs, then pairs (u16 charCode, u16 glyphIndex), then optional padding.
        # NOTE: there is NO reserved u16 here. Older versions of this UI wrote one by mistake.
        if len(p) < 2:
            return m
        num = struct.unpack_from(e+"H", p, 0)[0]
        base = 4 if _is_legacy_reserved_scan_cmap(cmap, e) else 2
        for i in range(num):
            q = base + i*4
            if q+4 > len(p):
                break
            code = struct.unpack_from(e+"H", p, q+0)[0]
            gi   = struct.unpack_from(e+"H", p, q+2)[0]
            if gi != 0xFFFF:
                m[code] = gi
    else:
        # unknown
        pass
    return m

def find_finf_offsets(b: bytes, blocks, e: str) -> Tuple[int,int,int,int]:
    finf = find_block(blocks, "FINF")
    tglp = find_block(blocks, "TGLP")
    cwdh = find_block(blocks, "CWDH")
    if not finf or not tglp or not cwdh:
        raise RuntimeError("Missing FINF/TGLP/CWDH")
    _, finf_off, finf_size = finf
    tglp_base = tglp[1] + 8
    cwdh_base = cwdh[1] + 8

    # FINF is small; we search for these bases and infer the third is cmap_base
    finf_data = b[finf_off+8:finf_off+finf_size]
    hits = []
    for i in range(0, len(finf_data)-3, 4):
        val = u32(finf_data, i, e)
        hits.append((i, val))
    # locate tglp_base and cwdh_base
    idx_t = next((i for i,v in hits if v == tglp_base), None)
    idx_c = next((i for i,v in hits if v == cwdh_base), None)
    # cmap_base usually is another u32 in FINF
    # pick candidate: value that equals some CMAP data base (off+8)
    cmap_bases = {off+8 for sig,off,size in blocks if sig == "CMAP"}
    idx_m = next((i for i,v in hits if v in cmap_bases), None)

    if idx_t is None or idx_c is None or idx_m is None:
        # fallback: choose 3 largest plausible offsets within file among FINF data u32
        plausible = [(i,v) for i,v in hits if 0 < v < len(b)]
        plausible.sort(key=lambda x: x[1], reverse=True)
        if len(plausible) >= 1 and idx_m is None:
            idx_m = plausible[0][0]
        if idx_t is None or idx_c is None or idx_m is None:
            raise RuntimeError("Cannot locate offsets in FINF (tglp/cwdh/cmap).")

    return finf_off, finf_size, idx_m, finf_off+8+idx_m  # finf field absolute offset for cmap_base

def traverse_cmap_chain(b: bytes, first_cmap_base: int, e: str) -> List[dict]:
    # first_cmap_base points to DATA BASE (blockStart+8)
    seen = set()
    out = []
    base = first_cmap_base
    while base and base not in seen:
        seen.add(base)
        off = base - 8
        cmap = parse_cmap_at(b, off, e)
        out.append(cmap)
        base = cmap["nextBase"]
    return out

def export_cmaps(b: bytes, blocks, out_dir: str, e: str):
    finf_off, finf_size, idx_m, cmap_field_abs = find_finf_offsets(b, blocks, e)
    first_cmap_base = u32(b, cmap_field_abs, e)
    cmaps = traverse_cmap_chain(b, first_cmap_base, e)

    # per-block export
    cmap_blocks = []
    merged: Dict[int,int] = {}
    for cm in cmaps:
        mapping = cmap_block_to_mapping(cm, e)
        # merge in order: earlier blocks win (so do not overwrite existing keys)
        for k,v in mapping.items():
            if k not in merged:
                merged[k] = v
        cmap_blocks.append({
            "off": cm["off"],
            "size": cm["size"],
            "codeBegin": cm["codeBegin"],
            "codeEnd": cm["codeEnd"],
            "method": cm["method"],
            "nextBase": cm["nextBase"],
            "entries": len(mapping),
        })

    # write
    os.makedirs(out_dir, exist_ok=True)
    all_path = os.path.join(out_dir, "cmap_all.json")
    blocks_path = os.path.join(out_dir, "cmap_blocks.json")

    # represent keys as hex strings for readability
    all_dump = {f"U+{k:04X}": int(v) for k,v in sorted(merged.items(), key=lambda x: x[0])}
    with open(all_path, "w", encoding="utf-8") as f:
        json.dump(all_dump, f, ensure_ascii=False, indent=2)

    with open(blocks_path, "w", encoding="utf-8") as f:
        json.dump(cmap_blocks, f, ensure_ascii=False, indent=2)

    return all_path, blocks_path, len(merged), first_cmap_base

# ------------------ CMAP remap/extend (prepend scan CMAP) ------------------

_HEX2 = re.compile(r"(?:U\+|0x)?([0-9a-fA-F]{1,6})")


def build_glyph_table(metrics: List[dict], cmap_all_path: str) -> List[dict]:
    """
    Combine metrics + CMAP to an edit-friendly table:
      [{glyphIndex,left,glyphWidth,charWidth,codes:[U+...., ...]}, ...]
    """
    try:
        cmap_dump = json.load(open(cmap_all_path, "r", encoding="utf-8"))
    except FileNotFoundError:
        cmap_dump = {}
    gi_to_codes: Dict[int, List[str]] = {}
    for k,v in cmap_dump.items():
        try:
            code = int(str(k).strip().upper().replace("U+","").replace("0X",""), 16)
            gi = int(v)
        except Exception:
            continue
        gi_to_codes.setdefault(gi, []).append(f"U+{code:04X}")
    # stable ordering of codes
    for gi in gi_to_codes:
        gi_to_codes[gi] = sorted(set(gi_to_codes[gi]), key=lambda s: int(s[2:],16))

    out = []
    seen = set()
    for m in metrics:
        gi = int(m.get("glyphIndex", 0))
        seen.add(gi)
        out.append({
            "glyphIndex": gi,
            "left": int(m.get("left", 0)),
            "glyphWidth": int(m.get("glyphWidth", 0)),
            "charWidth": int(m.get("charWidth", 0)),
            "codes": gi_to_codes.get(gi, []),
        })
    # include glyphIndex that exist only in CMAP but missing metrics (rare)
    for gi in sorted(gi_to_codes.keys()):
        if gi in seen:
            continue
        out.append({
            "glyphIndex": gi,
            "left": 0,
            "glyphWidth": 0,
            "charWidth": 0,
            "codes": gi_to_codes.get(gi, []),
        })
    return out

def parse_code_str(s: str) -> Optional[int]:
    s = s.strip().upper()
    if not s:
        return None
    # accept "U+3042", "3042", "0x3042"
    s = s.replace("U+","").replace("0X","")
    # allow "3042;" etc
    s = re.sub(r"[^0-9A-F]", "", s)
    if not s:
        return None
    try:
        v = int(s, 16)
    except Exception:
        return None
    if v < 0 or v > 0xFFFF:
        return None
    return v

def apply_cmap_from_glyph_table(in_path: str, glyph_table_path: str, out_path: Optional[str]=None):
    """
    Read glyph_table.json and prepend a scan-CMAP that maps every listed codepoint to its glyphIndex.
    This makes it easy to let many codes share the same glyph by adding them into 'codes' array.
    """
    table = json.load(open(glyph_table_path, "r", encoding="utf-8"))
    if not isinstance(table, list):
        raise ValueError("glyph_table.json phải là mảng JSON (list).")

    b = bytearray(open(in_path, "rb").read())
    e, header_size, num_blocks, blocks = parse_blocks(b)

    overrides: Dict[int,int] = {}
    for row in table:
        if not isinstance(row, dict):
            continue
        gi = row.get("glyphIndex")
        if gi is None:
            continue
        try:
            gi = int(gi)
        except Exception:
            continue
        codes = row.get("codes", [])
        if not isinstance(codes, list):
            continue
        for cs in codes:
            if cs is None:
                continue
            code = parse_code_str(str(cs))
            if code is None:
                continue
            overrides[code] = gi

    if not overrides:
        raise RuntimeError("Không tìm thấy codes hợp lệ trong glyph_table.json để ghi CMAP.")

    finf_off, finf_size, idx_m, cmap_field_abs = find_finf_offsets(b, blocks, e)
    old_first_base = u32(b, cmap_field_abs, e)

    new_cmap_block = build_cmap_scan_block(overrides, old_first_base, e)
    new_cmap_off = align4(len(b))
    if new_cmap_off > len(b):
        b += b"\x00" * (new_cmap_off - len(b))
    b += new_cmap_block

    new_first_base = new_cmap_off + 8
    b[cmap_field_abs:cmap_field_abs+4] = p32(new_first_base, e)

    b[0x0C:0x10] = p32(len(b), e)
    b[0x10:0x12] = p16(num_blocks + 1, e)

    if out_path is None:
        root, ext = os.path.splitext(in_path)
        out_path = root + "_cmap_table" + ext
    if b is None:
        raise RuntimeError("Internal error: output buffer is None. Hãy gửi lại log + folder input.")
    with open(out_path, "wb") as f:
        f.write(bytes(b))

    print("OK APPLY CMAP TABLE:", out_path)
    print(f" - Added override CMAP with {len(overrides)} codepoints (many can share glyph).")
    return out_path


def parse_map_file(map_path: str) -> List[Tuple[int,int]]:
    """
    Accepts lines like:
      3042 00C1
      U+3042 -> U+00C1
      0x3042=0x00C1
    Returns list of (srcCode, dstCode).
    """
    pairs = []
    with open(map_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            nums = _HEX2.findall(line)
            if len(nums) >= 2:
                a = int(nums[0], 16)
                b = int(nums[1], 16)
                pairs.append((a, b))
    if not pairs:
        raise ValueError("Map file không có dòng hợp lệ (cần 2 số hex mỗi dòng).")
    return pairs

def build_cmap_scan_block(pairs_code_to_glyph: Dict[int,int], next_base: int, e: str) -> bytes:
    items = sorted(pairs_code_to_glyph.items(), key=lambda x: x[0])
    num = len(items)
    if num > 0xFFFF:
        raise ValueError("Too many CMAP pairs (>65535).")
    # CMAP block (scan method):
    #   header 0x14 bytes
    #   payload: u16 numPairs + {u16 charCode, u16 glyphIndex} * num
    #   pad to 4-byte alignment
    # Important: BFFNT method=2 does NOT have a reserved u16 after numPairs.
    payload = bytearray()
    payload += p16(num, e)
    for code, gi in items:
        payload += p16(code, e)
        payload += p16(gi, e)

    size = align4(0x14 + len(payload))
    out = bytearray()
    out += b"CMAP"
    out += p32(size, e)
    out += p16(0x0000, e)
    out += p16(0xFFFF, e)
    out += p16(2, e)       # method 2 = scan
    out += p16(0, e)
    out += p32(next_base, e)  # nextBase points to next CMAP DATA BASE
    out += payload
    while len(out) < size:
        out += b"\x00"
    return bytes(out)

def remap_cmap_prepend(in_path: str, map_path: str, out_path: Optional[str]=None):
    b = bytearray(open(in_path, "rb").read())
    e, header_size, num_blocks, blocks = parse_blocks(b)

    # export current merged mapping (for glyphIndex lookup)
    # We need a lookup code->glyphIndex as the font currently defines it.
    base_dir = os.path.dirname(os.path.abspath(in_path))
    tmp_out = os.path.join(base_dir, "__tmp_cmap_export__")
    try:
        _, _, _, first_cmap_base = export_cmaps(b, blocks, tmp_out, e)
        # read back merged mapping
        merged = json.load(open(os.path.join(tmp_out, "cmap_all.json"), "r", encoding="utf-8"))
        code_to_gi = {int(k[2:], 16): int(v) for k,v in merged.items()}
    finally:
        # best-effort cleanup
        try:
            for fn in ("cmap_all.json","cmap_blocks.json"):
                p = os.path.join(tmp_out, fn)
                if os.path.isfile(p): os.remove(p)
            if os.path.isdir(tmp_out): os.rmdir(tmp_out)
        except Exception:
            pass

    pairs = parse_map_file(map_path)

    # Build new overrides: dstCode -> glyphIndex(from srcCode)
    overrides: Dict[int,int] = {}
    missing_src = []
    for src, dst in pairs:
        gi = code_to_gi.get(src)
        if gi is None:
            missing_src.append(src)
            continue
        overrides[dst] = gi

    if missing_src:
        miss_str = ", ".join([f"U+{c:04X}" for c in missing_src[:20]])
        print(f"[WARN] {len(missing_src)} mã nguồn không có trong font, sẽ bỏ qua: {miss_str}" + (" ..." if len(missing_src)>20 else ""))

    if not overrides:
        raise RuntimeError("Không có mapping nào hợp lệ để ghi (toàn bộ src bị thiếu?).")

    # locate FINF cmap field
    finf_off, finf_size, idx_m, cmap_field_abs = find_finf_offsets(b, blocks, e)
    old_first_base = u32(b, cmap_field_abs, e)

    # append new CMAP block at end of file
    new_cmap_block = build_cmap_scan_block(overrides, old_first_base, e)
    new_cmap_off = align4(len(b))
    if new_cmap_off > len(b):
        b += b"\x00" * (new_cmap_off - len(b))
    b += new_cmap_block

    new_first_base = new_cmap_off + 8

    # patch FINF cmap base to new one
    b[cmap_field_abs:cmap_field_abs+4] = p32(new_first_base, e)

    # patch header fileSize and numBlocks
    b[0x0C:0x10] = p32(len(b), e)
    b[0x10:0x12] = p16(num_blocks + 1, e)

    if out_path is None:
        root, ext = os.path.splitext(in_path)
        out_path = root + "_cmap_new" + ext
    if b is None:
        raise RuntimeError("Internal error: output buffer is None. Hãy gửi lại log + folder input.")
    with open(out_path, "wb") as f:
        f.write(bytes(b))

    print("OK REMAP/EXTEND CMAP:", out_path)
    print(f" - Added {len(overrides)} entries by prepending a new scan-CMAP (method=2).")
    return out_path

# ------------------ export/import v4 (sheet + metrics + cmap embedded) ------------------

def _collect_cmap_merged(b: bytes, blocks, e: str) -> Tuple[Dict[str,int], List[dict]]:
    """
    Returns:
      cmap_all_dump: {"U+XXXX": glyphIndex, ...} merged (earlier blocks win)
      cmap_blocks:   list of block descriptors (chain order)
    """
    # locate first CMAP base from FINF and traverse
    finf_off, finf_size, idx_m, cmap_field_abs = find_finf_offsets(b, blocks, e)
    first_cmap_base = u32(b, cmap_field_abs, e)
    cmaps = traverse_cmap_chain(b, first_cmap_base, e)

    cmap_blocks = []
    merged: Dict[int,int] = {}
    for cm in cmaps:
        mapping = cmap_block_to_mapping(cm, e)
        for k,v in mapping.items():
            if k not in merged:
                merged[k] = v
        cmap_blocks.append({
            "off": cm["off"],
            "size": cm["size"],
            "codeBegin": cm["codeBegin"],
            "codeEnd": cm["codeEnd"],
            "method": cm["method"],
            "nextBase": cm["nextBase"],
            "entries": len(mapping),
        })

    cmap_all_dump = {f"U+{k:04X}": int(v) for k,v in sorted(merged.items(), key=lambda x: x[0])}
    return cmap_all_dump, cmap_blocks


def export_bffnt(in_path: str):
    """
    v4 export:
      - sheet0.png
      - glyph_metrics.json  (gồm metrics + cmap + cmap_blocks)
      - glyph_table.json    (gồm glyphs(metrics+codes) + cmap + cmap_blocks)
      - meta.json
    KHÔNG xuất grid.png, KHÔNG xuất cmap_all.json/cmap_blocks.json riêng nữa.
    """
    b = open(in_path, "rb").read()
    e, header_size, num_blocks, blocks = parse_blocks(b)

    tglp = find_block(blocks, "TGLP")
    if not tglp:
        raise RuntimeError("TGLP not found")
    _, tglp_off, tglp_size = tglp

    t = parse_tglp_and_sheet(b, tglp_off, tglp_size, e)
    w, h = t["sheetWidth"], t["sheetHeight"]
    raw = t["rawSheet"]    # decode A8 -> PNG (alpha)  (multi-sheet)
    sheetSize = int(t["sheetSize"])
    sheetNum = int(t.get("sheetNum", t.get("field10", 1)))
    raw_all = raw
    if len(raw_all) < sheetSize:
        raise RuntimeError("TGLP raw sheet too small")

    def _decode_one(chunk: bytes):
        return decode_sheet_to_png(chunk, w, h, int(t.get("formatId", t.get("field11", 8))))

    # sheet0.png .. sheetN.png
    sheets = []
    for si in range(sheetNum):
        off = si * sheetSize
        if off + sheetSize > len(raw_all):
            break
        chunk = raw_all[off:off + sheetSize]
        sheets.append(_decode_one(chunk))
    if not sheets:
        raise RuntimeError("No sheets decoded")
    png = sheets[0]
    cwdh_descs = parse_cwdh_blocks(b, blocks, e)
    metrics = dump_metrics(b, cwdh_descs, e)

    cmap_all_dump, cmap_blocks = _collect_cmap_merged(b, blocks, e)

    base = os.path.splitext(os.path.basename(in_path))[0]
    out_dir = os.path.join(os.path.dirname(in_path), base + "_out")
    os.makedirs(out_dir, exist_ok=True)

    out_png   = os.path.join(out_dir, "sheet0.png")
    out_json  = os.path.join(out_dir, "glyph_metrics.json")
    out_table = os.path.join(out_dir, "glyph_table.json")
    out_meta  = os.path.join(out_dir, "meta.json")

    png.save(out_png)

    # grid.png (chỉ export; import sẽ bỏ qua)
    try:
        from PIL import Image, ImageDraw
        grid = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        gd = ImageDraw.Draw(grid)
        cell_w = int(t.get("cellWidth", 0)) or int(meta.get("cellWidth", 0)) if 'meta' in locals() else int(t.get("cellWidth", 0))
        cell_h = int(t.get("cellHeight", 0)) or int(meta.get("cellHeight", 0)) if 'meta' in locals() else int(t.get("cellHeight", 0))
        # sheetLine/Row in parsed TGLP (field14/field12), fallback by division
        cols = int(t.get("field14", 0)) or (w // cell_w if cell_w else 0)
        rows = int(t.get("field12", 0)) or (h // cell_h if cell_h else 0)
        if cell_w and cell_h and cols and rows:
            used_w = min(w, cols * cell_w)
            used_h = min(h, rows * cell_h)
            for c in range(cols + 1):
                x = c * cell_w
                gd.line([(x, 0), (x, used_h)], fill=(255, 0, 0, 80))
            for r in range(rows + 1):
                y = r * cell_h
                gd.line([(0, y), (used_w, y)], fill=(255, 0, 0, 80))
            grid.save(os.path.join(out_dir, "grid.png"))
    except Exception:
        pass

    # glyph_metrics.json: embed cmap + cmap_blocks for convenience
    metrics_pack = {
        "metrics": metrics,
        "cmap": cmap_all_dump,
        "cmap_blocks": cmap_blocks,
        "format": "bffnttool_v4_glyph_metrics"
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(metrics_pack, f, ensure_ascii=False, indent=2)

    # glyph_table.json: glyphs(metrics + codes)
    # build codes per glyphIndex from cmap
    gi_to_codes: Dict[int, List[str]] = {}
    for code_str, gi in cmap_all_dump.items():
        try:
            gi = int(gi)
        except Exception:
            continue
        gi_to_codes.setdefault(gi, []).append(code_str)
    for gi in gi_to_codes:
        gi_to_codes[gi] = sorted(set(gi_to_codes[gi]), key=lambda s: int(s.replace("U+",""), 16))

    glyphs = []
    for m in metrics:
        gi = int(m.get("glyphIndex", 0))
        glyphs.append({
            "glyphIndex": gi,
            "left": int(m.get("left", 0)),
            "glyphWidth": int(m.get("glyphWidth", 0)),
            "charWidth": int(m.get("charWidth", 0)),
            "codes": gi_to_codes.get(gi, [])
        })

    table_pack = {
        "glyphs": glyphs,
        "cmap": cmap_all_dump,
        "cmap_blocks": cmap_blocks,
        "format": "bffnttool_v4_glyph_table"
    }
    with open(out_table, "w", encoding="utf-8") as f:
        json.dump(table_pack, f, ensure_ascii=False, indent=2)

    meta = {
        "sourceFile": os.path.basename(in_path),
        "endian": "LE" if e == "<" else "BE",
        "sheetWidth": w,
        "sheetHeight": h,
        "cellWidth": t["cellWidth"],
        "cellHeight": t["cellHeight"],
        "baselinePos": t["baselinePos"],
        "maxCharWidth": t["maxCharWidth"],
        "formatId": t["formatId"],
        "a4_high_nibble_first": (png.info.get("a4_high_nibble_first","1") if isinstance(getattr(png, "info", None), dict) else "1"),
        "a4_nibble": ("high" if (png.info.get("a4_high_nibble_first","1") if isinstance(getattr(png, "info", None), dict) else "1") in ("1",1,True,"true") else "low"),
        "sheetSize": t["sheetSize"],
        "sheetDataAbs": t["sheetDataAbs"],
        "sheetDataOffset": t["sheetDataOffset"],
        "cwdhRanges": [{"start": d["start"], "end": d["end"], "off": d["off"], "size": d["size"]} for d in cwdh_descs],
    }
    with open(out_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print("OK EXPORT:", out_dir)
    print(" - sheet0.png")
    print(" - glyph_metrics.json (metrics + cmap embedded)")
    print(" - glyph_table.json (glyphs + codes + cmap embedded)")
    print(" - meta.json")


def _load_metrics_and_cmap_from_folder(folder: str) -> Tuple[List[dict], Dict[int,int]]:
    """
    Accepts:
      - glyph_table.json (preferred) OR glyph_metrics.json
    Returns:
      metrics_list: list of {glyphIndex,left,glyphWidth,charWidth}
      overrides: dict {codepoint(int) -> glyphIndex(int)} built from table 'codes' if available,
                 else from embedded 'cmap'.
    """
    folder = folder.strip().strip('"')
    a4_high = True
    meta_path = os.path.join(folder, "meta.json")
    if os.path.isfile(meta_path):
        try:
            m = json.load(open(meta_path, "r", encoding="utf-8"))
            v = m.get("a4_nibble")
            if isinstance(v, str) and v.lower().strip() in ("low","lo","0","false"):
                a4_high = False
            elif isinstance(v, str) and v.lower().strip() in ("high","hi","1","true"):
                a4_high = True
            elif str(m.get("a4_high_nibble_first", "")).strip() in ("0","false","False"):
                a4_high = False
        except Exception:
            pass
    tab_path = os.path.join(folder, "glyph_table.json")
    met_path = os.path.join(folder, "glyph_metrics.json")

    if os.path.isfile(tab_path):
        pack = json.load(open(tab_path, "r", encoding="utf-8"))
        if isinstance(pack, dict) and "glyphs" in pack:
            glyphs = pack.get("glyphs", [])
        elif isinstance(pack, list):
            # backward compat: list of glyph rows
            glyphs = pack
        else:
            raise ValueError("glyph_table.json không đúng định dạng.")

        metrics_list = []
        overrides: Dict[int,int] = {}
        for row in glyphs:
            if not isinstance(row, dict):
                continue
            gi = row.get("glyphIndex")
            if gi is None:
                continue
            gi = int(gi)
            metrics_list.append({
                "glyphIndex": gi,
                "left": int(row.get("left", 0)),
                "glyphWidth": int(row.get("glyphWidth", 0)),
                "charWidth": int(row.get("charWidth", 0)),
            })
            codes = row.get("codes", [])
            if isinstance(codes, list):
                for cs in codes:
                    code = parse_code_str(str(cs))
                    if code is None:
                        continue
                    overrides[int(code)] = gi
        # fallback: if no codes, try embedded cmap
        if not overrides and isinstance(pack, dict) and "cmap" in pack:
            cmap = pack.get("cmap", {})
            if isinstance(cmap, dict):
                for k,v in cmap.items():
                    code = parse_code_str(str(k))
                    if code is None:
                        continue
                    overrides[int(code)] = int(v)
        return metrics_list, overrides

    if os.path.isfile(met_path):
        pack = json.load(open(met_path, "r", encoding="utf-8"))
        if isinstance(pack, dict) and "metrics" in pack:
            metrics_list = pack.get("metrics", [])
            cmap = pack.get("cmap", {})
        elif isinstance(pack, list):
            metrics_list = pack
            cmap = {}
        else:
            raise ValueError("glyph_metrics.json không đúng định dạng.")

        overrides: Dict[int,int] = {}
        if isinstance(cmap, dict):
            for k,v in cmap.items():
                code = parse_code_str(str(k))
                if code is None:
                    continue
                overrides[int(code)] = int(v)
        return metrics_list, overrides

    raise FileNotFoundError("Thiếu glyph_table.json hoặc glyph_metrics.json trong thư mục.")



def _apply_cmap_overrides_prepend_bytes(b: bytearray, blocks, e: str, overrides: Dict[int,int]) -> bytearray:
    """
    Prepend scan-CMAP (method=2) to override existing CMAP chain.
    - Writes a new CMAP block at end (4-byte aligned)
    - Patches FINF firstCmapBase to point to new CMAP data base
    - Updates header fileSize + numBlocks
    Returns the mutated buffer.
    """
    if not overrides:
        return b

    finf_off, finf_size, idx_m, cmap_field_abs = find_finf_offsets(b, blocks, e)
    old_first_base = u32(b, cmap_field_abs, e)

    new_cmap_block = build_cmap_scan_block(overrides, old_first_base, e)
    new_cmap_off = align4(len(b))
    if new_cmap_off > len(b):
        b += b"\x00" * (new_cmap_off - len(b))
    b += new_cmap_block

    # FINF stores "base" (offset to CMAP data, i.e. blockOff + 8)
    new_first_base = new_cmap_off + 8
    b[cmap_field_abs:cmap_field_abs+4] = p32(new_first_base, e)

    # Patch header: fileSize + numBlocks
    b[0x0C:0x10] = p32(len(b), e)
    b[0x10:0x12] = p16(u16(b, 0x10, e) + 1, e)
    return b


def _effective_cmap_from_font(b: bytes, blocks, e: str) -> Dict[int,int]:
    """
    Compute the effective mapping as resolved by the CMAP chain:
    traverse from FINF first CMAP following next links; first mapping wins on overlaps.
    Returns dict {codepoint(int)->glyphIndex(int)}.
    """
    finf_off, finf_size, idx_m, cmap_field_abs = find_finf_offsets(b, blocks, e)
    first_cmap_base = u32(b, cmap_field_abs, e)
    cmaps = traverse_cmap_chain(b, first_cmap_base, e)

    merged: Dict[int,int] = {}
    for cm in cmaps:
        mapping = cmap_block_to_mapping(cm, e)
        for k, v in mapping.items():
            if k not in merged:
                merged[k] = v
    return merged

def import_bffnt_auto(in_path: str, folder: str):
    """
    v4 import:
      - hỏi thư mục (folder) chứa sheet0.png + (glyph_table.json hoặc glyph_metrics.json)
      - tự patch sheet0.png
      - tự patch metrics
      - tự remap/override cmap (prepend scan CMAP) dựa theo:
          + codes trong glyph_table.json (ưu tiên)
          + hoặc embedded cmap trong file json
      - bỏ qua grid hoàn toàn
      - output: *_new.bffnt
    """
    b = bytearray(open(in_path, "rb").read())
    e, header_size, num_blocks, blocks = parse_blocks(b)

    tglp = find_block(blocks, "TGLP")
    if not tglp:
        raise RuntimeError("TGLP not found")
    _, tglp_off, tglp_size = tglp
    t = parse_tglp_and_sheet(b, tglp_off, tglp_size, e)
    w, h = t["sheetWidth"], t["sheetHeight"]

    folder = folder.strip().strip('"')
    a4_high = True
    meta_path = os.path.join(folder, "meta.json")
    if os.path.isfile(meta_path):
        try:
            m = json.load(open(meta_path, "r", encoding="utf-8"))
            v = m.get("a4_nibble")
            if isinstance(v, str) and v.lower().strip() in ("low","lo","0","false"):
                a4_high = False
            elif isinstance(v, str) and v.lower().strip() in ("high","hi","1","true"):
                a4_high = True
            elif str(m.get("a4_high_nibble_first", "")).strip() in ("0","false","False"):
                a4_high = False
        except Exception:
            pass
    png_path = os.path.join(folder, "sheet0.png")  # required

    if not os.path.isfile(png_path):
        raise FileNotFoundError("Missing sheet0.png: " + png_path)

    metrics_list, overrides = _load_metrics_and_cmap_from_folder(folder)

    # Patch sheet (multi-sheet): sheet0.png + sheet1.png.. nếu có
    sheetSize = int(t["sheetSize"])
    sheetNum = int(t.get("sheetNum", t.get("field10", 1)))
    abs_off0 = t["sheetDataAbs"]

        # giới hạn số sheet thực sự có trong file (tránh out of range)
    tglp_end = tglp_off + tglp_size
    maxSheets = (tglp_end - abs_off0) // sheetSize if sheetSize > 0 else 0
    sheetNumEff = min(sheetNum, maxSheets)

    for si in range(sheetNumEff):
        pimg = os.path.join(folder, f"sheet{si}.png")
        # if user provides edited version, prefer it
        pedit = os.path.join(folder, f"sheet{si}_edit.png")
        if os.path.isfile(pedit):
            pimg = pedit
        if si == 0 and not os.path.isfile(pimg):
            pimg = png_path
        if not os.path.isfile(pimg):
            # missing sheet => keep original
            continue
        a8_linear = rgba_png_to_a8_linear(pimg, w, h)
        if a8_linear is None:
            raise RuntimeError("rgba_png_to_a8_linear() returned None")
        raw_swz = encode_png_to_sheet_raw(pimg, w, h, int(t.get("formatId", t.get("field11", 8))), expected_size=sheetSize, a4_high_nibble_first=a4_high)
        abs_off = abs_off0 + si * sheetSize
        if abs_off + len(raw_swz) > len(b):
            raise RuntimeError("Sheet data out of file range")
        b[abs_off:abs_off + len(raw_swz)] = raw_swz


    # Patch metrics
    cwdh_descs = parse_cwdh_blocks(b, blocks, e)
    apply_metrics_patch(b, cwdh_descs, metrics_list, e)

    # Auto CMAP override
    # Auto CMAP override (chỉ khi khác mapping gốc) để tránh "lệch glyph" khi repack không chỉnh gì
    if overrides:
        try:
            current = _effective_cmap_from_font(b, blocks, e)
            if current == overrides:
                overrides = {}
        except Exception:
            pass
    b = _apply_cmap_overrides_prepend_bytes(b, blocks, e, overrides)

    root, ext = os.path.splitext(in_path)
    out_path = root + "_new" + ext
    if b is None:
        raise RuntimeError("Internal error: output buffer is None. Hãy gửi lại log + folder input.")
    with open(out_path, "wb") as f:
        f.write(bytes(b))

    print("OK IMPORT:", out_path)
    if overrides:
        print(f" - Auto CMAP override: {len(overrides)} codepoints (prepend scan-CMAP).")
    else:
        print(" - Auto CMAP override: không có mapping (giữ nguyên CMAP).")
    return out_path

# ------------------ CLI/menu v4 (only Export/Import) ------------------

def menu():
    print("=== BFFNT Tool v4 (Export/Import auto CMAP) ===")
    print("1) Xuất: sheet0.png + glyph_metrics.json + glyph_table.json + meta.json")
    print("2) Nhập: hỏi thư mục -> patch ảnh + metrics + tự remap cmap -> *_new.bffnt")
    choice = input("Chọn (1/2): ").strip()

    if choice == "1":
        in_path = input("Nhập đường dẫn .bffnt: ").strip().strip('"')
        export_bffnt(in_path)
    elif choice == "2":
        in_path = input("Nhập đường dẫn .bffnt gốc: ").strip().strip('"')
        folder = input("Nhập thư mục chứa sheet0.png + glyph_table.json/glyph_metrics.json: ").strip().strip('"')
        import_bffnt_auto(in_path, folder)
    else:
        print("Hủy.")


def main(argv):
    if len(argv) <= 1:
        return menu()

    cmd = argv[1].lower()
    if cmd == "export" and len(argv) >= 3:
        return export_bffnt(argv[2])
    if cmd == "import" and len(argv) >= 3:
        in_path = argv[2]
        folder = argv[3] if len(argv) >= 4 else input("Nhập thư mục chứa sheet0.png + glyph_table.json/glyph_metrics.json: ").strip().strip('"')
        return import_bffnt_auto(in_path, folder)

    print("Usage:")
    print("  python bffnttool_v4.py")
    print("  python bffnttool_v4.py export <font.bffnt>")
    print("  python bffnttool_v4.py import <font.bffnt> <folder>")
    sys.exit(2)


# Expose core functions through the current module namespace.
class _CoreProxy:
    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name)

core = _CoreProxy()

def parse_hex_code(text: str) -> int:
    s = str(text).strip().upper()
    if not s:
        raise ValueError("Char code trống")
    s = s.replace("U+", "").replace("0X", "")
    s = "".join(ch for ch in s if ch in "0123456789ABCDEF")
    if not s:
        raise ValueError("Char code không hợp lệ")
    v = int(s, 16)
    if not (0 <= v <= 0xFFFF):
        raise ValueError("BFFNT CMAP trong tool này chỉ hỗ trợ code 0000..FFFF")
    return v


def parse_hex_code_optional(text: str):
    """Return None for blank input; otherwise parse BFFNT u16 char code."""
    raw = str(text).strip()
    if not raw:
        return None
    return parse_hex_code(raw)


def safe_chr(code: int) -> str:
    try:
        ch = chr(code)
        if ch.isprintable() and ch not in "\r\n\t":
            return ch
    except Exception:
        pass
    return ""


def make_visible_rgba(src: Image.Image, fg=(0, 0, 0)) -> Image.Image:
    """Use alpha as glyph mask and make RGB black, useful for preview/export."""
    src = src.convert("RGBA")
    alpha = src.split()[3]
    out = Image.new("RGBA", src.size, fg + (0,))
    out.putalpha(alpha)
    return out


def normalize_glyph_left(glyph: Image.Image, size: tuple[int, int], keep_vertical: bool = True, margin_left: int = 1) -> Image.Image:
    """
    Trim transparent left/right padding and paste the visible pixels close to the left edge.
    keep_vertical=True keeps the original top position, so accents/baseline stay close to the source glyph.
    Blank glyphs remain fully transparent. margin_left=1 matches this game family's real atlas cell.
    """
    glyph = glyph.convert("RGBA")
    if glyph.size != size:
        glyph = glyph.resize(size, Image.Resampling.NEAREST)

    alpha = glyph.split()[3]
    bbox = alpha.getbbox()
    out = Image.new("RGBA", size, (255, 255, 255, 0))
    if not bbox:
        return out

    crop = glyph.crop(bbox)
    margin_left = max(0, int(margin_left))
    if crop.width + margin_left > size[0]:
        margin_left = 0
    y = bbox[1] if keep_vertical else 0
    y = max(0, min(y, size[1] - crop.height))
    out.alpha_composite(crop, (margin_left, y))
    return out


def glyph_auto_width(glyph: Image.Image) -> int:
    """Return draw width from alpha bbox. Assumes glyph is already left-aligned."""
    alpha = glyph.convert("RGBA").split()[3]
    bbox = alpha.getbbox()
    if not bbox:
        return 0
    return max(0, min(glyph.size[0], int(bbox[2] - bbox[0])))


def import_image_to_glyph_alpha(path: str, size: tuple[int, int], parent=None) -> Image.Image:
    """
    Convert imported PNG to a glyph cell.
    - If alpha exists, use alpha.
    - If there is no useful alpha, infer alpha from black-on-white image: darker = more opaque.
    """
    img = Image.open(path).convert("RGBA")
    if img.size != size:
        ok = messagebox.askyesno(
            "Resize glyph?",
            f"Ảnh nhập có size {img.size}, glyph cần {size}.\nBạn có muốn resize về đúng size không?",
            parent=parent,
        )
        if not ok:
            raise ValueError("Hủy import vì sai kích thước glyph")
        img = img.resize(size, Image.Resampling.NEAREST)

    r, g, b, a = img.split()
    # If alpha is all opaque, assume user imported a flat black-on-white image and infer mask.
    amin, amax = a.getextrema()
    if amin == 255 and amax == 255:
        gray = img.convert("L")
        alpha = gray.point(lambda v: 255 - v)
    else:
        alpha = a
    out = Image.new("RGBA", size, (255, 255, 255, 0))
    out.putalpha(alpha)
    # Default behavior for this UI: trim horizontal padding and place the glyph at the left edge.
    # This makes replacement slots easier to edit and prevents old centered glyphs from keeping bad spacing.
    return normalize_glyph_left(out, size, keep_vertical=True)


class BffntDocument:
    def __init__(self):
        self.path = None
        self.buf = None
        self.endian = None
        self.header_size = None
        self.num_blocks = None
        self.blocks = None
        self.tglp_info = None
        self.cwdh_descs = None
        self.metrics_by_glyph = {}
        self.code_to_glyph = {}
        self.sheet_img = None
        self.a4_high = True
        self.grid_cols = 0
        self.x_pitch = 0
        self.row_pitch = 0
        self.sheet_format_id = 8
        self.force_cmap_rewrite = False
        self.dirty = False

    @property
    def cell_w(self):
        return int(self.tglp_info["cellWidth"])

    @property
    def cell_h(self):
        return int(self.tglp_info["cellHeight"])

    @property
    def sheet_w(self):
        return int(self.tglp_info["sheetWidth"])

    @property
    def sheet_h(self):
        return int(self.tglp_info["sheetHeight"])

    def _detect_sheet_format_id(self) -> int:
        """Prefer the real TGLP sheet format field when the older core parser exposes it as field12."""
        known = {8, 11, 0x24, 0x40, 36, 64}
        for key in ("field12", "formatId"):
            try:
                value = int(self.tglp_info.get(key, 0))
            except Exception:
                continue
            if value in known:
                return value
        return int(self.tglp_info.get("formatId", 8))

    def _detect_grid_cols(self) -> int:
        """
        Detect glyphs per row.
        The previous UI used sheetWidth // cellWidth (=10 for this font),
        but font_common.bffnt actually stores 9 glyph cells per row.
        field14 from the existing parser is the reliable column count for this case.
        """
        cw, ch = self.cell_w, self.cell_h
        if cw <= 0 or ch <= 0:
            return 1

        max_gi = 0
        if self.metrics_by_glyph:
            max_gi = max(max_gi, max(self.metrics_by_glyph.keys()))
        if self.code_to_glyph:
            max_gi = max(max_gi, max(int(v) for v in self.code_to_glyph.values()))

        normal_cols = max(1, self.sheet_w // cw)
        candidates = []
        try:
            f14 = int(self.tglp_info.get("field14", 0))
            if f14 > 0:
                candidates.append(f14)
        except Exception:
            pass
        candidates.append(normal_cols)

        seen = set()
        plausible = []
        for cols in candidates:
            if cols in seen:
                continue
            seen.add(cols)
            if cols <= 0:
                continue
            if cols * cw > self.sheet_w:
                continue
            rows_needed = (max_gi + cols) // cols
            if rows_needed * ch <= self.sheet_h:
                plausible.append(cols)

        return plausible[0] if plausible else normal_cols

    def _detect_x_pitch(self) -> int:
        """
        Detect horizontal pitch between glyph cells.

        These BFFNT sheets often have a 1 px separator column between cells:
        cellWidth=35 but real x pitch=36; cellWidth=25 but real x pitch=26.
        Using cellWidth as pitch makes later columns shift left, so imported glyphs are
        partly outside the cell used by the game and appear clipped.
        """
        cw = self.cell_w
        cols = max(1, int(self.grid_cols or self._detect_grid_cols() or 1))
        if cw <= 0:
            return 1

        candidates = []
        for v in (cw + 1, cw, int(self.tglp_info.get("maxCharWidth", 0) or 0), self.sheet_w // cols):
            if v and v not in candidates and cols * v <= self.sheet_w:
                candidates.append(v)
        if cw not in candidates and cols * cw <= self.sheet_w:
            candidates.append(cw)

        # Score by how stable the visible bbox left edge is across known glyphs.
        # Correct pitch usually gives bbox.left around 1 for all columns.
        sample_glyphs = []
        for gi in sorted(self.metrics_by_glyph.keys()):
            if len(sample_glyphs) >= 80:
                break
            try:
                row = int(gi) // cols
                col = int(gi) % cols
                if row < 0 or col < 0:
                    continue
                sample_glyphs.append(int(gi))
            except Exception:
                pass

        best = candidates[0] if candidates else cw
        best_score = None
        for pitch in candidates:
            lefts = []
            for gi in sample_glyphs:
                row = gi // cols
                col = gi % cols
                x = col * pitch
                y = row * int(self.row_pitch or self.cell_h)
                if x + cw > self.sheet_w or y + self.cell_h > self.sheet_h:
                    continue
                bbox = self.sheet_img.crop((x, y, x + cw, y + self.cell_h)).split()[3].getbbox()
                if bbox:
                    lefts.append(int(bbox[0]))
            if not lefts:
                continue
            mean = sum(lefts) / len(lefts)
            variance = sum((a - mean) ** 2 for a in lefts) / len(lefts)
            score = variance + abs(mean - 1) * 2 + max(lefts) * 0.05
            if best_score is None or score < best_score:
                best_score = score
                best = pitch
        return int(best)

    def _detect_row_pitch(self) -> int:
        """
        Detect vertical pitch between glyph rows.

        Some BFFNT files store cellHeight=27 but the texture advances 28 px per row
        because the TGLP row count field is 36 and sheetHeight // 36 = 28.
        If we use cellHeight directly, glyphs like a/z include pixels from the row above.
        """
        ch = self.cell_h
        if ch <= 0:
            return 1

        # In this font parser, the true row count is exposed as formatId when field12 is
        # the actual image format and field14 is the column count.
        candidates = []
        try:
            rows = int(self.tglp_info.get("formatId", 0))
            if rows > 0:
                candidates.append(rows)
        except Exception:
            pass

        # Generic fallbacks: infer from maximum glyph index and columns.
        max_gi = 0
        if self.metrics_by_glyph:
            max_gi = max(max_gi, max(self.metrics_by_glyph.keys()))
        if self.code_to_glyph:
            max_gi = max(max_gi, max(int(v) for v in self.code_to_glyph.values()))
        cols = max(1, int(self.grid_cols or self._detect_grid_cols() or 1))
        min_rows = (max_gi // cols) + 1
        candidates.append(min_rows)

        for rows in candidates:
            if rows <= 0:
                continue
            pitch = self.sheet_h // rows
            if pitch >= ch and pitch * min_rows <= self.sheet_h:
                return pitch

        return ch

    def set_grid_cols(self, cols: int):
        cols = int(cols)
        if cols <= 0:
            raise ValueError("Grid cols phải lớn hơn 0")
        if cols * self.cell_w > self.sheet_w:
            raise ValueError(f"Grid cols {cols} vượt sheetWidth {self.sheet_w}")
        self.grid_cols = cols
        self.row_pitch = self._detect_row_pitch()
        self.x_pitch = self._detect_x_pitch()

    def _has_legacy_reserved_scan_cmap(self) -> bool:
        """
        True when the FIRST effective CMAP block is the malformed method=2 block written by v4 UI.
        If a correct v5 override has already been prepended, older malformed blocks later in the chain
        are harmless because the renderer resolves the first matching mapping.
        """
        try:
            finf_off, finf_size, idx_m, cmap_field_abs = core.find_finf_offsets(self.buf, self.blocks, self.endian)
            first_cmap_base = core.u32(self.buf, cmap_field_abs, self.endian)
            cmaps = core.traverse_cmap_chain(self.buf, first_cmap_base, self.endian)
            if not cmaps:
                return False
            return core._is_legacy_reserved_scan_cmap(cmaps[0], self.endian)
        except Exception:
            return False

    def load(self, path: str):
        self.path = path
        self.buf = bytearray(open(path, "rb").read())
        self.endian, self.header_size, self.num_blocks, self.blocks = core.parse_blocks(self.buf)

        tglp = core.find_block(self.blocks, "TGLP")
        if not tglp:
            raise RuntimeError("Không tìm thấy block TGLP")
        _, tglp_off, tglp_size = tglp
        self.tglp_info = core.parse_tglp_and_sheet(self.buf, tglp_off, tglp_size, self.endian)

        self.sheet_format_id = self._detect_sheet_format_id()
        decoded = core.decode_sheet_to_png(
            self.tglp_info["rawSheet"],
            self.sheet_w,
            self.sheet_h,
            self.sheet_format_id,
        )
        if isinstance(getattr(decoded, "info", None), dict):
            self.a4_high = str(decoded.info.get("a4_high_nibble_first", "1")) not in ("0", "false", "False")
        self.sheet_img = decoded.convert("RGBA")

        self.cwdh_descs = core.parse_cwdh_blocks(self.buf, self.blocks, self.endian)
        metrics = core.dump_metrics(self.buf, self.cwdh_descs, self.endian)
        self.metrics_by_glyph = {int(m["glyphIndex"]): dict(m) for m in metrics}

        self.code_to_glyph = core._effective_cmap_from_font(self.buf, self.blocks, self.endian)
        self.force_cmap_rewrite = self._has_legacy_reserved_scan_cmap()
        self.grid_cols = self._detect_grid_cols()
        self.row_pitch = self._detect_row_pitch()
        self.x_pitch = self._detect_x_pitch()
        self.dirty = False

    def sorted_codes(self):
        return sorted(self.code_to_glyph.keys())

    def glyph_to_codes(self):
        out = {}
        for code, gi in self.code_to_glyph.items():
            out.setdefault(int(gi), []).append(int(code))
        for gi in out:
            out[gi] = sorted(set(out[gi]))
        return out

    def glyph_entries(self):
        """Return every editable glyph, not only glyphs that have CMAP char codes."""
        glyphs = set(int(k) for k in self.metrics_by_glyph.keys())
        glyphs.update(int(v) for v in self.code_to_glyph.values())
        g2c = self.glyph_to_codes()
        return [{"glyphIndex": gi, "codes": g2c.get(gi, [])} for gi in sorted(glyphs)]

    def glyph_rect(self, glyph_index: int):
        cw, ch = self.cell_w, self.cell_h
        if cw <= 0 or ch <= 0:
            raise RuntimeError("cellWidth/cellHeight không hợp lệ")
        cols = max(1, int(self.grid_cols or (self.sheet_w // cw)))
        row_pitch = int(self.row_pitch or ch)
        x_pitch = int(self.x_pitch or cw)
        x = (glyph_index % cols) * x_pitch
        y = (glyph_index // cols) * row_pitch
        if x + cw > self.sheet_w or y + ch > self.sheet_h:
            raise RuntimeError(
                f"Glyph index {glyph_index} nằm ngoài sheet0. Tool UI hiện chỉ sửa sheet0."
            )
        return (x, y, x + cw, y + ch)

    def get_glyph_image_by_glyph(self, glyph_index: int) -> Image.Image:
        return self.sheet_img.crop(self.glyph_rect(int(glyph_index)))

    def get_glyph_image_by_code(self, code: int) -> Image.Image:
        gi = int(self.code_to_glyph[code])
        return self.get_glyph_image_by_glyph(gi)

    def _sync_metric_from_glyph_image(self, glyph_index: int, glyph_img: Image.Image):
        """Update CWDH left/glyphWidth/charWidth from the visible alpha box."""
        gi = int(glyph_index)
        m = self.get_metric_by_glyph(gi)
        width = glyph_auto_width(glyph_img)
        m["left"] = 0
        m["glyphWidth"] = min(width, self.cell_w)
        # Advance gets one pixel of breathing room so neighboring glyphs do not touch.
        m["charWidth"] = min(255, width + (1 if width > 0 else 0))
        return m["charWidth"]

    def auto_fit_glyph(self, glyph_index: int):
        """Left-align the selected glyph and auto-update its metrics."""
        gi = int(glyph_index)
        rect = self.glyph_rect(gi)
        glyph_img = self.sheet_img.crop(rect)
        glyph_img = normalize_glyph_left(glyph_img, (self.cell_w, self.cell_h), keep_vertical=True)
        self.sheet_img.paste(glyph_img, rect[:2])
        width = self._sync_metric_from_glyph_image(gi, glyph_img)
        self.dirty = True
        return width

    def set_glyph_image_by_glyph(self, glyph_index: int, glyph_img: Image.Image):
        gi = int(glyph_index)
        rect = self.glyph_rect(gi)
        glyph_img = glyph_img.convert("RGBA")
        if glyph_img.size != (self.cell_w, self.cell_h):
            raise ValueError(f"Glyph size {glyph_img.size} != {(self.cell_w, self.cell_h)}")
        glyph_img = normalize_glyph_left(glyph_img, (self.cell_w, self.cell_h), keep_vertical=True)
        # Replace the whole glyph cell, including transparent pixels, so old pixels are cleared.
        self.sheet_img.paste(glyph_img, rect[:2])
        self._sync_metric_from_glyph_image(gi, glyph_img)
        self.dirty = True

    def set_glyph_image_by_code(self, code: int, glyph_img: Image.Image):
        gi = int(self.code_to_glyph[code])
        self.set_glyph_image_by_glyph(gi, glyph_img)

    def get_metric_by_glyph(self, glyph_index: int) -> dict:
        gi = int(glyph_index)
        if gi not in self.metrics_by_glyph:
            self.metrics_by_glyph[gi] = {
                "glyphIndex": gi,
                "left": 0,
                "glyphWidth": self.cell_w,
                "charWidth": self.cell_w,
            }
        return self.metrics_by_glyph[gi]

    def get_metric_by_code(self, code: int) -> dict:
        gi = int(self.code_to_glyph[code])
        return self.get_metric_by_glyph(gi)

    def set_width_by_glyph(self, glyph_index: int, width: int):
        if not (0 <= width <= 255):
            raise ValueError("Width phải nằm trong 0..255")
        m = self.get_metric_by_glyph(glyph_index)
        # BFFNT has both glyphWidth and charWidth. Some games use glyphWidth for draw/crop,
        # so changing only charWidth can look like the game is still using the old width.
        m["left"] = 0
        m["glyphWidth"] = min(int(width), self.cell_w)
        m["charWidth"] = int(width)
        self.dirty = True

    def set_width_by_code(self, code: int, width: int):
        gi = int(self.code_to_glyph[code])
        self.set_width_by_glyph(gi, width)

    def change_char_code_for_glyph(self, glyph_index: int, old_code, new_code):
        """Change/add/remove one CMAP code for a glyph. old_code/new_code may be None."""
        gi = int(glyph_index)
        if old_code is not None and int(old_code) in self.code_to_glyph:
            # Only remove if the selected old code belongs to this glyph.
            if int(self.code_to_glyph[int(old_code)]) == gi:
                del self.code_to_glyph[int(old_code)]
        if new_code is not None:
            new_code = int(new_code)
            existed = self.code_to_glyph.get(new_code)
            if existed is not None and int(existed) != gi:
                raise ValueError(f"Char code 0x{new_code:04X} đã thuộc glyph {int(existed)}")
            self.code_to_glyph[new_code] = gi
        self.dirty = True

    def change_char_code(self, old_code: int, new_code: int):
        if old_code not in self.code_to_glyph:
            raise KeyError("Old char code không còn trong danh sách")
        gi = self.code_to_glyph[old_code]
        self.change_char_code_for_glyph(gi, old_code, new_code)

    def save_as(self, out_path: str):
        if not self.path:
            raise RuntimeError("Chưa mở file BFFNT")

        b = bytearray(self.buf)

        # Patch glyph sheet through the original encoder.
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            self.sheet_img.save(tmp_path)
            raw_swz = core.encode_png_to_sheet_raw(
                tmp_path,
                self.sheet_w,
                self.sheet_h,
                int(self.sheet_format_id),
                expected_size=int(self.tglp_info["sheetSize"]),
                a4_high_nibble_first=self.a4_high,
            )
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

        abs_off = int(self.tglp_info["sheetDataAbs"])
        if abs_off + len(raw_swz) > len(b):
            raise RuntimeError("Sheet data vượt quá kích thước file")
        b[abs_off:abs_off + len(raw_swz)] = raw_swz

        # Patch CWDH metrics.
        metrics_list = [self.metrics_by_glyph[k] for k in sorted(self.metrics_by_glyph.keys())]
        core.apply_metrics_patch(b, self.cwdh_descs, metrics_list, self.endian)

        # Patch CMAP only if mapping changed. This prepends a scan-CMAP override.
        try:
            current_map = core._effective_cmap_from_font(self.buf, self.blocks, self.endian)
        except Exception:
            current_map = {}
        if self.force_cmap_rewrite or current_map != self.code_to_glyph:
            b = core._apply_cmap_overrides_prepend_bytes(b, self.blocks, self.endian, dict(self.code_to_glyph))

        with open(out_path, "wb") as f:
            f.write(bytes(b))
        self.dirty = False
        return out_path


class BffntUi(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("820x560")
        self.minsize(760, 500)

        self.doc = BffntDocument()
        self.current_glyph = None
        self.current_code = None  # primary/selected char code for this glyph, may be None for unmapped glyphs
        self.preview_photo = None

        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        top = ttk.Frame(self, padding=(8, 8, 8, 4))
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)

        ttk.Button(top, text="Open BFFNT", command=self.open_file).grid(row=0, column=0, padx=(0, 8))
        self.path_var = tk.StringVar(value="Chưa mở file")
        ttk.Label(top, textvariable=self.path_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(top, text="Save As", command=self.save_as).grid(row=0, column=2, padx=(8, 0))

        main = ttk.Frame(self, padding=(8, 4, 8, 8))
        main.grid(row=1, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        # Left: char list
        list_frame = ttk.LabelFrame(main, text="Danh sách ký tự", padding=8)
        list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        self.listbox = tk.Listbox(list_frame, exportselection=False, font=("Consolas", 11))
        self.listbox.grid(row=0, column=0, sticky="nsew")
        self.listbox.bind("<<ListboxSelect>>", self.on_select_char)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.listbox.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.listbox.configure(yscrollcommand=scroll.set)

        # Right: preview + controls
        right = ttk.LabelFrame(main, text="Preview / chức năng", padding=8)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        preview_wrap = ttk.Frame(right)
        preview_wrap.grid(row=0, column=0, sticky="nsew")
        preview_wrap.columnconfigure(0, weight=1)
        preview_wrap.rowconfigure(0, weight=1)

        self.preview_canvas = tk.Canvas(preview_wrap, width=240, height=240, bg="white", highlightthickness=1, highlightbackground="#444")
        self.preview_canvas.grid(row=0, column=0, pady=(0, 10))

        info = ttk.Frame(right)
        info.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        info.columnconfigure(1, weight=1)
        info.columnconfigure(3, weight=1)

        ttk.Label(info, text="Width:").grid(row=0, column=0, sticky="w", padx=(0, 4), pady=3)
        self.width_var = tk.StringVar()
        self.width_entry = ttk.Entry(info, textvariable=self.width_var, width=10)
        self.width_entry.grid(row=0, column=1, sticky="w", pady=3)
        ttk.Button(info, text="Apply", command=self.apply_width).grid(row=0, column=2, sticky="w", padx=(6, 18), pady=3)

        ttk.Label(info, text="Char code:").grid(row=0, column=3, sticky="e", padx=(0, 4), pady=3)
        self.code_var = tk.StringVar()
        self.code_entry = ttk.Entry(info, textvariable=self.code_var, width=12)
        self.code_entry.grid(row=0, column=4, sticky="w", pady=3)
        ttk.Button(info, text="Apply", command=self.apply_char_code).grid(row=0, column=5, sticky="w", padx=(6, 0), pady=3)

        ttk.Label(info, text="Grid cols:").grid(row=1, column=0, sticky="w", padx=(0, 4), pady=3)
        self.cols_var = tk.StringVar()
        self.cols_entry = ttk.Entry(info, textvariable=self.cols_var, width=10)
        self.cols_entry.grid(row=1, column=1, sticky="w", pady=3)
        ttk.Button(info, text="Apply", command=self.apply_grid_cols).grid(row=1, column=2, sticky="w", padx=(6, 18), pady=3)

        ttk.Label(info, text="X pitch:").grid(row=1, column=3, sticky="e", padx=(0, 4), pady=3)
        self.xpitch_var = tk.StringVar()
        self.xpitch_entry = ttk.Entry(info, textvariable=self.xpitch_var, width=12)
        self.xpitch_entry.grid(row=1, column=4, sticky="w", pady=3)
        ttk.Button(info, text="Apply", command=self.apply_x_pitch).grid(row=1, column=5, sticky="w", padx=(6, 0), pady=3)

        buttons = ttk.Frame(right)
        buttons.grid(row=2, column=0, sticky="ew")
        for i in range(5):
            buttons.columnconfigure(i, weight=1)
        ttk.Button(buttons, text="Export Glyph", command=self.export_glyph).grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        ttk.Button(buttons, text="Import Glyph", command=self.import_glyph).grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(buttons, text="Auto Fit", command=self.auto_fit_glyph).grid(row=0, column=2, sticky="ew", padx=4, pady=4)
        ttk.Button(buttons, text="Reload", command=self.reload_file).grid(row=0, column=3, sticky="ew", padx=4, pady=4)
        ttk.Button(buttons, text="Save As", command=self.save_as).grid(row=0, column=4, sticky="ew", padx=4, pady=4)

        self.status_var = tk.StringVar(value="Mở file .bffnt để bắt đầu")
        status = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=(6, 3))
        status.grid(row=2, column=0, sticky="ew")

    def set_status(self, text: str):
        self.status_var.set(text)

    def require_loaded(self):
        if not self.doc.path:
            messagebox.showwarning("Chưa mở file", "Hãy mở file .bffnt trước.", parent=self)
            return False
        return True

    def open_file(self):
        path = filedialog.askopenfilename(
            title="Chọn file BFFNT/BCFNT",
            filetypes=[("BFFNT/BCFNT", "*.bffnt *.bcfnt *.ffnt *.cfnt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            self.doc.load(path)
            self.path_var.set(path)
            self.populate_list()
            self.set_status(
                f"Đã mở: {os.path.basename(path)} | cell {self.doc.cell_w}x{self.doc.cell_h} | x pitch {self.doc.x_pitch} | row pitch {self.doc.row_pitch} | sheet {self.doc.sheet_w}x{self.doc.sheet_h} | grid cols {self.doc.grid_cols} | x pitch {self.doc.x_pitch}" + (" | phát hiện CMAP v4 lỗi, Save As để sửa" if self.doc.force_cmap_rewrite else "")
            )
        except Exception as e:
            messagebox.showerror("Lỗi mở file", str(e), parent=self)

    def reload_file(self):
        if not self.doc.path:
            return
        if self.doc.dirty:
            ok = messagebox.askyesno("Reload", "File đang có chỉnh sửa chưa lưu. Reload sẽ mất thay đổi. Tiếp tục?", parent=self)
            if not ok:
                return
        path = self.doc.path
        try:
            self.doc.load(path)
            self.populate_list()
            self.set_status("Đã reload file gốc")
        except Exception as e:
            messagebox.showerror("Lỗi reload", str(e), parent=self)

    def populate_list(self, keep_code=None, keep_glyph=None):
        self.listbox.delete(0, tk.END)
        entries = self.doc.glyph_entries()
        self._list_entries = entries

        for item in entries:
            gi = int(item["glyphIndex"])
            codes = item.get("codes", [])
            if codes:
                code_text = ",".join(f"{c:04X}" for c in codes[:4])
                if len(codes) > 4:
                    code_text += ",..."
                chars = "".join(safe_chr(c) for c in codes[:4])
                suffix = f"  {chars}" if chars else ""
                self.listbox.insert(tk.END, f"glyph {gi:04d}   code {code_text}{suffix}")
            else:
                self.listbox.insert(tk.END, f"glyph {gi:04d}   code ----")

        if entries:
            idx = 0
            if keep_glyph is not None:
                for i, item in enumerate(entries):
                    if int(item["glyphIndex"]) == int(keep_glyph):
                        idx = i
                        break
            elif keep_code is not None:
                for i, item in enumerate(entries):
                    if int(keep_code) in item.get("codes", []):
                        idx = i
                        break
            self.listbox.selection_set(idx)
            self.listbox.see(idx)
            item = entries[idx]
            codes = item.get("codes", [])
            self.show_glyph(int(item["glyphIndex"]), codes[0] if codes else None)
        else:
            self.current_glyph = None
            self.current_code = None
            self.preview_canvas.delete("all")
            self.width_var.set("")
            self.code_var.set("")
            self.cols_var.set("")
            self.xpitch_var.set("")

    def on_select_char(self, event=None):
        if not hasattr(self, "_list_entries"):
            return
        sel = self.listbox.curselection()
        if not sel:
            return
        item = self._list_entries[sel[0]]
        codes = item.get("codes", [])
        self.show_glyph(int(item["glyphIndex"]), codes[0] if codes else None)

    def show_code(self, code: int):
        gi = int(self.doc.code_to_glyph[code])
        self.show_glyph(gi, code)

    def show_glyph(self, glyph_index: int, primary_code=None):
        self.current_glyph = int(glyph_index)
        self.current_code = primary_code
        try:
            glyph = self.doc.get_glyph_image_by_glyph(self.current_glyph)
            self.draw_preview(glyph)
            m = self.doc.get_metric_by_glyph(self.current_glyph)
            self.width_var.set(str(int(m.get("charWidth", 0))))
            self.code_var.set(f"{int(primary_code):04X}" if primary_code is not None else "")
            self.cols_var.set(str(int(self.doc.grid_cols)))
            self.xpitch_var.set(str(int(self.doc.x_pitch)))
            codes = self.doc.glyph_to_codes().get(self.current_glyph, [])
            code_text = ", ".join(f"0x{c:04X}" for c in codes) if codes else "chưa map char code"
            self.set_status(
                f"Đang chọn glyph {self.current_glyph} | code {code_text} | grid cols {self.doc.grid_cols} | x pitch {self.doc.x_pitch} | row pitch {self.doc.row_pitch}"
            )
        except Exception as e:
            self.set_status(str(e))

    def draw_preview(self, glyph: Image.Image):
        self.preview_canvas.delete("all")
        glyph = make_visible_rgba(glyph, fg=(0, 0, 0))
        # Put glyph over white background and scale up using nearest.
        bg = Image.new("RGBA", glyph.size, (255, 255, 255, 255))
        bg.alpha_composite(glyph)
        max_w, max_h = 220, 220
        scale = max(1, min(max_w // max(1, bg.width), max_h // max(1, bg.height)))
        shown = bg.resize((bg.width * scale, bg.height * scale), Image.Resampling.NEAREST)
        self.preview_photo = ImageTk.PhotoImage(shown)
        x = (240 - shown.width) // 2
        y = (240 - shown.height) // 2
        self.preview_canvas.create_image(x, y, anchor="nw", image=self.preview_photo)
        # Draw border around scaled glyph cell.
        self.preview_canvas.create_rectangle(x, y, x + shown.width, y + shown.height, outline="#888")

    def export_glyph(self):
        if not self.require_loaded() or self.current_glyph is None:
            return
        folder = filedialog.askdirectory(title="Chọn thư mục lưu glyph PNG")
        if not folder:
            return
        try:
            gi = self.current_glyph
            img = self.doc.get_glyph_image_by_glyph(gi)
            out = make_visible_rgba(img, fg=(0, 0, 0))
            if self.current_code is not None:
                name = f"{int(self.current_code):04X}.png"
            else:
                name = f"glyph_{int(gi):04d}.png"
            out_path = os.path.join(folder, name)
            out.save(out_path)
            self.set_status(f"Đã export glyph: {out_path}")
        except Exception as e:
            messagebox.showerror("Lỗi export glyph", str(e), parent=self)

    def import_glyph(self):
        if not self.require_loaded() or self.current_glyph is None:
            return
        path = filedialog.askopenfilename(
            title="Chọn ảnh glyph PNG",
            filetypes=[("PNG image", "*.png"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            glyph = import_image_to_glyph_alpha(path, (self.doc.cell_w, self.doc.cell_h), parent=self)
            self.doc.set_glyph_image_by_glyph(self.current_glyph, glyph)
            m = self.doc.get_metric_by_glyph(self.current_glyph)
            self.show_glyph(self.current_glyph, self.current_code)
            self.set_status(f"Đã import glyph từ: {path} | auto width = {m.get('charWidth', 0)}")
        except Exception as e:
            messagebox.showerror("Lỗi import glyph", str(e), parent=self)

    def auto_fit_glyph(self):
        if not self.require_loaded() or self.current_glyph is None:
            return
        try:
            width = self.doc.auto_fit_glyph(self.current_glyph)
            self.show_glyph(self.current_glyph, self.current_code)
            self.set_status(f"Đã Auto Fit glyph {self.current_glyph}: sát mép an toàn, left=0, advance={width}")
        except Exception as e:
            messagebox.showerror("Lỗi Auto Fit", str(e), parent=self)

    def apply_x_pitch(self):
        if not self.require_loaded():
            return
        try:
            xp = int(self.xpitch_var.get().strip())
            if xp <= 0:
                raise ValueError("X pitch phải lớn hơn 0")
            if self.doc.grid_cols * xp > self.doc.sheet_w:
                raise ValueError(f"X pitch {xp} vượt sheetWidth {self.doc.sheet_w}")
            self.doc.x_pitch = xp
            if self.current_glyph is not None:
                self.show_glyph(self.current_glyph, self.current_code)
            self.set_status(f"Đã đổi x pitch = {xp}")
        except Exception as e:
            messagebox.showerror("Lỗi X pitch", str(e), parent=self)

    def apply_grid_cols(self):
        if not self.require_loaded():
            return
        try:
            cols = int(self.cols_var.get().strip())
            self.doc.set_grid_cols(cols)
            if self.current_glyph is not None:
                self.show_glyph(self.current_glyph, self.current_code)
            self.set_status(f"Đã đổi grid cols = {cols} | x pitch = {self.doc.x_pitch} | row pitch = {self.doc.row_pitch}")
        except Exception as e:
            messagebox.showerror("Lỗi grid cols", str(e), parent=self)

    def apply_width(self):
        if not self.require_loaded() or self.current_glyph is None:
            return
        try:
            w = int(self.width_var.get().strip())
            self.doc.set_width_by_glyph(self.current_glyph, w)
            self.populate_list(keep_glyph=self.current_glyph)
            self.set_status(f"Đã sửa width glyph {self.current_glyph}: left=0, glyphWidth={min(w, self.doc.cell_w)}, charWidth={w}")
        except Exception as e:
            messagebox.showerror("Lỗi sửa width", str(e), parent=self)

    def apply_char_code(self):
        if not self.require_loaded() or self.current_glyph is None:
            return
        try:
            old_code = self.current_code
            new_code = parse_hex_code_optional(self.code_var.get())
            self.doc.change_char_code_for_glyph(self.current_glyph, old_code, new_code)
            self.populate_list(keep_glyph=self.current_glyph)
            if new_code is None:
                self.set_status(
                    f"Đã bỏ mapping đang chọn khỏi glyph {self.current_glyph}. Khi Save As, tool sẽ ghi CMAP override."
                )
            elif old_code != new_code:
                self.current_code = new_code
                self.set_status(
                    f"Đã map glyph {self.current_glyph} thành char 0x{new_code:04X}. Khi Save As, tool sẽ ghi CMAP override."
                )
            else:
                self.set_status("Char code không thay đổi")
        except Exception as e:
            messagebox.showerror("Lỗi sửa char code", str(e), parent=self)

    def save_as(self):
        if not self.require_loaded():
            return
        root, ext = os.path.splitext(self.doc.path)
        default_name = os.path.basename(root + "_ui" + ext)
        out_path = filedialog.asksaveasfilename(
            title="Lưu file BFFNT mới",
            initialdir=os.path.dirname(self.doc.path),
            initialfile=default_name,
            defaultextension=ext or ".bffnt",
            filetypes=[("BFFNT/BCFNT", "*.bffnt *.bcfnt *.ffnt *.cfnt"), ("All files", "*.*")],
        )
        if not out_path:
            return
        try:
            saved = self.doc.save_as(out_path)
            self.set_status(f"Đã lưu: {saved}")
            messagebox.showinfo("Đã lưu", saved, parent=self)
        except Exception as e:
            messagebox.showerror("Lỗi save", str(e), parent=self)


def main():
    app = BffntUi()
    app.mainloop()


if __name__ == "__main__":
    main()
