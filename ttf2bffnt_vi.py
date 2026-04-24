#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ttf2bffnt_vi.py

Tạo Nintendo BFFNT/BCFNT từ TTF/OTF bằng cách dùng một file .bffnt có sẵn làm template.
Mục tiêu: hỗ trợ đầy đủ ký tự tiếng Việt Unicode dựng sẵn.

Yêu cầu:
  pip install pillow fonttools

Ví dụ:
  python ttf2bffnt_vi.py make font_common.bffnt MyFont.ttf out.bffnt
  python ttf2bffnt_vi.py make font_common.bffnt MyFont.ttf out.bffnt --font-size 22
  python ttf2bffnt_vi.py inspect font_common.bffnt
  python ttf2bffnt_vi.py charset > charset_vi.txt

Ghi chú quan trọng:
- Tool KHÔNG chuyển đổi TTF thành BFFNT hoàn toàn từ số 0; nó dùng .bffnt gốc làm template
  để giữ đúng header/FINF/TGLP/game-specific format, rồi render glyph mới vào texture.
- Tool tự mở rộng CWDH trong phạm vi số ô có sẵn trên texture sheet của template.
- Tool tự ghi CMAP method=2, mapping Unicode -> glyphIndex.
- Template phải có texture alpha 8-bit/tương đương 1 byte/pixel. Với font_common.bffnt mẫu:
  format=8, sheet 256x1024, cell 25x27, 9 cột x 36 dòng = 324 glyph slots.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

try:
    from fontTools.ttLib import TTFont
except Exception:
    TTFont = None


# ----------------------------- Unicode charset -----------------------------

ASCII_PRINTABLE = "".join(chr(i) for i in range(0x20, 0x7F))

# Vietnamese precomposed characters commonly required by Unicode text.
# Includes Latin-1 Vietnamese letters, Latin Extended-A letters, and Latin Extended Additional tone letters.
VIETNAMESE_PRECOMPOSED = (
    "ÀÁÂÃÈÉÊÌÍÒÓÔÕÙÚÝ"
    "àáâãèéêìíòóôõùúý"
    "ĂăĐđĨĩŨũƠơƯư"
    "ẠạẢảẤấẦầẨẩẪẫẬậẮắẰằẲẳẴẵẶặ"
    "ẸẹẺẻẼẽẾếỀềỂểỄễỆệ"
    "ỈỉỊị"
    "ỌọỎỏỐốỒồỔổỖỗỘộỚớỜờỞởỠỡỢợ"
    "ỤụỦủỨứỪừỬửỮữỰự"
    "ỲỳỴỵỶỷỸỹ"
)

# Helpful extra punctuation often appears in Vietnamese UI/dialog text.
DEFAULT_EXTRA = (
    "\u00A0"          # NBSP
    "“”‘’…–—•·"
    "₫"
)

LOW_PUNCT_SHIFT_1 = set(".,;:!?")
LOW_PUNCT_SHIFT_2 = {"…"}

def default_charset() -> str:
    chars = set(ASCII_PRINTABLE) | set(VIETNAMESE_PRECOMPOSED) | set(DEFAULT_EXTRA)
    # Keep ASCII first for compatibility, then everything else by codepoint.
    out = []
    seen = set()
    for ch in ASCII_PRINTABLE:
        if ch not in seen:
            out.append(ch); seen.add(ch)
    for ch in sorted(chars, key=ord):
        if ch not in seen:
            out.append(ch); seen.add(ch)
    return "".join(out)

def load_charset(path: Optional[str]) -> str:
    base = default_charset()
    if not path:
        return base
    data = open(path, "r", encoding="utf-8").read()
    # Accept either raw text or lines like U+1EA0.
    chars: List[str] = []
    for token in data.replace(",", " ").split():
        t = token.strip()
        if not t:
            continue
        if t.upper().startswith("U+"):
            try:
                chars.append(chr(int(t[2:], 16)))
                continue
            except Exception:
                pass
        for ch in t:
            if ch not in "\r\n\t":
                chars.append(ch)
    if not chars:
        # If the file is normal text with spaces, preserve unique visible chars.
        chars = [ch for ch in data if ch not in "\r\n\t"]
    merged = []
    seen = set()
    for ch in base + "".join(chars):
        if ch not in seen:
            merged.append(ch); seen.add(ch)
    return "".join(merged)


# ----------------------------- binary helpers ------------------------------

def detect_endian(b: bytes) -> str:
    if len(b) < 6:
        return "<"
    if struct.unpack_from("<H", b, 4)[0] == 0xFEFF:
        return "<"
    if struct.unpack_from(">H", b, 4)[0] == 0xFEFF:
        return ">"
    return "<"

def u16(b: bytes, off: int, e: str) -> int:
    return struct.unpack_from(e + "H", b, off)[0]

def u32(b: bytes, off: int, e: str) -> int:
    return struct.unpack_from(e + "I", b, off)[0]

def p16(v: int, e: str) -> bytes:
    return struct.pack(e + "H", v & 0xFFFF)

def p32(v: int, e: str) -> bytes:
    return struct.pack(e + "I", v & 0xFFFFFFFF)

def i8(v: int) -> int:
    if v < -128:
        v = -128
    if v > 127:
        v = 127
    return struct.pack("<b", v)[0]

def align4(n: int) -> int:
    return (n + 3) & ~3


# ----------------------------- BFFNT parsing -------------------------------

@dataclass
class Block:
    sig: str
    off: int
    size: int

@dataclass
class Tglp:
    off: int
    size: int
    cell_width: int
    cell_height: int
    sheet_count: int
    max_char_width: int
    sheet_size: int
    baseline_pos: int
    sheet_format: int
    sheet_columns: int
    sheet_rows: int
    sheet_width: int
    sheet_height: int
    sheet_data_offset: int
    sheet_data_abs: int

    @property
    def capacity(self) -> int:
        return self.sheet_count * self.sheet_columns * self.sheet_rows

def parse_blocks(b: bytes) -> Tuple[str, int, int, List[Block]]:
    if b[:4] not in (b"FFNT", b"CFNT"):
        raise ValueError("Không phải FFNT/CFNT BFFNT/BCFNT.")
    e = detect_endian(b)
    header_size = u16(b, 6, e)
    num_blocks = u16(b, 16, e)
    off = header_size
    blocks: List[Block] = []
    for _ in range(num_blocks):
        if off + 8 > len(b):
            raise ValueError("Block table vượt quá kích thước file.")
        sig = b[off:off+4].decode("ascii", errors="replace")
        size = u32(b, off+4, e)
        blocks.append(Block(sig, off, size))
        off += size
    return e, header_size, num_blocks, blocks

def find_block(blocks: Iterable[Block], sig: str) -> Optional[Block]:
    for bl in blocks:
        if bl.sig == sig:
            return bl
    return None

def parse_tglp(b: bytes, bl: Block, e: str) -> Tglp:
    # BFFNT TGLP data starts after block header:
    # u8 cellWidth, u8 cellHeight, u8 sheetCount, u8 maxCharWidth,
    # u32 sheetSize, u16 baselinePos, u16 sheetFormat,
    # u16 sheetColumn, u16 sheetRow, u16 sheetWidth, u16 sheetHeight, u32 sheetDataOffset
    base = bl.off + 8
    cell_w = b[base + 0]
    cell_h = b[base + 1]
    sheet_count = b[base + 2]
    max_char_w = b[base + 3]
    sheet_size = u32(b, base + 4, e)
    baseline = u16(b, base + 8, e)
    fmt = u16(b, base + 10, e)
    cols = u16(b, base + 12, e)
    rows = u16(b, base + 14, e)
    sheet_w = u16(b, base + 16, e)
    sheet_h = u16(b, base + 18, e)
    sheet_off = u32(b, base + 20, e)

    # Nintendo tools may store sheetDataOffset as absolute or relative. Detect safely.
    rel_abs = bl.off + sheet_off
    abs_abs = sheet_off
    if rel_abs + sheet_size * sheet_count <= bl.off + bl.size:
        sheet_abs = rel_abs
    elif abs_abs + sheet_size * sheet_count <= len(b):
        sheet_abs = abs_abs
    else:
        raise ValueError("Không xác định được vị trí sheet data trong TGLP.")

    return Tglp(
        off=bl.off, size=bl.size,
        cell_width=cell_w, cell_height=cell_h, sheet_count=sheet_count,
        max_char_width=max_char_w, sheet_size=sheet_size, baseline_pos=baseline,
        sheet_format=fmt, sheet_columns=cols, sheet_rows=rows,
        sheet_width=sheet_w, sheet_height=sheet_h,
        sheet_data_offset=sheet_off, sheet_data_abs=sheet_abs
    )

def locate_finf_pointer_fields(b: bytes, blocks: List[Block], e: str) -> Tuple[int, int, int]:
    finf = find_block(blocks, "FINF")
    tglp = find_block(blocks, "TGLP")
    cwdh = find_block(blocks, "CWDH")
    cmap = find_block(blocks, "CMAP")
    if not (finf and tglp and cwdh and cmap):
        raise ValueError("Template thiếu FINF/TGLP/CWDH/CMAP.")

    wanted = {
        "tglp": tglp.off + 8,
        "cwdh": cwdh.off + 8,
        "cmap": cmap.off + 8,
    }
    found: Dict[str, int] = {}
    data_start = finf.off + 8
    data_end = finf.off + finf.size
    for pos in range(data_start, data_end - 3, 4):
        val = u32(b, pos, e)
        for name, target in wanted.items():
            if val == target:
                found[name] = pos
    if set(found) != {"tglp", "cwdh", "cmap"}:
        raise ValueError("Không tìm được đủ pointer TGLP/CWDH/CMAP trong FINF.")
    return found["tglp"], found["cwdh"], found["cmap"]


# ----------------------------- texture swizzle -----------------------------

def morton3(x: int, y: int) -> int:
    r = 0
    for i in range(3):
        r |= ((x >> i) & 1) << (2*i)
        r |= ((y >> i) & 1) << (2*i + 1)
    return r

def swizzle_a8_tile8_morton(a8_linear: bytes, w: int, h: int) -> bytes:
    if w % 8 or h % 8:
        raise ValueError("A8 tile8 yêu cầu sheetWidth/sheetHeight chia hết cho 8.")
    tiles_x = w // 8
    out = bytearray(w * h)
    for y in range(h):
        ty, iy = divmod(y, 8)
        for x in range(w):
            tx, ix = divmod(x, 8)
            tile_base = (ty * tiles_x + tx) * 64
            out[tile_base + morton3(ix, iy)] = a8_linear[y*w + x]
    return bytes(out)

def unswizzle_a8_tile8_morton(raw: bytes, w: int, h: int) -> bytes:
    if w % 8 or h % 8:
        raise ValueError("A8 tile8 yêu cầu sheetWidth/sheetHeight chia hết cho 8.")
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


# ----------------------------- CWDH / CMAP build ---------------------------

def build_cwdh_block(metrics: List[Tuple[int, int, int]], e: str) -> bytes:
    # One continuous CWDH block, glyphIndex 0..N-1.
    # Header: 'CWDH', size, startIndex, endIndex, nextCWDHPtr, entries...
    n = len(metrics)
    if n <= 0 or n > 0xFFFF:
        raise ValueError("Số glyph không hợp lệ.")
    raw_size = 0x10 + n * 3
    size = align4(raw_size)
    out = bytearray()
    out += b"CWDH"
    out += p32(size, e)
    out += p16(0, e)
    out += p16(n - 1, e)
    out += p32(0, e)  # next CWDH base = 0
    for left, glyph_w, char_w in metrics:
        out.append(i8(left))
        out.append(max(0, min(255, int(glyph_w))))
        out.append(max(0, min(255, int(char_w))))
    out += b"\x00" * (size - len(out))
    return bytes(out)

def build_cmap_scan_block(code_to_glyph: Dict[int, int], e: str) -> bytes:
    items = sorted(code_to_glyph.items(), key=lambda kv: kv[0])
    if len(items) > 0xFFFF:
        raise ValueError("CMAP method=2 chỉ hỗ trợ tối đa 65535 pairs.")

    # BFFNT CMAP method=2 layout is:
    #   block header 0x14 bytes
    #   u16 pairCount
    #   repeated pairCount times: u16 codepoint, u16 glyphIndex
    #   padding to 4-byte boundary
    # There is NOT an extra reserved u16 after pairCount. Adding that reserved field
    # shifts every pair by 2 bytes and causes in-game text to show wrong glyphs.
    raw_size = 0x16 + len(items) * 4
    size = align4(raw_size)
    out = bytearray()
    out += b"CMAP"
    out += p32(size, e)
    out += p16(0x0000, e)
    out += p16(0xFFFF, e)
    out += p16(2, e)  # scan mapping
    out += p16(0, e)
    out += p32(0, e)  # no next CMAP
    out += p16(len(items), e)
    for code, gi in items:
        out += p16(code, e)
        out += p16(gi, e)
    out += b"\x00" * (size - len(out))
    return bytes(out)


# ----------------------------- glyph rendering -----------------------------

def font_supports(font_path: str, ch: str) -> bool:
    if TTFont is None:
        return True
    try:
        tt = TTFont(font_path, lazy=True)
        cmap = {}
        for table in tt["cmap"].tables:
            cmap.update(table.cmap)
        tt.close()
        return ord(ch) in cmap
    except Exception:
        return True

def supported_charset(font_path: str, charset: str, strict: bool) -> Tuple[str, List[str]]:
    if TTFont is None:
        return charset, []
    try:
        tt = TTFont(font_path, lazy=True)
        cmap = {}
        for table in tt["cmap"].tables:
            cmap.update(table.cmap)
        tt.close()
        ok = []
        missing = []
        for ch in charset:
            if ord(ch) in cmap or ch == " ":
                ok.append(ch)
            else:
                missing.append(ch)
        if strict and missing:
            sample = " ".join(f"U+{ord(c):04X}({c})" for c in missing[:30])
            raise ValueError(f"TTF thiếu {len(missing)} ký tự. Ví dụ: {sample}")
        return "".join(ok), missing
    except ValueError:
        raise
    except Exception:
        return charset, []

def choose_font_size(font_path: str, cell_w: int, cell_h: int, baseline_pos: int, charset: str) -> int:
    # Conservative auto fit: keep Vietnamese accents inside cell height.
    # Try from large to small and accept when tall glyphs fit.
    probe = "ÂĂÊÔƠƯẤẮỆỘỰỸỹỳgjpQ"
    probe = "".join(ch for ch in probe if ch in charset) or "Agjp"
    for size in range(max(6, cell_h + 10), 5, -1):
        font = ImageFont.truetype(font_path, size=size)
        asc, desc = font.getmetrics()
        top = max((font.getbbox(ch)[1] for ch in probe), default=0)
        bottom = min((font.getbbox(ch)[3] for ch in probe), default=0)
        # In PIL bbox relative to anchor default, usually y can be positive. Use actual ink height.
        max_h = 0
        max_w = 0
        for ch in probe:
            bb = font.getbbox(ch)
            max_h = max(max_h, bb[3] - bb[1])
            max_w = max(max_w, bb[2] - bb[0])
        if max_h <= cell_h - 2 and max_w <= cell_w + 8:
            return size
    return max(6, cell_h - 6)

def render_sheet(
    font_path: str,
    tglp: Tglp,
    charset: str,
    font_size: Optional[int],
    x_offset: int = 0,
    y_offset: int = 0,
    antialias: bool = True,
) -> Tuple[bytes, List[Tuple[int, int, int]], Dict[int, int], Image.Image]:
    if len(charset) > tglp.capacity:
        raise ValueError(
            f"Charset có {len(charset)} ký tự nhưng template chỉ có {tglp.capacity} ô "
            f"({tglp.sheet_columns}x{tglp.sheet_rows}x{tglp.sheet_count}). "
            "Hãy dùng template lớn hơn hoặc giảm charset."
        )

    size = font_size or choose_font_size(font_path, tglp.cell_width, tglp.cell_height, tglp.baseline_pos, charset)
    font = ImageFont.truetype(font_path, size=size)
    asc, desc = font.getmetrics()

    sheet = Image.new("L", (tglp.sheet_width, tglp.sheet_height), 0)
    draw = ImageDraw.Draw(sheet)

    metrics: List[Tuple[int, int, int]] = []
    code_to_glyph: Dict[int, int] = {}

    for gi, ch in enumerate(charset):
        sheet_i = gi // (tglp.sheet_columns * tglp.sheet_rows)
        gi_in_sheet = gi % (tglp.sheet_columns * tglp.sheet_rows)
        row = gi_in_sheet // tglp.sheet_columns
        col = gi_in_sheet % tglp.sheet_columns

        if sheet_i != 0:
            # This tool currently writes only sheet0, but keeps the template sheet_count check.
            # Most 3DS BFFNT templates used here have sheet_count=1.
            raise ValueError("Tool hiện chỉ render trực tiếp sheet_count=1.")

        cell_x = col * tglp.cell_width
        cell_y = row * tglp.cell_height

        if ch == " " or ch == "\u00A0":
            adv = max(3, int(round(font.getlength(" "))))
            metrics.append((0, 0, min(tglp.cell_width, adv)))
            code_to_glyph[ord(ch)] = gi
            continue

        # Draw glyphs using a baseline anchor so letters stay on the same line,
        # but keep conservative BFFNT metrics to avoid breaking in-game layout.
        bbox = font.getbbox(ch, anchor="ls")
        advance = int(math.ceil(font.getlength(ch)))
        ink_w = max(0, bbox[2] - bbox[0])
        ink_h = max(0, bbox[3] - bbox[1])

        # Horizontal: center the visible ink inside the cell, correcting with bbox[0].
        draw_x = cell_x + max(0, (tglp.cell_width - ink_w) // 2) - bbox[0] + x_offset
        # Vertical: use the template baseline. Move punctuation slightly downward so
        # dots/ellipsis do not float too high.
        punct_shift = 2 if ch in LOW_PUNCT_SHIFT_2 else (1 if ch in LOW_PUNCT_SHIFT_1 else 0)
        draw_y = cell_y + tglp.baseline_pos + y_offset + punct_shift
        draw.text((draw_x, draw_y), ch, font=font, fill=255, anchor="ls")

        left = 0
        # Keep a tiny safety margin so very thin glyphs like lowercase l/I are not lost.
        glyph_w = min(255, max(2, min(tglp.cell_width, ink_w + 1)))
        char_w = min(255, max(2, min(tglp.cell_width, max(advance + 1, ink_w + 1))))
        metrics.append((left, glyph_w, char_w))
        code_to_glyph[ord(ch)] = gi

    # Fill remaining slots with blank metrics to keep CWDH range equal to used glyphs only.
    raw_linear = sheet.tobytes()
    preview = Image.new("RGBA", sheet.size, (255, 255, 255, 0))
    preview.putalpha(sheet)
    return raw_linear, metrics, code_to_glyph, preview


# ----------------------------- rebuild font --------------------------------

def rebuild_from_ttf(
    template_path: str,
    font_path: str,
    out_path: str,
    charset_path: Optional[str] = None,
    font_size: Optional[int] = None,
    x_offset: int = 0,
    y_offset: int = 0,
    strict: bool = False,
    write_preview: bool = True,
) -> Dict[str, object]:
    b = bytearray(open(template_path, "rb").read())
    e, header_size, _num_blocks, blocks = parse_blocks(b)
    finf = find_block(blocks, "FINF")
    tglp_bl = find_block(blocks, "TGLP")
    if not finf or not tglp_bl:
        raise ValueError("Template thiếu FINF hoặc TGLP.")
    tglp = parse_tglp(b, tglp_bl, e)

    if tglp.sheet_count != 1:
        raise ValueError(f"Template có sheet_count={tglp.sheet_count}; bản này chỉ hỗ trợ 1 sheet.")
    if tglp.sheet_format not in (8, 36):
        # 8 is canonical A8; some tools mislabel/encounter equivalent 1-byte alpha format.
        raise ValueError(f"Sheet format {tglp.sheet_format} chưa được hỗ trợ. Cần template A8/1 byte-per-pixel.")

    charset = load_charset(charset_path)
    charset, missing = supported_charset(font_path, charset, strict=strict)

    raw_linear, metrics, cmap, preview = render_sheet(
        font_path=font_path,
        tglp=tglp,
        charset=charset,
        font_size=font_size,
        x_offset=x_offset,
        y_offset=y_offset,
    )

    if len(raw_linear) != tglp.sheet_width * tglp.sheet_height:
        raise RuntimeError("Kích thước sheet render không khớp.")
    raw_swizzled = swizzle_a8_tile8_morton(raw_linear, tglp.sheet_width, tglp.sheet_height)
    if len(raw_swizzled) != tglp.sheet_size:
        raise RuntimeError(
            f"Sheet data sau khi swizzle dài {len(raw_swizzled)} bytes, "
            f"khác sheetSize template {tglp.sheet_size}."
        )

    # Patch TGLP sheet data in-place.
    b[tglp.sheet_data_abs:tglp.sheet_data_abs + tglp.sheet_size] = raw_swizzled

    # Rebuild file with original header + FINF + original TGLP, then new CWDH + new CMAP.
    # Drop old CWDH/CMAP chain because offsets/sizes change.
    header = bytearray(b[:header_size])
    finf_bytes = bytearray(b[finf.off:finf.off + finf.size])
    tglp_bytes = bytearray(b[tglp_bl.off:tglp_bl.off + tglp_bl.size])

    cwdh_block = build_cwdh_block(metrics, e)
    cmap_block = build_cmap_scan_block(cmap, e)

    # Keep normal order: header, FINF, TGLP, CWDH, CMAP.
    out = bytearray()
    out += header
    finf_off = len(out)
    out += finf_bytes
    tglp_off = len(out)
    out += tglp_bytes
    cwdh_off = len(out)
    out += cwdh_block
    cmap_off = len(out)
    out += cmap_block

    # Patch header.
    out[0x0C:0x10] = p32(len(out), e)
    out[0x10:0x12] = p16(4, e)

    # Patch FINF pointer fields.
    # Use old FINF field locations relative to its own block.
    ptr_tglp, ptr_cwdh, ptr_cmap = locate_finf_pointer_fields(bytes(b), blocks, e)
    rel_tglp = ptr_tglp - finf.off
    rel_cwdh = ptr_cwdh - finf.off
    rel_cmap = ptr_cmap - finf.off
    out[finf_off + rel_tglp:finf_off + rel_tglp + 4] = p32(tglp_off + 8, e)
    out[finf_off + rel_cwdh:finf_off + rel_cwdh + 4] = p32(cwdh_off + 8, e)
    out[finf_off + rel_cmap:finf_off + rel_cmap + 4] = p32(cmap_off + 8, e)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(bytes(out))

    meta = {
        "template": os.path.basename(template_path),
        "ttf": os.path.basename(font_path),
        "output": os.path.basename(out_path),
        "glyph_count": len(metrics),
        "missing_count": len(missing),
        "missing": [f"U+{ord(ch):04X} {ch}" for ch in missing],
        "cell_width": tglp.cell_width,
        "cell_height": tglp.cell_height,
        "sheet_width": tglp.sheet_width,
        "sheet_height": tglp.sheet_height,
        "sheet_columns": tglp.sheet_columns,
        "sheet_rows": tglp.sheet_rows,
        "capacity": tglp.capacity,
        "font_size": font_size or "auto",
    }
    meta_path = os.path.splitext(out_path)[0] + "_build.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    if write_preview:
        preview_path = os.path.splitext(out_path)[0] + "_sheet0.png"
        preview.save(preview_path)

    return meta


def inspect_font(path: str) -> Dict[str, object]:
    b = open(path, "rb").read()
    e, header_size, num_blocks, blocks = parse_blocks(b)
    tglp_bl = find_block(blocks, "TGLP")
    tglp_info = None
    if tglp_bl:
        t = parse_tglp(b, tglp_bl, e)
        tglp_info = {
            "cell_width": t.cell_width,
            "cell_height": t.cell_height,
            "sheet_count": t.sheet_count,
            "max_char_width": t.max_char_width,
            "sheet_size": t.sheet_size,
            "baseline_pos": t.baseline_pos,
            "sheet_format": t.sheet_format,
            "sheet_columns": t.sheet_columns,
            "sheet_rows": t.sheet_rows,
            "sheet_width": t.sheet_width,
            "sheet_height": t.sheet_height,
            "capacity": t.capacity,
            "sheet_data_abs": t.sheet_data_abs,
        }
    return {
        "file": os.path.basename(path),
        "size": len(b),
        "endian": "LE" if e == "<" else "BE",
        "header_size": header_size,
        "num_blocks": num_blocks,
        "blocks": [{"sig": bl.sig, "off": bl.off, "size": bl.size} for bl in blocks],
        "tglp": tglp_info,
    }


# ----------------------------- CLI -----------------------------------------

def cmd_make(args: argparse.Namespace) -> None:
    meta = rebuild_from_ttf(
        template_path=args.template,
        font_path=args.ttf,
        out_path=args.output,
        charset_path=args.charset,
        font_size=args.font_size,
        x_offset=args.x_offset,
        y_offset=args.y_offset,
        strict=args.strict,
        write_preview=not args.no_preview,
    )
    print("OK:", args.output)
    print(f"- glyphs: {meta['glyph_count']}/{meta['capacity']}")
    print(f"- cell: {meta['cell_width']}x{meta['cell_height']}; sheet: {meta['sheet_width']}x{meta['sheet_height']}")
    print(f"- build meta: {os.path.splitext(args.output)[0]}_build.json")
    if not args.no_preview:
        print(f"- preview: {os.path.splitext(args.output)[0]}_sheet0.png")
    if meta["missing_count"]:
        print(f"[WARN] TTF thiếu {meta['missing_count']} ký tự; đã bỏ qua. Xem file *_build.json.")

def cmd_inspect(args: argparse.Namespace) -> None:
    print(json.dumps(inspect_font(args.bffnt), ensure_ascii=False, indent=2))

def cmd_charset(args: argparse.Namespace) -> None:
    cs = default_charset()
    if args.as_codepoints:
        for ch in cs:
            print(f"U+{ord(ch):04X}\t{ch}")
    else:
        print(cs)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="TTF/OTF -> BFFNT tiếng Việt bằng template BFFNT.")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("make", help="Render TTF vào template BFFNT và xuất BFFNT mới.")
    m.add_argument("template", help="File .bffnt/.bcfnt gốc dùng làm template.")
    m.add_argument("ttf", help="File .ttf/.otf nguồn.")
    m.add_argument("output", help="File .bffnt xuất ra.")
    m.add_argument("--charset", help="File charset bổ sung/tùy chỉnh. Mặc định đã gồm full tiếng Việt.")
    m.add_argument("--font-size", type=int, help="Cỡ font pixel. Không nhập thì auto-fit theo cell.")
    m.add_argument("--x-offset", type=int, default=0, help="Dịch glyph theo trục X trong ô.")
    m.add_argument("--y-offset", type=int, default=0, help="Dịch glyph theo trục Y trong ô.")
    m.add_argument("--strict", action="store_true", help="Báo lỗi nếu TTF thiếu ký tự trong charset.")
    m.add_argument("--no-preview", action="store_true", help="Không xuất file PNG preview sheet.")
    m.set_defaults(func=cmd_make)

    i = sub.add_parser("inspect", help="Xem thông tin template BFFNT.")
    i.add_argument("bffnt")
    i.set_defaults(func=cmd_inspect)

    c = sub.add_parser("charset", help="In charset tiếng Việt mặc định.")
    c.add_argument("--as-codepoints", action="store_true")
    c.set_defaults(func=cmd_charset)

    return p


def _ask_path(prompt: str, default: Optional[str] = None, must_exist: bool = True) -> str:
    while True:
        label = prompt + (f" [{default}]" if default else "")
        value = input(label + ": ").strip().strip('"').strip("'")
        if not value and default:
            value = default
        value = os.path.expanduser(value)
        if not value:
            print("Vui lòng nhập đường dẫn.")
            continue
        if must_exist and not os.path.isfile(value):
            print("Không tìm thấy file:", value)
            continue
        return value


def _ask_int(prompt: str, default: Optional[int] = None, min_value: Optional[int] = None, max_value: Optional[int] = None) -> Optional[int]:
    while True:
        label = prompt + (f" [{default}]" if default is not None else "")
        value = input(label + ": ").strip()
        if not value:
            return default
        try:
            n = int(value)
        except ValueError:
            print("Vui lòng nhập số nguyên.")
            continue
        if min_value is not None and n < min_value:
            print(f"Giá trị phải >= {min_value}.")
            continue
        if max_value is not None and n > max_value:
            print(f"Giá trị phải <= {max_value}.")
            continue
        return n


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    value = input(prompt + suffix + ": ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes", "c", "co", "có", "ok", "1")


def interactive_menu() -> int:
    print("=== TTF/OTF -> BFFNT tiếng Việt ===")
    print("Chạy nhanh: nhập TTF, size chữ và tên file muốn lưu.\n")

    here = os.path.dirname(os.path.abspath(__file__))
    default_template = os.path.join(here, "font_common.bffnt")
    if not os.path.isfile(default_template):
        cwd_template = os.path.abspath("font_common.bffnt")
        default_template = cwd_template if os.path.isfile(cwd_template) else None

    if default_template and _ask_yes_no("Dùng template mặc định font_common.bffnt không?", True):
        template = default_template
    else:
        template = _ask_path("Nhập đường dẫn file .bffnt/.bcfnt mẫu")

    ttf = _ask_path("Nhập đường dẫn file .ttf/.otf")

    suggested_size = None
    try:
        info = inspect_font(template)
        t = info.get("tglp") or {}
        if t:
            print(f"Template: cell {t.get('cell_width')}x{t.get('cell_height')}, sức chứa {t.get('capacity')} glyph.")
        cell_h = int(t.get("cell_height") or 0)
        if cell_h:
            suggested_size = max(8, cell_h - 5)
    except Exception as exc:
        print("[WARN] Không đọc được template:", exc)

    font_size = _ask_int("Nhập size chữ pixel, bỏ trống để auto-fit", suggested_size, 1, 255)
    x_offset = _ask_int("Dịch ngang x-offset, bỏ trống = 0", 0, -128, 128)
    y_offset = _ask_int("Dịch dọc y-offset, bỏ trống = 0", 0, -128, 128)

    default_out = os.path.splitext(os.path.basename(ttf))[0] + "_vi.bffnt"
    out = _ask_path("Nhập tên/đường dẫn file muốn lưu", default_out, must_exist=False)
    if not os.path.splitext(out)[1]:
        out += ".bffnt"

    charset_path = None
    if _ask_yes_no("Có dùng file charset riêng không?", False):
        charset_path = _ask_path("Nhập đường dẫn charset .txt")

    strict = _ask_yes_no("Báo lỗi nếu TTF thiếu ký tự?", False)
    write_preview = _ask_yes_no("Xuất ảnh preview sheet0 PNG?", True)

    try:
        meta = rebuild_from_ttf(
            template_path=template,
            font_path=ttf,
            out_path=out,
            charset_path=charset_path,
            font_size=font_size,
            x_offset=x_offset or 0,
            y_offset=y_offset or 0,
            strict=strict,
            write_preview=write_preview,
        )
    except Exception as exc:
        print("[ERROR] Build thất bại:", exc)
        return 1

    print("\nOK:", out)
    print(f"- glyphs: {meta['glyph_count']}/{meta['capacity']}")
    print(f"- cell: {meta['cell_width']}x{meta['cell_height']}; sheet: {meta['sheet_width']}x{meta['sheet_height']}")
    print(f"- build meta: {os.path.splitext(out)[0]}_build.json")
    if write_preview:
        print(f"- preview: {os.path.splitext(out)[0]}_sheet0.png")
    if meta.get("missing_count"):
        print(f"[WARN] TTF thiếu {meta['missing_count']} ký tự; xem *_build.json.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return interactive_menu()
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
