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
        # scan: u16 numPairs, u16 reserved, then pairs (u16 code, u16 glyphIndex)
        if len(p) < 4:
            return m
        num = struct.unpack_from(e+"H", p, 0)[0]
        base = 4
        for i in range(num):
            q = base + i*4
            if q+4 > len(p):
                break
            code = struct.unpack_from(e+"H", p, q+0)[0]
            gi   = struct.unpack_from(e+"H", p, q+2)[0]
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
    with open(out_path, "wb") as f:
        f.write(b)

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
    # CMAP block (scan method)
    # code range: 0x0000..0xFFFF
    payload = bytearray()
    payload += p16(num, e)
    payload += p16(0, e)
    for code, gi in items:
        payload += p16(code, e)
        payload += p16(gi, e)
    size = 0x18 + 4*num
    out = bytearray()
    out += b"CMAP"
    out += p32(size, e)
    out += p16(0x0000, e)
    out += p16(0xFFFF, e)
    out += p16(2, e)       # method 2 = scan
    out += p16(0, e)
    out += p32(next_base, e)  # nextBase points to next CMAP DATA BASE
    out += payload
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
    with open(out_path, "wb") as f:
        f.write(b)

    print("OK REMAP/EXTEND CMAP:", out_path)
    print(f" - Added {len(overrides)} entries by prepending a new scan-CMAP (method=2).")
    return out_path

# ------------------ export/import main (sheet + metrics + cmap) ------------------

def export_bffnt(in_path: str):
    b = open(in_path, "rb").read()
    e, header_size, num_blocks, blocks = parse_blocks(b)

    tglp = find_block(blocks, "TGLP")
    if not tglp:
        raise RuntimeError("TGLP not found")
    _, tglp_off, tglp_size = tglp

    t = parse_tglp_and_sheet(b, tglp_off, tglp_size, e)
    w, h = t["sheetWidth"], t["sheetHeight"]
    raw = t["rawSheet"]

    # decode A8
    a8_linear = unswizzle_a8_tile8_morton(raw, w, h)
    png = make_transparent_png_from_a8(a8_linear, w, h)
    grid = make_grid_png(w, h, t["cellWidth"], t["cellHeight"], line_alpha=96)

    cwdh_descs = parse_cwdh_blocks(b, blocks, e)
    metrics = dump_metrics(b, cwdh_descs, e)

    base = os.path.splitext(os.path.basename(in_path))[0]
    out_dir = os.path.join(os.path.dirname(in_path), base + "_out")
    os.makedirs(out_dir, exist_ok=True)

    out_png   = os.path.join(out_dir, "sheet0.png")
    out_grid  = os.path.join(out_dir, "grid.png")
    out_json  = os.path.join(out_dir, "glyph_metrics.json")
    out_meta  = os.path.join(out_dir, "meta.json")

    png.save(out_png)
    grid.save(out_grid)

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

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
        "sheetSize": t["sheetSize"],
        "sheetDataAbs": t["sheetDataAbs"],
        "sheetDataOffset": t["sheetDataOffset"],
        "cwdhRanges": [{"start": d["start"], "end": d["end"], "off": d["off"], "size": d["size"]} for d in cwdh_descs],
    }
    with open(out_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    # export CMAPs
    all_path, blocks_path, n_entries, first_base = export_cmaps(b, blocks, out_dir, e)
    # build glyph_table.json (metrics + codes per glyph)
    glyph_table = build_glyph_table(metrics, os.path.join(out_dir, "cmap_all.json"))
    with open(os.path.join(out_dir, "glyph_table.json"), "w", encoding="utf-8") as f:
        json.dump(glyph_table, f, ensure_ascii=False, indent=2)


    print("OK EXPORT:", out_dir)
    print(" - sheet0.png (glyph)")
    print(" - grid.png (empty grid)")
    print(" - glyph_metrics.json")
    print(" - meta.json")
    print(f" - cmap_all.json ({n_entries} entries)")
    print(" - cmap_blocks.json (list chain)")
    print(" - glyph_table.json (metrics + codes per glyph)")

def import_bffnt(in_path: str, folder: str):
    b = bytearray(open(in_path, "rb").read())
    e, header_size, num_blocks, blocks = parse_blocks(b)

    tglp = find_block(blocks, "TGLP")
    if not tglp:
        raise RuntimeError("TGLP not found")
    _, tglp_off, tglp_size = tglp
    t = parse_tglp_and_sheet(b, tglp_off, tglp_size, e)
    w, h = t["sheetWidth"], t["sheetHeight"]

    png_path = os.path.join(folder, "sheet0.png")
    metrics_path = os.path.join(folder, "glyph_metrics.json")

    if not os.path.isfile(png_path):
        raise FileNotFoundError("Missing: " + png_path)
    if not os.path.isfile(metrics_path):
        raise FileNotFoundError("Missing: " + metrics_path)

    # Patch sheet
    a8_linear = rgba_png_to_a8_linear(png_path, w, h)
    raw_swz = swizzle_a8_tile8_morton(a8_linear, w, h)
    abs_off = t["sheetDataAbs"]
    if abs_off + len(raw_swz) > len(b):
        raise RuntimeError("Sheet data out of file range")
    b[abs_off:abs_off + len(raw_swz)] = raw_swz

    # Patch metrics
    cwdh_descs = parse_cwdh_blocks(b, blocks, e)
    metrics = json.load(open(metrics_path, "r", encoding="utf-8"))
    apply_metrics_patch(b, cwdh_descs, metrics, e)

    root, ext = os.path.splitext(in_path)
    out_path = root + "_new" + ext
    with open(out_path, "wb") as f:
        f.write(b)

    print("OK IMPORT:", out_path)
    print("(CMAP không đổi trong chế độ import. Nếu cần remap/extend cmap, dùng lệnh/menu Remap.)")

# ------------------ CLI/menu ------------------

def menu():
    print("=== BFFNT Tool v2 (Export/Import/CMAP) ===")
    print("1) Xuất: sheet0.png + grid.png + glyph_metrics.json + cmap_all.json")
    print("2) Nhập: patch sheet0.png + glyph_metrics.json -> *_new.bffnt (bỏ qua grid.png)")
    print("3) Xuất CMAP-only (cmap_all.json + cmap_blocks.json)")
    print("4) Remap/Extend CMAP: dùng map.txt (prepend scan CMAP) -> *_cmap_new.bffnt")
    choice = input("Chọn (1/2/3/4): ").strip()

    if choice == "1":
        in_path = input("Nhập đường dẫn .bffnt: ").strip().strip('"')
        export_bffnt(in_path)

    elif choice == "2":
        in_path = input("Nhập đường dẫn .bffnt gốc: ").strip().strip('"')
        folder = input("Nhập thư mục chứa sheet0.png + glyph_metrics.json: ").strip().strip('"')
        import_bffnt(in_path, folder)

    elif choice == "3":
        in_path = input("Nhập đường dẫn .bffnt: ").strip().strip('"')
        b = open(in_path, "rb").read()
        e, _, _, blocks = parse_blocks(b)
        base = os.path.splitext(os.path.basename(in_path))[0]
        out_dir = os.path.join(os.path.dirname(in_path), base + "_out")
        all_path, blocks_path, n_entries, _ = export_cmaps(b, blocks, out_dir, e)
        print("OK EXPORT CMAP:", out_dir)
        print(f" - cmap_all.json ({n_entries} entries)")
        print(" - cmap_blocks.json")

    elif choice == "4":
        in_path = input("Nhập đường dẫn .bffnt gốc: ").strip().strip('"')
        map_path = input("Nhập đường dẫn map.txt (mỗi dòng: SRC_HEX DST_HEX): ").strip().strip('"')
        remap_cmap_prepend(in_path, map_path)

    elif choice == "5":
        in_path = input("Nhập đường dẫn .bffnt gốc: ").strip().strip('"')
        tab_path = input("Nhập đường dẫn glyph_table.json: ").strip().strip('"')
        apply_cmap_from_glyph_table(in_path, tab_path)

    else:
        print("Hủy.")

def main(argv):
    if len(argv) <= 1:
        return menu()

    cmd = argv[1].lower()
    if cmd == "export" and len(argv) >= 3:
        return export_bffnt(argv[2])
    if cmd == "import" and len(argv) >= 4:
        return import_bffnt(argv[2], argv[3])
    if cmd == "remap" and len(argv) >= 4:
        return remap_cmap_prepend(argv[2], argv[3])
    if cmd in ("cmaptab","applycmap") and len(argv) >= 4:
        return apply_cmap_from_glyph_table(argv[2], argv[3])

    print("Usage:")
    print("  python bffnttool_v3.py")
    print("  python bffnttool_v3.py export <font.bffnt>")
    print("  python bffnttool_v3.py import <font.bffnt> <folder_out>")
    print("  python bffnttool_v3.py remap  <font.bffnt> <map.txt>")
    sys.exit(2)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        print("[ERROR]", e)
        sys.exit(1)
