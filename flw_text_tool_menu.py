#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import struct
import unicodedata
from bisect import bisect_right
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ASCII_LABEL_RE = re.compile(rb'[A-Z0-9_]{6,}')
TXT_HEADER_RE = re.compile(r'^\[(\d{4,})\]\s+offset=0x([0-9A-Fa-f]+)(?:\s+label=(.+))?$')

# Các giá trị này trong biến thể FLW hiện tại là opcode/flag rất hay bị nhầm là pointer.
NON_POINTER_VALUES = {
    0x000007D0,
    0x000007D5,
    0x000007DD,
    0x00000800,
}


def is_useful_char(ch: str) -> bool:
    if ch in "\r\n\t":
        return True
    if ch == "\x00":
        return False
    cat = unicodedata.category(ch)
    if cat.startswith(('L', 'N', 'P', 'S')):
        return True
    if cat == 'Zs':
        return True
    return False


def text_score(text: str) -> float:
    if not text:
        return 0.0
    useful = sum(1 for ch in text if is_useful_char(ch))
    return useful / len(text)


def looks_like_ascii_label_blob(blob: bytes) -> bool:
    if not blob:
        return False
    ascii_printable = sum(1 for b in blob if 0x20 <= b <= 0x7E)
    zeros = blob.count(0)
    ascii_ratio = ascii_printable / len(blob)
    zero_ratio = zeros / len(blob)
    return ascii_ratio > 0.80 and zero_ratio < 0.20


def clean_text(text: str) -> str:
    text = text.replace('\ufeff', '')
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text.strip('\n')


def find_utf16_terminator(data: bytes, start: int) -> int:
    for pos in range(start, len(data) - 1, 2):
        if data[pos:pos + 2] == b"\x00\x00":
            return pos
    return -1


def find_nearest_label(data: bytes, start: int, window: int = 0x80) -> str:
    left = max(0, start - window)
    chunk = data[left:start]
    matches = list(ASCII_LABEL_RE.finditer(chunk))
    if not matches:
        return ''

    preferred = []
    for m in matches:
        raw = m.group().decode('ascii', errors='ignore')
        if (raw.startswith(('EV', 'MM_', 'MSG_', 'SCN_', 'V_')) or '_' in raw) and raw[:1].isalpha():
            preferred.append(raw)
    if preferred:
        return preferred[-1]
    return ''


def remove_overlaps(entries: List[dict]) -> List[dict]:
    if not entries:
        return []

    entries = sorted(entries, key=lambda x: (x['offset'], -(x['end'] - x['offset'])))
    out = []
    current_end = -1
    for e in entries:
        if e['offset'] < current_end:
            continue
        out.append(e)
        current_end = e['end'] + 2
    return out


def extract_utf16_strings(data: bytes, min_chars: int = 4) -> List[dict]:
    entries = []
    size = len(data)

    for i in range(0, size - 4, 2):
        end = find_utf16_terminator(data, i)
        if end == -1 or end <= i:
            continue

        blob = data[i:end]
        if len(blob) < min_chars * 2 or (len(blob) % 2) != 0:
            continue
        if looks_like_ascii_label_blob(blob):
            continue

        try:
            text = blob.decode('utf-16le')
        except UnicodeDecodeError:
            continue

        text = clean_text(text)
        if len(text) < min_chars:
            continue
        if text_score(text) < 0.92:
            continue
        if len(set(text)) == 1 and len(text) > 4:
            continue

        entries.append({
            'offset': i,
            'end': end,
            'label': find_nearest_label(data, i),
            'text': text,
        })

    deduped = []
    for e in entries:
        contained = False
        for other in entries:
            if other is e:
                continue
            if other['end'] == e['end'] and other['offset'] < e['offset']:
                contained = True
                break
        if not contained:
            deduped.append(e)

    out = []
    seen = set()
    for e in deduped:
        key = (e['offset'], e['text'])
        if key in seen:
            continue
        seen.add(key)
        out.append(e)

    out.sort(key=lambda x: x['offset'])
    out = remove_overlaps(out)
    return out


def save_txt(src_path: Path, out_path: Path, entries: List[dict]) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8-sig', newline='\n') as f:
        f.write(f'# Source: {src_path.name}\n')
        f.write(f'# Entries: {len(entries)}\n\n')
        for idx, e in enumerate(entries):
            f.write(f'[{idx:04d}] offset=0x{e["offset"]:X}')
            if e['label']:
                f.write(f' label={e["label"]}')
            f.write('\n')
            f.write(e['text'])
            f.write('\n\n')
    return out_path


def parse_txt_entries(txt_path: Path) -> List[dict]:
    raw = txt_path.read_text(encoding='utf-8-sig')
    lines = raw.replace('\r\n', '\n').replace('\r', '\n').split('\n')

    entries = []
    current = None
    buf: List[str] = []

    def flush_current():
        nonlocal current, buf
        if current is None:
            return
        text = '\n'.join(buf).strip('\n')
        current['text'] = text
        entries.append(current)
        current = None
        buf = []

    for line in lines:
        m = TXT_HEADER_RE.match(line)
        if m:
            flush_current()
            current = {
                'index': int(m.group(1)),
                'offset': int(m.group(2), 16),
                'label': (m.group(3) or '').strip(),
            }
            buf = []
            continue

        if current is None:
            continue
        buf.append(line)

    flush_current()
    return entries


def encode_text_utf16le(text: str) -> bytes:
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text.encode('utf-16le') + b'\x00\x00'


def remap_pos(old_pos: int, shift_points: List[Tuple[int, int]]) -> int:
    boundaries = [p for p, _ in shift_points]
    idx = bisect_right(boundaries, old_pos)
    if idx == 0:
        return old_pos
    return old_pos + shift_points[idx - 1][1]


def is_inside_any_range(pos: int, ranges: List[Tuple[int, int]]) -> bool:
    for a, b in ranges:
        if a <= pos < b:
            return True
    return False


def collect_pointer_candidates(data: bytes, original_entries: List[dict]) -> List[Tuple[int, int]]:
    """
    Heuristic an toàn hơn cho biến thể FLW này:
    - không quét bên trong vùng text
    - bỏ các opcode/flag hay bị nhầm là pointer
    - chỉ nhận giá trị chẵn (byte offset hợp lý)
    """
    text_ranges = [(e['offset'], e['end'] + 2) for e in original_entries]
    first_text = min(e['offset'] for e in original_entries)
    file_size = len(data)
    out: List[Tuple[int, int]] = []

    for pos in range(0, len(data) - 3, 4):
        if is_inside_any_range(pos, text_ranges):
            continue

        val = struct.unpack_from('<I', data, pos)[0]
        if val in NON_POINTER_VALUES:
            continue
        if val < first_text or val > file_size:
            continue
        if (val % 2) != 0:
            continue
        out.append((pos, val))
    return out


def build_repacked_file(data: bytes, original_entries: List[dict], replacement_map: Dict[int, str]) -> Tuple[bytes, List[Tuple[int, int]], List[dict]]:
    out = bytearray()
    cursor = 0
    cumulative_delta = 0
    shift_points: List[Tuple[int, int]] = []
    applied_info: List[dict] = []

    for e in original_entries:
        start = e['offset']
        end_exclusive = e['end'] + 2
        old_blob = data[start:end_exclusive]
        new_text = replacement_map.get(start, e['text'])
        new_blob = old_blob if new_text == e['text'] else encode_text_utf16le(new_text)

        out.extend(data[cursor:start])
        out.extend(new_blob)

        raw_delta = len(new_blob) - len(old_blob)
        cumulative_delta += raw_delta
        if raw_delta:
            shift_points.append((end_exclusive, cumulative_delta))

        applied_info.append({
            'offset': start,
            'old_len': len(old_blob),
            'new_len': len(new_blob),
            'delta': raw_delta,
            'old_text': e['text'],
            'new_text': new_text,
        })
        cursor = end_exclusive

    out.extend(data[cursor:])
    return bytes(out), shift_points, applied_info


def apply_pointer_patch(original_data: bytes, new_data: bytes, original_entries: List[dict], shift_points: List[Tuple[int, int]]) -> Tuple[bytes, int]:
    patched = bytearray(new_data)
    candidates = collect_pointer_candidates(original_data, original_entries)
    patched_count = 0

    for old_pos, old_val in candidates:
        new_pos = remap_pos(old_pos, shift_points)
        if new_pos + 4 > len(patched):
            continue

        if old_val == len(original_data):
            new_val = len(new_data)
        else:
            new_val = remap_pos(old_val, shift_points)

        struct.pack_into('<I', patched, new_pos, new_val)
        patched_count += 1

    return bytes(patched), patched_count


def import_one_flw(src_flw: Path, txt_flw: Path, out_flw: Path) -> Tuple[bool, str]:
    try:
        data = src_flw.read_bytes()
        original_entries = extract_utf16_strings(data)
        if not original_entries:
            return False, f'[SKIP] {src_flw.name}: không tìm thấy text UTF-16 phù hợp'

        txt_entries = parse_txt_entries(txt_flw)
        if not txt_entries:
            return False, f'[SKIP] {txt_flw.name}: TXT không có entry hợp lệ'

        original_offsets = {e['offset'] for e in original_entries}
        replacement_map: Dict[int, str] = {}
        used = 0
        unknown_offsets = []

        for te in txt_entries:
            off = te['offset']
            if off not in original_offsets:
                unknown_offsets.append(off)
                continue
            replacement_map[off] = te['text']
            used += 1

        new_data, shift_points, applied_info = build_repacked_file(data, original_entries, replacement_map)
        new_data, patched_count = apply_pointer_patch(data, new_data, original_entries, shift_points)

        out_flw.parent.mkdir(parents=True, exist_ok=True)
        out_flw.write_bytes(new_data)

        changed_entries = sum(1 for x in applied_info if x['old_text'] != x['new_text'])
        delta_total = len(new_data) - len(data)
        msg = (
            f'[OK] {src_flw.name} -> {out_flw.name} | '
            f'used_txt={used}/{len(original_entries)} | changed={changed_entries} | '
            f'delta={delta_total:+d} bytes | patched_ptr={patched_count}'
        )
        if unknown_offsets:
            msg += f' | bỏ qua offset lạ: {len(unknown_offsets)}'
        return True, msg
    except Exception as exc:
        return False, f'[ERR] {src_flw.name}: {exc}'


def collect_flw_files(root: Path) -> List[Path]:
    return sorted(p for p in root.rglob('*') if p.is_file() and p.suffix.lower() == '.flw')


def process_export_folder(folder_str: str) -> Optional[Tuple[Path, int]]:
    src_root = Path(folder_str.strip().strip('"')).resolve()
    if not src_root.exists() or not src_root.is_dir():
        print(f'[ERR] Không tìm thấy thư mục: {src_root}')
        return None

    out_root = src_root.parent / f'{src_root.name}_ex'
    flw_files = collect_flw_files(src_root)
    if not flw_files:
        print(f'[ERR] Không tìm thấy file .flw trong: {src_root}')
        return None

    print(f'\n[INFO] Chế độ XUẤT')
    print(f'[INFO] Nguồn : {src_root}')
    print(f'[INFO] Đích  : {out_root}')
    print(f'[INFO] Số file: {len(flw_files)}\n')

    count = 0
    for src_file in flw_files:
        rel = src_file.relative_to(src_root)
        out_file = out_root / rel.with_suffix(rel.suffix + '.txt')
        data = src_file.read_bytes()
        entries = extract_utf16_strings(data)
        save_txt(src_file, out_file, entries)
        count += 1
        print(f'[OK] {rel} -> {out_file.relative_to(out_root)} | {len(entries)} entries')

    return out_root, count


def process_import_folder(src_folder_str: str, txt_folder_str: str) -> Optional[Tuple[Path, int, int, int]]:
    src_root = Path(src_folder_str.strip().strip('"')).resolve()
    txt_root = Path(txt_folder_str.strip().strip('"')).resolve()

    if not src_root.exists() or not src_root.is_dir():
        print(f'[ERR] Không tìm thấy thư mục gốc FLW: {src_root}')
        return None
    if not txt_root.exists() or not txt_root.is_dir():
        print(f'[ERR] Không tìm thấy thư mục TXT: {txt_root}')
        return None

    out_root = src_root.parent / f'{src_root.name}_new'
    flw_files = collect_flw_files(src_root)
    if not flw_files:
        print(f'[ERR] Không tìm thấy file .flw trong: {src_root}')
        return None

    print(f'\n[INFO] Chế độ NHẬP')
    print(f'[INFO] FLW gốc  : {src_root}')
    print(f'[INFO] TXT sửa  : {txt_root}')
    print(f'[INFO] Xuất mới : {out_root}')
    print(f'[INFO] Số file  : {len(flw_files)}\n')

    ok_count = 0
    skip_count = 0
    err_count = 0

    for src_file in flw_files:
        rel = src_file.relative_to(src_root)
        txt_file = txt_root / rel.with_suffix(rel.suffix + '.txt')
        out_file = out_root / rel

        if not txt_file.exists():
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_bytes(src_file.read_bytes())
            skip_count += 1
            print(f'[COPY] {rel} | không có TXT tương ứng, giữ nguyên file gốc')
            continue

        ok, msg = import_one_flw(src_file, txt_file, out_file)
        print(msg)
        if ok:
            ok_count += 1
        else:
            err_count += 1

    return out_root, ok_count, skip_count, err_count


def print_menu() -> None:
    print('=' * 68)
    print('FLW TEXT TOOL - EXTRACT / IMPORT (FIX V3)')
    print('=' * 68)
    print('1. Xuất text từ thư mục FLW -> thư mục _ex')
    print('2. Nhập TXT vào thư mục FLW gốc -> thư mục _new')
    print('0. Thoát')
    print('=' * 68)


def main() -> None:
    if len(sys.argv) >= 3 and sys.argv[1] == '--export':
        result = process_export_folder(sys.argv[2])
        if result:
            out_root, count = result
            print(f'\n[DONE] Đã xuất {count} file vào: {out_root}')
        return

    if len(sys.argv) >= 4 and sys.argv[1] == '--import':
        result = process_import_folder(sys.argv[2], sys.argv[3])
        if result:
            out_root, ok_count, skip_count, err_count = result
            print(f'\n[DONE] Xuất vào: {out_root}')
            print(f'[DONE] OK={ok_count} | COPY={skip_count} | ERR={err_count}')
        return

    while True:
        print_menu()
        choice = input('Chọn chức năng: ').strip()

        if choice == '1':
            src = input('Nhập thư mục chứa file .flw: ').strip()
            result = process_export_folder(src)
            if result:
                out_root, count = result
                print(f'\n[DONE] Đã xuất {count} file vào: {out_root}\n')
            input('Nhấn Enter để quay lại menu...')

        elif choice == '2':
            src = input('Nhập thư mục gốc chứa file .flw: ').strip()
            txt = input('Nhập thư mục chứa file .txt đã sửa: ').strip()
            result = process_import_folder(src, txt)
            if result:
                out_root, ok_count, skip_count, err_count = result
                print(f'\n[DONE] Xuất vào: {out_root}')
                print(f'[DONE] OK={ok_count} | COPY={skip_count} | ERR={err_count}\n')
            input('Nhấn Enter để quay lại menu...')

        elif choice == '0':
            break
        else:
            print('[ERR] Lựa chọn không hợp lệ.\n')
            input('Nhấn Enter để chọn lại...')


if __name__ == '__main__':
    main()
