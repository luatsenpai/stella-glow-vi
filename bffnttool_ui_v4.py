# BFFNT Glyph UI Editor v4
# Requirements: pip install pillow
# Put this file in the same folder as bffnttool_v3.py, or keep both files from the zip together.
# Usage: python bffnttool_ui_v4.py

import os
import sys
import tempfile
import importlib.util
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from PIL import Image, ImageTk

APP_TITLE = "BFFNT Glyph UI Editor"


def load_core_module():
    """Load bffnttool_v3.py from the same folder as this UI script."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "bffnttool_v3.py"),
        os.path.join(base_dir, "bffnttool_v4.py"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            spec = importlib.util.spec_from_file_location("bffnt_core", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise FileNotFoundError(
        "Không tìm thấy bffnttool_v3.py. Hãy đặt bffnttool_ui.py cùng thư mục với bffnttool_v3.py."
    )


core = load_core_module()


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
    return out


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
        self.row_pitch = 0
        self.sheet_format_id = 8
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
        self.grid_cols = self._detect_grid_cols()
        self.row_pitch = self._detect_row_pitch()
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
        x = (glyph_index % cols) * cw
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

    def set_glyph_image_by_glyph(self, glyph_index: int, glyph_img: Image.Image):
        gi = int(glyph_index)
        rect = self.glyph_rect(gi)
        glyph_img = glyph_img.convert("RGBA")
        if glyph_img.size != (self.cell_w, self.cell_h):
            raise ValueError(f"Glyph size {glyph_img.size} != {(self.cell_w, self.cell_h)}")
        # Replace the whole glyph cell, including transparent pixels, so old pixels are cleared.
        self.sheet_img.paste(glyph_img, rect[:2])
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
        if current_map != self.code_to_glyph:
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

        buttons = ttk.Frame(right)
        buttons.grid(row=2, column=0, sticky="ew")
        for i in range(4):
            buttons.columnconfigure(i, weight=1)
        ttk.Button(buttons, text="Export Glyph", command=self.export_glyph).grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        ttk.Button(buttons, text="Import Glyph", command=self.import_glyph).grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(buttons, text="Reload", command=self.reload_file).grid(row=0, column=2, sticky="ew", padx=4, pady=4)
        ttk.Button(buttons, text="Save As", command=self.save_as).grid(row=0, column=3, sticky="ew", padx=4, pady=4)

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
                f"Đã mở: {os.path.basename(path)} | cell {self.doc.cell_w}x{self.doc.cell_h} | row pitch {self.doc.row_pitch} | sheet {self.doc.sheet_w}x{self.doc.sheet_h} | grid cols {self.doc.grid_cols}"
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
            codes = self.doc.glyph_to_codes().get(self.current_glyph, [])
            code_text = ", ".join(f"0x{c:04X}" for c in codes) if codes else "chưa map char code"
            self.set_status(
                f"Đang chọn glyph {self.current_glyph} | code {code_text} | grid cols {self.doc.grid_cols} | row pitch {self.doc.row_pitch}"
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
            self.show_glyph(self.current_glyph, self.current_code)
            self.set_status(f"Đã import glyph từ: {path}")
        except Exception as e:
            messagebox.showerror("Lỗi import glyph", str(e), parent=self)

    def apply_grid_cols(self):
        if not self.require_loaded():
            return
        try:
            cols = int(self.cols_var.get().strip())
            self.doc.set_grid_cols(cols)
            if self.current_glyph is not None:
                self.show_glyph(self.current_glyph, self.current_code)
            self.set_status(f"Đã đổi grid cols = {cols} | row pitch = {self.doc.row_pitch}")
        except Exception as e:
            messagebox.showerror("Lỗi grid cols", str(e), parent=self)

    def apply_width(self):
        if not self.require_loaded() or self.current_glyph is None:
            return
        try:
            w = int(self.width_var.get().strip())
            self.doc.set_width_by_glyph(self.current_glyph, w)
            self.populate_list(keep_glyph=self.current_glyph)
            self.set_status(f"Đã sửa width glyph {self.current_glyph} = {w}")
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
