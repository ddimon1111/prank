#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import traceback
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from PyQt6.QtCore import QMimeData, QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QDragEnterEvent, QDropEvent, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStyleFactory,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:
    import pefile
except Exception:
    pefile = None

try:
    import py7zr
except Exception:
    py7zr = None

try:
    import rarfile
except Exception:
    rarfile = None

APP_NAME = "EXE Analyzer Pro 5"
SETTINGS_FILE = Path.home() / ".exe_analyzer_pro_5.json"
ASCII_RE = re.compile(rb"[\x20-\x7E]{6,}")
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".cab"}
SUPPORTED_EXE_EXTS = {".exe", ".dll", ".scr", ".ocx", ".cpl", ".sys"}
MAX_VT_TIMEOUT = 30


@dataclass
class StaticResult:
    file_path: Path
    file_size: int
    sha256: str
    entry_point: str
    imports: list[str]
    strings: list[str]
    resources: list[dict]
    warnings: list[str]


class LogView(QTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setAcceptRichText(True)
        self.setFont(QFont("Consolas", 10))
        self.document().setDocumentMargin(10)

    def append_colored(self, text: str, color: str) -> None:
        safe = (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>")
        )
        self.append(f'<span style="color:{color};">{safe}</span>')


class DropArea(QLabel):
    file_dropped = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__("Перетащите EXE сюда")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setObjectName("dropArea")
        self.setMinimumHeight(84)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        mime = event.mimeData()
        if mime.hasUrls() and self._extract_first_file(mime):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        path = self._extract_first_file(event.mimeData())
        if path:
            self.file_dropped.emit(path)
            event.acceptProposedAction()
        else:
            event.ignore()

    @staticmethod
    def _extract_first_file(mime: QMimeData) -> str | None:
        for url in mime.urls():
            local = url.toLocalFile()
            if local and Path(local).is_file():
                return local
        return None


class WorkerSignals(QObject):
    progress = pyqtSignal(int)
    log = pyqtSignal(str, str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)


class StaticAnalyzerRunnable(QRunnable):
    def __init__(self, file_path: Path) -> None:
        super().__init__()
        self.file_path = file_path
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            result = static_analyze(self.file_path, self.signals.progress, self.signals.log)
            self.signals.finished.emit(result)
        except Exception as exc:
            self.signals.error.emit(f"Ошибка анализа: {exc}\n{traceback.format_exc()}")


class ExtractRunnable(QRunnable):
    def __init__(self, file_path: Path) -> None:
        super().__init__()
        self.file_path = file_path
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            out_dir = extract_everything(self.file_path, self.signals.progress, self.signals.log)
            self.signals.finished.emit(out_dir)
        except Exception as exc:
            self.signals.error.emit(f"Ошибка распаковки: {exc}\n{traceback.format_exc()}")


class VirusTotalRunnable(QRunnable):
    def __init__(self, sha256: str, api_key: str) -> None:
        super().__init__()
        self.sha256 = sha256
        self.api_key = api_key
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            self.signals.progress.emit(20)
            headers = {"x-apikey": self.api_key.strip()}
            url = f"https://www.virustotal.com/api/v3/files/{self.sha256}"
            resp = requests.get(url, headers=headers, timeout=MAX_VT_TIMEOUT)
            self.signals.progress.emit(75)
            if resp.status_code == 404:
                self.signals.finished.emit({"status": "not_found", "message": "Объект не найден в VirusTotal."})
                self.signals.progress.emit(100)
                return
            resp.raise_for_status()
            data = resp.json()
            self.signals.progress.emit(100)
            self.signals.finished.emit({"status": "ok", "data": data})
        except Exception as exc:
            self.signals.error.emit(f"Ошибка VT: {exc}\n{traceback.format_exc()}")


class AnalyzerWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1280, 860)
        self.thread_pool = QThreadPool.globalInstance()
        self.current_file: Path | None = None
        self.current_result: StaticResult | None = None
        self.settings_data = self._load_settings()
        self._build_ui()
        self._apply_styles()
        self._set_progress(0)
        self.log_success("Программа готова.")

    def _build_ui(self) -> None:
        root = QWidget()
        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        top_bar = QHBoxLayout()
        self.open_button = QPushButton("Открыть EXE")
        self.extract_button = QPushButton("Скачать содержимое")
        self.vt_button = QPushButton("Проверить VT")
        self.file_label = QLineEdit()
        self.file_label.setReadOnly(True)
        self.file_label.setPlaceholderText("Файл не выбран")
        top_bar.addWidget(self.open_button)
        top_bar.addWidget(self.extract_button)
        top_bar.addWidget(self.vt_button)
        top_bar.addWidget(self.file_label, 1)

        self.drop_area = DropArea()
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setRange(0, 100)
        self.progress.setFormat("%p%")

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.tabs = QTabWidget()
        self.general_view = QPlainTextEdit()
        self.api_view = QPlainTextEdit()
        self.strings_view = QPlainTextEdit()
        self.vt_view = QPlainTextEdit()
        for view in [self.general_view, self.api_view, self.strings_view, self.vt_view]:
            view.setReadOnly(True)
            view.setFont(QFont("Consolas", 10))
            view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        self.resources_tree = QTreeWidget()
        self.resources_tree.setHeaderLabels(["Имя", "Тип", "Размер", "Смещение"])
        self.resources_tree.setFont(QFont("Consolas", 10))

        settings_widget = QWidget()
        form = QFormLayout(settings_widget)
        self.vt_key_edit = QLineEdit(self.settings_data.get("vt_api_key", ""))
        self.vt_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.save_settings_button = QPushButton("Сохранить")
        form.addRow("VT API ключ", self.vt_key_edit)
        form.addRow("", self.save_settings_button)

        self.tabs.addTab(self.general_view, "Общее")
        self.tabs.addTab(self.api_view, "API")
        self.tabs.addTab(self.strings_view, "Строки")
        self.tabs.addTab(self.resources_tree, "Ресурсы")
        self.tabs.addTab(self.vt_view, "VirusTotal")
        self.tabs.addTab(settings_widget, "Настройки")

        self.log_view = LogView()
        splitter.addWidget(self.tabs)
        splitter.addWidget(self.log_view)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)

        main_layout.addLayout(top_bar)
        main_layout.addWidget(self.drop_area)
        main_layout.addWidget(self.progress)
        main_layout.addWidget(splitter, 1)
        self.setCentralWidget(root)

        self._build_menu()
        self.open_button.clicked.connect(self.open_file_dialog)
        self.extract_button.clicked.connect(self.extract_current)
        self.vt_button.clicked.connect(self.check_vt)
        self.drop_area.file_dropped.connect(self.load_file)
        self.save_settings_button.clicked.connect(self.save_settings)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("Файл")
        open_action = QAction("Открыть EXE", self)
        open_action.triggered.connect(self.open_file_dialog)
        file_menu.addAction(open_action)

    def _apply_styles(self) -> None:
        QApplication.setStyle(QStyleFactory.create("Fusion"))
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #12161d;
                color: #e8edf2;
                font-family: Segoe UI;
                font-size: 13px;
            }
            QPushButton {
                background: #2e6bff;
                color: white;
                border: none;
                border-radius: 12px;
                padding: 10px 16px;
                min-height: 18px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #3b78ff;
            }
            QPushButton:pressed {
                background: #2455cc;
            }
            QLineEdit, QPlainTextEdit, QTextEdit, QTreeWidget, QTabWidget::pane {
                background: #1a2029;
                border: 1px solid #2f3846;
                border-radius: 12px;
                padding: 6px;
            }
            QProgressBar {
                background: #1a2029;
                border: 1px solid #2f3846;
                border-radius: 10px;
                text-align: center;
                height: 22px;
            }
            QProgressBar::chunk {
                border-radius: 9px;
                background: #35c46a;
            }
            QTabBar::tab {
                background: #1f2632;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                padding: 9px 14px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background: #2e6bff;
            }
            #dropArea {
                background: #161d26;
                border: 2px dashed #3e85ff;
                border-radius: 16px;
                font: 600 14px 'Segoe UI';
            }
            QHeaderView::section {
                background: #1f2632;
                padding: 7px;
                border: none;
            }
            """
        )

    def _load_settings(self) -> dict:
        if SETTINGS_FILE.exists():
            try:
                return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def save_settings(self) -> None:
        self.settings_data["vt_api_key"] = self.vt_key_edit.text().strip()
        SETTINGS_FILE.write_text(json.dumps(self.settings_data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.log_success(f"Настройки сохранены: {SETTINGS_FILE}")

    def open_file_dialog(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите EXE/PE файл",
            str(Path.home()),
            "PE files (*.exe *.dll *.scr *.ocx *.cpl *.sys);;All files (*)",
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path: str) -> None:
        path = Path(file_path)
        if not path.is_file():
            self.log_error("Файл не найден.")
            return
        self.current_file = path
        self.current_result = None
        self.file_label.setText(str(path))
        self.general_view.clear()
        self.api_view.clear()
        self.strings_view.clear()
        self.vt_view.clear()
        self.resources_tree.clear()
        self._set_progress(0)
        self.log_success(f"Выбран файл: {path}")
        self.start_analysis(path)

    def start_analysis(self, path: Path) -> None:
        runnable = StaticAnalyzerRunnable(path)
        runnable.signals.progress.connect(self._set_progress)
        runnable.signals.log.connect(self._append_log)
        runnable.signals.error.connect(self._on_error)
        runnable.signals.finished.connect(self._on_analysis_done)
        self.thread_pool.start(runnable)

    def _on_analysis_done(self, result: StaticResult) -> None:
        self.current_result = result
        general_lines = [
            f"Файл: {result.file_path}",
            f"Размер: {result.file_size} байт",
            f"SHA256: {result.sha256}",
            f"EntryPoint: {result.entry_point}",
            f"Импортов: {len(result.imports)}",
            f"Ресурсов: {len(result.resources)}",
            f"ASCII строк: {len(result.strings)}",
        ]
        if result.warnings:
            general_lines.append("")
            general_lines.append("Предупреждения:")
            general_lines.extend(f"- {item}" for item in result.warnings)
        self.general_view.setPlainText("\n".join(general_lines))
        self.api_view.setPlainText("\n".join(result.imports) if result.imports else "Импорты не найдены.")
        self.strings_view.setPlainText("\n".join(result.strings) if result.strings else "Строки не найдены.")
        self.resources_tree.clear()
        for res in result.resources:
            item = QTreeWidgetItem(
                [
                    res.get("name", "resource"),
                    str(res.get("type", "?")),
                    str(res.get("size", 0)),
                    str(res.get("offset", "?")),
                ]
            )
            self.resources_tree.addTopLevelItem(item)
        self.resources_tree.expandAll()
        self._set_progress(100)
        self.log_success("Статический анализ завершён.")

    def extract_current(self) -> None:
        if not self.current_file:
            self.log_error("Сначала откройте EXE-файл.")
            return
        runnable = ExtractRunnable(self.current_file)
        runnable.signals.progress.connect(self._set_progress)
        runnable.signals.log.connect(self._append_log)
        runnable.signals.error.connect(self._on_error)
        runnable.signals.finished.connect(self._on_extract_done)
        self.thread_pool.start(runnable)

    def _on_extract_done(self, out_dir: Path) -> None:
        self._set_progress(100)
        self.log_success(f"Распаковка завершена: {out_dir}")
        QMessageBox.information(self, APP_NAME, f"Содержимое сохранено в:\n{out_dir}")

    def check_vt(self) -> None:
        if not self.current_result:
            self.log_error("Сначала дождитесь завершения анализа.")
            return
        api_key = self.vt_key_edit.text().strip() or self.settings_data.get("vt_api_key", "")
        if not api_key:
            self.log_error("Укажите VT API ключ на вкладке 'Настройки'.")
            self.tabs.setCurrentIndex(5)
            return
        self._set_progress(0)
        runnable = VirusTotalRunnable(self.current_result.sha256, api_key)
        runnable.signals.progress.connect(self._set_progress)
        runnable.signals.log.connect(self._append_log)
        runnable.signals.error.connect(self._on_error)
        runnable.signals.finished.connect(self._on_vt_done)
        self.thread_pool.start(runnable)

    def _on_vt_done(self, payload: dict) -> None:
        self.tabs.setCurrentIndex(4)
        if payload.get("status") == "not_found":
            self.vt_view.setPlainText(payload.get("message", "Не найдено."))
            self.log_success("Запрос VirusTotal выполнен: объект не найден.")
            return
        data = payload["data"]
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        lines = [
            f"SHA256: {self.current_result.sha256 if self.current_result else ''}",
            f"Тип: {attrs.get('type_description', '')}",
            f"Репутация: {attrs.get('reputation', '')}",
            "",
            "Статистика анализов:",
        ]
        for key in ["malicious", "suspicious", "undetected", "harmless", "timeout"]:
            lines.append(f"- {key}: {stats.get(key, 0)}")
        lines.append("")
        lines.append("Последние движки:")
        for engine, info in list(attrs.get("last_analysis_results", {}).items())[:30]:
            result = info.get("result") or info.get("category") or ""
            lines.append(f"- {engine}: {result}")
        self.vt_view.setPlainText("\n".join(lines))
        self.log_success("Запрос VirusTotal выполнен.")

    def _on_error(self, message: str) -> None:
        self._set_progress(0)
        self.log_error(message)
        QMessageBox.critical(self, APP_NAME, message)

    def _append_log(self, level: str, message: str) -> None:
        colors = {
            "success": "#5ce08c",
            "error": "#ff6b6b",
            "info": "#7fc3ff",
            "warning": "#ffca5b",
        }
        prefix = {
            "success": "[OK] ",
            "error": "[ERR] ",
            "info": "[INFO] ",
            "warning": "[WARN] ",
        }.get(level, "")
        self.log_view.append_colored(prefix + message, colors.get(level, "#d7dce2"))

    def log_success(self, text: str) -> None:
        self._append_log("success", text)

    def log_error(self, text: str) -> None:
        self._append_log("error", text)

    def _set_progress(self, value: int) -> None:
        value = max(0, min(100, int(value)))
        self.progress.setValue(value)
        self.progress.repaint()
        QApplication.processEvents()


def calculate_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_ascii_strings(file_path: Path) -> list[str]:
    data = file_path.read_bytes()
    return [m.decode("ascii", errors="ignore") for m in ASCII_RE.findall(data)]


def static_analyze(file_path: Path, progress_cb, log_cb) -> StaticResult:
    warnings: list[str] = []
    log_cb.emit("info", "Вычисление SHA256...")
    progress_cb.emit(8)
    sha256 = calculate_sha256(file_path)
    progress_cb.emit(16)

    imports: list[str] = []
    resources: list[dict] = []
    entry_point = "N/A"

    if pefile is None:
        warnings.append("Модуль pefile не установлен, PE-анализ ограничен.")
    else:
        log_cb.emit("info", "Разбор PE структуры...")
        pe = pefile.PE(str(file_path), fast_load=False)
        entry_point = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = (entry.dll or b"?").decode(errors="ignore")
                for imp in entry.imports:
                    api = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                    imports.append(f"{dll_name}!{api}")
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = resource_type_name(entry, pe)
                if not hasattr(entry, "directory"):
                    continue
                for name_entry in entry.directory.entries:
                    name_name = resource_name(name_entry, pe)
                    if not hasattr(name_entry, "directory"):
                        continue
                    for lang_entry in name_entry.directory.entries:
                        data_struct = lang_entry.data.struct
                        resources.append(
                            {
                                "type": type_name,
                                "name": name_name,
                                "size": int(data_struct.Size),
                                "offset": int(data_struct.OffsetToData),
                                "lang": getattr(lang_entry, "id", 0),
                            }
                        )
        pe.close()
    progress_cb.emit(50)

    log_cb.emit("info", "Извлечение ASCII строк...")
    strings = extract_ascii_strings(file_path)
    progress_cb.emit(80)

    file_size = file_path.stat().st_size
    progress_cb.emit(100)
    return StaticResult(
        file_path=file_path,
        file_size=file_size,
        sha256=sha256,
        entry_point=entry_point,
        imports=sorted(set(imports)),
        strings=strings,
        resources=resources,
        warnings=warnings,
    )


def resource_type_name(entry, pe) -> str:
    if entry.name is not None:
        return str(entry.name)
    rid = entry.struct.Id
    try:
        return pefile.RESOURCE_TYPE.get(rid, str(rid)) if pefile else str(rid)
    except Exception:
        return str(rid)


def resource_name(entry, pe) -> str:
    if entry.name is not None:
        return str(entry.name)
    try:
        return str(entry.id)
    except Exception:
        return "unnamed"


def desktop_output_dir(file_path: Path) -> Path:
    desktop = Path.home() / "Desktop"
    if not desktop.exists():
        desktop = Path.home()
    return desktop / f"{file_path.stem}_res"


def safe_unique_path(base_dir: Path, name: str) -> Path:
    candidate = base_dir / name
    stem = candidate.stem
    suffix = candidate.suffix
    idx = 1
    while candidate.exists():
        candidate = base_dir / f"{stem}_{idx}{suffix}"
        idx += 1
    return candidate


def write_resource_blobs(file_path: Path, out_dir: Path, log_cb) -> int:
    count = 0
    if pefile is None:
        log_cb.emit("warning", "pefile не установлен, PE ресурсы не извлечены.")
        return 0
    pe = pefile.PE(str(file_path), fast_load=False)
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        pe.close()
        return 0
    res_dir = out_dir / "resources"
    res_dir.mkdir(parents=True, exist_ok=True)
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = sanitize_name(resource_type_name(type_entry, pe))
        if not hasattr(type_entry, "directory"):
            continue
        for name_entry in type_entry.directory.entries:
            name_name = sanitize_name(resource_name(name_entry, pe))
            if not hasattr(name_entry, "directory"):
                continue
            for lang_entry in name_entry.directory.entries:
                data_rva = lang_entry.data.struct.OffsetToData
                size = lang_entry.data.struct.Size
                blob = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                filename = f"res_{type_name}_{name_name}_{count:04d}.bin"
                target = safe_unique_path(res_dir, filename)
                target.write_bytes(blob)
                count += 1
    pe.close()
    if count:
        log_cb.emit("success", f"PE ресурсы сохранены: {count}")
    return count


def sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned or "item"


def carve_cab_segments(file_path: Path, cab_dir: Path, log_cb) -> list[Path]:
    data = file_path.read_bytes()
    found: list[Path] = []
    start = 0
    index = 0
    while True:
        pos = data.find(b"MSCF", start)
        if pos < 0:
            break
        if pos + 12 <= len(data):
            try:
                cab_size = struct.unpack_from("<I", data, pos + 8)[0]
                if cab_size > 0 and pos + cab_size <= len(data):
                    blob = data[pos : pos + cab_size]
                    target = safe_unique_path(cab_dir, f"carved_{index:04d}.cab")
                    target.write_bytes(blob)
                    found.append(target)
                    index += 1
                    start = pos + cab_size
                    continue
            except Exception:
                pass
        start = pos + 4
    if found:
        log_cb.emit("success", f"Найдено CAB сегментов: {len(found)}")
    return found


def extract_cab(cab_path: Path, target_dir: Path, log_cb) -> bool:
    target_dir.mkdir(parents=True, exist_ok=True)
    commands = []
    if os.name == "nt":
        commands.extend([
            ["expand", str(cab_path), "-F:*", str(target_dir)],
            ["extrac32", "/Y", "/E", str(cab_path), str(target_dir)],
        ])
    seven_zip = shutil.which("7z") or shutil.which("7za")
    if seven_zip:
        commands.append([seven_zip, "x", "-y", f"-o{str(target_dir)}", str(cab_path)])
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode == 0:
                log_cb.emit("success", f"CAB распакован: {cab_path.name}")
                return True
        except Exception:
            continue
    log_cb.emit("warning", f"Не удалось распаковать CAB автоматически: {cab_path.name}")
    return False


def extract_archive(path: Path, target_dir: Path, log_cb) -> bool:
    suffix = path.suffix.lower()
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(path, "r") as zf:
                zf.extractall(target_dir)
            log_cb.emit("success", f"ZIP распакован: {path.name}")
            return True
        if suffix == ".7z":
            if py7zr is None:
                log_cb.emit("warning", f"py7zr не установлен, 7z пропущен: {path.name}")
                return False
            with py7zr.SevenZipFile(path, mode="r") as zf:
                zf.extractall(path=target_dir)
            log_cb.emit("success", f"7z распакован: {path.name}")
            return True
        if suffix == ".rar":
            if rarfile is None:
                log_cb.emit("warning", f"rarfile не установлен, RAR пропущен: {path.name}")
                return False
            with rarfile.RarFile(path) as rf:
                rf.extractall(target_dir)
            log_cb.emit("success", f"RAR распакован: {path.name}")
            return True
        if suffix == ".cab":
            return extract_cab(path, target_dir, log_cb)
    except Exception as exc:
        log_cb.emit("warning", f"Не удалось распаковать {path.name}: {exc}")
    return False


def iter_candidate_archives(root: Path) -> Iterable[Path]:
    for item in root.rglob("*"):
        if item.is_file() and item.suffix.lower() in ARCHIVE_EXTS:
            yield item


def maybe_copy_nested_pe(item: Path, out_dir: Path, log_cb) -> None:
    if item.suffix.lower() in SUPPORTED_EXE_EXTS:
        nested_dir = out_dir / "nested_pe"
        nested_dir.mkdir(parents=True, exist_ok=True)
        target = safe_unique_path(nested_dir, item.name)
        shutil.copy2(item, target)
        try:
            write_resource_blobs(target, nested_dir / f"{target.stem}_content", log_cb)
        except Exception as exc:
            log_cb.emit("warning", f"Не удалось извлечь ресурсы вложенного PE {item.name}: {exc}")


def extract_everything(file_path: Path, progress_cb, log_cb) -> Path:
    out_dir = desktop_output_dir(file_path)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    progress_cb.emit(5)
    original_copy = out_dir / file_path.name
    shutil.copy2(file_path, original_copy)
    log_cb.emit("success", f"Оригинал скопирован: {original_copy}")

    progress_cb.emit(20)
    write_resource_blobs(file_path, out_dir, log_cb)

    cab_dir = out_dir / "carved_cab"
    cab_dir.mkdir(parents=True, exist_ok=True)
    carved = carve_cab_segments(file_path, cab_dir, log_cb)
    for cab in carved:
        extract_archive(cab, cab_dir / cab.stem, log_cb)

    progress_cb.emit(45)
    queue = [out_dir]
    visited: set[Path] = set()
    rounds = 0
    while queue and rounds < 20:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        rounds += 1
        extracted_any = False
        archives = list(iter_candidate_archives(current))
        for archive in archives:
            target = archive.parent / f"{archive.stem}_unpacked"
            if target.exists() and any(target.iterdir()):
                continue
            if extract_archive(archive, target, log_cb):
                extracted_any = True
                queue.append(target)
        for item in current.rglob("*"):
            if item.is_file():
                maybe_copy_nested_pe(item, out_dir, log_cb)
        progress_cb.emit(min(95, 45 + rounds * 2))
        if not extracted_any and rounds > 2:
            break

    progress_cb.emit(100)
    return out_dir


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_NAME)
    window = AnalyzerWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
