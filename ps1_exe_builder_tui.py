#!/usr/bin/env python3
"""PowerShell to EXE Builder TUI based on Textual."""

import base64
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Input, Label, OptionList, RichLog, Select


class FilePickerScreen(ModalScreen[str | None]):
    """Simple modal screen to pick a file path."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("enter", "confirm", "Confirm"),
    ]

    def __init__(self, title: str, start_dir: Path | None = None) -> None:
        super().__init__()
        self.title = title
        self.start_dir = start_dir or Path.cwd()
        self.current_items: list[Path] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="picker_root"):
            yield Label(self.title)
            yield Label("Use arrows to select file. Enter to choose. Esc to cancel.")
            yield Input(str(self.start_dir), id="picker_path")
            yield OptionList(id="picker_list")
            with Horizontal():
                yield Button("Up", id="picker_up")
                yield Button("Refresh", id="picker_refresh")
                yield Button("Choose", variant="success", id="picker_choose")
                yield Button("Cancel", variant="error", id="picker_cancel")

    def on_mount(self) -> None:
        self._refresh_listing(Path(self.query_one("#picker_path", Input).value))

    def _refresh_listing(self, directory: Path) -> None:
        listing = self.query_one("#picker_list", OptionList)
        listing.clear_options()
        self.current_items = []
        if not directory.exists() or not directory.is_dir():
            return

        items = sorted(directory.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        for item in items:
            label = "[DIR] {0}".format(item.name) if item.is_dir() else item.name
            listing.add_option(label)
            self.current_items.append(item)

    @on(Button.Pressed, "#picker_refresh")
    def handle_refresh(self) -> None:
        path = Path(self.query_one("#picker_path", Input).value)
        self._refresh_listing(path)

    @on(Button.Pressed, "#picker_up")
    def handle_up(self) -> None:
        current = Path(self.query_one("#picker_path", Input).value)
        parent = current.parent if current.parent != current else current
        self.query_one("#picker_path", Input).value = str(parent)
        self._refresh_listing(parent)

    @on(Button.Pressed, "#picker_cancel")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#picker_choose")
    def handle_choose_button(self) -> None:
        self._choose_current()

    @on(OptionList.OptionSelected, "#picker_list")
    def handle_pick(self, event: OptionList.OptionSelected) -> None:
        if event.option_index is None:
            return
        picked = self.current_items[event.option_index]
        if picked.is_dir():
            self.query_one("#picker_path", Input).value = str(picked)
            self._refresh_listing(picked)
            return
        self.dismiss(str(picked))

    def _choose_current(self) -> None:
        listing = self.query_one("#picker_list", OptionList)
        highlighted = listing.highlighted
        if highlighted is None or highlighted >= len(self.current_items):
            return
        selected = self.current_items[highlighted]
        if selected.is_dir():
            self.query_one("#picker_path", Input).value = str(selected)
            self._refresh_listing(selected)
            return
        self.dismiss(str(selected))

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_confirm(self) -> None:
        self._choose_current()


class BuilderApp(App):
    """PowerShell to EXE builder app."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #columns {
        height: 1fr;
    }
    .column {
        width: 1fr;
        border: round #666666;
        padding: 1;
    }
    #log {
        height: 11;
        border: round #444444;
    }
    """

    BINDINGS = [
        ("b", "build", "Build"),
        ("s", "save_config", "Save"),
        ("l", "load_config", "Load"),
        ("o", "open_output", "Open"),
        ("q", "quit", "Quit"),
    ]

    class ScriptChanged(Message):
        def __init__(self, script_path: str | None) -> None:
            self.script_path = script_path
            super().__init__()

    def __init__(self) -> None:
        super().__init__()
        self.ps_scripts: list[Path] = []
        self.extra_files: list[str] = []
        self.selected_script: str | None = None
        self.last_output: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="columns"):
            with Vertical(classes="column"):
                yield Label("Scripts (.ps1)")
                yield OptionList(id="script_list")
            with Vertical(classes="column"):
                yield Label("Files")
                yield OptionList(id="files_list")
                yield Input(placeholder="Additional file path", id="file_input")
                with Horizontal():
                    yield Button("Browse", id="file_browse")
                    yield Button("Add", variant="primary", id="file_add")
                    yield Button("Remove", variant="warning", id="file_remove")
            with Vertical(classes="column"):
                yield Label("Settings")
                yield Input(value="output", placeholder="Output EXE name", id="output_name")
                yield Select(
                    options=[("Light", "light"), ("Medium", "medium"), ("Heavy", "heavy")],
                    value="light",
                    id="obf_level",
                )
                yield Input(placeholder="Icon path (.ico)", id="icon_input")
                with Horizontal():
                    yield Button("Browse", id="icon_browse")
                    yield Button("Build", variant="success", id="build_button")
                with Horizontal():
                    yield Button("Save JSON", id="save_button")
                    yield Button("Load JSON", id="load_button")
        yield RichLog(id="log", markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_scripts()
        self.log_debug("Application started")

    def log_debug(self, message: str) -> None:
        self._log("DEBUG", "cyan", message)

    def log_error(self, message: str) -> None:
        self._log("ERROR", "red", message)

    def log_success(self, message: str) -> None:
        self._log("SUCCESS", "green", message)

    def log_warning(self, message: str) -> None:
        self._log("WARNING", "yellow", message)

    def _log(self, level: str, color: str, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = "[{0}] [{1}]{2}[/{1}] {3}".format(timestamp, color, level, message)
        self.query_one("#log", RichLog).write(line)

    def refresh_scripts(self) -> None:
        script_list = self.query_one("#script_list", OptionList)
        script_list.clear_options()
        self.ps_scripts = sorted(Path.cwd().glob("*.ps1"))

        if not self.ps_scripts:
            script_list.add_option("No .ps1 files found")
            self.selected_script = None
            self.log_warning("No PowerShell scripts found in current directory")
            return

        for script in self.ps_scripts:
            script_list.add_option(script.name)

        self.selected_script = str(self.ps_scripts[0])
        script_list.highlighted = 0
        self.log_success("Found {0} script(s)".format(len(self.ps_scripts)))

    def refresh_files(self) -> None:
        files_list = self.query_one("#files_list", OptionList)
        files_list.clear_options()
        for item in self.extra_files:
            files_list.add_option(item)

    @on(OptionList.OptionSelected, "#script_list")
    def handle_script_select(self, event: OptionList.OptionSelected) -> None:
        if event.option_index is None:
            return
        if event.option_index >= len(self.ps_scripts):
            return
        selected = self.ps_scripts[event.option_index]
        self.selected_script = str(selected)
        self.log_debug("Selected script: {0}".format(self.selected_script))

    @on(Button.Pressed, "#file_browse")
    def handle_file_browse(self) -> None:
        self.push_screen(FilePickerScreen("Select additional file"), self._on_file_picked)

    def _on_file_picked(self, path: str | None) -> None:
        if not path:
            return
        self.query_one("#file_input", Input).value = path

    @on(Button.Pressed, "#icon_browse")
    def handle_icon_browse(self) -> None:
        self.push_screen(FilePickerScreen("Select icon file (.ico)"), self._on_icon_picked)

    def _on_icon_picked(self, path: str | None) -> None:
        if not path:
            return
        self.query_one("#icon_input", Input).value = path

    @on(Button.Pressed, "#file_add")
    def handle_file_add(self) -> None:
        raw = self.query_one("#file_input", Input).value.strip()
        if not raw:
            self.log_warning("File path is empty")
            return
        path = str(Path(raw).resolve())
        if not Path(path).exists():
            self.log_error("File does not exist: {0}".format(path))
            return
        if path in self.extra_files:
            self.log_warning("Already in list: {0}".format(path))
            return
        self.extra_files.append(path)
        self.refresh_files()
        self.log_success("Added file: {0}".format(path))

    @on(Button.Pressed, "#file_remove")
    def handle_file_remove(self) -> None:
        files_list = self.query_one("#files_list", OptionList)
        index = files_list.highlighted
        if index is None:
            self.log_warning("No file selected")
            return
        if index >= len(self.extra_files):
            self.log_warning("Invalid file selection")
            return
        removed = self.extra_files.pop(index)
        self.refresh_files()
        self.log_success("Removed file: {0}".format(removed))

    @on(Button.Pressed, "#build_button")
    def handle_build_button(self) -> None:
        self.action_build()

    @on(Button.Pressed, "#save_button")
    def handle_save_button(self) -> None:
        self.action_save_config()

    @on(Button.Pressed, "#load_button")
    def handle_load_button(self) -> None:
        self.action_load_config()

    def action_build(self) -> None:
        try:
            output_name = self.query_one("#output_name", Input).value.strip()
            icon_path = self.query_one("#icon_input", Input).value.strip()
            level = str(self.query_one("#obf_level", Select).value)

            if not self.selected_script:
                self.log_error("No script selected")
                return
            script_path = Path(self.selected_script)
            if not script_path.exists():
                self.log_error("Script not found: {0}".format(script_path))
                return
            if output_name == "":
                self.log_error("Output name cannot be empty")
                return

            self.log_debug("Starting build for {0}".format(script_path.name))
            exe_path = self.build_exe(script_path, output_name, level, icon_path)
            self.last_output = exe_path
            self.log_success("Build complete: {0}".format(exe_path))
        except Exception as exc:
            self.log_error("Build failed: {0}".format(exc))

    def build_exe(self, script_path: Path, output_name: str, level: str, icon_path: str) -> str:
        if os.name != "nt":
            raise RuntimeError("IExpress build works only on Windows")

        with tempfile.TemporaryDirectory(prefix="ps1_builder_") as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            payload_script = temp_dir / "payload.ps1"
            launcher_cmd = temp_dir / "launcher.cmd"
            sed_path = temp_dir / "build.sed"

            content = self._read_script(script_path)
            obfuscated = self.apply_obfuscation(content, level)
            payload_script.write_text(obfuscated, encoding="utf-8")
            launcher_cmd.write_text(
                "@echo off\r\n"
                "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%~dp0payload.ps1\"\r\n",
                encoding="utf-8",
            )

            file_paths = [launcher_cmd, payload_script]
            for extra in self.extra_files:
                src = Path(extra)
                if not src.exists() or not src.is_file():
                    self.log_warning("Skipping missing file: {0}".format(src))
                    continue
                dst = temp_dir / src.name
                shutil.copy2(src, dst)
                file_paths.append(dst)

            exe_name = output_name if output_name.lower().endswith(".exe") else "{0}.exe".format(output_name)
            target_exe = Path.cwd() / exe_name
            sed_content = self.generate_sed(temp_dir, target_exe, file_paths, icon_path)
            sed_path.write_text(sed_content, encoding="utf-8")

            command = ["iexpress", "/N", str(sed_path)]
            self.log_debug("Running: {0}".format(" ".join(command)))
            run = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )

            if run.stdout.strip() != "":
                self.log_debug("IExpress stdout: {0}".format(run.stdout.strip()))
            if run.stderr.strip() != "":
                self.log_warning("IExpress stderr: {0}".format(run.stderr.strip()))

            if run.returncode != 0:
                raise RuntimeError("IExpress failed with code {0}".format(run.returncode))

            if not target_exe.exists() or target_exe.stat().st_size == 0:
                raise RuntimeError("EXE file was not created")

            return str(target_exe)

    def _read_script(self, script_path: Path) -> str:
        encodings = ["utf-8", "cp1251", "utf-16"]
        for enc in encodings:
            try:
                return script_path.read_text(encoding=enc)
            except Exception:
                continue
        raise RuntimeError("Cannot read script with supported encodings")

    def apply_obfuscation(self, source: str, level: str) -> str:
        if level == "light":
            return self.obfuscate_light(source)
        if level == "medium":
            return self.obfuscate_medium(source)
        if level == "heavy":
            return self.obfuscate_heavy(source)
        return source

    def obfuscate_light(self, source: str) -> str:
        replaced = source
        dictionary = {
            "Invoke-Expression": "IEX",
            "Write-Host": "Write-Output",
            "Start-Process": "&",
            "Get-ChildItem": "gci",
            "Where-Object": "?",
            "ForEach-Object": "%",
        }
        for old, new in dictionary.items():
            replaced = replaced.replace(old, new)
        return replaced

    def obfuscate_medium(self, source: str) -> str:
        encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
        return (
            "$p='{0}';"
            "$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p));"
            "Invoke-Expression $d"
        ).format(encoded)

    def obfuscate_heavy(self, source: str) -> str:
        encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
        chunks = [encoded[i : i + 20] for i in range(0, len(encoded), 20)]
        joined = "\",\"".join(chunks)
        return (
            "$x=@(\"{0}\");"
            "$y=($x -join '');"
            "$z=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($y));"
            "$a=1;$b=2;$c=$a+$b;"
            "if($c -gt 0){{Invoke-Expression $z}}"
        ).format(joined)

    def generate_sed(self, temp_dir: Path, target_exe: Path, file_paths: list[Path], icon_path: str) -> str:
        lines = []
        lines.append("[Version]")
        lines.append("Class=IEXPRESS")
        lines.append("SEDVersion=3")
        lines.append("[Options]")
        lines.append("PackagePurpose=InstallApp")
        lines.append("ShowInstallProgramWindow=0")
        lines.append("HideExtractAnimation=1")
        lines.append("UseLongFileName=1")
        lines.append("InsideCompressed=0")
        lines.append("CAB_FixedSize=0")
        lines.append("CAB_ResvCodeSigning=0")
        lines.append("RebootMode=N")
        lines.append("InstallPrompt=%InstallPrompt%")
        lines.append("DisplayLicense=%DisplayLicense%")
        lines.append("FinishMessage=%FinishMessage%")
        lines.append("TargetName={0}".format(str(target_exe)))
        lines.append("FriendlyName=PowerShell EXE Builder Package")
        lines.append("AppLaunched=cmd /c launcher.cmd")
        lines.append("PostInstallCmd=<None>")
        lines.append("AdminQuietInstCmd=cmd /c launcher.cmd")
        lines.append("UserQuietInstCmd=cmd /c launcher.cmd")
        lines.append("SourceFiles=SourceFiles")
        lines.append("SelfDelete=0")

        if icon_path.strip() != "":
            icon_file = Path(icon_path)
            if icon_file.exists() and icon_file.suffix.lower() == ".ico":
                lines.append("TargetIcon={0}".format(str(icon_file)))
            else:
                self.log_warning("Icon file missing or not .ico: {0}".format(icon_path))

        lines.append("[Strings]")
        lines.append("InstallPrompt=")
        lines.append("DisplayLicense=")
        lines.append("FinishMessage=")

        for index, item in enumerate(file_paths):
            lines.append("FILE{0}={1}".format(index, item.name))

        lines.append("[SourceFiles]")
        lines.append("SourceFiles0={0}\\".format(str(temp_dir)))
        lines.append("[SourceFiles0]")
        for index, _item in enumerate(file_paths):
            lines.append("%FILE{0}%=".format(index))

        return "\n".join(lines) + "\n"

    def action_save_config(self) -> None:
        try:
            path = Path.cwd() / "builder_config.json"
            data = {
                "selected_script": self.selected_script,
                "extra_files": self.extra_files,
                "output_name": self.query_one("#output_name", Input).value,
                "obfuscation": str(self.query_one("#obf_level", Select).value),
                "icon": self.query_one("#icon_input", Input).value,
            }
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            self.log_success("Config saved: {0}".format(path))
        except Exception as exc:
            self.log_error("Cannot save config: {0}".format(exc))

    def action_load_config(self) -> None:
        try:
            path = Path.cwd() / "builder_config.json"
            if not path.exists():
                self.log_error("Config file not found: {0}".format(path))
                return
            data = json.loads(path.read_text(encoding="utf-8"))
            selected = data.get("selected_script")
            self.extra_files = [str(Path(item)) for item in data.get("extra_files", [])]
            self.query_one("#output_name", Input).value = str(data.get("output_name", "output"))
            self.query_one("#icon_input", Input).value = str(data.get("icon", ""))

            level = str(data.get("obfuscation", "light"))
            if level not in ["light", "medium", "heavy"]:
                level = "light"
            self.query_one("#obf_level", Select).value = level

            self.refresh_files()
            self.refresh_scripts()
            if selected:
                selected_name = Path(str(selected)).name
                for index, script in enumerate(self.ps_scripts):
                    if script.name == selected_name:
                        self.query_one("#script_list", OptionList).highlighted = index
                        self.selected_script = str(script)
                        break

            self.log_success("Config loaded: {0}".format(path))
        except Exception as exc:
            self.log_error("Cannot load config: {0}".format(exc))

    def action_open_output(self) -> None:
        try:
            if self.last_output and Path(self.last_output).exists():
                target = str(Path(self.last_output).parent)
            else:
                target = str(Path.cwd())
            if os.name == "nt":
                subprocess.run(["explorer", target], check=False)
            else:
                self.log_warning("Open action is intended for Windows explorer")
            self.log_debug("Open path: {0}".format(target))
        except Exception as exc:
            self.log_error("Cannot open path: {0}".format(exc))


if __name__ == "__main__":
    BuilderApp().run()
