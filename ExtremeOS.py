import os
import sys
import threading
import time
import subprocess
import logging
import winreg

try:
    from PIL import Image, ImageTk  # type: ignore
    _PIL_AVAILABLE = True
except Exception:
    _PIL_AVAILABLE = False
from dataclasses import dataclass
from typing import Callable, Optional, List, Tuple

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox

APP_TITLE = "Extreme OS"
WORK_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Work")
ICONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
ICON_MAX_PX = 34


def _setup_logging():
    os.makedirs(WORK_DIR, exist_ok=True)
    log_path = os.path.join(WORK_DIR, "app.log")

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    root_logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    root_logger.addHandler(ch)

    try:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)
        root_logger.addHandler(fh)
    except Exception:
        pass


logger = logging.getLogger(__name__)


def check_windows_version() -> Tuple[bool, str]:
    """Check if running on Windows 11 (build 22000 or higher)"""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
        winreg.CloseKey(key)
        
        build_num = int(build)
        if build_num >= 22000:
            return True, f"Windows 11 (Build {build_num})"
        else:
            return False, f"Windows 10 или старше (Build {build_num}). Требуется Windows 11 (Build 22000+)"
    except Exception as e:
        return False, f"Не удалось определить версию Windows: {e}"


def resource_icon(name: str) -> Optional[tk.PhotoImage]:
    candidates = []
    base = name
    if base:
        base = base.lower().rstrip()
    if not base:
        return None

    candidates.append(os.path.join(ICONS_DIR, f"{base}.png"))
    candidates.append(os.path.join(ICONS_DIR, f"{base}.ico"))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            if _PIL_AVAILABLE:
                img = Image.open(path)
                w, h = img.size
                m = max(w, h)
                if m > ICON_MAX_PX:
                    scale = ICON_MAX_PX / float(m)
                    new_size = (max(1, int(w * scale)), max(1, int(h * scale)))
                    img = img.resize(new_size, Image.LANCZOS)
                return ImageTk.PhotoImage(img)
            else:
                if path.lower().endswith(".ico"):
                    continue
                img = tk.PhotoImage(file=path)
                w, h = img.width(), img.height()
                m = max(w, h)
                if m > ICON_MAX_PX:
                    factor = max(2, (m + ICON_MAX_PX - 1) // ICON_MAX_PX)
                    img = img.subsample(factor, factor)
                return img
        except Exception:
            continue

    return None


def icon_label(parent, icon: Optional[tk.PhotoImage]) -> ctk.CTkLabel:
    if icon is None:
        lbl = ctk.CTkLabel(parent, text="", width=ICON_MAX_PX)
        lbl._icon_ref = None
        return lbl
    lbl = ctk.CTkLabel(parent, text="", image=icon)
    lbl._icon_ref = icon
    return lbl


def run_bat_file(bat_path: str, log_callback: Callable) -> Tuple[int, str]:
    try:
        logger.info(f"Running BAT: {bat_path}")
        process = subprocess.Popen(
            [bat_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=True,
            cwd=WORK_DIR
        )
        output = ""
        for line in process.stdout:
            output += line
            logger.info(line.rstrip("\n"))
        process.wait()
        logger.info(f"BAT finished with code: {process.returncode or 0}")
        return process.returncode or 0, output
    except Exception as e:
        logger.exception(f"Failed to run BAT: {bat_path}")
        return 1, f"ERROR: {e}\n"


class WizardState:
    def __init__(self):
        self.mod_choice: str = "None"  # "AtlasOS", "ReviOS", "WinClick", "None"
        self.browser_choice: str = "None"
        self.remove_edge: bool = True
        self.remove_defender: bool = True
        self.install_vcredist: bool = True
        self.install_directx: bool = True
        self.install_runtime: bool = True
        self.install_drivers: bool = True
        self.compress_system: bool = True
        self.visual_effects: bool = True
        self.performance_profile: str = "balanced"  # "power_saving", "balanced", "extreme"


class StepBase(ctk.CTkFrame):
    step_title = "Step"
    step_subtitle = ""

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, fg_color="transparent")
        self.state = state
        self.on_next = on_next
        self.on_back = on_back

    def validate(self) -> Tuple[bool, str]:
        return True, ""


class TileOption(ctk.CTkFrame):
    def __init__(
        self,
        master,
        text: str,
        icon_key: Optional[str] = None,
        mode: str = "radio",
        variable=None,
        value=None,
        on_change: Optional[Callable] = None,
        width: int = 230,
        height: int = 120,
    ):
        super().__init__(master, corner_radius=16, width=width, height=height)
        self.pack_propagate(False)

        self._mode = mode
        self._variable = variable
        self._value = value
        self._on_change = on_change

        self._icon = resource_icon(icon_key or "")
        self._bg_normal = "#15151A"
        self._bg_selected = "#1F2633"
        self._border_normal = "#23232A"
        self._border_selected = "#2A72FF"

        self.configure(fg_color=self._bg_normal, border_width=1, border_color=self._border_normal)

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=12, pady=12)

        icon_holder = ctk.CTkFrame(inner, fg_color="transparent")
        icon_holder.pack(fill="both", expand=True)
        icon_label(icon_holder, self._icon).pack(pady=(8, 6))

        self._lbl = ctk.CTkLabel(
            inner,
            text=text,
            font=ctk.CTkFont(size=13, weight="bold"),
            wraplength=width - 28,
            justify="center",
        )
        self._lbl.pack(pady=(0, 8))

        for w in (self, inner, icon_holder, self._lbl):
            w.bind("<Button-1>", self._clicked)

        self.refresh()

    def _clicked(self, _evt=None):
        if self._mode == "radio":
            if self._variable is not None and self._value is not None:
                self._variable.set(self._value)
        elif self._mode == "check":
            if self._variable is not None:
                self._variable.set(not bool(self._variable.get()))
        self.refresh()
        if self._on_change:
            self._on_change()

    def refresh(self):
        selected = False
        if self._mode == "radio":
            if self._variable is not None and self._value is not None:
                selected = str(self._variable.get()) == str(self._value)
        elif self._mode == "check":
            if self._variable is not None:
                selected = bool(self._variable.get())

        if selected:
            self.configure(fg_color=self._bg_selected, border_width=2, border_color=self._border_selected)
        else:
            self.configure(fg_color=self._bg_normal, border_width=1, border_color=self._border_normal)


class ModTileOption(ctk.CTkFrame):
    def __init__(
        self,
        master,
        text: str,
        desc: str = "",
        icon_key: Optional[str] = None,
        mode: str = "radio",
        variable=None,
        value=None,
        on_change: Optional[Callable] = None,
        width: int = 400,
        height: int = 100,
    ):
        super().__init__(master, corner_radius=16, width=width, height=height)
        self.pack_propagate(False)

        self._mode = mode
        self._variable = variable
        self._value = value
        self._on_change = on_change

        self._icon = resource_icon(icon_key or "")
        self._bg_normal = "#15151A"
        self._bg_selected = "#1F2633"
        self._border_normal = "#23232A"
        self._border_selected = "#2A72FF"

        self.configure(fg_color=self._bg_normal, border_width=1, border_color=self._border_normal)

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=12, pady=12)

        icon_holder = ctk.CTkFrame(inner, fg_color="transparent", width=50)
        icon_holder.pack(side="left", fill="y", padx=(0, 12))
        icon_holder.pack_propagate(False)
        icon_label(icon_holder, self._icon).pack(expand=True)

        text_frame = ctk.CTkFrame(inner, fg_color="transparent")
        text_frame.pack(side="left", fill="both", expand=True)
        
        self._lbl_title = ctk.CTkLabel(
            text_frame,
            text=text,
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        self._lbl_title.pack(anchor="w", pady=(0, 4))
        
        self._lbl_desc = ctk.CTkLabel(
            text_frame,
            text=desc,
            font=ctk.CTkFont(size=11),
            text_color=("#6E6E6E", "#B0B0B0"),
            anchor="w",
            wraplength=280,
            justify="left",
        )
        self._lbl_desc.pack(anchor="w")

        for w in (self, inner, icon_holder, text_frame, self._lbl_title, self._lbl_desc):
            w.bind("<Button-1>", self._clicked)

        self.refresh()

    def _clicked(self, _evt=None):
        if self._mode == "radio":
            if self._variable is not None and self._value is not None:
                self._variable.set(self._value)
        elif self._mode == "check":
            if self._variable is not None:
                self._variable.set(not bool(self._variable.get()))
        self.refresh()
        if self._on_change:
            self._on_change()

    def refresh(self):
        selected = False
        if self._mode == "radio":
            if self._variable is not None and self._value is not None:
                selected = str(self._variable.get()) == str(self._value)
        elif self._mode == "check":
            if self._variable is not None:
                selected = bool(self._variable.get())

        if selected:
            self.configure(fg_color=self._bg_selected, border_width=2, border_color=self._border_selected)
        else:
            self.configure(fg_color=self._bg_normal, border_width=1, border_color=self._border_normal)


class ProfileTileOption(ctk.CTkFrame):
    def __init__(
        self,
        master,
        text: str,
        desc: str = "",
        icon_key: Optional[str] = None,
        mode: str = "radio",
        variable=None,
        value=None,
        on_change: Optional[Callable] = None,
        width: int = 320,
        height: int = 120,
    ):
        super().__init__(master, corner_radius=16, width=width, height=height)
        self.pack_propagate(False)

        self._mode = mode
        self._variable = variable
        self._value = value
        self._on_change = on_change

        self._icon = resource_icon(icon_key or "")
        self._bg_normal = "#15151A"
        self._bg_selected = "#1F2633"
        self._border_normal = "#23232A"
        self._border_selected = "#2A72FF"

        self.configure(fg_color=self._bg_normal, border_width=1, border_color=self._border_normal)

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=12, pady=12)

        icon_holder = ctk.CTkFrame(inner, fg_color="transparent", width=50)
        icon_holder.pack(side="left", fill="y", padx=(0, 12))
        icon_holder.pack_propagate(False)
        icon_label(icon_holder, self._icon).pack(expand=True)

        text_frame = ctk.CTkFrame(inner, fg_color="transparent")
        text_frame.pack(side="left", fill="both", expand=True)
        
        self._lbl_title = ctk.CTkLabel(
            text_frame,
            text=text,
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        self._lbl_title.pack(anchor="w", pady=(0, 4))
        
        self._lbl_desc = ctk.CTkLabel(
            text_frame,
            text=desc,
            font=ctk.CTkFont(size=11),
            text_color=("#6E6E6E", "#B0B0B0"),
            anchor="w",
            wraplength=200,
            justify="left",
        )
        self._lbl_desc.pack(anchor="w")

        for w in (self, inner, icon_holder, text_frame, self._lbl_title, self._lbl_desc):
            w.bind("<Button-1>", self._clicked)

        self.refresh()

    def _clicked(self, _evt=None):
        if self._mode == "radio":
            if self._variable is not None and self._value is not None:
                self._variable.set(self._value)
        elif self._mode == "check":
            if self._variable is not None:
                self._variable.set(not bool(self._variable.get()))
        self.refresh()
        if self._on_change:
            self._on_change()

    def refresh(self):
        selected = False
        if self._mode == "radio":
            if self._variable is not None and self._value is not None:
                selected = str(self._variable.get()) == str(self._value)
        elif self._mode == "check":
            if self._variable is not None:
                selected = bool(self._variable.get())

        if selected:
            self.configure(fg_color=self._bg_selected, border_width=2, border_color=self._border_selected)
        else:
            self.configure(fg_color=self._bg_normal, border_width=1, border_color=self._border_normal)


class StepWelcome(StepBase):
    step_title = "Добро пожаловать"
    step_subtitle = "Extreme OS"

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)

        header = ctk.CTkLabel(self, text="Extreme OS", font=ctk.CTkFont(size=28, weight="bold"))
        header.pack(anchor="w", padx=24, pady=(24, 6))

        sub = ctk.CTkLabel(
            self,
            text="Модификации Windows 11\nУстановщик выполнит оптимизацию в один клик!",
            font=ctk.CTkFont(size=14),
            text_color=("#7A7A7A", "#B0B0B0"),
            wraplength=740,
            justify="left",
        )
        sub.pack(anchor="w", padx=24, pady=(0, 18))

        warn = ctk.CTkFrame(self, corner_radius=14)
        warn.pack(fill="x", padx=24, pady=(0, 18))

        ctk.CTkLabel(warn, text="Важно", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(12, 2))
        ctk.CTkLabel(
            warn,
            text="• Данная утилита предназначена ТОЛЬКО для Windows 11\n• Рекомендуется использовать Windows 11 Pro 24H2+\n• Запускайте установщик от имени Администратора\n• Утилита предназначена для свежеустановленной системы\n• Во время установки Проводник (explorer.exe) будет закрыт",
            wraplength=740,
            justify="left",
            text_color=("#6E6E6E", "#B0B0B0"),
        ).pack(anchor="w", padx=16, pady=(0, 12))


class StepModChoice(StepBase):
    step_title = "Выбор модификации"
    step_subtitle = "Выберите основную модификацию"

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)

        title = ctk.CTkLabel(self, text="Выбор модификации", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="w", padx=24, pady=(24, 10))

        ctk.CTkLabel(
            self,
            text="Выберите основную модификацию для установки:",
            text_color=("#6E6E6E", "#B0B0B0"),
        ).pack(anchor="w", padx=24, pady=(0, 10))

        self.var = ctk.StringVar(value=state.mod_choice)

        tiles_frame = ctk.CTkFrame(self, fg_color="transparent")
        tiles_frame.pack(fill="both", expand=True, padx=24, pady=12)

        def refresh_all():
            for t in tile_widgets:
                t.refresh()

        tile_widgets = []

        tile1 = ModTileOption(
            tiles_frame,
            text="AtlasOS",
            desc="Агрессивная оптимизация Windows 11. Удаление телеметрии, служб, компонентов. Максимальная производительность для игр.",
            icon_key="atlas",
            mode="radio",
            variable=self.var,
            value="AtlasOS",
            on_change=refresh_all,
            width=700,
            height=100,
        )
        tile1.pack(pady=10, fill="x")
        tile_widgets.append(tile1)

        tile2 = ModTileOption(
            tiles_frame,
            text="ReviOS",
            desc="Оптимизация для гейминга и производительности. Отключает ненужные службы, улучшает отклик системы, снижает задержки.",
            icon_key="revios",
            mode="radio",
            variable=self.var,
            value="ReviOS",
            on_change=refresh_all,
            width=700,
            height=100,
        )
        tile2.pack(pady=10, fill="x")
        tile_widgets.append(tile2)

        tile3 = ModTileOption(
            tiles_frame,
            text="WinClick",
            desc="Сбалансированная оптимизация Windows 11. Удаление мусора, приложений, настройка параметров, твики без потери функциональности.",
            icon_key="winclick",
            mode="radio",
            variable=self.var,
            value="WinClick",
            on_change=refresh_all,
            width=700,
            height=100,
        )
        tile3.pack(pady=10, fill="x")
        tile_widgets.append(tile3)

        tile4 = ModTileOption(
            tiles_frame,
            text="ExtremeOS",
            desc="Будут выполнены только дополнительные настройки (ExtremeOS)",
            mode="radio",
            variable=self.var,
            value="None",
            on_change=refresh_all,
            width=700,
            height=100,
        )
        tile4.pack(pady=10, fill="x")
        tile_widgets.append(tile4)

    def validate(self) -> Tuple[bool, str]:
        self.state.mod_choice = str(self.var.get())
        return True, ""


class StepBrowser(StepBase):
    step_title = "Браузер"
    step_subtitle = "Выберите браузер для установки"

    BROWSER_LIST = ["None", "Cent", "CatsXP", "Floorp", "Brave", "Zen"]

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)

        title = ctk.CTkLabel(self, text="Установка браузера", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="w", padx=24, pady=(24, 10))

        ctk.CTkLabel(
            self,
            text="Выберите браузер для установки:",
            text_color=("#6E6E6E", "#B0B0B0"),
        ).pack(anchor="w", padx=24, pady=(0, 10))

        self.var = ctk.StringVar(value=state.browser_choice)

        tiles = ctk.CTkFrame(self, corner_radius=14)
        tiles.pack(fill="both", expand=True, padx=24, pady=12)

        def refresh_all():
            for t in tile_widgets:
                t.refresh()

        tile_widgets = []
        cols = 2
        for idx, name in enumerate(self.BROWSER_LIST):
            r = idx // cols
            c = idx % cols
            t = TileOption(
                tiles,
                text=name if name != "None" else "Без браузера",
                icon_key=name.lower(),
                mode="radio",
                variable=self.var,
                value=name,
                on_change=refresh_all,
                width=320,
                height=120,
            )
            t.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")
            tile_widgets.append(t)

        tiles.grid_columnconfigure(0, weight=1)
        tiles.grid_columnconfigure(1, weight=1)

    def validate(self) -> Tuple[bool, str]:
        self.state.browser_choice = str(self.var.get())
        return True, ""


class StepOptions(StepBase):
    step_title = "Опции"
    step_subtitle = "Выберите дополнительные действия"

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)

        title = ctk.CTkLabel(self, text="Выбор опций", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="w", padx=24, pady=(24, 10))

        ctk.CTkLabel(
            self,
            text="Включите или отключите нужные действия с помощью переключателей:",
            text_color=("#6E6E6E", "#B0B0B0"),
        ).pack(anchor="w", padx=24, pady=(0, 10))

        scroll = ctk.CTkScrollableFrame(self, corner_radius=14)
        scroll.pack(fill="both", expand=True, padx=24, pady=12)

        self.var_edge = ctk.BooleanVar(value=state.remove_edge)
        self.var_defender = ctk.BooleanVar(value=state.remove_defender)
        self.var_vcredist = ctk.BooleanVar(value=state.install_vcredist)
        self.var_directx = ctk.BooleanVar(value=state.install_directx)
        self.var_runtime = ctk.BooleanVar(value=state.install_runtime)
        self.var_drivers = ctk.BooleanVar(value=state.install_drivers)
        self.var_compress = ctk.BooleanVar(value=state.compress_system)
        self.var_visual = ctk.BooleanVar(value=state.visual_effects)

        # Option 1: Remove Edge
        frame1 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame1.pack(fill="x", pady=8, padx=10)
        
        icon1 = resource_icon("edge")
        if icon1:
            icon_label(frame1, icon1).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame1, text="Удалить Microsoft Edge", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame1, text="Полностью удаляет браузер Edge и компонент WebView2", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch1 = ctk.CTkSwitch(frame1, text="", variable=self.var_edge, onvalue=True, offvalue=False, width=50)
        switch1.pack(side="right")

        # Option 2: Remove Defender
        frame2 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame2.pack(fill="x", pady=8, padx=10)
        
        icon2 = resource_icon("defender")
        if icon2:
            icon_label(frame2, icon2).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame2, text="Удалить Microsoft Defender", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame2, text="Полностью удаляет Защитник Windows", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch2 = ctk.CTkSwitch(frame2, text="", variable=self.var_defender, onvalue=True, offvalue=False, width=50)
        switch2.pack(side="right")

        # Option 3: Install Visual C++
        frame3 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame3.pack(fill="x", pady=8, padx=10)
        
        icon3 = resource_icon("vcredist")
        if icon3:
            icon_label(frame3, icon3).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame3, text="Установить Microsoft Visual C++", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame3, text="Устанавливает Visual C++ 2005-2022 (All-in-One)", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch3 = ctk.CTkSwitch(frame3, text="", variable=self.var_vcredist, onvalue=True, offvalue=False, width=50)
        switch3.pack(side="right")

        # Option 4: Install Custom DirectX V2
        frame4 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame4.pack(fill="x", pady=8, padx=10)
        
        icon4 = resource_icon("directx")
        if icon4:
            icon_label(frame4, icon4).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame4, text="Установить Custom DirectX V2", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame4, text="Устанавливает кастомный DirectX 12 (Custom DirectX V2)", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch4 = ctk.CTkSwitch(frame4, text="", variable=self.var_directx, onvalue=True, offvalue=False, width=50)
        switch4.pack(side="right")

        # Option 5: Install .NET SDK 9.0.312
        frame5 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame5.pack(fill="x", pady=8, padx=10)
        
        icon5 = resource_icon("runtime")
        if icon5:
            icon_label(frame5, icon5).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame5, text="Установить .NET SDK 9.0.312", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame5, text="Устанавливает .NET SDK 9.0.312 (x64)", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch5 = ctk.CTkSwitch(frame5, text="", variable=self.var_runtime, onvalue=True, offvalue=False, width=50)
        switch5.pack(side="right")

        # Option 6: Install Drivers
        frame6 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame6.pack(fill="x", pady=8, padx=10)
        
        icon6 = resource_icon("drivers")
        if icon6:
            icon_label(frame6, icon6).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame6, text="Установить драйверы", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame6, text="Устанавливает драйверы из папки Drivers на рабочем столе (если есть)", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch6 = ctk.CTkSwitch(frame6, text="", variable=self.var_drivers, onvalue=True, offvalue=False, width=50)
        switch6.pack(side="right")

        # Option 7: Visual Effects
        frame7 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame7.pack(fill="x", pady=8, padx=10)
        
        icon7 = resource_icon("visual")
        if icon7:
            icon_label(frame7, icon7).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame7, text="Визуальные эффекты", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame7, text="Применяет визуальные твики: темная тема, синие папки, иконки, обои, секунды в трее и другое", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch7 = ctk.CTkSwitch(frame7, text="", variable=self.var_visual, onvalue=True, offvalue=False, width=50)
        switch7.pack(side="right")

        # Option 8: Compress System
        frame8 = ctk.CTkFrame(scroll, fg_color="transparent")
        frame8.pack(fill="x", pady=8, padx=10)
        
        icon8 = resource_icon("compress")
        if icon8:
            icon_label(frame8, icon8).pack(side="left", padx=(0, 12))
        
        ctk.CTkLabel(frame8, text="Сжать систему LZX", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(frame8, text="Сжимает все системные файлы (последний шаг). На слабых ПК может занимать много времени", text_color=("#6E6E6E", "#B0B0B0"), font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 20), fill="x", expand=True)
        switch8 = ctk.CTkSwitch(frame8, text="", variable=self.var_compress, onvalue=True, offvalue=False, width=50)
        switch8.pack(side="right")

    def validate(self) -> Tuple[bool, str]:
        self.state.remove_edge = bool(self.var_edge.get())
        self.state.remove_defender = bool(self.var_defender.get())
        self.state.install_vcredist = bool(self.var_vcredist.get())
        self.state.install_directx = bool(self.var_directx.get())
        self.state.install_runtime = bool(self.var_runtime.get())
        self.state.install_drivers = bool(self.var_drivers.get())
        self.state.compress_system = bool(self.var_compress.get())
        self.state.visual_effects = bool(self.var_visual.get())
        return True, ""


class StepPerformanceProfile(StepBase):
    step_title = "Профиль производительности"
    step_subtitle = "Выберите уровень оптимизации ExtremeOS"

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)

        title = ctk.CTkLabel(self, text="Профиль производительности", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="w", padx=24, pady=(24, 10))

        ctk.CTkLabel(
            self,
            text="Выберите уровень оптимизации для ExtremeOS:",
            text_color=("#6E6E6E", "#B0B0B0"),
        ).pack(anchor="w", padx=24, pady=(0, 10))

        self.var = ctk.StringVar(value=state.performance_profile)

        tiles_frame = ctk.CTkFrame(self, fg_color="transparent")
        tiles_frame.pack(fill="both", expand=True, padx=24, pady=12)

        def refresh_all():
            for t in tile_widgets:
                t.refresh()

        tile_widgets = []

        # Profile 1: Энергосберегательный
        tile1 = ProfileTileOption(
            tiles_frame,
            text="Энергосберегательный",
            desc="Минимальное энергопотребление. Отключает фоновые процессы, снижает нагрузку на ЦП. Идеально для ноутбуков.",
            icon_key="power_saving",
            mode="radio",
            variable=self.var,
            value="power_saving",
            on_change=refresh_all,
            width=340,
            height=130,
        )
        tile1.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
        tile_widgets.append(tile1)

        # Profile 2: Идеальный
        tile2 = ProfileTileOption(
            tiles_frame,
            text="Идеальный",
            desc="Сбалансированная оптимизация. Хорошая производительность при умеренном энергопотреблении. Рекомендуется для большинства пользователей.",
            icon_key="balanced",
            mode="radio",
            variable=self.var,
            value="balanced",
            on_change=refresh_all,
            width=340,
            height=130,
        )
        tile2.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
        tile_widgets.append(tile2)

        # Profile 3: Экстремальный
        tile3 = ProfileTileOption(
            tiles_frame,
            text="Экстремальный",
            desc="Максимальная производительность. Отключает все службы, фоновые процессы и визуальные эффекты. Только для мощных ПК!",
            icon_key="extreme",
            mode="radio",
            variable=self.var,
            value="extreme",
            on_change=refresh_all,
            width=340,
            height=130,
        )
        tile3.grid(row=1, column=0, padx=15, pady=15, sticky="nsew")
        tile_widgets.append(tile3)

        tiles_frame.grid_columnconfigure(0, weight=1)
        tiles_frame.grid_columnconfigure(1, weight=1)

    def validate(self) -> Tuple[bool, str]:
        self.state.performance_profile = str(self.var.get())
        return True, ""


class StepReview(StepBase):
    step_title = "Проверка"
    step_subtitle = "Подтвердите выбор"

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)

        title = ctk.CTkLabel(self, text="Проверка настроек", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="w", padx=24, pady=(24, 10))

        self.info_box = ctk.CTkFrame(self, corner_radius=14)
        self.info_box.pack(fill="both", expand=True, padx=24, pady=12)
        self._render_info()

    def _render_info(self):
        for child in self.info_box.winfo_children():
            child.destroy()

        tasks = []
        
        mod_names = {
            "AtlasOS": "AtlasOS (агрессивная оптимизация)", 
            "ReviOS": "ReviOS (оптимизация для гейминга)",
            "WinClick": "WinClick (сбалансированная оптимизация)",
            "None": "ExtremeOS (только дополнительные настройки)"
        }
        tasks.append(f"🎯 Основная модификация: {mod_names.get(self.state.mod_choice, self.state.mod_choice)}")
        tasks.append("")
        
        profile_names = {
            "power_saving": "Энергосберегательный",
            "balanced": "Идеальный",
            "extreme": "Экстремальный"
        }
        tasks.append(f"⚡ Профиль производительности: {profile_names.get(self.state.performance_profile, self.state.performance_profile)}")
        tasks.append("")
        
        if self.state.browser_choice != "None":
            tasks.append(f"📦 Установка браузера: {self.state.browser_choice}")
        
        tasks.append("🔧 Дополнительные действия:")
        if self.state.remove_edge:
            tasks.append("  • Удаление Microsoft Edge")
        if self.state.remove_defender:
            tasks.append("  • Удаление Microsoft Defender")
        if self.state.install_drivers:
            tasks.append("  • Установка драйверов")
        if self.state.install_vcredist:
            tasks.append("  • Установка Microsoft Visual C++")
        if self.state.install_directx:
            tasks.append("  • Установка Custom DirectX V2")
        if self.state.install_runtime:
            tasks.append("  • Установка .NET SDK 9.0.312")
        if self.state.visual_effects:
            tasks.append("  • Визуальные твики")
        if self.state.compress_system:
            tasks.append("  • Сжатие системы LZX")

        ctk.CTkLabel(self.info_box, text="\n".join(tasks), justify="left", font=ctk.CTkFont(size=13), wraplength=800).pack(anchor="w", padx=16, pady=16)


class StepInstall(StepBase):
    step_title = "Установка"
    step_subtitle = "Выполнение"

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)
        self._is_running = False
        self._cancel_requested = False

        title = ctk.CTkLabel(self, text="Установка...", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="w", padx=24, pady=(24, 10))

        self.progress = ctk.CTkProgressBar(self)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=24, pady=(0, 10))

        self.status = ctk.CTkLabel(self, text="Готов", text_color=("#6E6E6E", "#B0B0B0"))
        self.status.pack(anchor="w", padx=24, pady=(0, 10))

        self.log = ctk.CTkTextbox(self, corner_radius=14, height=320)
        self.log.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.log.configure(state="disabled")

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(0, 18))

        self.btn_start = ctk.CTkButton(btns, text="Начать", command=self.start)
        self.btn_start.pack(side="left")

        self.btn_cancel = ctk.CTkButton(btns, text="Отмена", fg_color="#3A3A3A", hover_color="#2F2F2F", command=self.cancel)
        self.btn_cancel.pack(side="left", padx=10)

        self.btn_finish = ctk.CTkButton(btns, text="Далее", state="disabled", command=self.on_next)
        self.btn_finish.pack(side="right")

    def append_log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")
        try:
            t = text.rstrip("\n")
            if t:
                logger.info(t)
        except Exception:
            pass

    def set_status(self, text: str):
        self.status.configure(text=text)

    def update_progress(self, value: float):
        self.progress.set(value)

    def _restart_explorer(self):
        """Restart explorer.exe"""
        try:
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], capture_output=True, shell=True)
            time.sleep(1)
            subprocess.Popen(["explorer.exe"], shell=True)
            logger.info("Explorer restarted")
        except Exception as e:
            logger.warning(f"Failed to restart explorer: {e}")

    def _kill_explorer(self):
        """Kill explorer.exe before installation"""
        try:
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], capture_output=True, shell=True)
            logger.info("Explorer killed")
            time.sleep(0.5)
        except Exception as e:
            logger.warning(f"Failed to kill explorer: {e}")

    def start(self):
        if self._is_running:
            return
        self._is_running = True
        self._cancel_requested = False
        self.btn_start.configure(state="disabled")
        self.btn_finish.configure(state="disabled")
        
        # Kill explorer before starting
        self._kill_explorer()
        
        self.append_log(f"=== {APP_TITLE} ===\nНачало установки...\nПроводник (explorer.exe) закрыт для оптимальной работы\n\n")
        logger.info("Installation started")
        threading.Thread(target=self._run, daemon=True).start()

    def cancel(self):
        if not self._is_running:
            return
        self._cancel_requested = True
        self.append_log("\nОтмена запрошена...\n")
        logger.info("Cancellation requested")

    def _run_browser_install(self):
        """Run browser installation via bat file"""
        browser_bat = None
        browser_name = self.state.browser_choice
        
        if browser_name == "Cent":
            browser_bat = "browser_cent.bat"
        elif browser_name == "CatsXP":
            browser_bat = "browser_catsxp.bat"
        elif browser_name == "Floorp":
            browser_bat = "browser_floorp.bat"
        elif browser_name == "Brave":
            browser_bat = "browser_brave.bat"
        elif browser_name == "Zen":
            browser_bat = "browser_zen.bat"
        else:
            return
        
        bat_path = os.path.join(WORK_DIR, browser_bat)
        if not os.path.exists(bat_path):
            self._ui(lambda: self.append_log(f"  Файл не найден: {bat_path}\n"))
            return
        
        self._ui(lambda: self.append_log(f"\n>>> Установка браузера {browser_name}\n"))
        code, output = run_bat_file(bat_path, lambda x: None)
        if code != 0 and output.strip():
            self._ui(lambda: self.append_log(f"  Предупреждение: {output[:200]}\n"))
        self._ui(lambda: self.append_log(f"  Установка {browser_name} завершена (код: {code})\n"))

    def _get_mod_steps(self) -> List[Tuple[str, str]]:
        """Get list of steps based on selected modification"""
        steps = []
        
        if self.state.mod_choice == "AtlasOS":
            steps.append(("atlas.bat", "Установка AtlasOS"))
        elif self.state.mod_choice == "WinClick":
            steps.append(("01_cleanup.bat", "Удаление мусора"))
            steps.append(("02_apps.bat", "Удаление предустановленных приложений"))
            steps.append(("05_components.bat", "Удаление дополнительных компонентов"))
            steps.append(("06_schtasks.bat", "Отключение лишнего в Планировщике задач"))
            steps.append(("07_optimize.bat", "Оптимизация параметров"))
            steps.append(("08_windows_update.bat", "Настройка Центра обновления Windows"))
            steps.append(("09_tweaks.bat", "Применение полезных твиков"))
        elif self.state.mod_choice == "ReviOS":
            steps.append(("revi.bat", "Установка ReviOS"))
        
        return steps

    def _get_extra_steps(self) -> List[Tuple[str, str]]:
        """Get list of extra steps based on user options"""
        steps = []
        
        if self.state.remove_edge:
            steps.append(("03_edge.bat", "Удаление браузера Edge и WebView2"))
        if self.state.remove_defender:
            steps.append(("04_defender.bat", "Удаление Защитника Windows"))
        if self.state.install_drivers:
            steps.append(("10_drivers.bat", "Установка драйверов"))
        if self.state.install_vcredist:
            steps.append(("11_vcredist.bat", "Установка Microsoft Visual C++"))
        if self.state.install_directx:
            steps.append(("12_directx.bat", "Установка Custom DirectX V2"))
        if self.state.install_runtime:
            steps.append(("13_runtime.bat", "Установка .NET SDK 9.0.312"))
        if self.state.visual_effects:
            steps.append(("14_visual.bat", "Установка визуальных твиков"))
        if self.state.compress_system:
            steps.append(("15_compress.bat", "Сжатие системы LZX"))
        
        # Performance profile bat files
        profile_bat = None
        if self.state.performance_profile == "power_saving":
            profile_bat = "profile_power_saving.bat"
        elif self.state.performance_profile == "balanced":
            profile_bat = "profile_balanced.bat"
        elif self.state.performance_profile == "extreme":
            profile_bat = "profile_extreme.bat"
        
        if profile_bat:
            steps.append((profile_bat, f"Применение профиля: {self.state.performance_profile}"))
        
        # Always add extreme settings at the end
        steps.append(("16_settings.bat", "Остальные настройки"))
        # steps.append(("17_extreme.bat", "Игровые настройки"))
        
        return steps

    def _run_winclick_steps(self):
        """Run all steps based on selected modification and options"""
        all_steps = []
        
        # Add modification steps
        mod_steps = self._get_mod_steps()
        all_steps.extend(mod_steps)
        
        # Add extra steps
        extra_steps = self._get_extra_steps()
        all_steps.extend(extra_steps)
        
        total = len(all_steps)
        self._ui(lambda: self.update_progress(0))

        for idx, (bat_file, description) in enumerate(all_steps):
            if self._cancel_requested:
                self._ui(lambda: self.set_status("Отменено"))
                self._ui(lambda: self.append_log("\nУстановка отменена пользователем.\n"))
                break

            step_num = idx + 1
            self._ui(lambda: self.set_status(f"[{step_num}/{total}] {description}"))
            self._ui(lambda: self.append_log(f"\n>>> {description} [{step_num}/{total}]\n"))
            print(f">>> {description} [{step_num}/{total}]")
            logger.info(f"Step start: {description}")

            bat_path = os.path.join(WORK_DIR, bat_file)
            if not os.path.exists(bat_path):
                self._ui(lambda: self.append_log(f"  Файл не найден: {bat_path}\n"))
                self._ui(lambda: self.update_progress(step_num / total))
                continue

            code, output = run_bat_file(bat_path, lambda x: None)
            if code != 0 and output.strip():
                self._ui(lambda: self.append_log(f"  Предупреждение: {output[:200]}\n"))
            self._ui(lambda: self.append_log(f"  Завершено (код: {code})\n"))
            logger.info(f"Step finished: {description} (code={code})")
            self._ui(lambda: self.update_progress(step_num / total))
            time.sleep(0.1)

    def _run(self):
        # Install browser if selected
        if self.state.browser_choice != "None":
            self._ui(lambda: self.set_status(f"Установка браузера {self.state.browser_choice}..."))
            self._ui(lambda: self.append_log(f"\n=== Установка браузера: {self.state.browser_choice} ===\n"))
            self._run_browser_install()

        # Run main steps
        self._ui(lambda: self.set_status("Запуск оптимизации..."))
        self._ui(lambda: self.append_log("\n=== Запуск оптимизации ===\n"))
        self._run_winclick_steps()

        self._is_running = False
        if not self._cancel_requested:
            self._ui(lambda: self.set_status("Готово!"))
            self._ui(lambda: self.append_log("\n=== Установка завершена ===\n"))
            logger.info("Installation finished")
            
            # Restart explorer after completion
            self._ui(lambda: self.append_log("\nПерезапуск Проводника...\n"))
            self._restart_explorer()
            
        self._ui(lambda: self.btn_finish.configure(state="normal"))

    def _ui(self, fn: Callable):
        self.after(0, fn)


class StepDone(StepBase):
    step_title = "Завершение"
    step_subtitle = "Готово"

    def __init__(self, master, state: WizardState, on_next: Callable, on_back: Callable):
        super().__init__(master, state, on_next, on_back)

        title = ctk.CTkLabel(self, text="Установка завершена!", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(anchor="w", padx=24, pady=(24, 8))

        ctk.CTkLabel(self, text="Оптимизация Windows 11 выполнена.\n\nРекомендуется перезагрузить компьютер для применения всех изменений.", text_color=("#6E6E6E", "#B0B0B0"), wraplength=700, justify="left").pack(anchor="w", padx=24, pady=(0, 20))

        self.btn_reboot = ctk.CTkButton(self, text="Перезагрузить сейчас", command=self._reboot, fg_color="#2A72FF", height=40, width=200)
        self.btn_reboot.pack(anchor="w", padx=24, pady=10)

        ctk.CTkLabel(self, text="Вы также можете закрыть установщик и перезагрузиться позже.", text_color=("#6E6E6E", "#B0B0B0")).pack(anchor="w", padx=24, pady=(10, 0))

    def _reboot(self):
        if messagebox.askyesno("Перезагрузка", "Перезагрузить компьютер сейчас?"):
            subprocess.run(["shutdown", "/r", "/t", "5"], shell=True)
            self.on_next()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title(APP_TITLE)
        self.geometry("1400x720")
        self.minsize(1400, 720)

        self.state_data = WizardState()
        self.steps = [StepWelcome, StepModChoice, StepBrowser, StepOptions, StepPerformanceProfile, StepReview, StepInstall, StepDone]
        self.step_index = 0
        self.step_frame: Optional[StepBase] = None

        self._build_layout()
        self._show_step(0)

    def _build_layout(self):
        root = ctk.CTkFrame(self, fg_color="transparent")
        root.pack(fill="both", expand=True)

        self.nav = ctk.CTkFrame(root, width=240, corner_radius=0, fg_color=("#0B0B0D", "#0B0B0D"))
        self.nav.pack(side="left", fill="y")
        self.nav.pack_propagate(False)

        brand = ctk.CTkFrame(self.nav, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(18, 10))
        ctk.CTkLabel(brand, text="Extreme OS", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(brand, text="Модификации Windows 11", text_color=("#6E6E6E", "#B0B0B0")).pack(anchor="w", pady=(2, 0))

        self.nav_buttons = []
        nav_list = ctk.CTkFrame(self.nav, fg_color="transparent")
        nav_list.pack(fill="both", expand=True, padx=12, pady=10)

        for idx, cls in enumerate(self.steps):
            b = ctk.CTkButton(nav_list, text=cls.step_title, anchor="w", fg_color="transparent", hover_color="#17171B", text_color=("#D0D0D0", "#DADADA"), command=lambda i=idx: self._jump_to(i))
            b.pack(fill="x", pady=4)
            self.nav_buttons.append(b)

        self.main = ctk.CTkFrame(root, corner_radius=0, fg_color=("#0E0E10", "#0E0E10"))
        self.main.pack(side="left", fill="both", expand=True)

        self.footer = ctk.CTkFrame(self.main, fg_color="transparent")
        self.footer.pack(side="bottom", fill="x", padx=24, pady=18)

        self.btn_back = ctk.CTkButton(self.footer, text="Назад", fg_color="#2A2A2E", hover_color="#222226", command=self.back)
        self.btn_back.pack(side="left")

        self.btn_next = ctk.CTkButton(self.footer, text="Далее", command=self.next)
        self.btn_next.pack(side="right")

        self.error = ctk.CTkLabel(self.footer, text="", text_color=("#E08080", "#E08080"))
        self.error.pack(side="right", padx=12)

        self.content_host = ctk.CTkFrame(self.main, fg_color="transparent")
        self.content_host.pack(side="top", fill="both", expand=True)

    def _jump_to(self, index: int):
        if index > self.step_index:
            return
        self._show_step(index)

    def _update_nav(self):
        for idx, b in enumerate(self.nav_buttons):
            if idx == self.step_index:
                b.configure(fg_color="#17171B")
            else:
                b.configure(fg_color="transparent")
            if idx > self.step_index:
                b.configure(state="disabled", text_color=("#555555", "#555555"))
            else:
                b.configure(state="normal", text_color=("#D0D0D0", "#DADADA"))

    def _show_step(self, index: int):
        self.step_index = index
        self._update_nav()
        self.error.configure(text="")

        if self.step_frame:
            self.step_frame.destroy()

        cls = self.steps[index]
        self.step_frame = cls(self.content_host, self.state_data, self.next, self.back)
        self.step_frame.pack(fill="both", expand=True)

        is_first = index == 0
        is_last = index == len(self.steps) - 1
        self.btn_back.configure(state="disabled" if is_first else "normal")
        self.btn_next.configure(state="disabled" if is_last else "normal")

        if cls is StepInstall:
            self.btn_back.configure(state="disabled")
            self.btn_next.configure(state="disabled")
        elif cls is StepDone:
            self.btn_back.configure(state="disabled")
            self.btn_next.configure(text="Закрыть", command=self.destroy, state="normal")
        else:
            self.btn_next.configure(text="Далее", command=self.next)

    def back(self):
        if self.step_index <= 0:
            return
        self._show_step(self.step_index - 1)

    def next(self):
        if self.step_frame is None:
            return
        ok, msg = self.step_frame.validate()
        if not ok:
            self.error.configure(text=msg)
            return
        next_index = min(len(self.steps) - 1, self.step_index + 1)
        self._show_step(next_index)


def main():
    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(ICONS_DIR, exist_ok=True)
    _setup_logging()
    
    # Check Windows version
    is_win11, version_msg = check_windows_version()
    if not is_win11:
        logger.error(f"Unsupported Windows version: {version_msg}")
        messagebox.showerror(
            "Неподдерживаемая версия Windows",
            f"Данная утилита предназначена ТОЛЬКО для Windows 11!\n\n{version_msg}\n\nУстановка будет остановлена."
        )
    else:
        logger.info(f"Windows version check passed: {version_msg}")
    
    try:
        os.chdir(WORK_DIR)
        logger.info(f"Changed working directory to: {WORK_DIR}")
    except Exception as e:
        logger.warning(f"Failed to chdir to WORK_DIR: {e}")
    
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            messagebox.showwarning("Предупреждение", "Рекомендуется запустить программу от имени Администратора для полной функциональности.")
    except:
        pass
    
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
