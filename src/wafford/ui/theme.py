from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WaffordTheme:
    name: str
    primary: str
    secondary: str
    accent: str
    background: str
    surface: str
    error: str
    success: str
    warning: str
    text: str
    muted: str

    def to_textual_css(self) -> str:
        return f"""
$primary: {self.primary};
$secondary: {self.secondary};
$accent: {self.accent};
$background: {self.background};
$surface: {self.surface};
$error: {self.error};
$success: {self.success};
$warning: {self.warning};
$text: {self.text};
$muted: {self.muted};

Screen {{
    background: {self.background};
    color: {self.text};
}}

Button {{
    background: {self.primary};
    color: {self.text};
}}
Button:hover {{
    background: {self.accent};
}}
Button.-primary {{
    background: {self.primary};
}}
Button.-success {{
    background: {self.success};
}}
Button.-error {{
    background: {self.error};
}}
Button.-warning {{
    background: {self.warning};
}}

DataTable {{
    background: {self.surface};
    color: {self.text};
}}
DataTable > .datatable--header {{
    background: {self.primary};
    color: {self.background};
    text-style: bold;
}}
DataTable > .datatable--cursor {{
    background: {self.accent};
}}
DataTable > .datatable--hover {{
    background: {self.surface};
}}

Input {{
    background: {self.surface};
    color: {self.text};
    border: tall {self.muted};
}}
Input:focus {{
    border: tall {self.primary};
}}

Label {{
    color: {self.text};
}}

Static {{
    color: {self.text};
}}

Toast {{
    background: {self.surface};
    color: {self.text};
}}

Select {{
    background: {self.surface};
    color: {self.text};
}}

TabbedContent {{
    background: {self.background};
}}

TabPane {{
    background: {self.background};
}}

MarkdownH1 {{
    color: {self.primary};
}}
MarkdownH2 {{
    color: {self.secondary};
}}
"""


THEMES: dict[str, WaffordTheme] = {
    "DARK": WaffordTheme(
        name="DARK",
        primary="#00ff9f",
        secondary="#00b8ff",
        accent="#ff00ff",
        background="#0a0e14",
        surface="#131820",
        error="#ff3333",
        success="#00ff9f",
        warning="#ffcc00",
        text="#e0e0e0",
        muted="#555555",
    ),
    "HACKER_GREEN": WaffordTheme(
        name="HACKER_GREEN",
        primary="#00ff00",
        secondary="#00cc00",
        accent="#33ff33",
        background="#000000",
        surface="#0a0a0a",
        error="#ff0000",
        success="#00ff00",
        warning="#aaff00",
        text="#00ff00",
        muted="#005500",
    ),
    "SOLARIZED": WaffordTheme(
        name="SOLARIZED",
        primary="#268bd2",
        secondary="#2aa198",
        accent="#cb4b16",
        background="#002b36",
        surface="#073642",
        error="#dc322f",
        success="#859900",
        warning="#b58900",
        text="#839496",
        muted="#586e75",
    ),
    "DRACULA": WaffordTheme(
        name="DRACULA",
        primary="#bd93f9",
        secondary="#8be9fd",
        accent="#ff79c6",
        background="#282a36",
        surface="#44475a",
        error="#ff5555",
        success="#50fa7b",
        warning="#f1fa8c",
        text="#f8f8f2",
        muted="#6272a4",
    ),
    "NORD": WaffordTheme(
        name="NORD",
        primary="#88c0d0",
        secondary="#81a1c1",
        accent="#b48ead",
        background="#2e3440",
        surface="#3b4252",
        error="#bf616a",
        success="#a3be8c",
        warning="#ebcb8b",
        text="#eceff4",
        muted="#4c566a",
    ),
    "LIGHT": WaffordTheme(
        name="LIGHT",
        primary="#0066cc",
        secondary="#009933",
        accent="#cc6600",
        background="#ffffff",
        surface="#f0f0f0",
        error="#cc0000",
        success="#009933",
        warning="#cc9900",
        text="#1a1a1a",
        muted="#999999",
    ),
    "CYBERPUNK": WaffordTheme(
        name="CYBERPUNK",
        primary="#fcee09",
        secondary="#ff2a6d",
        accent="#05d9e8",
        background="#01012b",
        surface="#0d1137",
        error="#ff2a6d",
        success="#05d9e8",
        warning="#fcee09",
        text="#d1f7ff",
        muted="#44446a",
    ),
    "OCEAN": WaffordTheme(
        name="OCEAN",
        primary="#0077b6",
        secondary="#00b4d8",
        accent="#ff6b6b",
        background="#023e8a",
        surface="#0096c7",
        error="#ff6b6b",
        success="#48cae4",
        warning="#ffc300",
        text="#caf0f8",
        muted="#00509d",
    ),
    "TOKYO_NIGHT": WaffordTheme(
        name="TOKYO_NIGHT",
        primary="#7aa2f7",
        secondary="#bb9af7",
        accent="#7dcfff",
        background="#1a1b26",
        surface="#24283b",
        error="#f7768e",
        success="#9ece6a",
        warning="#e0af68",
        text="#c0caf5",
        muted="#565f89",
    ),
    "CATPPUCCIN": WaffordTheme(
        name="CATPPUCCIN",
        primary="#89b4fa",
        secondary="#cba6f7",
        accent="#f5c2e7",
        background="#1e1e2e",
        surface="#313244",
        error="#f38ba8",
        success="#a6e3a1",
        warning="#f9e2af",
        text="#cdd6f4",
        muted="#6c7086",
    ),
    "OLED": WaffordTheme(
        name="OLED",
        primary="#00e5ff",
        secondary="#76ff03",
        accent="#ff007f",
        background="#000000",
        surface="#0c0c0c",
        error="#ff1744",
        success="#00e676",
        warning="#ffd600",
        text="#ffffff",
        muted="#333333",
    ),
    "SYNTHWAVE": WaffordTheme(
        name="SYNTHWAVE",
        primary="#ff7edb",
        secondary="#36f9f6",
        accent="#fe4450",
        background="#262335",
        surface="#34294f",
        error="#fe4450",
        success="#72f1b8",
        warning="#fede5d",
        text="#f92aad",
        muted="#614d85",
    ),
}

_DEFAULT_THEME = "DARK"


def get_theme(name: str | None = None) -> WaffordTheme:
    key = (name or _DEFAULT_THEME).upper()
    return THEMES.get(key, THEMES[_DEFAULT_THEME])


def list_themes() -> list[str]:
    return list(THEMES.keys())


def apply_theme(app, theme_name: str | None = None) -> None:
    """Register the Wafford theme with Textual and switch the app to it."""
    from textual.theme import Theme

    wt = get_theme(theme_name)
    textual_theme = Theme(
        name=wt.name.lower(),
        primary=wt.primary,
        secondary=wt.secondary,
        accent=wt.accent,
        error=wt.error,
        success=wt.success,
        warning=wt.warning,
        foreground=wt.text,
        background=wt.background,
        surface=wt.surface,
        dark=True,
        variables={
            "muted": wt.muted,
            "text": wt.text,
            "background": wt.background,
            "surface": wt.surface,
            "primary": wt.primary,
            "secondary": wt.secondary,
            "accent": wt.accent,
            "error": wt.error,
            "success": wt.success,
            "warning": wt.warning,
        },
    )
    try:
        app.unregister_theme(textual_theme.name)
    except Exception:
        pass
    app.register_theme(textual_theme)
    try:
        app.theme = textual_theme.name
    except Exception:
        pass
