from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import ProgressBar, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult


class WaffordProgressBar(Vertical):
    CSS = """
    WaffordProgressBar {
        height: 3;
        width: 100%;
    }
    #bar-row {
        height: 1;
        width: 100%;
        layout: horizontal;
    }
    #bar-label {
        width: auto;
        min-width: 20;
        color: $text;
        height: 1;
    }
    #bar-percent {
        width: 6;
        text-align: right;
        color: $accent;
        height: 1;
    }
    #bar-eta {
        width: 12;
        text-align: right;
        color: $muted;
        height: 1;
    }
    #bar-track {
        width: 1fr;
        height: 1;
    }
    """

    progress: reactive[float] = reactive(0.0)
    total: reactive[float] = reactive(100.0)
    label_text: reactive[str] = reactive("")
    indeterminate: reactive[bool] = reactive(False)
    _pulse_pos: float = 0.0

    def __init__(
        self,
        label: str = "",
        total: float = 100.0,
        show_eta: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.label_text = label
        self.total = total
        self.show_eta = show_eta
        self._start_time = 0.0
        self._eta_seconds: float = 0.0

    def compose(self) -> ComposeResult:
        with Horizontal(id="bar-row"):
            yield Static(self.label_text, id="bar-label")
            yield ProgressBar(total=100, show_eta=False, id="bar-track")
            yield Static("0%", id="bar-percent")
            yield Static("", id="bar-eta")

    def on_mount(self) -> None:
        import time
        self._start_time = time.time()

    def update_progress(self, current: float, total: float | None = None) -> None:
        if total is not None:
            self.total = total
        self.progress = current
        pct = (current / self.total * 100) if self.total > 0 else 0
        try:
            bar = self.query_one("#bar-track", ProgressBar)
            bar.progress = current
            bar.total = self.total
        except Exception:
            pass
        self.query_one("#bar-percent", Static).update(f"{pct:.1f}%")
        if self.show_eta and pct > 0:
            import time
            elapsed = time.time() - self._start_time
            if pct < 100:
                remaining = elapsed * (100 - pct) / pct
                self._eta_seconds = remaining
                self.query_one("#bar-eta", Static).update(self._format_eta(remaining))
            else:
                self.query_one("#bar-eta", Static).update("done")

    def set_indeterminate(self, active: bool) -> None:
        self.indeterminate = active
        if active:
            self._pulse_pos = 0.0

    def _format_eta(self, seconds: float) -> str:
        if seconds < 60:
            return f"ETA {seconds:.0f}s"
        if seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return f"ETA {m}m{s:02d}s"
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"ETA {h}h{m:02d}m"

    def reset(self) -> None:
        import time
        self.progress = 0.0
        self._start_time = time.time()
        try:
            bar = self.query_one("#bar-track", ProgressBar)
            bar.progress = 0
        except Exception:
            pass
        self.query_one("#bar-percent", Static).update("0%")
        self.query_one("#bar-eta", Static).update("")

    def set_label(self, label: str) -> None:
        self.label_text = label
        try:
            self.query_one("#bar-label", Static).update(label)
        except Exception:
            pass
