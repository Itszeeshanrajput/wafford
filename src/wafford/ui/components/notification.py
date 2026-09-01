from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class NotificationLevel(Enum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


LEVEL_STYLES = {
    NotificationLevel.INFO: ("#0077b6", "ℹ"),
    NotificationLevel.SUCCESS: ("#00ff9f", "✓"),
    NotificationLevel.WARNING: ("#ffcc00", "⚠"),
    NotificationLevel.ERROR: ("#ff3333", "✗"),
}


@dataclass
class Notification:
    title: str
    message: str
    level: NotificationLevel = NotificationLevel.INFO
    timestamp: float = field(default_factory=time.time)
    dismissed: bool = False
    duration: float = 5.0
    _id: int = 0

    @property
    def icon(self) -> str:
        return LEVEL_STYLES[self.level][1]

    @property
    def color(self) -> str:
        return LEVEL_STYLES[self.level][0]

    @property
    def age(self) -> float:
        return time.time() - self.timestamp


Listener = Callable[[Notification], None]


class NotificationManager:
    def __init__(self, max_history: int = 200, default_duration: float = 5.0) -> None:
        self._listeners: list[Listener] = []
        self._history: deque[Notification] = deque(maxlen=max_history)
        self._active: list[Notification] = []
        self._default_duration = default_duration
        self._counter = 0

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def unsubscribe(self, listener: Listener) -> None:
        self._listeners = [l for l in self._listeners if l is not listener]

    def _emit(self, notification: Notification) -> None:
        for listener in self._listeners:
            try:
                listener(notification)
            except Exception:
                pass

    def notify(
        self,
        title: str,
        message: str,
        level: NotificationLevel = NotificationLevel.INFO,
        duration: float | None = None,
    ) -> Notification:
        self._counter += 1
        n = Notification(
            title=title,
            message=message,
            level=level,
            duration=duration if duration is not None else self._default_duration,
            _id=self._counter,
        )
        self._history.append(n)
        self._active.append(n)
        self._emit(n)
        return n

    def info(self, title: str, message: str, duration: float | None = None) -> Notification:
        return self.notify(title, message, NotificationLevel.INFO, duration)

    def success(self, title: str, message: str, duration: float | None = None) -> Notification:
        return self.notify(title, message, NotificationLevel.SUCCESS, duration)

    def warning(self, title: str, message: str, duration: float | None = None) -> Notification:
        return self.notify(title, message, NotificationLevel.WARNING, duration)

    def error(self, title: str, message: str, duration: float | None = None) -> Notification:
        return self.notify(title, message, NotificationLevel.ERROR, duration)

    def dismiss(self, notification: Notification) -> None:
        notification.dismissed = True
        self._active = [n for n in self._active if n is not notification]

    def dismiss_all(self) -> None:
        for n in self._active:
            n.dismissed = True
        self._active.clear()

    def get_active(self) -> list[Notification]:
        now = time.time()
        self._active = [
            n for n in self._active
            if not n.dismissed and (now - n.timestamp) < n.duration
        ]
        return list(self._active)

    def get_history(self, limit: int = 50) -> list[Notification]:
        items = list(self._history)
        return items[-limit:]

    def clear_history(self) -> None:
        self._history.clear()


_manager_instance: NotificationManager | None = None


def get_notification_manager() -> NotificationManager:
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = NotificationManager()
    return _manager_instance
