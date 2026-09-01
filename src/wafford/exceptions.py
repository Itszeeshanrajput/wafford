"""Exception hierarchy for the Wafford framework."""

from __future__ import annotations


class WaffordError(Exception):
    """Base exception for all Wafford errors."""

    def __init__(self, message: str = "", *, code: int = 1) -> None:
        self.message = message
        self.code = code
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.message:
            return f"[{self.__class__.__name__}] {self.message}"
        return self.__class__.__name__


class InterfaceError(WaffordError):
    """Raised for interface-related errors."""

    def __init__(self, message: str = "", *, interface: str = "", code: int = 10) -> None:
        self.interface = interface
        super().__init__(message, code=code)

    def __str__(self) -> str:
        base = super().__str__()
        if self.interface:
            return f"{base} (interface: {self.interface})"
        return base


class ScanError(WaffordError):
    """Raised for scan-related errors."""

    def __init__(self, message: str = "", *, code: int = 20) -> None:
        super().__init__(message, code=code)


class AttackError(WaffordError):
    """Raised for attack-related errors."""

    def __init__(self, message: str = "", *, attack_type: str = "", code: int = 30) -> None:
        self.attack_type = attack_type
        super().__init__(message, code=code)

    def __str__(self) -> str:
        base = super().__str__()
        if self.attack_type:
            return f"{base} (attack: {self.attack_type})"
        return base


class CrackError(WaffordError):
    """Raised for password cracking errors."""

    def __init__(self, message: str = "", *, code: int = 40) -> None:
        super().__init__(message, code=code)


class ToolNotFoundError(WaffordError):
    """Raised when a required external tool is not found."""

    def __init__(self, message: str = "", *, tool: str = "", code: int = 50) -> None:
        self.tool = tool
        super().__init__(message, code=code)

    def __str__(self) -> str:
        base = super().__str__()
        if self.tool:
            return f"{base} (tool: {self.tool})"
        return base


class DependencyError(WaffordError):
    """Raised for missing or broken dependencies."""

    def __init__(
        self, message: str = "", *, missing: list[str] | None = None, code: int = 55
    ) -> None:
        self.missing = missing or []
        super().__init__(message, code=code)

    def __str__(self) -> str:
        base = super().__str__()
        if self.missing:
            return f"{base} (missing: {', '.join(self.missing)})"
        return base


class ConfigError(WaffordError):
    """Raised for configuration errors."""

    def __init__(self, message: str = "", *, code: int = 60) -> None:
        super().__init__(message, code=code)


class PluginError(WaffordError):
    """Raised for plugin-related errors."""

    def __init__(self, message: str = "", *, plugin: str = "", code: int = 70) -> None:
        self.plugin = plugin
        super().__init__(message, code=code)

    def __str__(self) -> str:
        base = super().__str__()
        if self.plugin:
            return f"{base} (plugin: {self.plugin})"
        return base


class PermissionError(WaffordError):  # noqa: A001
    """Raised for permission-related errors."""

    def __init__(self, message: str = "Root privileges required", *, code: int = 80) -> None:
        super().__init__(message, code=code)


class ValidationError(WaffordError):
    """Raised for input validation errors."""

    def __init__(self, message: str = "", *, field: str = "", code: int = 90) -> None:
        self.field = field
        super().__init__(message, code=code)

    def __str__(self) -> str:
        base = super().__str__()
        if self.field:
            return f"{base} (field: {self.field})"
        return base


class DatabaseError(WaffordError):
    """Raised for database-related errors."""

    def __init__(self, message: str = "", *, code: int = 100) -> None:
        super().__init__(message, code=code)


class ReportError(WaffordError):
    """Raised for report generation errors."""

    def __init__(self, message: str = "", *, code: int = 110) -> None:
        super().__init__(message, code=code)
