"""Wafford — Professional WiFi Auditing Framework."""

from __future__ import annotations

from wafford.version import (
    APP_AUTHOR,
    APP_DESCRIPTION,
    APP_LICENSE,
    APP_NAME,
    BUILD_DATE,
    PYTHON_MIN,
    REPOSITORY_URL,
    VERSION,
)

__version__: str = VERSION
__build_date__: str = BUILD_DATE
__app_name__: str = APP_NAME
__description__: str = APP_DESCRIPTION
__author__: str = APP_AUTHOR
__license__: str = APP_LICENSE
__python_min__: str = PYTHON_MIN
__repository__: str = REPOSITORY_URL

__all__ = [
    "__version__",
    "__build_date__",
    "__app_name__",
    "__description__",
    "__author__",
    "__license__",
    "__python_min__",
    "__repository__",
]
