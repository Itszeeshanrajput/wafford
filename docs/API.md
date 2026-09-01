# Wafford API Reference

## Core Modules

### Database Manager

```python
from wafford.db.manager import DatabaseManager

db = DatabaseManager()
await db.init_db()

# Create session
session_id = await db.create_session("My Audit")

# Get sessions
sessions = await db.get_sessions()

# Save scan results
scan_id = await db.save_scan(session_id, "wlan0", results)

# Backup database
backup_path = await db.backup()

# Export to JSON
json_path = await db.export_json("/tmp/export.json")

await db.close()
```

### Configuration Manager

```python
from wafford.config import ConfigManager

mgr = ConfigManager(profile="default")
cfg = mgr.load()

# Access config values
duration = mgr.get("scan.duration")

# Set config values
mgr.set("scan.duration", 60)
mgr.save()

# Get all profiles
profiles = mgr.list_profiles()
```

### Plugin System

```python
from wafford.plugins.loader import PluginRegistry

registry = PluginRegistry()

# Discover plugins
plugins = registry.discover_plugins()

# Load a plugin
plugin = registry.load_plugin("my_plugin")

# Get plugin info
info = registry.get_plugin_info("my_plugin")

# List all plugins
all_plugins = registry.list_plugins()
```

### Report Generation

```python
from wafford.reports.builder import JSONReportBuilder, HTMLReportBuilder

# JSON report
json_builder = JSONReportBuilder()
json_builder.add_data("networks", networks_data)
report_path = json_builder.generate()

# HTML report
html_builder = HTMLReportBuilder()
html_builder.add_data("networks", networks_data)
report_path = html_builder.generate()
```

### Logging

```python
from wafford.logging.setup import setup_logging

setup_logging(
    level="DEBUG",
    log_format="detailed",
    log_to_file=True,
    log_to_console=True
)

import logging
logger = logging.getLogger(__name__)
logger.info("Application started")
```

## Exception Hierarchy

```python
from wafford.exceptions import (
    WaffordError,          # Base exception
    InterfaceError,        # Interface-related
    ScanError,             # Scan failures
    AttackError,           # Attack failures
    CrackError,            # Cracking failures
    ToolNotFoundError,     # Missing tools
    DependencyError,       # Missing dependencies
    ConfigError,           # Config issues
    PluginError,           # Plugin issues
    DatabaseError,         # Database issues
    ReportError,           # Report generation
)
```

## CLI Commands

### Scan
```bash
wafford scan -i wlan0 -c 1,6,11 -d 30
```

### Interfaces
```bash
wafford interfaces
```

### Monitor Mode
```bash
wafford monitor -i wlan0
wafford monitor -i wlan0 --stop
```

### MAC Address
```bash
wafford mac -i wlan0                  # Randomize
wafford mac -i wlan0 --restore       # Restore
```

### Database
```bash
wafford db init
wafford db status
wafford db backup --output /tmp/backup.db
wafford db export --output /tmp/export.json
```

### Configuration
```bash
wafford config show
wafford config get scan.duration
wafford config set scan.duration 60
wafford config reset
wafford config min           # Show minimal config
```
