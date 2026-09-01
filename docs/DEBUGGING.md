# Wafford Debugging Guide

This guide helps troubleshoot common Wafford issues.

## Common Issues

### 1. Root Privileges Required

**Error**: "Root privileges required"

**Solution**: Run Wafford with `sudo`:
```bash
sudo wafford
```

### 2. Missing Required Tools

**Error**: "Some required tools are missing"

**Solution**: Install required tools (aircrack-ng suite):
```bash
sudo apt install aircrack-ng mdk4 macchanger iw rfkill
```

Check which tools are missing:
```bash
wafford --check-deps
```

### 3. No Wireless Interfaces Detected

**Error**: "No wireless interfaces detected"

**Solutions**:
- Verify your wireless adapter is recognized:
  ```bash
  iwconfig
  ifconfig
  ```
- Check if the adapter is blocked by rfkill:
  ```bash
  rfkill list
  rfkill unblock all  # if needed
  ```
- Restart network manager:
  ```bash
  sudo systemctl restart networking
  ```

### 4. Monitor Mode Not Enabled

**Error**: "Failed to enable monitor mode"

**Solution**: Manually enable monitor mode:
```bash
sudo airmon-ng start wlan0
```

Check interface is in monitor mode:
```bash
iwconfig
```

### 5. Scan Returns No Results

**Solutions**:
- Increase scan duration in config:
  ```bash
  wafford config set scan.duration 60
  ```
- Check if interface is in monitor mode
- Verify WiFi is enabled on your adapter
- Try different channels:
  ```bash
  wafford config set scan.channels [1,6,11,36,40,44]
  ```

### 6. Database Connection Error

**Error**: "Database initialization failed"

**Solution**: Check database directory permissions:
```bash
ls -la ~/.wafford/data/
chmod 755 ~/.wafford/data/
```

### 7. Config File Errors

**Error**: "Failed to load config"

**Solutions**:
- Check YAML syntax in `~/.wafford/config.yaml`
- Reset to defaults:
  ```bash
  wafford config reset
  ```
- Print minimal config:
  ```bash
  wafford --minconfig
  ```

## Debugging Tips

### Enable Debug Logging

```bash
wafford --log-level DEBUG
```

### Check Configuration

```bash
wafford config show
```

### View Logs

```bash
tail -f ~/.wafford/logs/wafford.log
```

### Environment Variables

Set environment variables to override config:
```bash
export WAFFORD_LOG_LEVEL=DEBUG
export WAFFORD_INTERFACE=wlan0
wafford
```

## Reporting Issues

When reporting issues, include:
1. Output of `wafford --check-deps`
2. Relevant log entries from `~/.wafford/logs/wafford.log`
3. Your configuration (sanitize sensitive data):
   ```bash
   wafford config show > config_dump.yaml
   ```
4. Steps to reproduce the issue
