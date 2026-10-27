---
name: webmonitor-deploy
description: Validate, test, package, and deploy the WebMonitor project to the production Linux server (oracle-server) or inspect live server logs. Use when the user asks to update the server, deploy changes, check server status, or view production logs.
---

# WebMonitor Test, Package & Deploy Skill

## When to Use
Activate this skill whenever the user wants to:
- Test and package the `webmonitor` project (`monitor-deploy.zip`)
- Deploy new code to the production Linux server (`oracle-server`)
- Check `monitor-service` status or read live `journalctl` logs on the server

## Workflow

### Step 1: Validate & Run Unit Tests Locally
Run configuration validation and the unit test suite in `c:\Users\HAMIDREZA\Downloads\prozhe baressi site ha`:
```powershell
.\.venv\Scripts\python.exe monitor_system.py validate
$env:WEBMONITOR_SKIP_BROWSER="1"; .\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Step 2: Build the Deployment Package
```powershell
.\.venv\Scripts\python.exe monitor_system.py package -o monitor-deploy.zip
```

### Step 3: Upload & Restart on `oracle-server`
The server SSH alias `oracle-server` is configured in `C:\Users\HAMIDREZA\.ssh\config` (`130.61.88.47`, user `ubuntu`).
To update the code without overwriting the server's live `monitor-config.json`:
```powershell
scp "c:\Users\HAMIDREZA\Downloads\prozhe baressi site ha\monitor-deploy.zip" oracle-server:~/monitor-deploy.zip
ssh oracle-server "sudo unzip -o ~/monitor-deploy.zip -d /opt/monitor -x monitor-config.json && sudo chown -R monitorsvc:monitorsvc /opt/monitor/webmonitor /opt/monitor/monitor_system.py /opt/monitor/deploy /opt/monitor/tests && sudo systemctl restart monitor-service && sudo systemctl status monitor-service --no-pager"
```

### Step 4: Verify Live Logs
```powershell
ssh oracle-server "sudo journalctl -u monitor-service -n 40 --no-pager"
```
