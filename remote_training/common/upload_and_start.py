#!/usr/bin/env python3
"""Upload and start training"""
import paramiko

HOST = "login.npsf.cdac.in"
USER = "isea13"
PASSWORD = "eXYV_mnJ"

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, username=USER, password=PASSWORD)

sftp = client.open_sftp()

print("Uploading updated script...")
sftp.put("soc-analyst-llm/training/train_remote.py", "train_remote.py")

print("Starting training...")
client.exec_command("pkill -f train_remote.py")
client.exec_command("source venv/bin/activate && nohup python train_remote.py --epochs 3 > training.log 2>&1 &")

print("Done!")
sftp.close()
client.close()
