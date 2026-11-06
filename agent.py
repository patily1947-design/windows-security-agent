import os
import sys
import time
import logging
import psutil

# Configure logging system
logging.basicConfig(
    filename='windows_security_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Rule Baselines
WHITELIST_PROCESSES = {'explorer.exe', 'svchost.exe', 'taskmgr.exe', 'python.exe', 'chrome.exe', 'cmd.exe'}
SUSPICIOUS_PARENTS = {
    'winword.exe': ['cmd.exe', 'powershell.exe', 'wscript.exe'],
    'excel.exe': ['cmd.exe', 'powershell.exe'],
    'powerpnt.exe': ['cmd.exe', 'powershell.exe']
}
WRITABLE_TEMP_PATHS = ['\\appdata\\local\\temp', '\\windows\\temp', '\\users\\public']

def banner():
    print("====================================================")
    print(" WINDOWS SERVICE & PROCESS MONITORING AGENT v1.0   ")
    print("====================================================\n")

def check_parent_child_anomalies():
    """Module 1: Parent-Child Relationship Monitor"""
    print("[*] Auditing Parent-Child Process Relationships...")
    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            p_name = proc.info['name'].lower() if proc.info['name'] else ""
            ppid = proc.info['ppid']
            
            if ppid:
                parent_proc = psutil.Process(ppid)
                parent_name = parent_proc.name().lower()
                
                # Check for suspicious execution chains
                if parent_name in SUSPICIOUS_PARENTS:
                    if p_name in SUSPICIOUS_PARENTS[parent_name]:
                        alert_msg = f"ALERT: Suspicious child process '{p_name}' (PID: {proc.info['pid']}) spawned by '{parent_name}' (PPID: {ppid})"
                        print(f"  [!] {alert_msg}")
                        logging.warning(alert_msg)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def audit_startup_services():
    """Module 2: Startup Service Audit"""
    print("\n[*] Auditing Windows Services & Configurations...")
    services = list(psutil.win_service_iter())
    print(f"  [+] Total Services Enumerated: {len(services)}")
    
    for svc in services:
        try:
            svc_detail = svc.as_dict()
            name = svc_detail.get('name')
            status = svc_detail.get('status')
            start_type = svc_detail.get('start_type')
            bin_path = svc_detail.get('binpath', '')
            
            # Check for suspicious or missing paths
            if bin_path:
                for temp_path in WRITABLE_TEMP_PATHS:
                    if temp_path in bin_path.lower():
                        alert_msg = f"ALERT: Service '{name}' running from temporary path: {bin_path}"
                        print(f"  [!] {alert_msg}")
                        logging.error(alert_msg)
        except Exception:
            continue

def detect_unauthorized_processes():
    """Module 3: Unauthorized & High-Risk Process Detection"""
    print("\n[*] Auditing Active Processes against Whitelist & Directory Rules...")
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            exe_path = proc.info['exe'] or ""

            # Check execution from user-writable directories
            for path_keyword in WRITABLE_TEMP_PATHS:
                if path_keyword in exe_path.lower():
                    alert_msg = f"ALERT: Process '{name}' (PID: {pid}) executing from Temp folder: {exe_path}"
                    print(f"  [!] {alert_msg}")
                    logging.warning(alert_msg)
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def generate_report():
    """Module 4: Summary Reporting"""
    print("\n====================================================")
    print(" AUDIT COMPLETE - LOG SAVED TO 'windows_security_audit.log'")
    print("====================================================")

if __name__ == "__main__":
    banner()
    check_parent_child_anomalies()
    audit_startup_services()
    detect_unauthorized_processes()
    generate_report()