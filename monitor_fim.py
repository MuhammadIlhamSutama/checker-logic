import time
import json
import os
import sys
import requests
import urllib3
import subprocess
import threading # <-- [BARU] Untuk mengatasi masalah Blocking I/O
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from main_scoring import get_threat_analysis
except ImportError:
    print("❌ Error Fatal: File 'main_scoring.py' tidak ditemukan!")
    sys.exit(1)

# ─── KONFIGURASI WAZUH API ───────────────────────────────────────────────────
WAZUH_API_URL = "https://127.0.0.1:55000"
WAZUH_API_USER = "chimera_api"
WAZUH_API_PASS = "P@ssw0rd2025"
CDB_LIST_PATH = '/var/ossec/etc/lists/malware-hashes'

LOG_FILE = "/var/ossec/logs/alerts/alerts.json"
FIM_STATE_FILE = "fim_state.json"
POINTER_FILE = "fim_log_pos.txt"
CHIMERA_LOG = "/var/log/chimera_cti.json"
IGNORE_EXT = ('.part', '.tmp', '.crdownload', '.swp', '.temp')

def append_to_cdb_silently(sha256_hash: str, malware_name: str):
    if not sha256_hash: return
    if os.path.exists(CDB_LIST_PATH):
        with open(CDB_LIST_PATH, 'r') as f:
            if sha256_hash in f.read(): return
    try:
        with open(CDB_LIST_PATH, 'a') as f:
            f.write(f"{sha256_hash}:{malware_name}\n")
        subprocess.run(['/var/ossec/bin/ossec-makelists'], check=True, stdout=subprocess.DEVNULL)
        print(f"✅ [CDB] Hash {sha256_hash} berhasil ditambahkan!")
    except Exception as e:
        pass

def trigger_active_response(agent_id: str, file_path: str):
    print(f"\n[*] [SOAR] Mengubah strategi: Menggunakan Jalur Log Internal Wazuh...")
    
    # File tempat kita menaruh "Surat Perintah"
    log_file = "/var/log/chimera_soar.json"
    
    # Format JSON ini dibuat persis seperti yang diharapkan oleh skrip Agen kita
    payload = {
        "chimera": {"action": "remove-threat"},
        "data": {
            "target": {
                "path": file_path,
                "agent_id": agent_id
            }
        }
    }
    
    try:
        # Menulis log secara instan
        with open(log_file, "a") as f:
            f.write(json.dumps(payload) + "\n")
        print(f"✅ [SOAR] Sukses! Surat perintah penghapusan diserahkan ke Rule Engine Wazuh.")
    except Exception as e:
        print(f"❌ [SOAR] Gagal menulis log lokal: {e}")

def save_fim_state(file_hash: str, file_path: str, agent_id: str):
    state = {}
    if os.path.exists(FIM_STATE_FILE):
        try:
            with open(FIM_STATE_FILE, 'r') as f: state = json.load(f)
        except json.JSONDecodeError: pass
    state[file_hash] = {"path": file_path, "agent_id": agent_id, "ts": datetime.now().isoformat()}
    with open(FIM_STATE_FILE, 'w') as f: json.dump(state, f, indent=2)
    
def emit_to_wazuh(data: dict):
    """Tulis hasil CTI ke file yang dipantau Wazuh."""
    try:
        with open(CHIMERA_LOG, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as e:
        print(f"[!] Gagal emit log: {e}")

def follow_log(filepath: str):
    if not os.path.exists(filepath): sys.exit(1)
    
    last_pos = 0
    if os.path.exists(POINTER_FILE):
        try:
            with open(POINTER_FILE, 'r') as p:
                last_pos = int(p.read().strip())
        except ValueError:
            pass

    with open(filepath, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        current_size = f.tell()
        
        if last_pos > current_size:
            last_pos = 0
            
        f.seek(last_pos)
        print(f"    Melanjutkan pembacaan dari byte ke-{last_pos}...\n")
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            with open(POINTER_FILE, 'w') as p:
                p.write(str(f.tell()))
                
            yield line

# <-- [BARU] FUNGSI BACKGROUND WORKER UNTUK MENGATASI BLOCKING -->
def run_analysis_background(sha256_fim, file_path, agent_id, filename):
    """
    Fungsi ini akan dijalankan di thread terpisah.
    Tujuannya agar proses request ke VT/CTX yang memakan waktu lama
    TIDAK menghentikan/nge-block proses follow_log() utama.
    """
    print(f"DEBUG [{filename}]: Sebelum analysis (Memulai CTI Request...)")
    try:
        analysis_data = get_threat_analysis(
            file_hash=sha256_fim, src_ip="127.0.0.1", dest_ip="127.0.0.1",
            file_path=file_path, source="fim"
        )
        
        print(f"DEBUG [{filename}]: Sesudah analysis (CTI Request Selesai!)")
        
        if analysis_data:
            if 'target' not in analysis_data: analysis_data['target'] = {}
            analysis_data['target']['agent_id'] = agent_id
            analysis_data['target']['file_hash'] = sha256_fim
            analysis_data['target']['filename'] = filename
            analysis_data['target']['path'] = file_path
            
            print(json.dumps(analysis_data, indent=2))
            
            emit_to_wazuh(analysis_data)

            scores = analysis_data.get('scores', {})
            if scores.get('status') == 'MALICIOUS':
                target = analysis_data.get('target', {})
                append_to_cdb_silently(target.get('file_hash'), target.get('filename', 'Unknown'))
                if file_path and agent_id != '000':
                    trigger_active_response(agent_id, file_path)
    except Exception as e:
        print(f"DEBUG [{filename}]: Analysis Error: {e}")

def process_fim(json_line: str):
    try:
        log = json.loads(json_line)
    except json.JSONDecodeError: return

    syscheck = log.get('syscheck', {})
    sha256_fim = syscheck.get('sha256_after')
    
    if sha256_fim:
        file_path = syscheck.get('path', 'Unknown')
        filename = os.path.basename(file_path)
        agent_id = log.get('agent', {}).get('id', '000')

        if filename.lower().endswith(IGNORE_EXT): return

        print(f"\n[!] Trigger [FIM] → {filename}")
        print(f"    Hash : {sha256_fim[:24]}...")
        print(f"    Path : {file_path}")

        # Simpan state dieksekusi instan tanpa nunggu API
        save_fim_state(sha256_fim, file_path, agent_id)

        # <-- [PERUBAHAN UTAMA] -->
        # Lempar proses get_threat_analysis ke background thread!
        # Log tailer akan langsung lanjut baca baris berikutnya dalam hitungan milidetik.
        bg_thread = threading.Thread(
            target=run_analysis_background, 
            args=(sha256_fim, file_path, agent_id, filename)
        )
        bg_thread.start()

if __name__ == "__main__":
    print("[*] Terminal 1: Monitor FIM Aktif! Memantau file yang terdeteksi...")
    for new_line in follow_log(LOG_FILE):
        process_fim(new_line)
