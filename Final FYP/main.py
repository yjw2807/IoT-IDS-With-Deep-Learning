import os
import sys
import time
import json
import subprocess
import threading
from datetime import datetime
from ipaddress import ip_address, ip_network

import joblib
import numpy as np
import pandas as pd
from flask import Flask, render_template
from flask_socketio import SocketIO
import smtplib
from email.mime.text import MIMEText

# ================= CONFIGURATION =================
ZEEK_LOG_DIR = "/tmp/zeek_ids"
ZEEK_CMD_PATH = "/opt/zeek/bin/zeek" 

# Protected Subnet (Your Network)
PROTECTED_SUBNET = ip_network('192.168.50.0/24')
MIN_PREDICTION_CONFIDENCE = 0.5

# ================= FLASK SETUP =================
async_mode = 'eventlet'
app = Flask(__name__)
# High timeouts to prevent disconnection during floods
socketio = SocketIO(app, async_mode=async_mode, ping_timeout=60, ping_interval=25)

# ================= GLOBAL STATE =================
zeek_process = None
stop_event = threading.Event()
ml_artifacts = {}
active_clients = set() 
EMAIL_CONFIG = {"sender_email": "", "password": "", "recipient_email": ""}
LABEL_MAP = {}

# THROTTLING VARIABLES
alert_history = {} 
last_global_alert_time = 0

# ================= LOGGING HELPER =================
def log_debug(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [DEBUG] {msg}")

def log_error(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [ERROR] {msg}")

# ================= BACKGROUND TASKS =================
def broadcast_clients_loop():
    """Sends the list of connected devices to UI every 5 seconds."""
    log_debug("Client broadcast loop started.")
    while not stop_event.is_set():
        socketio.sleep(5)
        if active_clients:
            client_list = []
            for ip in active_clients:
                client_list.append({
                    'ip': ip,
                    'mac': 'Unknown', 
                    'hostname': 'Device' 
                })
            try:
                socketio.emit('hotspot_clients', client_list)
            except:
                pass

# ================= ZEEK MONITOR =================
def tail_zeek_log(logfile):
    """Reads new lines from Zeek's conn.log without blocking."""
    log_debug(f"Tailer started. Waiting for file: {logfile}")
    
    while not os.path.exists(logfile):
        if stop_event.is_set(): return
        socketio.sleep(1.0) 

    log_debug(f"Found Zeek log file! Opening: {logfile}")
    f = open(logfile, 'r')
    f.seek(0, 2) 

    while not stop_event.is_set():
        line = f.readline()
        if not line:
            socketio.sleep(0.2) 
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            pass 

def zeek_runner(interface):
    """Starts Zeek DIRECTLY (Native Mode)."""
    global zeek_process
    
    if not os.path.exists(ZEEK_LOG_DIR):
        os.makedirs(ZEEK_LOG_DIR)
        
    log_path = os.path.join(ZEEK_LOG_DIR, "conn.log")
    if os.path.exists(log_path):
        try: os.remove(log_path)
        except: pass

    cmd = [
        ZEEK_CMD_PATH, 
        "-i", interface,
        f"Log::default_logdir={ZEEK_LOG_DIR}",
        "policy/tuning/json-logs.zeek"
    ]
    
    log_debug(f"Starting Zeek: {' '.join(cmd)}")
    
    try:
        zeek_process = subprocess.Popen(cmd, cwd=ZEEK_LOG_DIR)
        log_debug(f"Zeek PID: {zeek_process.pid}")
        socketio.emit('status_update', {'msg': f'Zeek running on {interface}...', 'status': 'running'})
    except Exception as e:
        log_error(f"Failed to start Zeek: {e}")
        socketio.emit('status_update', {'msg': 'Error starting Zeek', 'status': 'error'})

def analysis_loop(interface):
    """Main loop."""
    global zeek_process
    
    # 1. Start Client Broadcast Background Task
    socketio.start_background_task(broadcast_clients_loop)

    # 2. Start Zeek
    zeek_runner(interface)
    
    conn_log_path = os.path.join(ZEEK_LOG_DIR, "conn.log")
    
    # 3. Read Logs
    count = 0
    for flow in tail_zeek_log(conn_log_path):
        if stop_event.is_set(): break
        
        # Keep connection alive
        count += 1
        if count % 10 == 0:
            socketio.sleep(0) 
        
        # Capture Clients 
        src = flow.get('id.orig_h')
        if src and is_private_ip(src): 
            active_clients.add(src)

        # Filter: Process if either side is local (for Logging)
        dst = flow.get('id.resp_h')
        if not (is_protected(src) or is_protected(dst)):
            continue

        # 4. Predict
        predict_and_alert(flow)
    
    if zeek_process:
        log_debug("Killing Zeek process...")
        zeek_process.terminate()
        zeek_process = None

# ================= ML PREDICTION =================
def predict_and_alert(flow_dict):
    global last_global_alert_time
    if not ml_artifacts: return

    try:
        # Map Zeek JSON to DataFrame
        data = {
            'id.orig_p': int(flow_dict.get('id.orig_p', 0)),
            'id.resp_p': int(flow_dict.get('id.resp_p', 0)),
            'proto': str(flow_dict.get('proto', 'tcp')),
            'service': str(flow_dict.get('service', '-')),
            'duration': float(flow_dict.get('duration', 0.0)),
            'orig_bytes': int(flow_dict.get('orig_bytes', 0)),
            'resp_bytes': int(flow_dict.get('resp_bytes', 0)),
            'conn_state': str(flow_dict.get('conn_state', 'OTH')),
            'orig_pkts': int(flow_dict.get('orig_pkts', 0)),
            'resp_pkts': int(flow_dict.get('resp_pkts', 0)),
        }
        
        df = pd.DataFrame([data])
        model_cols = ml_artifacts['feature_names']
        row = pd.DataFrame(0, index=[0], columns=model_cols)
        
        for col in model_cols:
            val = data.get(col, 0)
            if col in ml_artifacts['encoders']:
                enc = ml_artifacts['encoders'][col]
                val = str(val)
                val = enc.transform([val])[0] if val in enc.classes_ else -1
            row[col] = val

        X = ml_artifacts['scaler'].transform(row)
        probs = ml_artifacts['model'].predict_proba(X)[0]
        pred_idx = np.argmax(probs)
        confidence = probs[pred_idx]
        pred_label = LABEL_MAP.get(pred_idx, "Unknown")

        src_ip = flow_dict.get('id.orig_h')
        dst_ip = flow_dict.get('id.resp_h')
        
        # --- 1. TERMINAL LOGGING (Always Show Flow) ---
        # This fixes "Where is the detailed log?"
        if confidence > 0.4:
            ts = datetime.now().strftime("%H:%M:%S")
        #    print(f"[{ts}] [FLOW] {src_ip} -> {dst_ip} | {pred_label} ({confidence:.2f})")

        # --- 2. UI ALERTING (Victim Protection Only) ---
        should_alert_ui = False
        
        # Only alert if TARGET is in our subnet (We are being attacked)
        if confidence >= MIN_PREDICTION_CONFIDENCE and pred_label != 'normal' and is_protected(dst_ip):
            
            now = time.time()
            
            # RULE 1: Global Speed Limit (Max 2 alerts per second)
            if (now - last_global_alert_time) > 0.5:
                
                # RULE 2: Per-Target throttling (Don't spam same alert)
                alert_key = (src_ip, dst_ip, pred_label)
                if alert_key not in alert_history or (now - alert_history[alert_key] > 2.0):
                    should_alert_ui = True
                    alert_history[alert_key] = now
                    last_global_alert_time = now

        # Send to UI if allowed
        if should_alert_ui:
            msg = f"Target: {dst_ip} | Attack: {pred_label.upper()} | Conf: {confidence:.2f}"
            print(f"    [!] ALERT SENT TO UI: {msg}") 
            socketio.emit('new_alert', {'label': pred_label, 'message': msg})
            send_email_alert(f"IDS Alert: {pred_label}", msg)

    except Exception:
        pass

# ================= UTILS =================
def is_protected(ip):
    try:
        return ip_address(ip) in PROTECTED_SUBNET
    except ValueError:
        return False

def is_private_ip(ip):
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False

def send_email_alert(subject, body):
    if not EMAIL_CONFIG['sender_email']: return
    try:
        socketio.start_background_task(_send_email_bg, subject, body)
    except: pass

def _send_email_bg(subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = EMAIL_CONFIG['recipient_email']
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['password'])
            s.sendmail(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['recipient_email'], msg.as_string())
    except: pass

# ================= FLASK ROUTES =================
@app.route('/')
def index(): return render_template('index.html')

@socketio.on('connect')
def on_connect():
    log_debug("Web client connected.")
    status = 'running' if zeek_process else 'stopped'
    socketio.emit('status_update', {'msg': f'System is {status}', 'status': status})
    safe_conf = EMAIL_CONFIG.copy()
    safe_conf['password'] = '******'
    socketio.emit('email_config_update', safe_conf)

@socketio.on('get_interfaces')
def get_interfaces():
    all_ifaces = os.listdir('/sys/class/net')
    clean_ifaces = [i for i in all_ifaces if not (i.startswith('docker') or i.startswith('br-') or i.startswith('veth'))]
    socketio.emit('interfaces_list', [{'name': i, 'description': i} for i in clean_ifaces])

@socketio.on('start_sniffing')
def start_sniffing(data):
    if zeek_process is not None:
        return 
    interface = data.get('interface')
    log_debug(f"UI requested START on: {interface}")
    stop_event.clear()
    socketio.start_background_task(analysis_loop, interface)

@socketio.on('stop_sniffing')
def stop_sniffing():
    log_debug("UI requested STOP.")
    stop_event.set()
    if zeek_process:
        try: zeek_process.terminate()
        except: pass
    socketio.emit('status_update', {'msg': 'Stopped.', 'status': 'stopped'})

@socketio.on('update_email_config')
def update_email(data):
    EMAIL_CONFIG['sender_email'] = data.get('sender_email')
    EMAIL_CONFIG['recipient_email'] = data.get('recipient_email')
    if data.get('password') and '***' not in data['password']:
        EMAIL_CONFIG['password'] = data['password']
    socketio.emit('status_update', {'msg': 'Email saved.', 'status': 'stopped'})
    
@socketio.on('send_test_email')
def send_test_email():
    """Sends a test email using the current configuration."""
    print("[*] Received request to send a test email.")
    socketio.emit('status_update', {'msg': 'Sending test email...', 'status': 'running'})
    subject = "IDS Test Email"
    body = "This is a test email from the Network IDS system. If you received this, your email configuration is working correctly."
    send_email_alert(subject, body)
    socketio.emit('status_update', {'msg': 'Test email sent! Check the recipient inbox.', 'status': 'stopped'})

# ================= MAIN =================
def load_ml():
    global LABEL_MAP
    try:
        base = '3'
        ml_artifacts['model'] = joblib.load(os.path.join(base, 'toniot_multiclass_model.pkl'))
        ml_artifacts['scaler'] = joblib.load(os.path.join(base, 'scaler.pkl'))
        ml_artifacts['encoders'] = joblib.load(os.path.join(base, 'feature_encoders.pkl'))
        ml_artifacts['feature_names'] = joblib.load(os.path.join(base, 'feature_names.pkl'))
        te = joblib.load(os.path.join(base, 'target_encoder.pkl'))
        LABEL_MAP = {i: l for i, l in enumerate(te.classes_)}
        return True
    except Exception as e:
        log_error(f"Failed to load ML artifacts: {e}")
        return False

if __name__ == '__main__':
    if load_ml():
        log_debug("Starting Server...")
        socketio.run(app, host='127.0.0.1', port=5000, debug=False)
