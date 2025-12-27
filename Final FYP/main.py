import os
import platform
import sys
import time
from collections import defaultdict
from threading import Event, Thread

import joblib
import numpy as np
import pandas as pd
from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import IP, TCP, UDP
from ipaddress import ip_address, ip_network
##----------Email Feature  Start -----------
import smtplib
from email.mime.text import MIMEText
##----------Email Feature  End -----------

# ==========================================
# APP & SOCKET.IO SETUP
# ==========================================
# Use eventlet for long-running background tasks
async_mode = 'eventlet'
app = Flask(__name__)
socketio = SocketIO(app, async_mode=async_mode)

# ==========================================
# GLOBAL STATE
# ==========================================
# Use a flag and an event to control the sniffer background task
sniffer_running = False
stop_sniffing_event = Event()

# This will hold the loaded model and preprocessors
ml_artifacts = {}

# This will hold the IPs of discovered clients
active_clients = set()

# This will hold the email configuration set from the UI
EMAIL_CONFIG = {
    "sender_email": "",
    "password": "",
    "recipient_email": ""
}



# ==========================================
# MACHINE LEARNING & IDS CONFIG
# ==========================================
PREDICTION_INTERVAL_PACKETS = 15  # Predict every N packets in a flow
MIN_PREDICTION_CONFIDENCE = 0.5  # Minimum confidence to trigger an alert

# Map of common ports to service names for feature enrichment.
# This helps the model by providing a 'service' feature.
SERVICE_MAP = {
    20: 'ftp', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'dns', 67: 'dhcp', 68: 'dhcp', 80: 'http', 110: 'pop3',
    123: 'ntp', 143: 'imap', 443: 'https', 465: 'smtps', 993: 'imaps',
    995: 'pop3s'
}

# Based on the training script, this map is now generated dynamically.
LABEL_MAP = {}


class Flow:
    """Represents a network flow and its statistics."""

    def __init__(self, packet):
        self.start_time = self.last_seen = time.time()
        self.proto = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(packet[IP].proto, 'other')
        self.src_ip, self.dst_ip = packet[IP].src, packet[IP].dst
        
        if self.proto == 'tcp' or self.proto == 'udp':
            self.src_port, self.dst_port = packet.sport, packet.dport
        else:
            self.src_port = self.dst_port = 0

        self.service = SERVICE_MAP.get(self.dst_port, SERVICE_MAP.get(self.src_port, 'other'))
        self.src_pkts = self.dst_pkts = 0
        self.src_bytes = self.dst_bytes = 0
        self.update(packet)

    def update(self, packet):
        """Updates flow stats based on the direction of the given packet."""
        packet_len = len(packet)
        self.last_seen = time.time()

        if packet[IP].src == self.src_ip:  # Forward packet
            self.src_pkts += 1
            self.src_bytes += packet_len
        else:  # Backward packet
            self.dst_pkts += 1
            self.dst_bytes += packet_len

    @property
    def duration(self):
        return self.last_seen - self.start_time

    @property
    def total_packets(self):
        return self.src_pkts + self.dst_pkts


def get_flow_key(packet) -> tuple:
    """Creates a direction-agnostic key for a flow."""
    p_src_ip, p_dst_ip = packet[IP].src, packet[IP].dst
    proto_num = packet[IP].proto
    protocol_name = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(proto_num, 'other')

    if protocol_name in ['tcp', 'udp']:
        p_src_port, p_dst_port = packet.sport, packet.dport
    else:
        p_src_port = p_dst_port = 0

    # Normalize flow key to be direction-agnostic
    if p_src_ip > p_dst_ip or (p_src_ip == p_dst_ip and p_src_port > p_dst_port):
        return (p_dst_ip, p_src_ip, p_dst_port, p_src_port, protocol_name)
    return (p_src_ip, p_dst_ip, p_src_port, p_dst_port, protocol_name)


def extract_features_df(flow: Flow) -> pd.DataFrame:
    """
    Extracts features from a flow and returns them as a pandas DataFrame.
    This is required to avoid the sklearn UserWarning about missing feature names.
    """
    data = {
        'duration': flow.duration,
        'proto': flow.proto,
        'service': flow.service,
        'src_bytes': flow.src_bytes,
        'dst_bytes': flow.dst_bytes,
        'src_pkts': flow.src_pkts,
        'dst_pkts': flow.dst_pkts,
        'src_port': flow.src_port,
        'dst_port': flow.dst_port,
        # NOTE: conn_state is complex to track live. Defaulting to 'OTH'.
        'conn_state': 'OTH'
    }

    row_data = {}
    for feature in ml_artifacts['feature_names']:
        # Use the live value if available, otherwise default to 0.
        # WARNING: This is a key limitation. The training script used the column
        # mean for missing values, but that data was not saved. Using 0 may
        # reduce model accuracy.
        value = data.get(feature, 0)
        
        # If the feature is categorical (has an encoder), transform it
        if feature in ml_artifacts['encoders']:
            encoder = ml_artifacts['encoders'][feature]
            val_str = str(value)
            # Use the encoded value if known, otherwise use -1 for "unseen"
            if val_str in encoder.classes_:
                value = encoder.transform([val_str])[0]
            else:
                value = -1  # Represents an unseen category
        row_data[feature] = value
        
    return pd.DataFrame([row_data])


def predict_and_alert(flow: Flow):
    """Makes a prediction on a flow and emits an alert if it's an attack."""
    if not ml_artifacts:
        return  # Can't predict if model failed to load

    flow_key_str = f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} ({flow.proto})"
    
    # 1. Extract features into a DataFrame
    features_df = extract_features_df(flow)

    # 2. Scale the features. The warning is now suppressed.
    scaled_features = ml_artifacts['scaler'].transform(features_df)

    # 3. Predict probabilities
    probs = ml_artifacts['model'].predict_proba(scaled_features)[0]
    pred_idx = np.argmax(probs)
    confidence = probs[pred_idx]
    
    if confidence >= MIN_PREDICTION_CONFIDENCE:
        # 4. Map the numeric label (e.g., 0, 1, 2...) to its string name
        pred_label_str = LABEL_MAP.get(pred_idx, f'UNKNOWN({pred_idx})')

        # 5. ONLY alert if the prediction is NOT normal
        if pred_label_str != 'normal':
            message = (
                f"Flow: {flow_key_str} | Prediction: <strong>{pred_label_str.upper()}</strong> "
                f"| Confidence: {confidence:.2f} | Packets: {flow.total_packets}"
            )
            socketio.emit('new_alert', {'label': pred_label_str, 'message': message})
            ##----------Email Feature  Start -----------
            #sending email ...
            email_subject = f"IDS Alert: {pred_label_str.upper()} Detected"
            email_body = message.replace('<strong>', '').replace('</strong>', '')
            send_email_alert(email_subject, email_body)
            ##----------Email Feature  End -----------

##----------Email Feature  Start -----------
def send_email_alert(subject, body):
    """Connects to an SMTP server and sends an email alert."""

    # --- Configuration ---
    # Read configuration from the global variable set by the UI
    sender_email = EMAIL_CONFIG.get('sender_email')
    password = EMAIL_CONFIG.get('password')
    recipient_email = EMAIL_CONFIG.get('recipient_email')

    if not all([sender_email, password, recipient_email]):
        print("[-] Email configuration not set in the UI. Skipping email alert.", file=sys.stderr)
        return

    # --- Create the Email ---
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    # --- Send the Email ---
    try:
        print(f"[*] Attempting to send email alert to {recipient_email}...")
        # This example uses Gmail's SMTP server.
        # If you use another provider, you will need to change the server and port.
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender_email, password)
            smtp_server.sendmail(sender_email, recipient_email, msg.as_string())
        print("[+] Email alert sent successfully.")
    except Exception as e:
        print(f"[-] Failed to send email alert: {e}", file=sys.stderr)
##----------Email Feature  End -----------

def is_private_ip(ip: str) -> bool:
    """Checks if an IP address is in a private range (RFC 1918)."""
    private_nets = [
        ip_network('10.0.0.0/8'),
        ip_network('172.16.0.0/12'),
        ip_network('192.168.0.0/16')
    ]
    try:
        addr = ip_address(ip)
        if addr.is_loopback or addr.is_multicast:
            return False
        for net in private_nets:
            if addr in net:
                return True
    except ValueError:
        return False  # Not a valid IP address
    return False


def packet_sniffer_thread(interface: str):
    """The main packet sniffing and processing loop, running in a background task."""
    global sniffer_running, active_clients
    sniffer_running = True
    
    from scapy.all import sniff
    # Check for root/admin privileges
    try:
        if platform.system() == "Windows":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError("Administrator privileges are required on Windows.")
        elif os.geteuid() != 0:
            raise PermissionError("Root privileges (e.g., 'sudo') are required on Linux.")
    except (PermissionError, AttributeError) as e:
        print(f"[-] PERMISSION ERROR: {e}", file=sys.stderr)
        socketio.emit('status_update', {'msg': f'Error: {e}', 'status': 'error'})
        sniffer_running = False
        return
    
    active_flows = {}
    total_packet_count = 0
    active_clients.clear() # Clear clients from previous sessions

    def process_packet(packet):
        nonlocal total_packet_count
        if stop_sniffing_event.is_set() or IP not in packet:
            return
     # Add any private IP address to our set of active clients
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        if is_private_ip(src_ip):
            active_clients.add(src_ip)
        if is_private_ip(dst_ip):
            active_clients.add(dst_ip)

        total_packet_count += 1
        if total_packet_count % 10 == 0:  # Update UI periodically
            socketio.emit('packet_count_update', {'count': total_packet_count})
            socketio.sleep(0)

        try:
            flow_key = get_flow_key(packet)
            if flow_key not in active_flows:
                active_flows[flow_key] = Flow(packet)
            else:
                active_flows[flow_key].update(packet)

            flow = active_flows[flow_key]
            if flow.total_packets % PREDICTION_INTERVAL_PACKETS == 0:
                predict_and_alert(flow)
        except Exception as e:
            print(f"[-] Error processing packet: {e}", file=sys.stderr)

    print(f"[*] Starting sniffer on interface '{interface}'...")
    socketio.emit('status_update', {'msg': f'Monitoring started on {interface}.', 'status': 'running'}) 
    
    while not stop_sniffing_event.is_set():
        sniff(iface=interface, prn=process_packet, store=0, timeout=1)

    print("[*] Sniffer thread stopped.")
    socketio.emit('status_update', {'msg': 'Monitor stopped.', 'status': 'stopped'})
    active_flows.clear()
    sniffer_running = False


def client_monitor_thread():
    """Periodically sends the set of discovered client IPs to the UI."""
    while True:
        # Convert set to a list of dicts for the UI, then emit
        client_list = [{'ip': ip, 'mac': 'N/A', 'hostname': 'N/A'} for ip in sorted(list(active_clients))]
        socketio.emit('hotspot_clients', client_list)
        socketio.sleep(5)


# ==========================================
# FLASK & SOCKET.IO ROUTES
# ==========================================
@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')


@socketio.on('connect')
def on_connect():
    """Handles a new client connection."""
    print('[+] Client connected.')
    socketio.emit('status_update', {'msg': 'Ready. Select an interface to start.', 'status': 'stopped'})
    get_email_config() # Send current email config to the new client

@socketio.on('get_email_config')
def get_email_config():
    """Sends the current (redacted) email configuration to the client."""
    safe_config = EMAIL_CONFIG.copy()
    if safe_config.get('password'):
        safe_config['password'] = '********'
    socketio.emit('email_config_update', safe_config)

@socketio.on('update_email_config')
def update_email_config(data):
    """Updates the email configuration from the UI."""
    global EMAIL_CONFIG
    print("[*] Received request to update email configuration.")
    
    EMAIL_CONFIG['sender_email'] = data.get('sender_email', '')
    EMAIL_CONFIG['recipient_email'] = data.get('recipient_email', '')
    
    # For security, don't update the password if the user sends back the placeholder
    if data.get('password') and data['password'] != '********':
        EMAIL_CONFIG['password'] = data['password']
        
    print(f"[+] Email configuration updated. Recipient: {EMAIL_CONFIG['recipient_email']}")
    socketio.emit('status_update', {'msg': 'Email configuration saved successfully!', 'status': 'stopped'})
    # Send the updated (redacted) config back to all clients
    get_email_config()

@socketio.on('send_test_email')
def send_test_email():
    """Sends a test email using the current configuration."""
    print("[*] Received request to send a test email.")
    socketio.emit('status_update', {'msg': 'Sending test email...', 'status': 'running'})
    subject = "IDS Test Email"
    body = "This is a test email from the Network IDS system. If you received this, your email configuration is working correctly."
    send_email_alert(subject, body)
    socketio.emit('status_update', {'msg': 'Test email sent! Check the recipient inbox.', 'status': 'stopped'})



@socketio.on('get_interfaces')
def get_interfaces():
    """Gets and returns a list of network interfaces to the client."""
    from scapy.all import get_if_list
    interfaces = []
    try:
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            interfaces = [{'name': iface['name'], 'description': iface['description']} for iface in get_windows_if_list()]
        else:
            interfaces = [{'name': name, 'description': name} for name in get_if_list()]
    except ImportError:
        print("[-] Could not import scapy's interface list. Falling back.", file=sys.stderr)
        interfaces = [{'name': 'any', 'description': 'Default Sniffing Interface'}]
    socketio.emit('interfaces_list', interfaces)


@socketio.on('start_sniffing')
def start_sniffing(message):
    """Starts the packet sniffer in a background task."""
    global sniffer_running
    if sniffer_running:
        print("[-] Sniffer is already running.")
        return

    interface = message.get('interface')
    if not interface:
        return
    
    print(f"[*] Received request to start sniffer on '{interface}'.")
    stop_sniffing_event.clear()
    socketio.start_background_task(packet_sniffer_thread, interface)

@socketio.on('stop_sniffing')
def stop_sniffing():
    """Signals the sniffer task to stop."""
    global sniffer_running
    if not sniffer_running:
        print("[-] Sniffer is not running.")
        return

    print("[*] Received request to stop sniffer.")
    socketio.emit('status_update', {'msg': 'Stopping monitor... Please wait.', 'status': 'running'})
    stop_sniffing_event.set()


# ==========================================
# MAIN EXECUTION
# ==========================================
def load_ml_artifacts():
    """Loads the ML model and preprocessors from disk."""
    global LABEL_MAP
    print("[*] Loading Machine Learning artifacts...")
    try:
        base_path = '3'
        ml_artifacts['model'] = joblib.load(os.path.join(base_path, 'toniot_multiclass_model.pkl'))
        ml_artifacts['scaler'] = joblib.load(os.path.join(base_path, 'scaler.pkl'))
        ml_artifacts['encoders'] = joblib.load(os.path.join(base_path, 'feature_encoders.pkl'))
        ml_artifacts['feature_names'] = joblib.load(os.path.join(base_path, 'feature_names.pkl'))
        # Load the target encoder and build the label map dynamically
        target_encoder = joblib.load(os.path.join(base_path, 'target_encoder.pkl'))
        LABEL_MAP = {i: label for i, label in enumerate(target_encoder.classes_)}
        print(f"[+] Artifacts loaded successfully. Label map: {LABEL_MAP}")
        return True
    except FileNotFoundError as e:
        print(f"[-] ERROR: Missing artifact file: {e.filename}. Ensure the '3' directory with model files exists.", file=sys.stderr)
        return False

if __name__ == '__main__':
    if not load_ml_artifacts():
        print("[-] Could not load ML model. IDS will run without predictions.", file=sys.stderr)
        sys.exit(1)

    print("[*] Starting client discovery monitor.")
    socketio.start_background_task(client_monitor_thread)

    print("[*] Starting web server at http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)