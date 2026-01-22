import os
import warnings

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')

import json
import pandas as pd
import joblib
import numpy as np
from flask import Flask, render_template, request, g
from tensorflow.keras.models import load_model
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

DATABASE_URL = os.environ.get('DATABASE_URL')

models = {
    "phys": {},
    "cyber": {}
}

print(">> STARTING SERVER & LOADING MODELS...")

try:
    models["phys"]["zone_models"] = joblib.load('models/physical/zone_models.joblib')
    models["phys"]["zone_scalers"] = joblib.load('models/physical/zone_scalers.joblib')
    print(f"   [+] Physical Models Loaded: {len(models['phys']['zone_models'])} zones active")
except Exception as e:
    print(f"   [!] PHYSICAL MODEL ERROR: {e}")

try:
    cyber_artifacts = joblib.load('models/cyber/cyber_atk_hybrid_model.joblib')
    models["cyber"]["rf"] = cyber_artifacts["rf_model"]
    models["cyber"]["scaler"] = cyber_artifacts["scaler"]
    models["cyber"]["encoders"] = cyber_artifacts.get("encoders", {})
    models["cyber"]["lstm"] = load_model('models/cyber/lstm_autoencoder.keras')
    print("   [+] Cyber Hybrid System Loaded (RF + LSTM)")
except Exception as e:
    print(f"   [!] CYBER MODEL ERROR: {e}")

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        if DATABASE_URL:
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
            db = conn
        else:
            conn = sqlite3.connect('local_data.db')
            conn.row_factory = sqlite3.Row
            db = conn
        setattr(g, '_database', db)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_dbs():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        id_type = "SERIAL PRIMARY KEY" if DATABASE_URL else "INTEGER PRIMARY KEY AUTOINCREMENT"
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS predictions (
                id {id_type},
                sensor_id INTEGER,
                location INTEGER,
                voltage REAL,
                current REAL,
                power REAL,
                prediction_result TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS cyber_logs (
                id {id_type},
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                packet_len INTEGER,
                prediction_result TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

init_dbs()

def load_json_data(filepath):
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(base_dir, filepath)
        with open(full_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

@app.route('/')
def index():
    return render_template('gateway.html')

@app.route('/physical')
def physical_home():
    return render_template('physical/index.html')

@app.route('/physical/input_feed')
def physical_input_feed():
    data = load_json_data('data/physical/input_data.json')
    headers = data[0].keys() if data else []
    return render_template('physical/input_feed.html', data=data, headers=headers)

@app.route('/physical/analysis')
def physical_analysis():
    data = load_json_data('data/physical/anomaly_output.json')
    return render_template('physical/analysis.html', data=data)

@app.route('/physical/graphs')
def physical_graphs():
    images = [
        'images/phys_graph1.png', 'images/phys_graph2.png',
        'images/phys_graph3.png', 'images/phys_graph4.png'
    ]
    return render_template('physical/graphs.html', images=images)

@app.route('/physical/predictor', methods=['GET', 'POST'])
def physical_predictor():
    result = None
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        try:
            s_id = int(request.form['sensor_id'])
            loc = int(request.form['location'])
            vol = float(request.form['voltage'])
            cur = float(request.form['current'])
            pow_ = float(request.form['power'])
            freq = float(request.form['frequency'])
            pf = float(request.form['power_factor'])

            status = "Model Not Loaded"

            if "zone_models" in models["phys"] and loc in models["phys"]["zone_models"]:
                V_MIN, V_MAX = 210, 245
                I_MIN, I_MAX = 2.5, 7.5
                P_MIN, P_MAX = 0.5, 1.8
                BUFFER_PCT = 0.001

                is_normal = (
                    (V_MIN <= vol <= V_MAX) and
                    (I_MIN <= cur <= I_MAX) and
                    (P_MIN <= pow_ <= P_MAX)
                )

                in_moderate_zone = (
                    (V_MIN * (1 - BUFFER_PCT) <= vol <= V_MAX * (1 + BUFFER_PCT)) and
                    (I_MIN * (1 - BUFFER_PCT) <= cur <= I_MAX * (1 + BUFFER_PCT)) and
                    (P_MIN * (1 - BUFFER_PCT) <= pow_ <= P_MAX * (1 + BUFFER_PCT))
                )

                if is_normal:
                    status = "NORMAL (Safe Range)"
                elif in_moderate_zone:
                    status = "MODERATE ALERT"
                else:
                    status = "CRITICAL ALERT"

                if status == "NORMAL (Safe Range)":
                    features = pd.DataFrame(
                        [[vol, cur, pow_, freq, pf, s_id]],
                        columns=["Voltage (V)", "Current (A)", "Power (kW)", "Frequency (Hz)", "Power_Factor", "Sensor_ID"]
                    )
                    scaler = models["phys"]["zone_scalers"][loc]
                    model = models["phys"]["zone_models"][loc]
                    X_scaled = scaler.transform(features)
                    pred = model.predict(X_scaled)[0]
                    if pred == -1:
                        status = "ANOMALY DETECTED (ML)"
            else:
                status = f"Unknown Zone {loc} (No Model)"

            result = {'status': status, 'voltage': vol, 'current': cur, 'power': pow_}

            cursor.execute('''
                INSERT INTO predictions (sensor_id, location, voltage, current, power, prediction_result)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''' if DATABASE_URL else '''
                INSERT INTO predictions (sensor_id, location, voltage, current, power, prediction_result)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (s_id, loc, vol, cur, pow_, status))
            db.commit()
        except Exception as e:
            result = {'status': f"Error: {str(e)}"}

    cursor.execute('SELECT * FROM predictions ORDER BY id DESC LIMIT 10')
    history = cursor.fetchall()
    return render_template('physical/predictor.html', result=result, history=history)

@app.route('/cyber')
def cyber_home():
    return render_template('cyber/index.html')

@app.route('/cyber/input_feed')
def cyber_input_feed():
    data = load_json_data('data/cyber/input_data.json')[:50]
    headers = data[0].keys() if data else []
    return render_template('cyber/input_feed.html', data=data, headers=headers)

@app.route('/cyber/analysis')
def cyber_analysis():
    data = load_json_data('data/cyber/anomaly_detected.json')
    return render_template('cyber/analysis.html', data=data)

@app.route('/cyber/graphs')
def cyber_graphs():
    images = [
        'images/cyber_graph1.png', 'images/cyber_graph2.png',
        'images/cyber_graph3.png', 'images/cyber_graph4.png',
        'images/cyber_graph5.png'
    ]
    return render_template('cyber/graphs.html', images=images)

@app.route('/cyber/predictor', methods=['GET', 'POST'])
def cyber_predictor():
    result = None
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        try:
            src = request.form['source_ip']
            dst = request.form['dest_ip']
            proto = request.form['protocol']
            pkt_len = float(request.form['packet_length'])

            status = "SAFE TRAFFIC"

            if pkt_len > 1500:
                status = "MALICIOUS (Oversized Packet)"
            elif "666" in src:
                status = "BLACKLISTED IP DETECTED"
            elif proto.upper() == "UDP" and pkt_len > 800:
                status = "POSSIBLE DDOS (UDP Flood)"
            elif "rf" in models["cyber"] and models["cyber"]["rf"]:
                try:
                    input_data = {
                        "Source_IP": [src],
                        "Destination_IP": [dst],
                        "Port": [80],
                        "Protocol": [proto],
                        "Packet_Size": [pkt_len],
                        "Duration": [50.0],
                        "Attack_Type": ["Normal"],
                        "Packet_Loss": [0],
                        "Latency": [10],
                        "Throughput": [100],
                        "Jitter": [5],
                        "Authentication_Failure": [0]
                    }
                    features = pd.DataFrame(input_data)
                    encoders = models["cyber"].get("encoders", {})
                    for col in ["Source_IP", "Destination_IP", "Protocol", "Attack_Type"]:
                        if col in encoders:
                            try:
                                features[col] = encoders[col].transform(features[col])
                            except:
                                features[col] = 0
                        else:
                            features[col] = 0
                    if "scaler" in models["cyber"]:
                        features_scaled = models["cyber"]["scaler"].transform(features)
                        pred = models["cyber"]["rf"].predict(features_scaled)[0]
                        if pred == 1:
                            status = "ANOMALY DETECTED (Hybrid AI)"
                except Exception as e:
                    print(f"   [!] Cyber ML Inference Error: {e}")

            result = {"status": status, "src": src, "protocol": proto, "len": pkt_len}

            cursor.execute('''
                INSERT INTO cyber_logs (source_ip, dest_ip, protocol, packet_len, prediction_result)
                VALUES (%s, %s, %s, %s, %s)
            ''' if DATABASE_URL else '''
                INSERT INTO cyber_logs (source_ip, dest_ip, protocol, packet_len, prediction_result)
                VALUES (?, ?, ?, ?, ?)
            ''', (src, dst, proto, pkt_len, status))
            db.commit()
        except Exception as e:
            result = {"status": f"Error: {str(e)}"}

    cursor.execute('SELECT * FROM cyber_logs ORDER BY id DESC LIMIT 10')
    history = cursor.fetchall()
    return render_template('cyber/predictor.html', result=result, history=history)

@app.route('/cyber/visualization')
def cyber_visualization():
    return render_template('cyber/visualization.html')

@app.route('/cyber/graph_data')
def cyber_graph_data():
    return load_json_data('data/cyber/cyber_graph_data.json')

@app.route('/physical/visualization')
def physical_visualization():
    return render_template('physical/visualization.html')

@app.route('/physical/graph_data')
def physical_graph_data():
    return load_json_data('data/physical/physical_graph_data.json')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
