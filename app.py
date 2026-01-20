import os
import json
import pandas as pd
import joblib
import numpy as np
from flask import Flask, render_template, request, g

# Database Imports
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# --- DATABASE CONFIGURATION ---
# Render provides a 'DATABASE_URL' environment variable. 
# If it exists, we use Postgres. If not, we use local SQLite.
DATABASE_URL = os.environ.get('DATABASE_URL')

models = {
    "phys": {},
    "cyber": {}
}

# --- LOAD MODELS ---
try:
    models["phys"]["zone_models"] = joblib.load('models/physical/zone_models.joblib')
    models["phys"]["zone_scalers"] = joblib.load('models/physical/zone_scalers.joblib')
except Exception:
    pass # Fail silently or log error

try:
    models["cyber"]["rf"] = joblib.load('models/cyber/rf_model.joblib')
    models["cyber"]["scaler"] = joblib.load('models/cyber/scaler.joblib')
except Exception:
    pass

# --- DATABASE HELPER FUNCTIONS ---
def get_db():
    """Smart connection: Uses Postgres on Render, SQLite locally."""
    db = getattr(g, '_database', None)
    if db is None:
        if DATABASE_URL:
            # Connect to Render's Postgres
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
            db = conn
        else:
            # Connect to local SQLite (Merges both physical/cyber into one file for simplicity)
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
    """Initializes tables for both systems."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # SQL Syntax differs slightly between SQLite and Postgres
        if DATABASE_URL:
            # Postgres Syntax (SERIAL instead of AUTOINCREMENT)
            id_type = "SERIAL PRIMARY KEY"
        else:
            # SQLite Syntax
            id_type = "INTEGER PRIMARY KEY AUTOINCREMENT"

        # Create Physical Table
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

        # Create Cyber Table
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

# Initialize DB on startup
init_dbs()

def load_json_data(filepath):
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(base_dir, filepath)
        with open(full_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# ================= ROUTES =================

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
            if "zone_models" in models["phys"]:
                # Prediction logic
                if loc in models["phys"]["zone_models"]:
                    features = pd.DataFrame([[vol, cur, pow_, freq, pf, s_id]], 
                                          columns=["Voltage (V)", "Current (A)", "Power (kW)", "Frequency (Hz)", "Power_Factor", "Sensor_ID"])
                    scaler = models["phys"]["zone_scalers"][loc]
                    model = models["phys"]["zone_models"][loc]
                    X_scaled = scaler.transform(features)
                    pred = model.predict(X_scaled)[0]
                    status = "ANOMALY DETECTED" if pred == 1 else "NORMAL"
                else:
                    status = "Unknown Zone"

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
            if pkt_len > 1500 or "666" in src:
                status = "MALICIOUS PACKET DETECTED"
            elif proto.upper() == "UDP" and pkt_len > 800:
                status = "POSSIBLE DDOS"
            
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