import os
import json
import sqlite3
import pandas as pd
import joblib
import numpy as np
from flask import Flask, render_template, request, g

app = Flask(__name__)

PHYSICAL_DB = 'physical.db'
CYBER_DB = 'cyber.db'

models = {
    "phys": {},
    "cyber": {}
}

try:
    models["phys"]["zone_models"] = joblib.load('models/physical/zone_models.joblib')
    models["phys"]["zone_scalers"] = joblib.load('models/physical/zone_scalers.joblib')
    print(">> PHYSICAL MODELS LOADED")
except Exception as e:
    print(f"!! WARNING: Physical models missing: {e}")

try:
    models["cyber"]["rf"] = joblib.load('models/cyber/rf_model.joblib')
    models["cyber"]["scaler"] = joblib.load('models/cyber/scaler.joblib')
    print(">> CYBER MODELS LOADED")
except Exception as e:
    print(f"!! WARNING: Cyber models missing: {e}")


def get_db(db_name):
    """Connects to the specific database requested."""
    db_attr = f'_database_{db_name}'
    db = getattr(g, db_attr, None)
    if db is None:
        db = sqlite3.connect(db_name)
        db.row_factory = sqlite3.Row
        setattr(g, db_attr, db)
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes all active database connections."""
    for db_name in [PHYSICAL_DB, CYBER_DB]:
        db_attr = f'_database_{db_name}'
        db = getattr(g, db_attr, None)
        if db is not None:
            db.close()

def init_dbs():
    """Creates tables for both databases if they don't exist."""
    with app.app_context():
        db_phys = get_db(PHYSICAL_DB)
        db_phys.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_id INTEGER,
                location INTEGER,
                voltage REAL,
                current REAL,
                power REAL,
                prediction_result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db_phys.commit()

        db_cyber = get_db(CYBER_DB)
        db_cyber.execute('''
            CREATE TABLE IF NOT EXISTS cyber_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                packet_len INTEGER,
                prediction_result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db_cyber.commit()

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
    analysis_data = load_json_data('data/physical/anomaly_output.json')
    return render_template('physical/analysis.html', data=analysis_data)

@app.route('/physical/graphs')
def physical_graphs():
    images = [
        'images/phys_graph1.png', 
        'images/phys_graph2.png', 
        'images/phys_graph3.png', 
        'images/phys_graph4.png'
    ]
    return render_template('physical/graphs.html', images=images)

@app.route('/physical/predictor', methods=['GET', 'POST'])
def physical_predictor():
    result = None
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
                features = pd.DataFrame([[vol, cur, pow_, freq, pf, s_id]], 
                                        columns=["Voltage (V)", "Current (A)", "Power (kW)", "Frequency (Hz)", "Power_Factor", "Sensor_ID"])
                
                if loc in models["phys"]["zone_models"]:
                    scaler = models["phys"]["zone_scalers"][loc]
                    model = models["phys"]["zone_models"][loc]
                    
                    X_scaled = scaler.transform(features)
                    pred = model.predict(X_scaled)[0]
                    status = "ANOMALY DETECTED" if pred == 1 else "NORMAL"
                else:
                    status = "Unknown Zone"

            result = {'status': status, 'voltage': vol, 'current': cur, 'power': pow_}

            db = get_db(PHYSICAL_DB)
            db.execute('INSERT INTO predictions (sensor_id, location, voltage, current, power, prediction_result) VALUES (?, ?, ?, ?, ?, ?)',
                       (s_id, loc, vol, cur, pow_, status))
            db.commit()

        except Exception as e:
            result = {'status': f"Error: {str(e)}"}

    db = get_db(PHYSICAL_DB)
    cur = db.execute('SELECT * FROM predictions ORDER BY id DESC LIMIT 10')
    history = cur.fetchall()
    
    return render_template('physical/predictor.html', result=result, history=history)


@app.route('/cyber')
def cyber_home():
    return render_template('cyber/index.html')

@app.route('/cyber/input_feed')
def cyber_input_feed():
    data = load_json_data('data/cyber/input_data.json')
    data = data[:50] 
    headers = data[0].keys() if data else []
    return render_template('cyber/input_feed.html', data=data, headers=headers)

@app.route('/cyber/analysis')
def cyber_analysis():
    data = load_json_data('data/cyber/anomaly_detected.json')
    return render_template('cyber/analysis.html', data=data)

@app.route('/cyber/graphs')
def cyber_graphs():
    images = [
        'images/cyber_graph1.png', 
        'images/cyber_graph2.png', 
        'images/cyber_graph3.png', 
        'images/cyber_graph4.png', 
        'images/cyber_graph5.png'
    ]
    return render_template('cyber/graphs.html', images=images)

@app.route('/cyber/predictor', methods=['GET', 'POST'])
def cyber_predictor():
    result = None
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

            db = get_db(CYBER_DB)
            db.execute('INSERT INTO cyber_logs (source_ip, dest_ip, protocol, packet_len, prediction_result) VALUES (?, ?, ?, ?, ?)',
                       (src, dst, proto, pkt_len, status))
            db.commit()

        except Exception as e:
            result = {"status": f"Error: {str(e)}"}

    db = get_db(CYBER_DB)
    cur = db.execute('SELECT * FROM cyber_logs ORDER BY id DESC LIMIT 10')
    history = cur.fetchall()
    
    return render_template('cyber/predictor.html', result=result, history=history)


@app.route('/cyber/visualization')
def cyber_visualization():
    return render_template('cyber/visualization.html')

@app.route('/cyber/graph_data')
def cyber_graph_data():
    data = load_json_data('data/cyber/cyber_graph_data.json')
    return data 


@app.route('/physical/visualization')
def physical_visualization():
    return render_template('physical/visualization.html')

@app.route('/physical/graph_data')
def physical_graph_data():
    data = load_json_data('data/physical/physical_graph_data.json')
    return data

if __name__ == '__main__':
    app.run(debug=True, port=5000)