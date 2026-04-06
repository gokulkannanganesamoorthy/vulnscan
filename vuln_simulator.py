from flask import Flask, jsonify, Response

app = Flask(__name__)

# ==========================================
# Module 24: Wireless Controller Simulator
# ==========================================

@app.route('/')
def home():
    # Simulating an Aruba or Cisco server header
    response = Response("Welcome to the Controller Dashboard")
    response.headers['Server'] = 'Aruba Networks / WLC'
    return response

@app.route('/config.xml')
def wlc_config():
    # Simulates an exposed config backup
    xml = """<?xml version="1.0"?>
    <config>
        <admin>
            <username>admin</username>
            <password>admin123</password>
        </admin>
        <wifi>
            <ssid>Corp_Network</ssid>
            <psk>SuperSecretWiFiKey99</psk>
        </wifi>
    </config>"""
    return Response(xml, mimetype='application/xml')

@app.route('/backup.cfg')
def wlc_backup():
    return "ENABLE_PASSWORD=cisco\nSNMP_COMMUNITY=public"

# ==========================================
# Module 25: WSN/IoT API Simulator
# ==========================================

@app.route('/api/v1/sensors')
def sensors_api():
    # Simulates broken auth on a sensor gateway
    return jsonify({
        "status": "success",
        "sensors": [
            {"id": "SENS-01", "type": "Temperature", "val": 22.5},
            {"id": "SENS-02", "type": "Door_Lock", "state": "UNLOCKED"}
        ]
    })

@app.route('/namf-comm/v1/ue-contexts')
def fgc_api():
    # Simulates an exposed 5G Core Network AMF Interface
    return jsonify({
        "status": "success",
        "ue_contexts": [
            {"imsi": "310410123456789", "state": "IDLE"},
            {"imsi": "310410987654321", "state": "CONNECTED"}
        ]
    })

if __name__ == '__main__':
    print("==================================================")
    print(" Starting Vulnerable Wireless & IoT Simulator")
    print("==================================================")
    print(" Target URL for VulnScan: http://127.0.0.1:5000")
    print(" Modules to test: 24 (WLC) and 25 (WSN/IoT)")
    print(" Press CTRL+C to stop.")
    app.run(host='127.0.0.1', port=5000)
