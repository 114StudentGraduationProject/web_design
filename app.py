from flask import Flask, render_template, jsonify, request
import os
import psutil
import subprocess
import time
import re  # 用於正則表達式解析 fast.log
import signal

app = Flask(__name__)

# Initialize previous_data
previous_data = {}
suricata_process = None  # 保存 Suricata 進程的變數
tail_process = None


# Render homepage
@app.route('/')
def index():
    return render_template('index.html')

# Get available network interfaces
@app.route('/get_interfaces', methods=['GET'])
def get_interfaces():
    interfaces = psutil.net_if_stats().keys()
    return jsonify({'interfaces': list(interfaces)})

# Get network traffic rate
@app.route('/get_network_traffic', methods=['POST'])
def get_network_traffic():
    global previous_data
    data = request.get_json()
    selected_interface = data.get('interface')
    
    if selected_interface and selected_interface in psutil.net_io_counters(pernic=True):
        net_io = psutil.net_io_counters(pernic=True)[selected_interface]
        current_time = time.time()
        
        if selected_interface not in previous_data:
            previous_data[selected_interface] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'time': current_time
            }
            return jsonify({'status': 'success', 'traffic_data': {'rate_sent': 0, 'rate_recv': 0}}), 200
        
        elapsed_time = current_time - previous_data[selected_interface]['time']
        rate_sent = (net_io.bytes_sent - previous_data[selected_interface]['bytes_sent']) * 8 / elapsed_time / 1_000_000
        rate_recv = (net_io.bytes_recv - previous_data[selected_interface]['bytes_recv']) * 8 / elapsed_time / 1_000_000
        
        previous_data[selected_interface] = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'time': current_time
        }
        return jsonify({'status': 'success', 'traffic_data': {'rate_sent': rate_sent, 'rate_recv': rate_recv}}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid or missing network interface'}), 400

# Function to start Suricata and tail fast.log
def start_suricata(interface='eth0'):
    global suricata_process, tail_process
    if suricata_process is None:
        try:
            # Start Suricata
            suricata_command = ['sudo', 'suricata', '-c', '/etc/suricata/suricata.yaml', '-i', interface]
            suricata_process = subprocess.Popen(suricata_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Start tail on fast.log
            tail_command = ['sudo', 'tail', '-f', '/var/log/suricata/fast.log']
            tail_process = subprocess.Popen(tail_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            return {'status': 'success', 'message': 'Suricata and log tailing started'}
        except Exception as e:
            return {'status': 'error', 'message': f'Failed to start Suricata or tail fast.log: {str(e)}'}
    else:
        return {'status': 'error', 'message': 'Suricata is already running'}

@app.route('/start_suricata', methods=['POST'])
def start_suricata_endpoint():
    response = start_suricata()
    return jsonify(response)

@app.route('/get_scan_results', methods=['GET'])
def get_scan_results():
    log_path = '/var/log/suricata/fast.log'
    results = []

    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as file:
                lines = file.readlines()
                for line in lines[-10:]:
                    match = re.search(r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]\s+\[.*?\]\s+\[.*?\]\s+\{(.*?)\}\s+(\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(\d+\.\d+\.\d+\.\d+):\d+', line)
                    if match:
                        results.append({
                            'time': match.group(1),
                            'msg': match.group(2),
                            'source_ip': match.group(4),
                            'destination_ip': match.group(5)
                        })
        except IOError as e:
            return jsonify({'status': 'error', 'message': f'Error reading log file: {str(e)}'}), 500
    else:
        return jsonify({'status': 'error', 'message': 'Log file not found'}), 404

    return jsonify({'results': results})


# Get Wireshark data
@app.route('/get_wireshark_data', methods=['GET'])
def get_wireshark_data():
    selected_interface = request.args.get('interface', 'lo')
    try:
        command = ['tshark', '-i', selected_interface, '-c', '10', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.protocols', '-e', 'frame.len', '-e', '_ws.col.Info']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            return jsonify({'status': 'error', 'message': result.stderr}), 500

        output = result.stdout.strip().split('\n')
        data = []
        for line in output:
            fields = line.split('\t')
            if len(fields) >= 5:
                data.append({
                    'source': fields[0],
                    'destination': fields[1],
                    'protocol': fields[2],
                    'length': fields[3],
                    'info': fields[4]
                })

        return jsonify({'status': 'success', 'data': data}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
