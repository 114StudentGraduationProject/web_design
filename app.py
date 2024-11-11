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
        
        # 初次查詢介面流量時初始化 previous_data
        if selected_interface not in previous_data:
            previous_data[selected_interface] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'time': current_time
            }
            return jsonify({'status': 'success', 'traffic_data': {'rate_sent': 0, 'rate_recv': 0}}), 200

        # 計算發送和接收速率
        elapsed_time = current_time - previous_data[selected_interface]['time']
        rate_sent = (net_io.bytes_sent - previous_data[selected_interface]['bytes_sent']) * 8 / elapsed_time / 1_000_000
        rate_recv = (net_io.bytes_recv - previous_data[selected_interface]['bytes_recv']) * 8 / elapsed_time / 1_000_000

        # 更新前次數據並回傳給前端
        previous_data[selected_interface] = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'time': current_time
        }
        return jsonify({'status': 'success', 'traffic_data': {'rate_sent': rate_sent, 'rate_recv': rate_recv}}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid or missing network interface'}), 400

# Function to start Suricata and tail fast.log
# Function to start Suricata and tail fast.log with configuration validation
def start_suricata(interface='eth0'):
    global suricata_process, tail_process
    if suricata_process is None:
        try:
            # Test Suricata configuration first
            test_command = ['sudo', 'suricata', '-T', '-c', '/etc/suricata/suricata.yaml']
            test_result = subprocess.run(test_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Check if the configuration test was successful
            if test_result.returncode != 0:
                return {'status': 'error', 'message': f'Suricata configuration test failed: {test_result.stderr}'}

            # Start Suricata
            suricata_command = ['sudo', 'suricata', '-c', '/etc/suricata/suricata.yaml', '-i', interface]
            suricata_process = subprocess.Popen(suricata_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Start tail on fast.log
            tail_command = ['sudo', 'tail', '-f', '/var/log/suricata/fast.log']
            tail_process = subprocess.Popen(tail_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            return {'status': 'success', 'message': 'Suricata configuration validated and monitoring started'}
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

# Get Error Packet data from Suricata's fast.log
@app.route('/get_error_packet_data', methods=['GET'])
def get_error_packet_data():
    log_path = '/var/log/suricata/fast.log'  # 修改為您的實際 Suricata 日誌路徑
    error_packets = []

    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as file:
                lines = file.readlines()
                for line in lines[-50:]:  # 只讀取最後 50 行，以獲取最近的錯誤封包
                    # 使用正則表達式解析 fast.log 中的錯誤封包資料
                    match = re.search(r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]\s+\[.*?\]\s+\[.*?\]\s+\{(.*?)\}\s+(\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(\d+\.\d+\.\d+\.\d+):\d+', line)
                    if match:
                        error_packets.append({
                            "time": match.group(1),    # 時間
                            "source": match.group(4),  # 來源 IP
                            "destination": match.group(5),  # 目標 IP
                            "protocol": match.group(3),  # 協定
                            "length": "N/A",  # 此處可以設計為取得真實的封包長度，如果 fast.log 中有
                            "info": match.group(2)  # 錯誤或告警訊息
                        })

        except IOError as e:
            return jsonify({"status": "error", "message": f"Error reading log file: {str(e)}"}), 500
    else:
        return jsonify({"status": "error", "message": "Log file not found"}), 404

    return jsonify({"status": "success", "data": error_packets})


# 用於驗證 Suricata 規則格式的正則表達式
RULE_REGEX = re.compile(r'^(alert|drop|pass|reject) (tcp|udp|icmp|ip) any any -> any any \((.*?)\)$')

# Suricata rule added
@app.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.get_json()
    rule = data.get("rule")

    if not rule:
        return jsonify({"status": "error", "message": "No rule provided"}), 400

    # 驗證規則格式
    if not RULE_REGEX.match(rule):
        return jsonify({"status": "error", "message": "Invalid rule format"}), 400

    try:
        # Append the rule to a.rules
        with open('/home/kali/Desktop/a.rules', 'a') as f:
            f.write(rule + "\n")

        # Test Suricata configuration with the new rule
        result = subprocess.run(
            ["sudo", "suricata", "-T", "-c", "/etc/suricata/suricata.yaml"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Check if the command was successful
        if result.returncode == 0:
            return jsonify({"status": "success", "message": "Rule added successfully."})
        else:
            # If there's an error, return the stderr output and remove the invalid rule
            return jsonify({"status": "error", "message": result.stderr}), 500

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
    
if __name__ == '__main__':
    app.run(debug=True)
