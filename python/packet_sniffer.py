import logging
import logging.handlers
import requests
import json
import os
import threading
import time
import geoip2.database
from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
from datetime import datetime

# UnityのHTTP受信サーバーURL
UNITY_SERVER_URL = "http://localhost:8765"
INTERFACE = "\\Device\\NPF_{23FE3796-0B4B-461E-999E-C711816C4C61}" #BAE165C8-FDF3-18C9-8019-307924B0EE9E(server)  23FE3796-0B4B-461E-999E-C711816C4C61(pc)


# 通信統計保持用
port_traffic = defaultdict(int)  # ポート別通信量（パケット数）
port_ip_traffic = defaultdict(lambda: defaultdict(int))  # ポート×IP別通信数
ip_traffic = defaultdict(int)  # {IPアドレス: 通信回数}
# IPアドレスごとの国名保存用
ip_country = {}
# スキャン検出データ
scan_detection = defaultdict(lambda: {"ports": set(), "last_time": 0})
last_stats_send_time = 0
last_mtime = 0
syslog_logger = logging.getLogger("METIS-Syslog")
syslog_logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address=("localhost", 514), facility=logging.handlers.SysLogHandler.LOG_USER)
syslog_logger.addHandler(handler)


lock = threading.Lock()

# 🔧 config.json 読み込みと監視用
config = {}
config_path = r"C:\Users\nakah\Desktop\metis\config.json"
config_lock = threading.Lock()
last_sent_danger_ports = []

def send_syslog_alert(message: str):
    syslog_logger.info(message)

def send_danger_ports_to_unity():               #Unityに危険ポートのリストを送信。
    try:
        with config_lock:
            ports = config.get("dangerous_ports", [])
        headers = {"Content-Type": "application/json"}
        payload = {
            "type": "danger_ports_update",
            "ports": ports
        }
        response = requests.post(UNITY_SERVER_URL, json=payload, headers=headers, timeout=3)
    except Exception as e:
        print(f"[!] 危険ポート送信エラー: {e}")
                 
def load_config():                               #config.json を読み込んで、Python側に設定反映
    global config
    try:
        with open(config_path, "r") as f:
            new_config = json.load(f)
            new_config["dangerous_ports"] = [int(p) for p in new_config.get("dangerous_ports", [])]
            new_config["scan_threshold_ports"] = int(new_config.get("scan_threshold_ports", 3))
            new_config["scan_threshold_seconds"] = int(new_config.get("scan_threshold_seconds", 10))
            with config_lock:
                config = new_config
            print(f"[✓] 設定再読み込み: {config}")
            send_danger_ports_to_unity()
    except Exception as e:
        print(f"[!] 設定読み込みエラー: {e}")


def config_watcher(interval=5):                   #config.json の更新時刻を定期チェックして、変更があれば load_config() を呼ぶ
    global last_sent_danger_ports, last_mtime
    while True:
        try:
            current_mtime = os.path.getmtime(config_path)
            if current_mtime != last_mtime:
                last_mtime = current_mtime

                # ✅ 設定を再読み込み
                load_config()
                print("[✓] config.json に変更あり → 再読み込み")

                with config_lock:
                    danger_ports = config.get("dangerous_ports", [])
                if danger_ports != last_sent_danger_ports:
                    send_danger_ports_to_unity()
                    last_sent_danger_ports = danger_ports.copy()

        except Exception as e:
            print(f"[!] 設定監視中エラー: {e}")

        time.sleep(interval)



# ✅ 起動時の初回読み込み＋スレッド起動
load_config()
threading.Thread(target=config_watcher, daemon=True).start()




def save_log(data, log_dir='logs'):         #JSON形式でログを logs/packet_log_YYYYMMDD.jsonl に追記保存
    base_dir = os.path.dirname(os.path.abspath(__file__))  # 今動かしてる.pyの場所
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True) # ログディレクトリがなければ作る

    # ファイル名を日付ごとに変える
    date_str = datetime.now().strftime("%Y%m%d")
    log_path = os.path.join(log_dir, f"packet_log_{date_str}.jsonl")

    # 1行ずつJSONで追記モード
    with open(log_path, 'a', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False)
        f.write('\n')
    print(f"[✓] ログ保存成功: {log_path}")



def send_packet_to_unity(packet_data):                 #Unityに1パケットの詳細（src, dst, size, protocol, portなど）を送信
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(UNITY_SERVER_URL, json=packet_data, headers=headers)
        print(f"[✓] 送信: {packet_data['src']} → {packet_data['dst']} | ステータス: {response.status_code}")
    except Exception as e:
        print(f"[!] 送信エラー: {e}")


def send_live_packet_to_unity(src_ip, dst_ip):
    try:
        payload = {
            "type": "live_packet",
            "src": src_ip,
            "dst": dst_ip
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(UNITY_SERVER_URL, json=payload, headers=headers, timeout=2)
        print(f"[LIVE] パケット通知: {src_ip} -> {dst_ip} | ステータス: {response.status_code}")
    except Exception as e:
        print(f"[!] ライブパケット送信エラー: {e}")

        
def send_scan_alert_to_unity(ip):               #ポートスキャンを検知した時にUnityへ警告データを送る。    
    try:
        headers = {"Content-Type": "application/json"}
        alert_data = {
            "type": "scan_alert",
            "src_ip": ip
        }
        response = requests.post(UNITY_SERVER_URL, json=alert_data, headers=headers)
        print(f"[🚨] スキャンアラート送信: {ip} | ステータス: {response.status_code}")

        alert_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "scan_detected",
            "src_ip": ip,
            "dst_ip": None,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "size": 0,
            "country": get_country(ip),
            "alert": "Port scan detected"
        }
        save_log(alert_log)
        send_syslog_alert(f"METIS Alert: Port scan detected from {ip}")
    except Exception as e:
        print(f"[!] スキャンアラート送信エラー: {e}")
    
reader = geoip2.database.Reader(r'C:\Users\nakah\Desktop\metis\GeoLite2-Country_20250404\GeoLite2-Country.mmdb')
def get_country(ip):        #GeoIPデータベースを使って、IPアドレスの国名を取得
    try:
        response = reader.country(ip)
        return response.country.name
    except:
        return "Unknown"

def packet_callback(packet):                       #Scapyがキャプチャしたパケットを解析・記録・送信するメイン処理。危険ポート/スキャン検知/統計収集など全部ここでやる
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            send_live_packet_to_unity(src_ip, dst_ip)

            dport = None
            protocol = "Other"

            if packet.haslayer(TCP):
                protocol = "TCP"
                dport = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                dport = packet[UDP].dport

            size = len(packet)

            if dport is not None:
                if src_ip not in scan_detection:
                    scan_detection[src_ip] = {"ports": set(), "last_time": time.time()}

                scan_detection[src_ip]["ports"].add(dport)
                scan_detection[src_ip]["last_time"] = time.time()

            src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
            dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

            with config_lock:
                dangerous_ports = set(config.get("dangerous_ports", [23, 445, 3389]))

                print(f"[デバッグ] {src_ip} のポート記録: {scan_detection[src_ip]['ports']}")
                scan_threshold_seconds = int(config.get("scan_threshold_seconds", 20))
                scan_threshold_ports = int(config.get("scan_threshold_ports", 3))

                print(f"[デバッグ] {src_ip} のポート記録: {scan_detection[src_ip]['ports']}")

            if dst_port in dangerous_ports:
                print(f"[⚠️] 危険ポート {dst_port} へのアクセス検知！")

                danger_alert_log = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "dangerous_port_detected",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "size": size,
                    "country": get_country(src_ip),
                    "alert": f"Access to dangerous port {dst_port}"
                }            
                save_log(danger_alert_log)

            payload = packet[Raw].load.hex() if Raw in packet else None

            now = time.time()
            if dst_port:
                data = scan_detection[src_ip]

                if now - data["last_time"] > scan_threshold_seconds:
                    data["ports"].clear()

                data["ports"].add(dst_port)
                data["last_time"] = now

                if len(data["ports"]) > scan_threshold_ports:
                    print(f"[⚠️] スキャン検知: {src_ip}")
                    send_scan_alert_to_unity(src_ip)
                    data["ports"].clear()

            src_country = get_country(src_ip)
            dst_country = get_country(dst_ip)

            with lock:
                if src_ip not in ip_country:
                    ip_country[src_ip] = src_country
                if dst_ip not in ip_country:
                    ip_country[dst_ip] = dst_country

                print(f"[TRACK] dst_port = {dst_port} (type: {type(dst_port)})")

                if dst_port:
                    port_traffic[dst_port] += 1
                    print(f"[✅] port_traffic[{dst_port}] = {port_traffic[dst_port]}")
                    port_ip_traffic[dst_port][src_ip] += 1
                else:
                    ip_traffic[src_ip] += 1
                    ip_traffic[dst_ip] += 1

            packet_data = {
                "type": "packet",
                "src": src_ip,
                "dst": dst_ip,
                "src_country": src_country,
                "dst_country": dst_country,
                "protocol": protocol,
                "size": size,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": payload
            }
            send_packet_to_unity(packet_data)
            save_log(packet_data)

            global last_stats_send_time
            if now - last_stats_send_time >= 1:
                send_port_ip_stats()
                last_stats_send_time = now

    except Exception as e:
        print(f"[❌] packet_callback 内で例外発生: {e}")





def send_port_ip_stats():     #各ポートとIPごとの統計をUnityに送信
    try:
        with lock:
            # 統計データのディープコピー（送信中の変更防止）
            stats_copy = {port: dict(ip_counts) for port, ip_counts in port_ip_traffic.items()}
        print(f"[デバッグ] port_ip_traffic 現在の内容: {stats_copy}")
        
        payload = {
            "type": "port_ip_stats",
            "port_ip_counts": stats_copy
        }

        headers = {"Content-Type": "application/json"}
        response = requests.post(UNITY_SERVER_URL, json=payload, headers=headers)

        print(f"[📤] ポート×IP統計送信: {len(stats_copy)}件 | ステータス: {response.status_code}")
    except Exception as e:
        print(f"[!] ポート統計送信エラー: {e}")



  
def send_stats_periodically(interval=5):        #5秒おきに通信統計（ポート数、IP数など）をまとめてUnityへ送る
    headers = {"Content-Type": "application/json"}
    while True:
        time.sleep(interval)

        # ★ ここでデータ作る（ロック中）
        with lock:
            stats_data = {
                "type": "port_stats",
                "port_counts": dict(port_traffic)
            }
            port_traffic.clear()

            send_ip_stats = {}
            for port, ip_counts in port_ip_traffic.items():
                send_ip_stats[port] = dict(ip_counts)

            ip_ports = {}
            for port, ip_counts in port_ip_traffic.items():
                for ip in ip_counts:
                    if ip not in ip_ports:
                        ip_ports[ip] = set()
                    ip_ports[ip].add(port)

            port_ip_traffic.clear()

        # ★ ロック抜けたあとに送信開始

        # 送信①: ポートごとのパケット数
        try:
            response = requests.post(UNITY_SERVER_URL, json=stats_data, headers=headers)
            print(f"[★] ポート統計送信: {len(stats_data['port_counts'])}件")
        except Exception as e:
            print(f"[!] ポート統計送信エラー: {e}")

        # 送信②: ポート×IP統計
        try:
            if send_ip_stats:

                print("[デバッグ] 送信するポート×IP統計:")
                print(json.dumps(send_ip_stats, indent=2))
                port_ip_data = {
                    "type": "port_ip_stats",
                    "port_ip_counts": send_ip_stats
                }
                response = requests.post(UNITY_SERVER_URL, json=port_ip_data, headers=headers)
                print(f"[★] ポート×IP統計送信: {len(port_ip_data['port_ip_counts'])}件")
        except Exception as e:
            print(f"[!] ポート×IP統計送信エラー: {e}")

        # 送信③: IPごとの使用ポート一覧
        try:
            if ip_ports:
                ip_port_data = {
                    "type": "ip_port_stats",
                    "ip_ports": {ip: list(ports) for ip, ports in ip_ports.items()}
                }
                response = requests.post(UNITY_SERVER_URL, json=ip_port_data, headers=headers)
                print(f"[🌐] IP×ポート情報送信: {len(ip_port_data['ip_ports'])}件")
        except Exception as e:
            print(f"[!] IP×ポート情報送信エラー: {e}")

        # 送信④: IPごとの通信回数
        try:
            if ip_traffic:
                ip_traffic_data = {
                    "type": "ip_traffic_stats",
                    "ip_traffic_counts": dict(ip_traffic)
                }
                response = requests.post(UNITY_SERVER_URL, json=ip_traffic_data, headers=headers)
                print(f"[📈] IP通信回数送信: {len(ip_traffic_data['ip_traffic_counts'])}件")
                ip_traffic.clear()  # 送信後リセット
        except Exception as e:
            print(f"[!] IP通信回数送信エラー: {e}")

        # 送信⑤: IPごとの国名情報
        try:
            if ip_country:
                ip_country_data = {
                    "type": "ip_country_stats",
                    "ip_countries": dict(ip_country)
                }
                response = requests.post(UNITY_SERVER_URL, json=ip_country_data, headers=headers)
                print(f"[🌎] IP国名情報送信: {len(ip_country_data['ip_countries'])}件")
                ip_country.clear()  # 送信後リセット
        except Exception as e:
            print(f"[!] IP国名送信エラー: {e}")



def start_sniffing():                                             #パケットスニファーを開始。packet_callback() をリアルタイムで呼び続ける
    print(f"[*] リアルタイムでパケットを送信します（Ctrl+Cで終了）")

    # 統計送信スレッド開始
    stats_thread = threading.Thread(target=send_stats_periodically, daemon=True)
    stats_thread.start()

    sniff(prn=packet_callback, store=False, iface=INTERFACE)

if __name__ == "__main__":
    save_log({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "test": "初期動作確認ログ"
     })
    start_sniffing()






