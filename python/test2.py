import socket

target_ip = "127.0.0.1"  # 宛先IP（自分のデフォルトゲートウェイなどでも可）
danger_ports = [23, 445, 3389, 53, 80, 10000]

message = b"metis_test_packet"

for port in danger_ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDPソケットを使用
        sock.sendto(message, (target_ip, port))
        print(f"✅ Port {port} にUDPパケット送信しました")
    except Exception as e:
        print(f"❌ Port {port} の送信失敗: {e}")
    finally:
        sock.close()
