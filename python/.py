import asyncio
import websockets
from scapy.all import sniff, IP, TCP, UDP

# WebSocketサーバーの設定
WEBSOCKET_SERVER = "ws://localhost:8765"

async def send_packet_data(packet):
    """パケット情報をWebSocketでUnityに送信"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        size = len(packet)

        # JSONデータを作成
        data = f'{{"src": "{src_ip}", "dst": "{dst_ip}", "protocol": "{protocol}", "size": {size}}}'

        try:
            async with websockets.connect(WEBSOCKET_SERVER) as websocket:
                await websocket.send(data)
        except Exception as e:
            print(f"[!] WebSocket送信エラー: {e}")

def packet_callback(packet):
    """パケットを受信したときの処理"""
    asyncio.run(send_packet_data(packet))

def start_sniffing():
    """ネットワークのパケットをキャプチャ"""
    print("[*] パケットキャプチャを開始...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
