from scapy.arch.windows import get_windows_if_list

print("[*] Scapyインターフェース詳細:")
for iface in get_windows_if_list():
    print(f"  - 名前       : {iface['name']}")
    print(f"    説明       : {iface['description']}")
    print(f"    GUID       : {iface['guid']}")
    print(f"    MACアドレス: {iface['mac']}")
    print()

