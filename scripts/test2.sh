# 1. DPDK 版本 (决定 telemetry API 版本)
sudo dpdk-testpmd --version

# 2. 列出所有可用 telemetry 命令
sudo python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.settimeout(3)
s.connect('/var/run/dpdk/rte/dpdk_telemetry.v2')
s.sendall(json.dumps({'action':0,'command':'/','token':1}).encode()+b'\n')
print(s.recv(65536).decode(errors='replace')[:3000])
"