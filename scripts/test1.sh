sudo python3 -c "
import socket, json, glob, os

# 找套接字
path = '/var/run/dpdk/rte/dpdk_telemetry.v2'
for c in [path] + sorted(glob.glob(path + '.*')):
    if os.path.exists(c):
        for st in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
            try:
                s = socket.socket(socket.AF_UNIX, st); s.settimeout(3); s.connect(c)
                print('=== socket:', c, 'type:', 'STREAM' if st==socket.SOCK_STREAM else 'SEQPACKET')
                s.sendall(json.dumps({'action':0,'command':'/ethdev/stats','token':1}).encode()+b'\n')
                print(s.recv(65536).decode(errors='replace')[:2000])
                s.close()
                break
            except OSError as e:
                try: s.close()
                except: pass
"