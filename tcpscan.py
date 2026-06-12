import sys
import socket
import ssl
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0

def syn_scan(target, ports):
    open_ports = []

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)

        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            rst = IP(dst=target) / TCP(dport=port, flags="R")
            sr1(rst, timeout=1, verbose=0)

    return open_ports

def print_bytes(data):
    return ''.join([chr(byte) if 32 <= byte <= 126 else '.' for byte in data])

def tcp_probe(target, port):
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.settimeout(2)

        try:
            data = s.recv(1024)
            if data:
                s.close()
                return (1, print_bytes(data))
        except socket.timeout:
            pass

        try:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = s.recv(1024)
            if data:
                s.close()
                return (3, print_bytes(data))
        except:
            pass

        try:
            s.sendall(b"\r\n\r\n\r\n\r\n")
            data = s.recv(1024)
            s.close()
            if data:
                return (5, print_bytes(data))
            else:
                return (5, "none")
        except:
            s.close()
            return (5, "none")
        
    except:
        return None

def tls_probe(target, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw_sock = socket.create_connection((target, port), timeout=2)
        raw_sock.settimeout(2)

        ssock = context.wrap_socket(raw_sock, server_hostname=target)

        cert = ssock.getpeercert()
        cn = "unknown"
        if cert:
            for item in cert.get('subject', []):
                if item[0][0] == 'commonName':
                    cn = item[0][1]

        try:
            data = ssock.recv(1024)
            if data:
                ssock.close()
                return (2, cn, print_bytes(data))
        except socket.timeout:
            pass

        try:
            ssock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = ssock.recv(1024)
            if data:
                ssock.close()
                return (4, cn, print_bytes(data))
        except:
            pass

        try:
            ssock.sendall(b"\r\n\r\n\r\n\r\n")
            data = ssock.recv(1024)
            ssock.close()
            if data:
                return (6, cn, print_bytes(data))
            else:
                return (6, cn, "none")
        except:
            ssock.close()
            return (6, cn, "none")

    except:
        return None

def fingerprint(target, port):
    tls_result = tls_probe(target, port)
    if tls_result:
        return tls_result

    tcp_result = tcp_probe(target, port)
    if tcp_result:
        return tcp_result

    return None

def print_result(target, port, result):
    if not result:
        return

    possible_states = {
        1: "TCP server-initiated",
        2: "TLS server-initiated",
        3: "HTTP server",
        4: "HTTPS server",
        5: "Generic TCP server",
        6: "Generic TLS server"
    }

    print(f"Host: {target}:{port}")

    if result[0] in [2, 4, 6]:
        _, cn, data = result
        print(f"Type: ({result[0]}) {possible_states[result[0]]} | CN {cn}")
        print(f"Response: {data}")
    else:
        _, data = result
        print(f"Type: ({result[0]}) {possible_states[result[0]]}")
        print(f"Response: {data}")

    print()

def main():
    if len(sys.argv) not in [2,4]:
        print("Usage: tcpscan.py [-p port_range] target")
        sys.exit()
    
    target = sys.argv[-1]
    ports_to_scan = [21,22,23,25,80,110,143,443,587,853,993,3389,8080]

    if len(sys.argv) == 4 and sys.argv[1] == "-p":
        if "-" in sys.argv[2]:
            start_port = int(sys.argv[2].split("-")[0])
            end_port = int(sys.argv[2].split("-")[1])
            ports_to_scan = list(range(start_port, end_port+1))
        elif "," in sys.argv[2]:
            ports_to_scan = list(map(int, sys.argv[2].split(",")))
        else:
            ports_to_scan = [int(sys.argv[2])]

    open_ports = syn_scan(target, ports_to_scan)
    for port in open_ports:
        print_result(target, port, fingerprint(target, port))

if __name__ == "__main__":
    main()