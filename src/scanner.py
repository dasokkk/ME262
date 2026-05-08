"""
Scanning Agent — Evasive Raw Packet Scanner (Stealth SYN)

Instead of using full TCP connections via the kernel, this scanner crafts
raw IP/TCP packets using Scapy to completely control its fingerprint.

Features:
- Stealth half-open SYN scanning (evades full-connect logs)
- Randomized IP headers (ID, DF flags)
- Randomized TCP characteristics (Source Port, Window Size, MSS, Options)
- Background sniffer to catch returning SYN-ACKs asynchronously.
"""

import time
import random
import threading
from typing import List, Dict, Optional
from queue import Queue
from dataclasses import dataclass

try:
    from scapy.all import IP, TCP, Raw, send, conf, AsyncSniffer, fragment
except ImportError:
    pass

@dataclass
class ScanEvent:
    
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    scan_type: str      
    result: str           # 'open', 'closed', 'filtered', 'sent'
    duration_ms: float
    handshake_complete: bool



TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9090, 11434, 27017
]

EXTENDED_PORTS = list(range(1, 1025))


PROFILES = {
    "aggressive": {
        "scan_rate": 20.0,
        "port_strategy": "top",
        "timing_model": "fixed",
        "timeout": 0.4,
        "scan_type": "stealth_syn",
    },
    "normal": {
        "scan_rate": 3.0,
        "port_strategy": "top",
        "timing_model": "jitter",
        "timeout": 1.0,
        "scan_type": "stealth_syn",
    },
    "stealth": {
        "scan_rate": 0.5,
        "port_strategy": "random",
        "timing_model": "longtail",
        "timeout": 2.0,
        "scan_type": "stealth_syn",
    },
}

class ScannerAgent:
    """
    Evasive Stealth SYN Scanner.
    Crafts raw packets to bypass common signatures.
    """

    def __init__(self, target: str, event_queue: Queue, iface: str = None):
        self.target = target
        self.event_queue = event_queue
        self.iface = iface

        self.scan_rate: float = 3.0
        self.port_strategy: str = "top"
        self.timing_model: str = "jitter"
        self.scan_type: str = "stealth_syn"
        self.timeout: float = 1.0
        self.jitter_range: float = 0.3
        self.burst_size: int = 5
        self.burst_delay: float = 2.0
        self.source_port: Optional[int] = None
        self.spoof_app: bool = False
        self.full_connect: bool = False
        self.ssl_scan: bool = False
        self.proxy: Optional[str] = None
        self.mtu: Optional[int] = None

        self._running = False
        self._paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()
        
        self._send_thread: Optional[threading.Thread] = None
        self._sniffer: Optional[AsyncSniffer] = None
        
        self._scan_count = 0
        self._open_ports: List[int] = []
        self._lock = threading.Lock()
        
        
        self._sent_timestamps: Dict[int, float] = {}

    

    def apply_profile(self, name: str):
        if name in PROFILES:
            self.update_params(**PROFILES[name])

    def update_params(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k) and not k.startswith("_"):
                    setattr(self, k, v)

    @property
    def params_dict(self) -> Dict:
        with self._lock:
            return {
                "scan_rate": self.scan_rate,
                "port_strategy": self.port_strategy,
                "timing_model": self.timing_model,
                "scan_type": self.scan_type,
                "timeout": self.timeout,
                "source_port": self.source_port if self.source_port else "random",
                "spoof_app": self.spoof_app,
                "full_connect": self.full_connect,
                "ssl_scan": self.ssl_scan,
                "proxy": self.proxy if self.proxy else "none",
                "mtu": self.mtu if self.mtu else "none",
                "interface": str(self.iface or "auto"),
            }

    @property
    def scan_count(self) -> int:
        return self._scan_count

    @property
    def open_ports(self) -> List[int]:
        return list(set(self._open_ports))

    @property
    def is_paused(self) -> bool:
        return self._paused

    

    def start(self):
        self._running = True
        
        
        bpf_filter = f"tcp and src host {self.target}"
        if not getattr(self, "proxy", None):
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                filter=bpf_filter,
                prn=self._recv_packet,
                store=False
            )
            self._sniffer.start()
        
        
        
        self._send_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._send_thread.start()

    def pause(self):
        self._paused = True
        self._pause_event.clear()

    def resume(self):
        self._paused = False
        self._pause_event.set()

    def stop(self):
        self._running = False
        self._pause_event.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._send_thread:
            self._send_thread.join(timeout=3)

    

    def _get_ports(self) -> List[int]:
        with self._lock:
            strategy = self.port_strategy

        if strategy == "top":
            return list(TOP_PORTS)
        elif strategy == "random":
            return random.sample(range(1, 65536), 50)
        elif strategy == "sequential":
            return list(EXTENDED_PORTS)
        elif strategy == "weighted":
            extra = random.sample(range(1025, 65536), 20)
            return list(TOP_PORTS) + extra
        return list(TOP_PORTS)

    def _get_delay(self) -> float:
        with self._lock:
            base = 1.0 / max(self.scan_rate, 0.01)
            model = self.timing_model
            jitter = self.jitter_range
            bsz = self.burst_size
            bdl = self.burst_delay

        if model == "fixed":
            return base
        elif model == "jitter":
            return max(0.005, base + random.uniform(-jitter, jitter))
        elif model == "burst":
            if self._scan_count % bsz == 0 and self._scan_count > 0:
                return bdl
            return 0.01
        elif model == "longtail":
            return random.expovariate(1.0 / max(base, 0.1))
        return base

    

    def _craft_packet(self, dport: int):
        
        
        ip_layer = IP(
            dst=self.target,
            id=random.randint(1, 65535),
            ttl=random.choice([64, 128, 255])  
        )
        
        
        win_size = random.choice([8192, 14600, 29200, 65535])
        sport = getattr(self, "source_port", None)
        if sport is None:
            sport = random.randint(10000, 65000)
        
        
        options = [('MSS', random.choice([1460, 1400, 1380]))]
        if random.random() > 0.5:
            options.append(('SAckOK', ''))
        if random.random() > 0.5:
            options.append(('WScale', random.randint(2, 8)))
        if random.random() > 0.3:
            options.append(('NOP', None))
            
        random.shuffle(options) 

        tcp_layer = TCP(
            sport=sport,
            dport=dport,
            flags="S",
            seq=random.randint(1000, 4294967295),
            window=win_size,
            options=options
        )
        
        pkt = ip_layer / tcp_layer
        
        if getattr(self, "spoof_app", False):
            if dport in (80, 8080):
                payload = b"GET / HTTP/1.1\r\nHost: " + self.target.encode(errors="ignore") + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                pkt = pkt / Raw(load=payload)
            elif dport in (443, 8443):
                import os
                # Dummy TLS ClientHello
                payload = bytes.fromhex("160301002f0100002b0303") + os.urandom(28) + bytes.fromhex("000002c02b0100")
                pkt = pkt / Raw(load=payload)
            elif dport == 53:
                # Dummy DNS query for google.com
                payload = bytes.fromhex("abcd0100000100000000000006676f6f676c6503636f6d0000010001")
                pkt = pkt / Raw(load=payload)
                
        return pkt

    

    def _scan_loop(self):
        ports = self._get_ports()
        
        proxy = getattr(self, "proxy", None)
        if proxy:
            self._proxy_scan_loop(ports, proxy)
            return

        for port in ports:
            self._pause_event.wait()
            if not self._running:
                return
            
            pkt = self._craft_packet(port)
            
            
            self._sent_timestamps[port] = time.time()
            
            
            try:
                if getattr(self, "mtu", None):
                    # Fragment the packet based on provided MTU
                    frags = fragment(pkt, fragsize=self.mtu)
                    for f in frags:
                        send(f, verbose=False)
                        # Add a tiny delay between fragments to mimic natural flow
                        time.sleep(0.001)
                else:
                    send(pkt, verbose=False)
                self._scan_count += 1
            except Exception as e:
                
                pass
            
            
            ev = ScanEvent(
                timestamp=time.time(),
                src_ip=pkt[IP].src,
                dst_ip=self.target,
                dst_port=port,
                scan_type=self.scan_type,
                result="sent",
                duration_ms=0.0,
                handshake_complete=False
            )
            self.event_queue.put(ev)
            
            time.sleep(self._get_delay())
            
        
        time.sleep(self.timeout)
        with self._lock:
            now = time.time()
            to_delete = []
            for p, marked_time in self._sent_timestamps.items():
                if now - marked_time >= self.timeout:
                    to_delete.append(p)
                    ev = ScanEvent(
                        timestamp=time.time(),
                        src_ip="local",
                        dst_ip=self.target,
                        dst_port=p,
                        scan_type=self.scan_type,
                        result="filtered",
                        duration_ms=self.timeout * 1000,
                        handshake_complete=False
                    )
                    self.event_queue.put(ev)
            for p in to_delete:
                del self._sent_timestamps[p]
                
       
        self._running = False

    def _proxy_scan_loop(self, ports, proxy):
        import socket
        try:
            import socks
        except ImportError:
            socks = None

        proxy_list = [p.strip() for p in proxy.split(",") if p.strip()]

        for port in ports:
            self._pause_event.wait()
            if not self._running:
                return

            self._scan_count += 1
            start_t = time.time()
            result = "closed"
            
            current_proxy = random.choice(proxy_list)
            
            try:
                if socks:
                    # Parse proxy string e.g. socks5://127.0.0.1:9050 or http://10.0.0.1:8080
                    proxy_type_str, proxy_addr = current_proxy.split("://", 1)
                    proxy_host, proxy_port = proxy_addr.split(":", 1)
                    
                    if proxy_type_str.lower() == "socks5":
                        ptype = socks.SOCKS5
                    elif proxy_type_str.lower() == "socks4":
                        ptype = socks.SOCKS4
                    else:
                        ptype = socks.HTTP
                        
                    s = socks.socksocket()
                    s.set_proxy(ptype, proxy_host, int(proxy_port))
                    s.settimeout(self.timeout)
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout)

                s.connect((self.target, port))
                result = "open"
                
                with self._lock:
                    self._open_ports.append(port)
                    
                if getattr(self, "ssl_scan", False) or getattr(self, "spoof_app", False):
                    # We send some dummy application layer data inside the proxy tunnel
                    try:
                        req = b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n"
                        s.sendall(req)
                    except Exception:
                        pass
                
                s.close()
            except Exception:
                pass
                
            rtt = (time.time() - start_t) * 1000.0
            
            ev = ScanEvent(
                timestamp=time.time(),
                src_ip="proxy",
                dst_ip=self.target,
                dst_port=port,
                scan_type="proxy_connect",
                result=result,
                duration_ms=rtt,
                handshake_complete=result == "open"
            )
            self.event_queue.put(ev)
            
            time.sleep(self._get_delay())
            
        self._running = False

    def _ssl_poke(self, port: int):
        import socket
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    req = b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\nConnection: close\r\n\r\n"
                    ssock.sendall(req)
        except Exception:
            pass

    

    def _recv_packet(self, pkt):
        if TCP in pkt and IP in pkt:
            src_ip = pkt[IP].src
            src_port = pkt[TCP].sport
            flags = pkt[TCP].flags

            scan_type_str = self.scan_type
            hs_complete = False

            with self._lock:
                if src_port not in self._sent_timestamps:
                    return
                rtt = (time.time() - self._sent_timestamps[src_port]) * 1000.0

                # SYN-ACK -> Open
                if flags == 0x12:
                    result = "open"
                    self._open_ports.append(src_port)
                    
                    if getattr(self, "ssl_scan", False):
                        scan_type_str = "tls_connect"
                        hs_complete = True
                        
                        rst_pkt = IP(dst=self.target, src=pkt[IP].dst) / TCP(
                            sport=pkt[TCP].dport, 
                            dport=src_port, 
                            flags="R", 
                            seq=pkt[TCP].ack
                        )
                        send(rst_pkt, verbose=False)
                        
                        threading.Thread(target=self._ssl_poke, args=(src_port,), daemon=True).start()
                        
                    elif getattr(self, "full_connect", False):
                        scan_type_str = "connect"
                        hs_complete = True
                        # Complete the 3-way handshake with ACK
                        ack_pkt = IP(dst=self.target, src=pkt[IP].dst) / TCP(
                            sport=pkt[TCP].dport, 
                            dport=src_port, 
                            flags="A", 
                            seq=pkt[TCP].ack, 
                            ack=pkt[TCP].seq + 1
                        )
                        send(ack_pkt, verbose=False)
                        
                        # Gracefully close with RST-ACK
                        rst_pkt = IP(dst=self.target, src=pkt[IP].dst) / TCP(
                            sport=pkt[TCP].dport, 
                            dport=src_port, 
                            flags="RA", 
                            seq=pkt[TCP].ack, 
                            ack=pkt[TCP].seq + 1
                        )
                        send(rst_pkt, verbose=False)
                        
                elif flags & 0x04:
                    result = "closed"
                else:
                    return

                del self._sent_timestamps[src_port]

            ev = ScanEvent(
                timestamp=time.time(),
                src_ip=pkt[IP].dst,
                dst_ip=src_ip,
                dst_port=src_port,
                scan_type=scan_type_str,
                result=result,
                duration_ms=rtt,
                handshake_complete=hs_complete
            )
            self.event_queue.put(ev)