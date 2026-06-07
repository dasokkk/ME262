"""
Scanning Agent — Evasive Raw Packet Scanner (Stealth SYN).

Instead of using full TCP connections via the kernel, this scanner crafts raw
IP/TCP packets with Scapy to fully control its fingerprint.

Capabilities:
- Stealth half-open SYN scanning (evades full-connect logs)
- Randomized IP headers (ID, TTL) and TCP characteristics (source port,
  window size, MSS, shuffled options)
- Decoy source IPs, source IP/MAC spoofing, custom TTL, IP options, bad checksum
- App-layer payload spoofing, full-connect, real SSL/TLS handshakes, proxy routing
- IP fragmentation by MTU
- Optional banner/version grab on open ports
- Background sniffer to catch returning SYN-ACKs asynchronously
"""

import time
import random
import threading
from typing import List, Dict, Optional
from queue import Queue
from dataclasses import dataclass

try:
    from scapy.all import (
        IP, TCP, Raw, Ether, IPOption,
        send, sendp, fragment, getmacbyip, AsyncSniffer,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class ScanEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    scan_type: str
    result: str
    duration_ms: float
    handshake_complete: bool
    banner: str = ""


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9090, 11434, 27017,
]

EXTENDED_PORTS = list(range(1, 1025))

PROFILES = {
    "aggressive": {"scan_rate": 20.0, "port_strategy": "top", "timing_model": "fixed", "timeout": 0.4},
    "normal": {"scan_rate": 3.0, "port_strategy": "top", "timing_model": "jitter", "timeout": 1.0},
    "stealth": {"scan_rate": 0.5, "port_strategy": "random", "timing_model": "longtail", "timeout": 2.0},
}


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


class ScannerAgent:
    """Evasive stealth SYN scanner that crafts raw packets to bypass signatures."""

    def __init__(self, target: str, event_queue: Queue, iface: str = None,
                 target_ip: str = None):
        self.target = target
        self.target_ip = target_ip or target
        self.event_queue = event_queue
        self.iface = iface

        self.scan_rate: float = 3.0
        self.port_strategy: str = "top"
        self.timing_model: str = "jitter"
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

        self.decoys: List[str] = []
        self.spoof_ip: Optional[str] = None
        self.spoof_mac: Optional[str] = None
        self.ttl: Optional[int] = None
        self.ip_options: Optional[str] = None
        self.badsum: bool = False
        self.banner_grab: bool = False

        self._running = False
        self._paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()

        self._send_thread: Optional[threading.Thread] = None
        self._sniffer: Optional["AsyncSniffer"] = None

        self._scan_count = 0
        self._open_ports: List[int] = []
        self._service_info: Dict[int, str] = {}
        self._sent_timestamps: Dict[int, float] = {}
        self._lock = threading.Lock()

    def apply_profile(self, name: str):
        if name in PROFILES:
            self.update_params(**PROFILES[name])

    def update_params(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k) and not k.startswith("_"):
                    setattr(self, k, v)

    def _scan_type_label(self) -> str:
        if self.proxy:
            return "proxy_connect"
        if self.ssl_scan:
            return "tls_connect"
        if self.full_connect:
            return "tcp_connect"
        return "stealth_syn"

    @property
    def params_dict(self) -> Dict:
        with self._lock:
            decoys = self.decoys if isinstance(self.decoys, list) else [self.decoys]
            return {
                "scan_rate": self.scan_rate,
                "port_strategy": self.port_strategy,
                "timing_model": self.timing_model,
                "scan_type": self._scan_type_label(),
                "timeout": self.timeout,
                "source_port": self.source_port if self.source_port else "random",
                "spoof_app": self.spoof_app,
                "full_connect": self.full_connect,
                "ssl_scan": self.ssl_scan,
                "proxy": self.proxy if self.proxy else "none",
                "mtu": self.mtu if self.mtu else "none",
                "ttl": self.ttl if self.ttl else "random",
                "badsum": self.badsum,
                "decoys": ", ".join(d for d in decoys if d) or "none",
                "spoof_ip": self.spoof_ip or "none",
                "spoof_mac": self.spoof_mac or "none",
                "banner_grab": self.banner_grab,
                "interface": str(self.iface or "auto"),
            }

    @property
    def scan_count(self) -> int:
        return self._scan_count

    @property
    def open_ports(self) -> List[int]:
        with self._lock:
            return sorted(set(self._open_ports))

    @property
    def service_info(self) -> Dict[int, str]:
        with self._lock:
            return dict(self._service_info)

    @property
    def is_paused(self) -> bool:
        return self._paused

    def start(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed — run: pip install scapy")
        self._running = True

        if not self.proxy:
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                filter=f"tcp and src host {self.target_ip}",
                prn=self._recv_packet,
                store=False,
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
        if strategy == "random":
            return random.sample(range(1, 65536), 50)
        if strategy == "sequential":
            return list(EXTENDED_PORTS)
        if strategy == "weighted":
            return list(TOP_PORTS) + random.sample(range(1025, 65536), 20)
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
        if model == "jitter":
            return max(0.005, base + random.uniform(-jitter, jitter))
        if model == "burst":
            if self._scan_count % bsz == 0 and self._scan_count > 0:
                return bdl
            return 0.01
        if model == "longtail":
            return random.expovariate(1.0 / max(base, 0.1))
        return base

    def _parse_ip_options(self):
        if not self.ip_options:
            return None
        cleaned = self.ip_options.replace("\\x", "").replace("0x", "").replace(" ", "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            return None
        return [IPOption(raw)]

    def _craft_packet(self, dport: int, src_ip: Optional[str] = None):
        ip_kwargs = {
            "dst": self.target_ip,
            "id": random.randint(1, 65535),
            "ttl": self.ttl if self.ttl else random.choice([64, 128, 255]),
        }
        chosen_src = src_ip or self.spoof_ip
        if chosen_src:
            ip_kwargs["src"] = chosen_src
        ip_opts = self._parse_ip_options()
        if ip_opts:
            ip_kwargs["options"] = ip_opts
        ip_layer = IP(**ip_kwargs)

        sport = self.source_port or random.randint(10000, 65000)
        options = [("MSS", random.choice([1460, 1400, 1380]))]
        if random.random() > 0.5:
            options.append(("SAckOK", ""))
        if random.random() > 0.5:
            options.append(("WScale", random.randint(2, 8)))
        if random.random() > 0.3:
            options.append(("NOP", None))
        random.shuffle(options)

        tcp_kwargs = {
            "sport": sport,
            "dport": dport,
            "flags": "S",
            "seq": random.randint(1000, 4294967295),
            "window": random.choice([8192, 14600, 29200, 65535]),
            "options": options,
        }
        if self.badsum:
            tcp_kwargs["chksum"] = random.randint(1, 0xFFFF)
        tcp_layer = TCP(**tcp_kwargs)

        pkt = ip_layer / tcp_layer
        if self.spoof_app:
            pkt = self._attach_app_payload(pkt, dport)
        return pkt

    def _attach_app_payload(self, pkt, dport: int):
        if dport in (80, 8080):
            payload = (b"GET / HTTP/1.1\r\nHost: " + self.target.encode(errors="ignore")
                       + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
            return pkt / Raw(load=payload)
        if dport in (443, 8443):
            import os
            payload = bytes.fromhex("160301002f0100002b0303") + os.urandom(28) + bytes.fromhex("000002c02b0100")
            return pkt / Raw(load=payload)
        if dport == 53:
            payload = bytes.fromhex("abcd0100000100000000000006676f6f676c6503636f6d0000010001")
            return pkt / Raw(load=payload)
        return pkt

    def _decoy_sources(self) -> List[str]:
        decoys = self.decoys if isinstance(self.decoys, list) else self.decoys.split(",")
        out: List[str] = []
        for token in decoys:
            t = token.strip().upper()
            if t in ("", "ME"):
                continue
            out.append(_random_ip() if t in ("RND", "RAND", "RANDOM") else token.strip())
        return out

    def _send_pkt(self, pkt):
        try:
            if self.spoof_mac:
                dst_mac = getmacbyip(self.target_ip)
                if dst_mac:
                    sendp(Ether(src=self.spoof_mac, dst=dst_mac) / pkt,
                          iface=self.iface, verbose=False)
                    return
            if self.mtu:
                for frag in fragment(pkt, fragsize=self.mtu):
                    send(frag, verbose=False)
                    time.sleep(0.001)
            else:
                send(pkt, verbose=False)
        except Exception:
            pass

    def _send_decoys(self, dport: int):
        for decoy_ip in self._decoy_sources():
            try:
                send(self._craft_packet(dport, src_ip=decoy_ip), verbose=False)
            except Exception:
                pass

    def _scan_loop(self):
        ports = self._get_ports()
        if self.proxy:
            self._proxy_scan_loop(ports)
            return

        for port in ports:
            self._pause_event.wait()
            if not self._running:
                return

            pkt = self._craft_packet(port)
            with self._lock:
                self._sent_timestamps[port] = time.time()
                self._scan_count += 1
            self._send_pkt(pkt)
            if self.decoys:
                self._send_decoys(port)

            self.event_queue.put(ScanEvent(
                timestamp=time.time(),
                src_ip=pkt[IP].src,
                dst_ip=self.target_ip,
                dst_port=port,
                scan_type=self._scan_type_label(),
                result="sent",
                duration_ms=0.0,
                handshake_complete=False,
            ))
            time.sleep(self._get_delay())

        time.sleep(self.timeout)
        with self._lock:
            now = time.time()
            stale = [p for p, t in self._sent_timestamps.items() if now - t >= self.timeout]
            for port in stale:
                del self._sent_timestamps[port]
                self.event_queue.put(ScanEvent(
                    timestamp=time.time(),
                    src_ip="local",
                    dst_ip=self.target_ip,
                    dst_port=port,
                    scan_type=self._scan_type_label(),
                    result="filtered",
                    duration_ms=self.timeout * 1000,
                    handshake_complete=False,
                ))
        self._running = False

    def _proxy_scan_loop(self, ports: List[int]):
        import socket
        try:
            import socks
        except ImportError:
            socks = None

        proxy_list = [p.strip() for p in self.proxy.split(",") if p.strip()]

        for port in ports:
            self._pause_event.wait()
            if not self._running:
                return

            with self._lock:
                self._scan_count += 1
            start_t = time.time()
            result = "closed"

            try:
                s = self._open_proxy_socket(random.choice(proxy_list), socks)
                s.connect((self.target_ip, port))
                result = "open"
                with self._lock:
                    self._open_ports.append(port)
                if self.ssl_scan or self.spoof_app:
                    try:
                        s.sendall(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                    except Exception:
                        pass
                s.close()
            except Exception:
                pass

            self.event_queue.put(ScanEvent(
                timestamp=time.time(),
                src_ip="proxy",
                dst_ip=self.target_ip,
                dst_port=port,
                scan_type="proxy_connect",
                result=result,
                duration_ms=(time.time() - start_t) * 1000.0,
                handshake_complete=result == "open",
            ))
            time.sleep(self._get_delay())
        self._running = False

    def _open_proxy_socket(self, proxy_url: str, socks):
        import socket
        if not socks:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            return s
        scheme, addr = proxy_url.split("://", 1)
        host, port = addr.split(":", 1)
        ptype = {
            "socks5": socks.SOCKS5,
            "socks4": socks.SOCKS4,
        }.get(scheme.lower(), socks.HTTP)
        s = socks.socksocket()
        s.set_proxy(ptype, host, int(port))
        s.settimeout(self.timeout)
        return s

    def _grab_banner(self, port: int):
        import socket
        banner = ""
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as conn:
                conn.settimeout(self.timeout)
                if port in (80, 8080, 443, 8443):
                    try:
                        conn.sendall(b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                    except Exception:
                        pass
                data = conn.recv(256)
            banner = data.decode("latin-1", "ignore").strip().splitlines()[0] if data else ""
        except Exception:
            return
        if banner:
            with self._lock:
                self._service_info[port] = banner
            self.event_queue.put(ScanEvent(
                timestamp=time.time(),
                src_ip="local",
                dst_ip=self.target_ip,
                dst_port=port,
                scan_type="banner",
                result="banner",
                duration_ms=0.0,
                handshake_complete=True,
                banner=banner,
            ))

    def _ssl_poke(self, port: int):
        import socket
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    ssock.sendall(b"GET / HTTP/1.1\r\nHost: " + self.target.encode()
                                  + b"\r\nConnection: close\r\n\r\n")
        except Exception:
            pass

    def _recv_packet(self, pkt):
        if TCP not in pkt or IP not in pkt:
            return
        src_port = pkt[TCP].sport
        flags = pkt[TCP].flags
        scan_type_str = self._scan_type_label()
        hs_complete = False

        with self._lock:
            if src_port not in self._sent_timestamps:
                return
            rtt = (time.time() - self._sent_timestamps[src_port]) * 1000.0

            if flags == 0x12:
                result = "open"
                self._open_ports.append(src_port)
                if self.ssl_scan:
                    scan_type_str = "tls_connect"
                    hs_complete = True
                    self._send_reset(pkt, src_port)
                    threading.Thread(target=self._ssl_poke, args=(src_port,), daemon=True).start()
                elif self.full_connect:
                    scan_type_str = "tcp_connect"
                    hs_complete = True
                    self._complete_handshake(pkt, src_port)
            elif flags & 0x04:
                result = "closed"
            else:
                return

            del self._sent_timestamps[src_port]

        if result == "open" and self.banner_grab:
            threading.Thread(target=self._grab_banner, args=(src_port,), daemon=True).start()

        self.event_queue.put(ScanEvent(
            timestamp=time.time(),
            src_ip=pkt[IP].dst,
            dst_ip=pkt[IP].src,
            dst_port=src_port,
            scan_type=scan_type_str,
            result=result,
            duration_ms=rtt,
            handshake_complete=hs_complete,
        ))

    def _send_reset(self, pkt, src_port: int):
        send(IP(dst=self.target_ip, src=pkt[IP].dst) / TCP(
            sport=pkt[TCP].dport, dport=src_port, flags="R", seq=pkt[TCP].ack,
        ), verbose=False)

    def _complete_handshake(self, pkt, src_port: int):
        send(IP(dst=self.target_ip, src=pkt[IP].dst) / TCP(
            sport=pkt[TCP].dport, dport=src_port, flags="A",
            seq=pkt[TCP].ack, ack=pkt[TCP].seq + 1,
        ), verbose=False)
        send(IP(dst=self.target_ip, src=pkt[IP].dst) / TCP(
            sport=pkt[TCP].dport, dport=src_port, flags="RA",
            seq=pkt[TCP].ack, ack=pkt[TCP].seq + 1,
        ), verbose=False)
