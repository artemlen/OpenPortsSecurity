import socket
import threading
import time
import re
from datetime import datetime
from prometheus_client import Counter, Histogram, start_http_server

# === МЕТРИКИ PROMETHEUS ===
REQUESTS_TOTAL = Counter('security_proxy_requests_total', 'Total requests', ['port', 'action'])
BLOCKED_REQUESTS = Counter('security_proxy_blocked_total', 'Blocked or faked requests', ['port'])
REQUEST_DURATION = Histogram('security_proxy_request_duration_seconds', 'Request duration', ['port'])

# === КОНФИГУРАЦИЯ ===
PROXY_PORT_WEB = 9000
PROXY_PORT_DB = 9001
PROXY_PORT_ADMIN = 9002

TARGET_HOST = "127.0.0.1"
TARGET_PORT_WEB = 5000
TARGET_PORT_DB = 5001
TARGET_PORT_ADMIN = 5002

LOG_FILE = "security.log"

def log_event(event: str):
    line = f"[{datetime.now().isoformat()}] {event}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# === Прокси-функции с метриками ===

def proxy_http(client_sock, client_addr):
    start = time.time()
    port_label = str(PROXY_PORT_WEB)
    try:
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.connect((TARGET_HOST, TARGET_PORT_WEB))
        request = client_sock.recv(4096)
        if not request:
            REQUESTS_TOTAL.labels(port=port_label, action="empty_request").inc()
            return

        target.sendall(request)
        response = b""
        while True:
            chunk = target.recv(4096)
            if not chunk:
                break
            response += chunk
        target.close()

        try:
            resp_str = response.decode('utf-8', errors='ignore')
            resp_str = re.sub(r'^Server:.*$', 'Server: Apache/2.4.52', resp_str, flags=re.MULTILINE)
            resp_str = re.sub(r'Warehouse ERP v2\.4', 'Internal Portal', resp_str, flags=re.IGNORECASE)
            resp_str = re.sub(r'Warehouse Management System', 'Service Dashboard', resp_str, flags=re.IGNORECASE)
            resp_str = re.sub(r'Powered by Python Legacy Backend', 'Powered by Secure Infrastructure', resp_str, flags=re.IGNORECASE)
            client_sock.sendall(resp_str.encode('utf-8'))
            REQUESTS_TOTAL.labels(port=port_label, action="allowed_with_filtering").inc()
        except Exception:
            client_sock.sendall(response)
            REQUESTS_TOTAL.labels(port=port_label, action="raw_forward").inc()

    except Exception as e:
        log_event(f"HTTP ERROR: {client_addr} – {e}")
    finally:
        duration = time.time() - start
        REQUEST_DURATION.labels(port=port_label).observe(duration)
        client_sock.close()

def proxy_tcp_generic(client_sock, client_addr, target_port, fake_banner=None, hide_real=True, proxy_port=None):
    start = time.time()
    port_label = str(proxy_port)
    try:
        if hide_real and fake_banner is not None:
            client_sock.sendall(fake_banner.encode() + b"\n")
            BLOCKED_REQUESTS.labels(port=port_label).inc()
            REQUESTS_TOTAL.labels(port=port_label, action="fake_banner_sent").inc()
            log_event(f"TCP FAKE: {client_addr[0]}:{client_addr[1]} → фейковый баннер")
        else:
            # Прямой прокси (редко используется)
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.connect((TARGET_HOST, target_port))
            data = client_sock.recv(1024)
            target.sendall(data)
            resp = target.recv(4096)
            client_sock.sendall(resp)
            REQUESTS_TOTAL.labels(port=port_label, action="direct_proxy").inc()
            target.close()
    except Exception as e:
        log_event(f"TCP ERROR: {client_addr} – {e}")
    finally:
        duration = time.time() - start
        REQUEST_DURATION.labels(port=port_label).observe(duration)
        client_sock.close()

# === СЛУЖБЫ ===

def serve_web():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PROXY_PORT_WEB))
    server.listen(10)
    log_event(f"🛡️ HTTP Proxy запущен на порту {PROXY_PORT_WEB}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=proxy_http, args=(client, addr), daemon=True).start()

def serve_db():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PROXY_PORT_DB))
    server.listen(10)
    log_event(f"🛡️ DB Proxy запущен на порту {PROXY_PORT_DB}")
    while True:
        client, addr = server.accept()
        threading.Thread(
            target=proxy_tcp_generic,
            args=(client, addr, TARGET_PORT_DB),
            kwargs={
                "fake_banner": "SSH-2.0-OpenSSH_8.9",
                "hide_real": True,
                "proxy_port": PROXY_PORT_DB
            },
            daemon=True
        ).start()

def serve_admin():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PROXY_PORT_ADMIN))
    server.listen(10)
    log_event(f"🛡️ Admin Proxy запущен на порту {PROXY_PORT_ADMIN}")
    while True:
        client, addr = server.accept()
        threading.Thread(
            target=proxy_tcp_generic,
            args=(client, addr, TARGET_PORT_ADMIN),
            kwargs={
                "fake_banner": "Login:",
                "hide_real": True,
                "proxy_port": PROXY_PORT_ADMIN
            },
            daemon=True
        ).start()

# === ЗАПУСК ===
if __name__ == "__main__":
    # Запускаем HTTP-сервер метрик Prometheus на порту 8000
    start_http_server(8000)
    print("📊 Prometheus metrics доступны на http://localhost:8000/metrics")

    print(">>> Запуск Security Proxy...")
    print(f"    Веб:     внешний порт {PROXY_PORT_WEB}")
    print(f"    База:    внешний порт {PROXY_PORT_DB}")
    print(f"    Админка: внешний порт {PROXY_PORT_ADMIN}")
    print(f"    Лог: {LOG_FILE}\n")

    t_web = threading.Thread(target=serve_web, daemon=True)
    t_db = threading.Thread(target=serve_db, daemon=True)
    t_admin = threading.Thread(target=serve_admin, daemon=True)

    t_web.start()
    t_db.start()
    t_admin.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nОстановка Security Proxy...")