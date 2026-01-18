import socket
import threading
import time
import re
import os
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

TARGET_HOST = "app"
TARGET_PORT_WEB = 5000
TARGET_PORT_DB = 5001
TARGET_PORT_ADMIN = 5002

# Настройка папки для логов
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    try: os.makedirs(LOG_DIR)
    except: pass
LOG_FILE = os.path.join(LOG_DIR, "security_events.log")

def write_log(client_ip, port, action, details):
    """Пишет лог в консоль и в файл"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {client_ip:<15} -> :{port} | {action:<20} | {details}"
        
        # 1. В консоль (для docker logs)
        print(log_line, flush=True)
        
        # 2. В файл
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
    except Exception:
        pass # Логирование не должно ломать работу прокси

def init_metrics():
    """Инициализация метрик нулями"""
    print(">>> Инициализация метрик Prometheus...", flush=True)
    ports = [str(PROXY_PORT_WEB), str(PROXY_PORT_DB), str(PROXY_PORT_ADMIN)]
    for p in ports:
        REQUESTS_TOTAL.labels(port=p, action="none").inc(0)
        BLOCKED_REQUESTS.labels(port=p).inc(0)

def proxy_http(client_sock, client_addr):
    start = time.time()
    port_label = str(PROXY_PORT_WEB)
    client_ip = client_addr[0]
    
    try:
        client_sock.settimeout(5.0)
        request = b""
        while True:
            try:
                chunk = client_sock.recv(4096)
                if not chunk: break
                request += chunk
                if b"\r\n\r\n" in request or len(request) > 8192: break
            except socket.timeout:
                break

        if not request:
            # 1. Метрика
            REQUESTS_TOTAL.labels(port=port_label, action="empty_request").inc()
            # 2. Лог
            write_log(client_ip, PROXY_PORT_WEB, "DROP_EMPTY", "Пустой запрос (Scan)")
            # 3. Сеть
            client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return

        # Подключение к приложению
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.settimeout(5.0)
        try:
            target.connect((TARGET_HOST, TARGET_PORT_WEB))
            target.sendall(request)
        except OSError:
            write_log(client_ip, PROXY_PORT_WEB, "ERROR", "App недоступен")
            return

        response = b""
        while True:
            try:
                chunk = target.recv(4096)
                if not chunk: break
                response += chunk
            except socket.timeout:
                break
        target.close()

        # Фильтрация
        try:
            resp_str = response.decode('utf-8', errors='ignore')
            
            # Лог действий
            if "Warehouse" in resp_str:
                write_log(client_ip, PROXY_PORT_WEB, "OBFUSCATION", "Скрыты заголовки")
            else:
                write_log(client_ip, PROXY_PORT_WEB, "FORWARD", "Пропущен")

            # Подмена заголовков
            resp_str = re.sub(r'^Server:.*$', 'Server: Apache/2.4.52', resp_str, flags=re.MULTILINE)
            resp_str = re.sub(r'Warehouse ERP v2\.4', 'Internal Portal', resp_str, flags=re.IGNORECASE)
            resp_str = re.sub(r'Powered by Python Legacy Backend', 'Powered by Secure Sys', resp_str) 
            
            # 1. Метрика (До отправки!)
            REQUESTS_TOTAL.labels(port=port_label, action="allowed_with_filtering").inc()
            
            # 2. Отправка
            client_sock.sendall(resp_str.encode('utf-8'))
            
        except Exception:
            REQUESTS_TOTAL.labels(port=port_label, action="raw_forward").inc()
            client_sock.sendall(response)

    except Exception:
        pass
    finally:
        duration = time.time() - start
        REQUEST_DURATION.labels(port=port_label).observe(duration)
        try: client_sock.close()
        except: pass

def proxy_tcp_generic(client_sock, client_addr, target_port, fake_banner=None, proxy_port=None):
    start = time.time()
    port_label = str(proxy_port)
    client_ip = client_addr[0]
    
    try:
        if fake_banner:
            # 1. Метрики (Сразу!)
            BLOCKED_REQUESTS.labels(port=port_label).inc()
            REQUESTS_TOTAL.labels(port=port_label, action="fake_banner_sent").inc()
            
            # 2. Лог
            write_log(client_ip, proxy_port, "HONEYPOT_TRIGGER", f"Атака перехвачена")
            
            # 3. Сеть
            client_sock.sendall(fake_banner.encode() + b"\n")
        else:
            # Прямой прокси
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.connect((TARGET_HOST, target_port))
            data = client_sock.recv(1024)
            if data:
                target.sendall(data)
                resp = target.recv(4096)
                client_sock.sendall(resp)
            target.close()
            REQUESTS_TOTAL.labels(port=port_label, action="direct_proxy").inc()

    except Exception:
        pass
    finally:
        duration = time.time() - start
        REQUEST_DURATION.labels(port=port_label).observe(duration)
        try: client_sock.close()
        except: pass

def serve(port, func, **kwargs):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(10)
        print(f"🛡️ Proxy запущен на порту {port}", flush=True)
    except Exception as e:
        print(f"Ошибка запуска на порту {port}: {e}")
        return

    while True:
        try:
            client, addr = server.accept()
            threading.Thread(target=func, args=(client, addr), kwargs=kwargs, daemon=True).start()
        except Exception:
            pass

if __name__ == "__main__":
    start_http_server(8000)
    init_metrics()
    
    print(f">>> Логирование включено в {LOG_FILE}", flush=True)

    threading.Thread(target=serve, args=(PROXY_PORT_WEB, proxy_http), daemon=True).start()
    
    threading.Thread(target=serve, args=(PROXY_PORT_DB, proxy_tcp_generic), 
                     kwargs={"target_port": TARGET_PORT_DB, "fake_banner": "SSH-2.0-OpenSSH_8.9", "proxy_port": PROXY_PORT_DB}, daemon=True).start()
    
    threading.Thread(target=serve, args=(PROXY_PORT_ADMIN, proxy_tcp_generic), 
                     kwargs={"target_port": TARGET_PORT_ADMIN, "fake_banner": "Login:", "proxy_port": PROXY_PORT_ADMIN}, daemon=True).start()

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nОстановка...")