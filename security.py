import socket
import threading
import time
import re
from datetime import datetime

# === КОНФИГУРАЦИЯ ===
# Публичные порты (слушаем на них)
PROXY_PORT_WEB = 9000
PROXY_PORT_DB = 9001
PROXY_PORT_ADMIN = 9002

# Внутренние порты целевого приложения (должно быть запущено отдельно)
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

def proxy_http(client_sock, client_addr):
    """Прокси для HTTP с фильтрацией заголовков и тела"""
    try:
        # Подключаемся к реальному сервису
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.connect((TARGET_HOST, TARGET_PORT_WEB))
        
        # Пересылаем запрос
        request = client_sock.recv(4096)
        if not request:
            return
        target.sendall(request)

        # Получаем ответ
        response = b""
        while True:
            chunk = target.recv(4096)
            if not chunk:
                break
            response += chunk
        target.close()

        # Декодируем (игнорируем ошибки)
        try:
            resp_str = response.decode('utf-8', errors='ignore')
        except:
            client_sock.sendall(response)
            return

        # Удаляем/подменяем Server header
        resp_str = re.sub(r'^Server:.*$', 'Server: Apache/2.4.52', resp_str, flags=re.MULTILINE)

        # Убираем упоминания системы из HTML
        resp_str = re.sub(r'Warehouse ERP v2\.4', 'Internal Portal', resp_str, flags=re.IGNORECASE)
        resp_str = re.sub(r'Warehouse Management System', 'Service Dashboard', resp_str, flags=re.IGNORECASE)
        resp_str = re.sub(r'Powered by Python Legacy Backend', 'Powered by Secure Infrastructure', resp_str, flags=re.IGNORECASE)

        # Отправляем клиенту
        client_sock.sendall(resp_str.encode('utf-8'))
        log_event(f"HTTP: {client_addr[0]}:{client_addr[1]} → пропущен с фильтрацией")
    except Exception as e:
        log_event(f"HTTP ERROR: {client_addr} – {e}")
    finally:
        client_sock.close()

def proxy_tcp_generic(client_sock, client_addr, target_port, fake_banner=None, hide_real=True):
    """
    Универсальный TCP-прокси с опциональной подменой баннера.
    Если hide_real=True — не читаем реальный баннер, а сразу отправляем fake_banner или ничего.
    """
    try:
        if hide_real and fake_banner is not None:
            # Не подключаемся к реальному сервису сразу — сначала отправляем фейк
            client_sock.sendall(fake_banner.encode() + b"\n")
            log_event(f"TCP FAKE: {client_addr[0]}:{client_addr[1]} → отправлен фейковый баннер")
            client_sock.close()
            return

        # Иначе — обычный прокси (редко используется в нашем случае)
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.connect((TARGET_HOST, target_port))

        # Просто пересылаем трафик в обе стороны (упрощённо)
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(1024)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass
            finally:
                src.close()
                dst.close()

        log_event(f"TCP PASS: {client_addr[0]}:{client_addr[1]} → прямой прокси (без фильтрации)")

        t1 = threading.Thread(target=forward, args=(client_sock, target))
        t2 = threading.Thread(target=forward, args=(target, client_sock))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join(10)
        t2.join(10)

    except Exception as e:
        log_event(f"TCP ERROR: {client_addr} – {e}")
        client_sock.close()

# === СЛУЖБЫ ПРОКСИ ===

def serve_web():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PROXY_PORT_WEB))
    server.listen(10)
    log_event(f"🛡️  HTTP Proxy запущен на порту {PROXY_PORT_WEB}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=proxy_http, args=(client, addr), daemon=True).start()

def serve_db():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PROXY_PORT_DB))
    server.listen(10)
    log_event(f"🛡️  DB Proxy запущен на порту {PROXY_PORT_DB}")
    while True:
        client, addr = server.accept()
        # Отправляем фейковый SSH-баннер вместо WH-DB-PROTOCOL
        threading.Thread(
            target=proxy_tcp_generic,
            args=(client, addr, TARGET_PORT_DB),
            kwargs={"fake_banner": "SSH-2.0-OpenSSH_8.9", "hide_real": True},
            daemon=True
        ).start()

def serve_admin():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PROXY_PORT_ADMIN))
    server.listen(10)
    log_event(f"🛡️  Admin Proxy запущен на порту {PROXY_PORT_ADMIN}")
    while True:
        client, addr = server.accept()
        # Отправляем нейтральное приглашение
        threading.Thread(
            target=proxy_tcp_generic,
            args=(client, addr, TARGET_PORT_ADMIN),
            kwargs={"fake_banner": "Login:", "hide_real": True},
            daemon=True
        ).start()

# === ЗАПУСК ===
if __name__ == "__main__":
    print(">>> Запуск Security Proxy...")
    print(f"    Веб:     внешний порт {PROXY_PORT_WEB} → внутренний {TARGET_PORT_WEB}")
    print(f"    База:    внешний порт {PROXY_PORT_DB} → внутренний {TARGET_PORT_DB}")
    print(f"    Админка: внешний порт {PROXY_PORT_ADMIN} → внутренний {TARGET_PORT_ADMIN}")
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