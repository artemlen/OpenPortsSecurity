import socket
import threading
import signal
import sys

# Конфигурация портов
PORT_WEB = 5000       # Веб-интерфейс (HTTP)
PORT_DB_MOCK = 5001   # Имитация базы данных (Custom TCP)
PORT_ADMIN = 5002     # Консоль администратора (Telnet-like)

# Флаг для координации остановки
shutdown_event = threading.Event()

def service_web_ui():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", PORT_WEB))
        server.listen(5)
        server.settimeout(1.0)  # чтобы accept() не блокировался навсегда
        print(f"[APP] Web UI запущен на порту {PORT_WEB}")
    except OSError as e:
        print(f"[ERROR] Не удалось запустить Web UI на порту {PORT_WEB}: {e}")
        return

    while not shutdown_event.is_set():
        try:
            client, _ = server.accept()
        except socket.timeout:
            continue  # проверяем флаг остановки
        except OSError:
            break  # сокет закрыт — выходим

        try:
            request = client.recv(1024)

            html_body = """
            <html>
            <head><title>Warehouse ERP v2.4</title></head>
            <body>
                <h1>Warehouse Management System</h1>
                <p>Status: <span style='color:green'>ONLINE</span></p>
                <hr>
                <small>Powered by Python Legacy Backend</small>
            </body>
            </html>
            """

            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Warehouse-Internal-HTTPd/2.4\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Connection: close\r\n"
                "\r\n"
                + html_body
            )
            client.sendall(response.encode('utf-8'))
        except Exception:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    server.close()
    print("[APP] Web UI остановлен")


def service_database_mock():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", PORT_DB_MOCK))
        server.listen(5)
        server.settimeout(1.0)
        print(f"[APP] Data Service (Mock) запущен на порту {PORT_DB_MOCK}")
    except OSError as e:
        print(f"[ERROR] Не удалось запустить DB Mock на порту {PORT_DB_MOCK}: {e}")
        return

    while not shutdown_event.is_set():
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            banner = "WH-DB-PROTOCOL-v1.0-RELEASE\nREADY\n"
            client.sendall(banner.encode('utf-8'))
            data = client.recv(1024)
            if data:
                client.sendall(b"ERROR: AUTH_REQUIRED\n")
        except Exception:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    server.close()
    print("[APP] Data Service остановлен")


def service_admin_console():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", PORT_ADMIN))
        server.listen(5)
        server.settimeout(1.0)
        print(f"[APP] Admin Console запущен на порту {PORT_ADMIN}")
    except OSError as e:
        print(f"[ERROR] Не удалось запустить Admin Console на порту {PORT_ADMIN}: {e}")
        return

    while not shutdown_event.is_set():
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            client.sendall(b"*** WAREHOUSE ROOT CONSOLE ***\n")
            client.sendall(b"Login: ")
            client.recv(1024)
            client.sendall(b"\nAccess Denied.\n")
        except Exception:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    server.close()
    print("[APP] Admin Console остановлен")


def signal_handler(signum, frame):
    print("\nПолучен сигнал завершения. Остановка служб...")
    shutdown_event.set()


if __name__ == "__main__":
    print(">>> Запуск микросервиса 'Warehouse App'...")

    # Регистрация обработчика сигналов
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    t1 = threading.Thread(target=service_web_ui, daemon=True)
    t2 = threading.Thread(target=service_database_mock, daemon=True)
    t3 = threading.Thread(target=service_admin_console, daemon=True)

    t1.start()
    t2.start()
    t3.start()

    try:
        # Ждём завершения всех потоков или сигнала
        while t1.is_alive() or t2.is_alive() or t3.is_alive():
            t1.join(0.5)
            t2.join(0.5)
            t3.join(0.5)
    except KeyboardInterrupt:
        shutdown_event.set()

    print("Приложение завершено.")