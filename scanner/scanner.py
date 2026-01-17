import socket
import sys
import re
import time
from typing import Dict, List

# === НАСТРОЙКИ ===
DEFAULT_HOST = "127.0.0.1"
PORT_RANGE = range(8999, 9005)  # Можно расширить
TIMEOUT_CONNECT = 2
TIMEOUT_READ = 3

# Эвристики для определения типа сервиса
HTTP_SIGNATURES = [b"HTTP/", b"<!DOCTYPE", b"<html", b"Content-Type"]
SSH_SIGNATURES = [b"SSH-"]
FTP_SIGNATURES = [b"220", b"FTP"]
SMTP_SIGNATURES = [b"220", b"ESMTP"]
TELNET_LIKE = [b"login:", b"password:", b"console", b"***"]

def tcp_connect(host: str, port: int) -> socket.socket | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT_CONNECT)
        s.connect((host, port))
        return s
    except (OSError, socket.timeout):
        return None

def safe_recv(s: socket.socket) -> bytes:
    try:
        s.settimeout(TIMEOUT_READ)
        data = b""
        while len(data) < 8192:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        return data
    except Exception:
        return b""

def send_probe(s: socket.socket, is_likely_http: bool = False) -> bytes:
    try:
        if is_likely_http:
            probe = b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        else:
            probe = b"\n"  # Наименее агрессивный запрос
        s.sendall(probe)
        return safe_recv(s)
    except Exception:
        return b""

def detect_service_type(banner: bytes, response: bytes) -> str:
    total = banner + response
    total_lower = total.lower()

    if any(sig in total for sig in HTTP_SIGNATURES):
        return "HTTP-like"
    if any(sig in total for sig in SSH_SIGNATURES):
        return "SSH"
    if any(sig in banner for sig in FTP_SIGNATURES):
        return "FTP"
    if any(sig in banner for sig in SMTP_SIGNATURES):
        return "SMTP"
    if any(sig in total_lower for sig in [b"login:", b"password:", b"console", b"access denied"]):
        return "Telnet/Admin Console"
    if b"ready" in total_lower or b"error" in total_lower:
        return "Custom TCP Service"
    return "Unknown Service"

def extract_risks(full_data: bytes) -> List[str]:
    text = full_data.decode('utf-8', errors='ignore')
    lines = text.splitlines()
    risks = []

    # Ищем версии в формате x.y, v..., /x.y и т.п.
    version_patterns = [
        r'\b\d+\.\d+(\.\d+)?\b',
        r'[vV]\d+\.?\d*',
        r'/\d+\.\d+',
        r'-v\d+\.\d+',
    ]
    for pattern in version_patterns:
        matches = re.findall(pattern, text)
        if matches:
            risks.append(f"Обнаружены версии: {', '.join(set(str(m) if isinstance(m, str) else m[0] for m in matches))}")

    # Известные опасные заголовки (HTTP)
    for line in lines:
        if line.lower().startswith("server:") or line.lower().startswith("x-powered-by:"):
            risks.append(f"Раскрыт заголовок: {line.strip()}")

    # Ключевые слова, указывающие на внутреннюю логику
    sensitive_keywords = [
        "erp", "warehouse", "internal", "legacy", "backend", "console",
        "admin", "root", "powered by", "built with", "debug", "test"
    ]
    found = []
    for kw in sensitive_keywords:
        if kw in text.lower():
            found.append(kw)
    if found:
        risks.append(f"Найдены чувствительные ключевые слова: {', '.join(found)}")

    # Уникальные строки с восклицаниями, звёздочками — часто баннеры
    if "***" in text or "!!!" in text:
        risks.append("Обнаружен стилизованный баннер (часто указывает на кастомный сервис)")

    return risks

def scan_port(host: str, port: int) -> Dict:
    result = {
        "port": port,
        "open": False,
        "initial_banner": "",
        "response_to_probe": "",
        "full_text": "",
        "service_guess": "Closed",
        "risks": []
    }

    s = tcp_connect(host, port)
    if not s:
        return result

    result["open"] = True

    # Шаг 1: читаем то, что присылают сразу
    banner = safe_recv(s)
    result["initial_banner"] = banner.decode('utf-8', errors='ignore').strip()

    # Шаг 2: отправляем пробный запрос
    is_likely_http = (port in (80, 443, 8080, 5000, 3000, 8000))
    response = send_probe(s, is_likely_http=is_likely_http)
    result["response_to_probe"] = response.decode('utf-8', errors='ignore').strip()

    full_data = banner + response
    result["full_text"] = full_data.decode('utf-8', errors='ignore')

    # Анализ
    result["service_guess"] = detect_service_type(banner, response)
    result["risks"] = extract_risks(full_data)

    try:
        s.close()
    except:
        pass

    return result

def main():
    if len(sys.argv) < 2:
        print("Использование: python generic_recon_scanner.py <целевой_хост> [порт_начало-порт_конец]")
        sys.exit(1)

    host = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            start, end = map(int, sys.argv[2].split('-'))
            ports = range(start, end + 1)
        except Exception:
            print("Неверный формат диапазона. Пример: 1-1000")
            sys.exit(1)
    else:
        ports = PORT_RANGE

    print(f"[+] Сканирование {host} на порты {ports.start}-{ports.stop - 1}")
    print("[+] Режим: пассивная рекогносцировка (без эксплуатации)\n")

    open_count = 0
    all_results = []

    start_time = time.time()

    for port in ports:
        if port % 500 == 0:
            print(f"[ ] Проверено {port} портов...")

        res = scan_port(host, port)
        all_results.append(res)

        if res["open"]:
            open_count += 1
            print(f"\n[OPEN] Порт {port}/tcp")
            print(f"  → Сервис (гипотеза): {res['service_guess']}")
            if res["initial_banner"]:
                print(f"  → Баннер:\n      " + "\n      ".join(res["initial_banner"].splitlines()[:3]))
            if res["response_to_probe"] and not res["initial_banner"]:
                print(f"  → Ответ на запрос:\n      " + "\n      ".join(res["response_to_probe"].splitlines()[:3]))

            if res["risks"]:
                print("  → ПОТЕНЦИАЛЬНЫЕ РИСКИ:")
                for r in res["risks"]:
                    print(f"      • {r}")
            else:
                print("  → Явных рисков не обнаружено (но порт открыт!)")

    elapsed = time.time() - start_time
    print(f"\n[✓] Сканирование завершено за {elapsed:.1f} сек. Открыто портов: {open_count}")

    # Сохраняем полный отчёт
    report = {
        "target": host,
        "port_range": [ports.start, ports.stop - 1],
        "open_ports_count": open_count,
        "results": [r for r in all_results if r["open"]]
    }

    with open("recon_report.json", "w", encoding="utf-8") as f:
        import json
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("\n[+] Полный отчёт сохранён в recon_report.json")

if __name__ == "__main__":
    main()