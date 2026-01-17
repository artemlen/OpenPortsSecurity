# scanner.py
import socket
import sys
import re
import time
import json
from typing import Dict, List, Tuple

# === ЭВРИСТИКИ ===
HTTP_SIGNATURES = [
    b"HTTP/", b"<!DOCTYPE", b"<html", b"<HTML", b"Content-Type",
    b"Server:", b"X-Powered-By", b"Set-Cookie", b"Location:"
]
SSH_SIGNATURES = [b"SSH-"]
FTP_SIGNATURES = [b"220", b"FTP"]
SMTP_SIGNATURES = [b"220", b"ESMTP", b"SMTP"]
TELNET_LIKE = [b"login:", b"password:", b"console", b"***", b"access denied", b"Login:", b"Username:"]

SENSITIVE_KEYWORDS = [
    "erp", "warehouse", "internal", "legacy", "backend", "console",
    "admin", "root", "powered by", "built with", "debug", "test",
    "dashboard", "portal", "service", "ready", "error", "protocol",
    "database", "db", "management", "system"
]

def tcp_connect(host: str, port: int, timeout: float = 3.0) -> socket.socket | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except (OSError, socket.timeout):
        return None

def safe_recv(s: socket.socket, timeout: float = 3.0, max_bytes: int = 8192) -> bytes:
    try:
        s.settimeout(timeout)
        data = b""
        while len(data) < max_bytes:
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

def send_and_recv(s: socket.socket, probe: bytes) -> bytes:
    try:
        if probe:
            s.sendall(probe)
        return safe_recv(s)
    except Exception:
        return b""

def detect_service_from_data(data: bytes) -> str:
    total = data.lower()
    if any(sig.lower() in total for sig in HTTP_SIGNATURES):
        return "HTTP-like"
    if any(sig in data for sig in SSH_SIGNATURES):
        return "SSH"
    if any(sig in data for sig in FTP_SIGNATURES):
        return "FTP"
    if any(sig in data for sig in SMTP_SIGNATURES):
        return "SMTP"
    if any(kw in total for kw in [b"login:", b"password:", b"console", b"access denied", b"***", b"login", b"username:"]):
        return "Telnet/Admin Console"
    if b"ready" in total or b"error" in total or b"protocol" in total:
        return "Custom TCP Service"
    return "Unknown Service"

def extract_risks(full_data: bytes) -> List[str]:
    text = full_data.decode('utf-8', errors='ignore')
    lines = text.splitlines()
    risks = []

    # Версии
    version_patterns = [
        r'\b\d+\.\d+(?:\.\d+)?\b',
        r'[vV]\d+\.?\d*',
        r'/\d+\.\d+',
        r'-v\d+\.\d+',
    ]
    found_versions = set()
    for pattern in version_patterns:
        matches = re.findall(pattern, text)
        for m in matches:
            ver = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) else str(m))
            found_versions.add(ver)
    if found_versions:
        risks.append(f"Обнаружены версии: {', '.join(sorted(found_versions))}")

    # Заголовки
    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith(("server:", "x-powered-by:", "x-generator:", "x-backend:")):
            risks.append(f"Раскрыт заголовок: {stripped}")

    # Ключевые слова
    text_lower = text.lower()
    found_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in text_lower]
    if found_keywords:
        risks.append(f"Чувствительные ключевые слова: {', '.join(sorted(set(found_keywords)))}")

    if "***" in text or "!!!" in text or "###" in text:
        risks.append("Обнаружен стилизованный баннер")

    return risks

def scan_port(host: str, port: int) -> Dict:
    result = {
        "port": port,
        "open": False,
        "initial_banner": "",
        "responses": {},
        "full_text": "",
        "service_guess": "Closed",
        "risks": []
    }

    s = tcp_connect(host, port)
    if not s:
        return result

    result["open"] = True

    # Сбор всех ответов
    responses = {}

    # 1. Получаем начальный баннер (без отправки данных)
    banner = safe_recv(s)
    responses["banner"] = banner
    all_data = banner

    # 2. Пробуем HTTP
    s2 = tcp_connect(host, port)
    if s2:
        http_probe = b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: ReconScanner/1.0\r\nConnection: close\r\n\r\n"
        http_resp = send_and_recv(s2, http_probe)
        responses["http"] = http_resp
        all_data += http_resp
        s2.close()

    # 3. Пробуем нейтральный пробник
    s3 = tcp_connect(host, port)
    if s3:
        neutral_resp = send_and_recv(s3, b"\n")
        responses["neutral"] = neutral_resp
        all_data += neutral_resp
        s3.close()

    # Объединяем всё для анализа
    full_data = all_data
    result["initial_banner"] = banner.decode('utf-8', errors='ignore').strip()
    result["responses"] = {
        k: v.decode('utf-8', errors='ignore').strip() for k, v in responses.items() if v
    }
    result["full_text"] = full_data.decode('utf-8', errors='ignore')

    # Определяем тип по всему набору данных
    result["service_guess"] = detect_service_from_data(full_data)
    result["risks"] = extract_risks(full_data)

    try:
        s.close()
    except:
        pass

    return result

def parse_port_range(arg: str) -> range:
    try:
        if '-' in arg:
            start, end = map(int, arg.split('-'))
            if start > end:
                raise ValueError("Начало диапазона больше конца")
            return range(start, end + 1)
        else:
            port = int(arg)
            return range(port, port + 1)
    except Exception as e:
        print(f"Ошибка в формате диапазона портов: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Использование: python scanner.py <хост> <диапазон_портов>")
        print("Пример: python scanner.py localhost 9000-9002")
        sys.exit(1)

    host = sys.argv[1]
    port_range = parse_port_range(sys.argv[2])
    ports = list(port_range)

    print(f"[+] Сканирование хоста: {host}")
    print(f"[+] Диапазон портов: {ports[0]}–{ports[-1]} (всего: {len(ports)})")
    print("[+] Режим: мультипротокольная пассивная рекогносцировка\n")

    open_count = 0
    all_results = []
    start_time = time.time()

    for port in ports:
        res = scan_port(host, port)
        all_results.append(res)

        if res["open"]:
            open_count += 1
            print(f"\n[OPEN] Порт {port}/tcp")
            print(f"  → Сервис (гипотеза): {res['service_guess']}")
            
            if res["initial_banner"]:
                banner_lines = res["initial_banner"].splitlines()[:3]
                print(f"  → Баннер:\n      " + "\n      ".join(banner_lines))
            else:
                print("  → Баннер не получен")

            # Показываем наиболее информативный ответ
            best_resp = ""
            for key, resp in res["responses"].items():
                if resp and len(resp) > len(best_resp):
                    best_resp = resp
            if best_resp:
                resp_lines = best_resp.splitlines()[:3]
                print(f"  → Наиболее полный ответ:\n      " + "\n      ".join(resp_lines))

            if res["risks"]:
                print("  → ПОТЕНЦИАЛЬНЫЕ РИСКИ:")
                for r in res["risks"]:
                    print(f"      • {r}")
            else:
                print("  → Явных рисков не обнаружено")

    elapsed = time.time() - start_time
    print(f"\n[✓] Сканирование завершено за {elapsed:.1f} сек. Открыто портов: {open_count}")

    report = {
        "target": host,
        "scanned_ports": [ports[0], ports[-1]],
        "open_ports_count": open_count,
        "results": [r for r in all_results if r["open"]]
    }

    with open("recon_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("\n[+] Полный отчёт сохранён в recon_report.json")

if __name__ == "__main__":
    main()