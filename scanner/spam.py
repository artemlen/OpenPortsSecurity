import socket
import time

TARGET_IP = "127.0.0.1"
PORTS = [9000, 9001, 9002]

print(f"=== ЗАПУСК TCP-ФЛУДА на {TARGET_IP} ===")

while True:
    for port in PORTS:
        try:
            # Создаем сокет
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1) # Таймаут 1 сек
            
            # Просто соединяемся (стучим в дверь)
            s.connect((TARGET_IP, port))
            
            # Отправляем немного мусора, чтобы прокси среагировал
            s.sendall(b"HELLO\n")
            
            # Читаем ответ (чтобы убедиться, что связь есть)
            try:
                data = s.recv(1024)
                print(f"[OK] Порт {port} ответил: {len(data)} байт")
            except:
                print(f"[OK] Порт {port} открыт (без ответа)")
                
            s.close()
        except Exception as e:
            print(f"[FAIL] Ошибка порта {port}: {e}")
            
    time.sleep(0.5) # Долбим 2 раза в секунду