warehouse-security-pattern/
├── app/                 # Основное приложение
│   ├── app.py
│   └── Dockerfile.app
├── proxy/               # Security Proxy
│   ├── security.py
│   └── Dockerfile.proxy
├── scanner/             # Сканер (для тестирования, не в прод)
│   └── scanner.py
├── monitoring/
│   └── prometheus.yml   # Конфиг Prometheus
├── docker-compose.yml   # Оркестрация
└── README.md