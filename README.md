# black Marker scanner

### Автоматизированная система сканирования безопасности API банковских систем

## Возможности

- 10+ OWASP API сканеров - Полное покрытие OWASP API Security Top 10

- Веб-интерфейс - Интуитивный UI для управления сканированиями

- CLI интерфейс - Автоматизация и интеграция в CI/CD

- REST API - Интеграция с другими системами

- Подробные отчеты - JSON, TXT, CSV, PDF форматы

- История сканирований - PostgreSQL для хранения результатов

- Docker поддержка - Простое развертывание

## Быстрый старт

### Предварительные требования

- Docker & Docker Compose (рекомендуется)

- Или Java 21+ и PostgreSQL 15+

### Docker запуск (рекомендуется)

```bash
  # Клонируйте репозиторий
  git clone https://github.com/PaulLeMot/test-til-blackout.git
```

```bash
  # Запустите все сервисы
  docker-compose up -d
```
После запуска откройте: http://localhost:8081

## Docker запуск

Стандартный запуск (веб-интерфейс + API)

```bash
  # Запуск всех сервисов
  docker-compose up -d
  
  # Просмотр логов
  docker-compose logs -f security-scanner
  
  # Остановка
  docker-compose down
```

Сервисы будут доступны:

- Веб-интерфейс: http://localhost:8081

- База данных: localhost:5432

## Только API режим

```bash
  # Запуск только API сервера
  docker-compose -f docker-compose.api.yml up -d
```

## Docker Compose файлы
Основной docker-compose.yml:

```yaml
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: security_scanner
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: admin
    ports: ["5432:5432"]
    volumes: [postgres_data:/var/lib/postgresql/data]

  security-scanner:
    build:
      context: .
      dockerfile: docker/Dockerfile.backend
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: security_scanner
      DB_USER: admin
      DB_PASSWORD: admin
    ports: ["8081:8081"]
    depends_on: [postgres]
    volumes:
      - ./logs:/app/logs
      - ./webapp:/app/webapp
```

## Ручная установка

### Требования

- Java 21 или новее

- PostgreSQL 15 или новее

## Установка и запуск

```bash
# 1. Клонирование репозитория
  git clone https://github.com/PaulLeMot/test-til-blackout.git
  cd BlackMarker_scanner
  
  # 2. Установите PostgreSQL и создайте базу данных
  sudo apt-get install postgresql postgresql-contrib
  sudo -u postgres psql -c "CREATE DATABASE security_scanner;"
  sudo -u postgres psql -c "CREATE USER admin WITH PASSWORD 'admin';"
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE security_scanner TO admin;"
  
  # 3. Компиляция проекта
  find . -name "*.java" > sources.txt
  javac -cp "lib/*" -d build @sources.txt
  
  # 4. Запуск приложения
  java -cp "build:lib/*" core.Main
```

## Конфигурация
### Создание конфигурационного файла
Создайте файл config.json

```json
    {
  "bankId": "team172",
  "banks": [
    {
      "baseUrl": "https://api.sandbox.bank.com",
      "specUrl": "https://api.sandbox.bank.com/openapi.json"
    },
    {
      "baseUrl": "https://api2.sandbox.bank.com",
      "specUrl": "https://api2.sandbox.bank.com/openapi.json"
    }
  ],
  "credentials": [
    {
      "username": "team172-1",
      "password": "password123"
    },
    {
      "username": "team172-2",
      "password": "password123"
    }
  ]
}
```

### Параметры конфигурации

![img.png](img.png)

## CLI режим

### Установка CLI

```bash 
  # Компиляция CLI
  javac -cp "lib/*" -d build core/CLI.java
  
  # Проверка установки
  java -cp "build:lib/*" core.CLI --help
```

```bash 
  # Справка по командам
  java -cp "build:lib/*" core.CLI --help
  
  # Быстрое сканирование
  java -cp "build:lib/*" core.CLI scan --output report
  
  # С конфигурационным файлом
  java -cp "build:lib/*" core.CLI --config config.json
  
  # Полное сканирование с параметрами
  java -cp "build:lib/*" core.CLI \
    --config config.json \
    --output scan_report \
    --format json \
    --fail-on HIGH \
    --timeout 1800
```

## Параметры CLI

![img_1.png](img_1.png)

```bash 
# Запуск через Main (веб + API)
java -cp "build:lib/*" core.Main

# Или только API (если настроено)
java -cp "build:lib/*" core.ApiMain
```

## API Endpoints

### Запуск сканирования

```bash 
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d @config.json
```

Проверка статуса

```bash 
curl http://localhost:8081/api/v1/status
```

Получение результатов

```bash 
# Все результаты
curl http://localhost:8081/api/v1/results

# С фильтрацией
curl "http://localhost:8081/api/v1/results?severity=CRITICAL"
```

### Веб-интерфейс
Откройте в браузере: http://localhost:8081
