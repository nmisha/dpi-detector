<p align="center">
  <img src="https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/logo.jpg" width="100%">
  <br>
  <i>«Маяк на скале у гаснущего горизонта свободного интернета»</i><br>
  Сквозь цифровые сумерки. Смотритель маяка, <a href="https://github.com/Runnin4ik"><b>Runni</b></a>
</p>

# 🔍 DPI Detector
[![Python 3.8+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://github.com/Runnin4ik/dpi-detector/pkgs/container/dpi-detector)

Инструмент для анализа цензуры трафика в России: обнаруживает и классифицирует блокировки сайтов, хостингов и CDN (TCP16-20 блокировки), а также подмену DNS-запросов провайдером.

![Пример результатов](https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/screenshot.png)

## 🎯 Возможности

- **TCP 16-20KB блокировка** — обнаруживает обрыв соединения к CDN и хостингам после передачи 14-34KB
- **Проверка доступности заблокированных сайтов** — тестирует TLS 1.2, TLS 1.3 и HTTP
- **Проверка DNS** — выявляет перехват UDP/53, подмену IP-адресов заглушками и блокировку DoH
- **Классификация ошибок** — различает TCP RST, Connection Abort,
  Handshake/Read Timeout, TLS MITM, SNI-блокировку и другие
- **Гибкая настройка** — таймауты, потоки, свои списки доменов, DNS-серверы
  и IPv4-only режим

### ⚙️ Кастомизация
Следующие файлы могут быть переопределены. Инструкции ниже.

1.  `domains.txt` — список доменов для проверки.
2.  `tcp16.json` — цели для теста TCP 16-20KB.
3.  `config.py` — параметры таймаутов, макс. соединений...

## 🐋 Docker (Рекомендовано)

### Быстрый старт
Docker проверит наличие обновлений и скачает свежую версию перед запуском
```bash
docker run --rm -it --pull=always ghcr.io/runnin4ik/dpi-detector:latest
```
Или запускайте с указанием определенной версии  
Это избавляет от постоянных скачиваний, но нужно следить за актуальностью версий
```bash
docker run --rm -it ghcr.io/runnin4ik/dpi-detector:2.0
```

#### С кастомизацией
Переопределите нужные файлы: `domains.txt`, `tcp16.json` или `config.py`  
Запустите с монтированием (можно монтировать один или несколько файлов)
```bash
# Bash (Linux / macOS)
docker run --rm -it --pull=always \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/tcp16.json:/app/tcp16.json \
  -v $(pwd)/config.py:/app/config.py \
  ghcr.io/runnin4ik/dpi-detector:latest
```
<details>
<summary>Команды для PowerShell и CMD</summary>

PowerShell (Windows)
```bash
docker run --rm -it --pull=always `
  -v ${PWD}/domains.txt:/app/domains.txt `
  -v ${PWD}/tcp16.json:/app/tcp16.json `
  -v ${PWD}/config.py:/app/config.py `
  ghcr.io/runnin4ik/dpi-detector:latest
```

CMD (Windows)
```bash
docker run --rm -it --pull=always ^
  -v %cd%/domains.txt:/app/domains.txt ^
  -v %cd%/tcp16.json:/app/tcp16.json ^
  -v %cd%/config.py:/app/config.py ^
  ghcr.io/runnin4ik/dpi-detector:latest
```
</details>

## 🐍 Python 3.8+
**Требования:** httpx>=0.28, rich>=14.3

**Установка:**
```bash
git clone https://github.com/Runnin4ik/dpi-detector.git
cd dpi-detector
python -m pip install -r requirements.txt
```

**Запуск:**
```bash
python dpi_detector.py
```

## 🪟 Windows (Готовые сборки)

Для использования программы не обязательно устанавливать Python. Скачайте подходящий `.exe` файл в разделе [Releases -> Assets](https://github.com/Runnin4ik/dpi-detector/releases):

*   **[Скачать для Windows 10 / 11](https://github.com/Runnin4ik/dpi-detector/releases/download/v2.0.0/dpi_detector_v2.0_win10.exe)**
*   **[Скачать для Windows 7 / 8](https://github.com/Runnin4ik/dpi-detector/releases/download/v2.0.0/dpi_detector_v2.0_win7.exe)**

#### С кастомизацией

Переопределите нужные файлы: `domains.txt`, `tcp16.json` или `config.py`  
И положите их в папку рядом с `.exe` файлом.

## 🤝 Вклад в проект
Приветствуются Issue и Pull Request'ы и предложения функционала!

## 📜 Лицензия

[MIT License](LICENSE) — свободное использование, модификация и распространение.

## ⚠️ Дисклеймер

Этот инструмент предназначен исключительно для образовательных и диагностических целей. Автор не несет ответственности за использование данного ПО.

## 🙏 Благодарности

- Проекту [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) за вдохновение
- **0ka** за помощь и консультации

## Star History

<a href="https://www.star-history.com/#Runnin4ik/dpi-detector&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Runnin4ik/dpi-detector&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Runnin4ik/dpi-detector&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Runnin4ik/dpi-detector&type=date&legend=top-left" />
 </picture>
</a>