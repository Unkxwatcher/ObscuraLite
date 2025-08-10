# Obscura Lite

**Обзор:**  
Obscura Lite — это простой и удобный инструмент для мониторинга подозрительных сетевых подключений с геолокацией, статусом угроз и функцией "Incognito". Программа работает с тёмной темой и поддерживает блокировку IP через встроенный Windows firewall.

---

## Требования

- Python 3.8 и выше  
- Модули Python: `psutil`, `geoip2` (опционально), `network_monitor` (если есть)  
- Windows с правами администратора (для блокировки IP через firewall)  
- Файл базы GeoIP: `GeoLite2-City.mmdb` (можно скачать с [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)) — положить рядом с `obscura_gui.py`

---

## Установка зависимостей

```bash
pip install psutil geoip2

Если нет модуля network_monitor — программа работает с fallback-сканером.


Запусти GUI:
python obscura_gui.py

Возможности:

1. Отображение текущих сетевых подключений с процессами и PID

2. Автоматический расчет уровня угрозы на основе процессов, портов и статусов

3. Геолокация IP-адресов с помощью базы MaxMind GeoLite2

4. Блокировка и разблокировка IP через Windows firewall

5. Функция Incognito для скрытия мониторинга

6. Экспорт подозрительных подключений для последующего анализа или обучения ML моделей

7. Тёмная тема для комфортного использования в любое время суток

Лицензия
MIT License — см. файл LICENSE

Контакты
Если есть вопросы или предложения, открывайте issue на GitHub или пишите.

Примечание
Для правильной работы блокировки IP запускайте программу с правами администратора Windows.
---

# 3. .gitignore

```text
__pycache__/
*.pyc
*.pyo
*.pyd
env/
venv/
data/*.log
data/*.json
.DS_Store
*.db

4. Инструкции для терминала

git init
git add .
git commit -m "Initial commit: Obscura Lite GUI with network monitoring"
git branch -M main
git remote add origin https://github.com/Unkxwatcher/Obscura-Lite.git
git push -u origin main