# Оповещение о цене криптовалют

Crypto-Price-Alert - это Python-скрипт для мониторинга цен криптовалют через CoinGecko и отправки оповещений в консоль, Telegram и Email при достижении заданных порогов/выходе из диапазона.

---

## ✨ Возможности

* Запрос текущих цен по **нескольким монетам** одним батчем (CoinGecko `/simple/price`).
* Условия срабатывания:

  * `--above` — цена **выше или равна** порогу.
  * `--below` — цена **ниже или равна** порогу.
  * `--range` — **выход из диапазона** `min:max`.
* Каналы уведомлений:

  * Консоль (обязательно).
  * **Опционально:** Telegram-бот.
  * **Опционально:** Email (SMTP).
* **Антиспам-логика:** повторное оповещение отправляется только после «разармирования» условия (когда цена вернулась обратно).
* Ретраи и таймауты для сетевых запросов, обработка 429/5xx.
* Конфигурация из **CLI** или **JSON/YAML** файла.
* Поддержка `.env` (через `python-dotenv`) для секретов.

---

## 🧩 Требования

* **Python** 3.9+
* Пакеты:

  * обязательные: `requests`
  * опциональные: `python-dotenv` (для `.env`), `PyYAML` (для `config.yaml`)
* Доступ в интернет к API CoinGecko.

---

## 📦 Установка

```bash
git clone https://github.com/Mironov1994/Crypto-Price-Alert.git
cd Crypto-Price-Alert

# (рекомендуется) создать виртуальное окружение
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt  # если есть
# или
pip install requests python-dotenv PyYAML
```

> Скрипт односценарный: достаточно файла **`crypto_price_alert.py`**.

---

## 🚀 Быстрый старт

Однократная проверка **BTC/USD** на пробой сверху `65000`:

```bash
python crypto_price_alert.py -s BTC --vs USD --above 65000 --once
```

Непрерывный мониторинг **BTC** (пробой сверху) и **ETH** (выход из диапазона) каждые 20 сек с уведомлениями в консоль и Telegram:

```bash
python crypto_price_alert.py \
  -s BTC -s ETH --vs USD \
  --above 65000 --range N/A,2800:3500 \
  --notify console --notify telegram \
  --interval 20 \
  --tg-token "$TG_TOKEN" --tg-chat-id "$TG_CHAT_ID"
```

Через **конфиг** + отправка на Email:

```bash
python crypto_price_alert.py --config alerts.json --notify email --smtp-tls
```

`alerts.json`:

```json
[
  {"symbol":"BTC","vs":"USD","above":65000},
  {"symbol":"ETH","vs":"USD","range":"2800:3500"}
]
```

---

## ⚙️ Параметры CLI

```text
-s, --symbol           Тикер монеты (BTC, ETH). Можно повторять.
--coingecko-id         Явный CoinGecko ID (например, bitcoin). По позициям к --symbol.
--vs                   Валюта котировки (по умолчанию USD).

--above                Порог пробоя сверху (число) или CSV по позициям.
--below                Порог пробоя снизу (число) или CSV по позициям.
--range                Диапазон "min:max" (оповещает при выходе) или CSV по позициям.

--interval             Интервал опроса в секундах (по умолчанию 30).
--once                 Однократная проверка (без бесконечного цикла).

--notify               Каналы уведомлений: console | telegram | email. Можно несколько.

--tg-token             Токен Telegram-бота (или ENV TG_TOKEN).
--tg-chat-id           Чат ID для Telegram (или ENV TG_CHAT_ID).

--smtp-host/port/user/pass/email-from/email-to  SMTP/Email параметры (см. ENV ниже).
--smtp-tls             Использовать STARTTLS.

--config               Путь к JSON/YAML конфигу.
--log-level            DEBUG | INFO | WARNING | ERROR | CRITICAL (по умолчанию INFO).
--state-file           Файл состояния антиспама (по умолчанию .alert_state.json).
```

### CSV по позициям

Можно задавать условия списком, соответствующим позициям `--symbol`:

```bash
python crypto_price_alert.py \
  -s BTC -s ETH -s SOL \
  --vs USD \
  --above 65000,N/A,200 \
  --range N/A,2800:3500,N/A
```

`N/A` — пропустить позицию для данного типа условия.

> В рамках одного символа через CLI поддерживается **одно** условие. Для нескольких условий создайте несколько записей в конфиге.

---

## 🗂️ Конфигурация через JSON/YAML

**Структура элемента:**

```json
{
  "symbol": "BTC",
  "coingecko_id": "bitcoin",     // опционально, можно не указывать
  "vs": "USD",
  "above": 65000                  // ИЛИ "below": ..., ИЛИ "range": "min:max"
}
```

**Пример YAML:**

```yaml
- symbol: BTC
  vs: USD
  above: 65000

- symbol: ETH
  vs: USD
  range: "2800:3500"
```

> Для YAML требуется `PyYAML`.

---

## 🔔 Каналы уведомлений

### Консоль

Включена по умолчанию. Читаемые сообщения с заголовком и деталями:

```
[ALERT] BTC/USD crossed ABOVE 65000 @ 65210.45
Condition: price >= 65000
Current price: 65210.45
Time (UTC): 2025-10-06T08:15:12Z
Interval: 20s
Source: CoinGecko /simple/price
```

### Telegram

Параметры:

* `--notify telegram`
* `--tg-token` (или `ENV TG_TOKEN`)
* `--tg-chat-id` (или `ENV TG_CHAT_ID`)

Отправка через `https://api.telegram.org/bot{token}/sendMessage` (ретраи, обработка 429/5xx).

### Email (SMTP)

Минимальные параметры:

* `--notify email`
* `--smtp-host`, `--smtp-port`
* `--email-from`, `--email-to`
* при необходимости: `--smtp-user`, `--smtp-pass`, `--smtp-tls`

Отправка простого `text/plain` письма через `smtplib` (+TLS при флаге).

---

## 🔒 Секреты и переменные окружения

Поддерживается загрузка `.env` (если установлен `python-dotenv`):

```env
TG_TOKEN=123456:ABCDEF...
TG_CHAT_ID=123456789

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@example.com
SMTP_PASS=app-specific-password
EMAIL_FROM=you@example.com
EMAIL_TO=alerts@example.com
```

Рекомендуется добавить `.env` в `.gitignore`.

---

## 🧠 Антиспам и файл состояния

Скрипт хранит состояние в JSON-файле (по умолчанию `.alert_state.json`), чтобы **не слать одно и то же оповещение** постоянно:

* Когда условие **выполняется** и состояние `armed = true` → отправка оповещения + `armed = false`.
* Когда условие **перестаёт выполняться** → `armed = true` (готов к следующему оповещению).
* Ключ состояния уникален для `SYMBOL/VS/тип_условия/порог`.

Путь к файлу можно поменять флагом `--state-file`.

---

## 🧪 Тестовые сценарии (ручные)

* **Порог вверх:** поставить `--above` чуть ниже текущей цены (должно сработать).
* **Порог вниз:** поставить `--below` чуть выше текущей цены (не должно сработать).
* **Диапазон:** выбрать `--range` около текущей цены и проверить выход/возврат.
* **Антиспам:** удерживать цену «в зоне» — оповещение приходит только один раз; вернуть цену — готовность восстанавливается.
* **Сеть:** временно отключить интернет — должны появляться предупреждения и ретраи без падения процесса.
* **Каналы:** проверить корректность Telegram и Email (тема/тело письма, приход сообщений).

---

## ⚠️ Ограничения и примечания

* Используется публичное API **CoinGecko** `/simple/price` (без ключа). Учитывайте возможные **ограничения частоты** запросов.
  Рекомендуемый интервал опроса — ≥ 20–30 секунд.
* Значения цен — спотовые по данным CoinGecko; возможны расхождения с ценами конкретной биржи.
* Скрипт не является торговым советом и не исполняет сделки.

---

## 📜 Лицензия

Этот проект распространяется по лицензии **MIT**. Подробности см. в файле `LICENSE`.
