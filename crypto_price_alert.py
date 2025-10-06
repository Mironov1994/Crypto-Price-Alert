#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
crypto_price_alert.py
Оповещения о цене криптовалют (CoinGecko) с уведомлениями в консоль, Telegram и Email.

- Один файл, без внешних сервисов, кроме публичного API CoinGecko.
- Поддержка нескольких монет, разных условий (>=, <=, выход из диапазона).
- Защита от спама: повторные уведомления рассылаются только после "разармирования" условия.
- Ретраи и таймауты для сетевых запросов.
- Опциональная загрузка .env (python-dotenv, если установлен).
- Опциональный YAML-конфиг (PyYAML, если установлен).

Примеры:
  # Однократная проверка BTC на пробой сверху 65000
  python crypto_price_alert.py -s BTC --vs USD --above 65000 --once

  # BTC + ETH, интервальный мониторинг, алерты в Telegram
  python crypto_price_alert.py -s BTC -s ETH --vs USD \
      --above 65000 --range N/A,2800:3500 \
      --notify console --notify telegram \
      --interval 20 \
      --tg-token "$TG_TOKEN" --tg-chat-id "$TG_CHAT_ID"

  # Через конфиг JSON
  python crypto_price_alert.py --config alerts.json --notify email --smtp-tls
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import math
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Внешние зависимости
try:
    import requests
except ImportError:
    print("Требуется пакет 'requests' (pip install requests)", file=sys.stderr)
    sys.exit(2)

# Опциональные зависимости
try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    load_dotenv = None  # необязательно

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # необязательно

import smtplib
import ssl
from email.message import EmailMessage

COINGECKO_SIMPLE_PRICE_URL = "https://api.coingecko.com/api/v3/simple/price"

DEFAULT_INTERVAL = 30
DEFAULT_STATE_FILE = ".alert_state.json"

# Базовый словарь сопоставления тикеров к CoinGecko ID (можно расширить)
SYMBOL_TO_COINGECKO_ID: Dict[str, str] = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "BNB": "binancecoin",
    "SOL": "solana",
    "XRP": "ripple",
    "ADA": "cardano",
    "DOGE": "dogecoin",
    "TRX": "tron",
    "TON": "the-open-network",
    "DOT": "polkadot",
    "MATIC": "matic-network",
    "LTC": "litecoin",
    "BCH": "bitcoin-cash",
    "LINK": "chainlink",
    "ATOM": "cosmos",
    "XLM": "stellar",
    "UNI": "uniswap",
    "AAVE": "aave",
    "AVAX": "avalanche-2",
    "NEAR": "near",
    "ETC": "ethereum-classic",
    "XMR": "monero",
    "FIL": "filecoin",
    "EGLD": "multiversx",
    "APT": "aptos",
    "ARB": "arbitrum",
    "OP": "optimism",
    "SUI": "sui",
    "PEPE": "pepe",
    "SHIB": "shiba-inu",
}


@dataclass
class Condition:
    """Условие срабатывания алерта"""
    mode: str  # 'above' | 'below' | 'range'
    above: Optional[float] = None
    below: Optional[float] = None
    range_min: Optional[float] = None
    range_max: Optional[float] = None

    def describe(self) -> str:
        if self.mode == "above":
            return f"price >= {self.above}"
        if self.mode == "below":
            return f"price <= {self.below}"
        if self.mode == "range":
            return f"price < {self.range_min} or price > {self.range_max}"
        return "unknown condition"


@dataclass
class MonitorTask:
    """Единица мониторинга: монета / валюта котировки / условие"""
    symbol: str
    cg_id: str
    vs: str
    condition: Condition


# -------------------------- Вспомогательные утилиты -------------------------- #

def safe_float(x: str) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None


def parse_range(spec: str) -> Tuple[Optional[float], Optional[float]]:
    """
    Парсинг диапазона вида "min:max".
    Разрешается отсутствие одной границы (":3500" или "2800:").
    Возвращает (min, max) как float|None.
    """
    parts = spec.split(":")
    if len(parts) != 2:
        raise ValueError("Формат диапазона должен быть 'min:max'")
    lo = parts[0].strip()
    hi = parts[1].strip()
    lo_val = safe_float(lo) if lo else None
    hi_val = safe_float(hi) if hi else None
    if lo_val is None and hi_val is None:
        raise ValueError("В диапазоне должна быть хотя бы одна граница")
    if (lo_val is not None) and (hi_val is not None) and lo_val >= hi_val:
        raise ValueError("Нижняя граница должна быть меньше верхней")
    return lo_val, hi_val


def try_load_env():
    """Опциональная загрузка .env, если доступен python-dotenv"""
    if load_dotenv is not None:
        load_dotenv()  # загрузит .env если он есть


def load_state(path: str) -> Dict[str, dict]:
    """Загрузка состояния (armed/last_price/last_trigger) из JSON"""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.warning("Не удалось загрузить state-файл %s: %s", path, e)
        return {}


def save_state(path: str, state: Dict[str, dict]) -> None:
    """Сохранение состояния в JSON"""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        logging.error("Не удалось сохранить state-файл %s: %s", path, e)


def state_key(symbol: str, vs: str, cond: Condition) -> str:
    """Ключ состояния уникален для символа/валюты/типа условия и порога"""
    if cond.mode == "above":
        suffix = f"above:{cond.above}"
    elif cond.mode == "below":
        suffix = f"below:{cond.below}"
    else:
        suffix = f"range:{cond.range_min}:{cond.range_max}"
    return f"{symbol.upper()}/{vs.upper()}/{suffix}"


def format_alert_title(symbol: str, vs: str, cond: Condition, price: float) -> str:
    """Заголовок алерта в стиле: [ALERT] BTC/USD crossed ABOVE 65000"""
    if cond.mode == "above":
        edge = f"ABOVE {cond.above}"
    elif cond.mode == "below":
        edge = f"BELOW {cond.below}"
    else:
        edge = f"OUTSIDE {cond.range_min}:{cond.range_max}"
    return f"[ALERT] {symbol.upper()}/{vs.upper()} crossed {edge} @ {price:.8g}"


def now_utc_iso() -> str:
    """Текущее время UTC в ISO 8601 (без зависимостей)"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def nvl(a, b):
    return a if a is not None else b


# -------------------------- Парсинг аргументов CLI -------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Оповещение о цене криптовалют (CoinGecko).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Символы/коин-айди
    p.add_argument("-s", "--symbol", action="append", help="Тикер криптовалюты (например, BTC). Можно повторять.", default=[])
    p.add_argument("--coingecko-id", action="append", default=[], help="Явный CoinGecko ID (например, 'bitcoin'). Соответствует символам по позициям.")
    p.add_argument("--vs", default="USD", help="Валюта котировки (fiat/crypto)")

    # Пороги: либо above, либо below, либо range. Допускаем CSV-списки по позициям.
    p.add_argument("--above", default=None, help="Порог пробоя сверху, число или CSV по позициям (пример: 65000, N/A, 1.2)")
    p.add_argument("--below", default=None, help="Порог пробоя снизу, число или CSV по позициям")
    p.add_argument("--range", dest="range_", default=None, help="Диапазон min:max или CSV по позициям (пример: 2800:3500, N/A)")

    # Режим работы
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Интервал опроса (сек)")
    p.add_argument("--once", action="store_true", help="Однократная проверка и выход")

    # Нотификации
    p.add_argument("--notify", action="append", choices=["console", "telegram", "email"], default=["console"],
                   help="Куда отправлять уведомления (можно повторять)")

    # Telegram
    p.add_argument("--tg-token", default=None, help="Токен бота Telegram (или ENV TG_TOKEN)")
    p.add_argument("--tg-chat-id", default=None, help="Chat ID для Telegram (или ENV TG_CHAT_ID)")

    # Email (SMTP)
    p.add_argument("--smtp-host", default=None, help="SMTP хост (или ENV SMTP_HOST)")
    p.add_argument("--smtp-port", type=int, default=None, help="SMTP порт (или ENV SMTP_PORT)")
    p.add_argument("--smtp-user", default=None, help="SMTP логин (или ENV SMTP_USER)")
    p.add_argument("--smtp-pass", default=None, help="SMTP пароль/токен (или ENV SMTP_PASS)")
    p.add_argument("--email-from", default=None, help="Адрес отправителя (или ENV EMAIL_FROM)")
    p.add_argument("--email-to", default=None, help="Адрес получателя (или ENV EMAIL_TO)")
    p.add_argument("--smtp-tls", action="store_true", help="Использовать TLS при отправке email")

    # Конфиг и логирование
    p.add_argument("--config", default=None, help="Путь к JSON/YAML конфигу с массивом задач")
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO", help="Уровень логов")
    p.add_argument("--state-file", default=DEFAULT_STATE_FILE, help="Файл для запоминания состояния (анти-спам)")

    return p


def align_csv_to_symbols(symbols: List[str], value: Optional[str]) -> List[Optional[str]]:
    """
    Превращает CSV-значение (строка) в список по количеству symbols.
    Разрешено 'N/A' или пустая позиция для пропуска.
    Если value == None -> возвращает список [None, None, ...].
    Если value одна, применяется ко всем символам (broadcast).
    """
    n = len(symbols)
    if n == 0:
        return []
    if value is None:
        return [None] * n
    # Если есть запятые — парсим по позициям
    if "," in value:
        raw = [s.strip() for s in value.split(",")]
        if len(raw) == 1:
            raw = raw * n
        elif len(raw) < n:
            # Дополняем None
            raw = raw + [None] * (n - len(raw))
        elif len(raw) > n:
            raw = raw[:n]
        return [None if (v is None or v == "" or v.upper() == "N/A") else v for v in raw]
    else:
        # Одна величина — broadcast
        v = None if (value.strip() == "" or value.strip().upper() == "N/A") else value.strip()
        return [v] * n


def build_tasks_from_cli(args: argparse.Namespace) -> List[MonitorTask]:
    """
    Формирует задачи мониторинга из CLI (без конфига).
    Поддерживает CSV по позициям: --symbol BTC,ETH  --above 65000,N/A  --range N/A,2800:3500
    """
    symbols = [s.strip().upper() for s in args.symbol]
    if not symbols and not args.config:
        raise ValueError("Нужно указать хотя бы один символ (-s/--symbol) или --config")

    ids_by_pos = align_csv_to_symbols(symbols, ",".join(args.coingecko_id) if args.coingecko_id else None)
    above_by_pos = align_csv_to_symbols(symbols, args.above)
    below_by_pos = align_csv_to_symbols(symbols, args.below)
    range_by_pos = align_csv_to_symbols(symbols, args.range_)

    tasks: List[MonitorTask] = []
    for i, sym in enumerate(symbols):
        cg_id = nvl(ids_by_pos[i], SYMBOL_TO_COINGECKO_ID.get(sym))
        if not cg_id:
            raise ValueError(f"Неизвестный символ '{sym}' — укажите --coingecko-id вручную")

        # Определяем условие для данной позиции
        cond_candidates = []

        if above_by_pos[i] is not None:
            val = safe_float(above_by_pos[i])
            if val is None:
                raise ValueError(f"--above для {sym} должно быть числом")
            cond_candidates.append(Condition(mode="above", above=val))

        if below_by_pos[i] is not None:
            val = safe_float(below_by_pos[i])
            if val is None:
                raise ValueError(f"--below для {sym} должно быть числом")
            cond_candidates.append(Condition(mode="below", below=val))

        if range_by_pos[i] is not None:
            rmin, rmax = parse_range(range_by_pos[i])
            cond_candidates.append(Condition(mode="range", range_min=rmin, range_max=rmax))

        if len(cond_candidates) == 0:
            raise ValueError(f"Для {sym} нужно указать хотя бы одно условие (--above/--below/--range)")
        if len(cond_candidates) > 1:
            # В рамках ТЗ — взаимоисключающие (на одну монету одно условие через CLI)
            # Если очень нужно — разбить на несколько -s одинаковых символов с разными условиями.
            raise ValueError(f"Для {sym} указано несколько условий. Укажите только одно на символ в CLI.")

        tasks.append(MonitorTask(symbol=sym, cg_id=cg_id, vs=args.vs.upper(), condition=cond_candidates[0]))

    return tasks


def load_tasks_from_config(path: str) -> List[MonitorTask]:
    """
    Загрузка задач из JSON/YAML.
    Формат элементов:
      { "symbol": "BTC", "coingecko_id": "bitcoin", "vs": "USD", "above": 65000 }
      { "symbol": "ETH", "vs": "USD", "range": "2800:3500" }
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Файл конфига не найден: {path}")

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    data = None
    # Пробуем JSON, затем YAML
    try:
        data = json.loads(text)
    except Exception:
        if yaml is not None:
            data = yaml.safe_load(text)
        else:
            raise ValueError("Не удалось распарсить конфиг как JSON. Установите PyYAML для поддержки YAML.")

    if not isinstance(data, list):
        raise ValueError("Конфиг должен быть списком объектов")

    tasks: List[MonitorTask] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Элемент #{i} в конфиге должен быть объектом")

        sym = str(item.get("symbol", "")).strip().upper()
        if not sym:
            raise ValueError(f"Элемент #{i}: поле 'symbol' обязательно")

        vs = str(item.get("vs", "USD")).strip().upper()
        cg_id = str(item.get("coingecko_id", "")).strip() or SYMBOL_TO_COINGECKO_ID.get(sym)
        if not cg_id:
            raise ValueError(f"Элемент #{i}: не удалось определить coingecko_id для символа '{sym}'")

        # Определяем условие: один из above/below/range
        cond_fields = [k for k in ("above", "below", "range") if k in item and item[k] not in (None, "")]
        if len(cond_fields) != 1:
            raise ValueError(f"Элемент #{i}: укажите ровно одно из полей: above/below/range")

        if "above" in item:
            val = safe_float(str(item["above"]))
            if val is None:
                raise ValueError(f"Элемент #{i}: 'above' должно быть числом")
            cond = Condition(mode="above", above=val)
        elif "below" in item:
            val = safe_float(str(item["below"]))
            if val is None:
                raise ValueError(f"Элемент #{i}: 'below' должно быть числом")
            cond = Condition(mode="below", below=val)
        else:
            r = str(item["range"])
            rmin, rmax = parse_range(r)
            cond = Condition(mode="range", range_min=rmin, range_max=rmax)

        tasks.append(MonitorTask(symbol=sym, cg_id=cg_id, vs=vs, condition=cond))

    return tasks


def merge_tasks(cli_tasks: List[MonitorTask], cfg_tasks: List[MonitorTask]) -> List[MonitorTask]:
    """
    Объединяет задачи из CLI и конфига.
    Никакой дедупликации не делаем: явное дублирование = отдельные условия.
    """
    return cfg_tasks + cli_tasks


# -------------------------- Работа с CoinGecko -------------------------- #

def fetch_prices_batch(ids: List[str], vs: str, timeout: float = 8.0, retries: int = 3) -> Dict[str, float]:
    """
    Получение цен одним батчем для списка CoinGecko ID в валюте vs.
    Возвращает словарь {id: price}.
    Ретраи с экспоненциальной паузой (0.5, 1.0, 2.0 ...).
    """
    params = {
        "ids": ",".join(sorted(set(ids))),
        "vs_currencies": vs.lower(),
    }

    backoff = 0.5
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(COINGECKO_SIMPLE_PRICE_URL, params=params, timeout=timeout)
            # Обработка rate limit/серверных ошибок
            if resp.status_code == 429:
                logging.warning("CoinGecko вернул 429 Too Many Requests, попытка %d/%d", attempt, retries)
                time.sleep(backoff)
                backoff *= 2
                continue
            if resp.status_code >= 500:
                logging.warning("CoinGecko 5xx (%s), попытка %d/%d", resp.status_code, attempt, retries)
                time.sleep(backoff)
                backoff *= 2
                continue

            resp.raise_for_status()
            data = resp.json()
            out: Dict[str, float] = {}
            for k, v in data.items():
                # v должен быть {"usd": price} или {"eur": price} и т.п.
                if isinstance(v, dict) and vs.lower() in v and isinstance(v[vs.lower()], (int, float)):
                    out[k] = float(v[vs.lower()])
            return out
        except (requests.RequestException, ValueError) as e:
            last_err = e
            logging.warning("Ошибка запроса к CoinGecko: %s (попытка %d/%d)", e, attempt, retries)
            time.sleep(backoff)
            backoff *= 2

    # Если не удалось
    if last_err:
        raise RuntimeError(f"Не удалось получить цены из CoinGecko: {last_err}")
    return {}


# -------------------------- Проверка условий и (де)армирование -------------------------- #

def condition_met(price: float, cond: Condition) -> bool:
    """Проверка выполнения условия для текущей цены"""
    if cond.mode == "above" and cond.above is not None:
        return price >= cond.above
    if cond.mode == "below" and cond.below is not None:
        return price <= cond.below
    if cond.mode == "range":
        # 'range' означает ОПОВЕСТИТЬ, когда цена ВНЕ диапазона
        lo = cond.range_min
        hi = cond.range_max
        if lo is not None and price < lo:
            return True
        if hi is not None and price > hi:
            return True
        return False
    return False


def update_arm_state(price: float, cond: Condition, st_entry: dict) -> None:
    """
    Логика "армирования":
      - По умолчанию armed=True (готов отправить алерт).
      - Когда условие сработало -> отправляем алерт и ставим armed=False.
      - Когда условие перестаёт выполняться -> armed=True (готовность к следующему алерту).
    """
    # Если условие выполняется — разармируем (после отправки)
    if condition_met(price, cond):
        st_entry["armed"] = False
    else:
        # Условие больше не выполняется — снова готов к алерту
        st_entry["armed"] = True


# -------------------------- Каналы уведомлений -------------------------- #

def notify_console(title: str, body: str) -> None:
    """Оповещение в консоль"""
    print(title)
    print(body)
    print("-" * 60, flush=True)


def notify_telegram(token: str, chat_id: str, text: str, timeout: float = 8.0, retries: int = 3) -> None:
    """Отправка сообщения в Telegram ботом"""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    backoff = 0.5
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code >= 500 or r.status_code == 429:
                logging.warning("Telegram ответил %s (попытка %d/%d)", r.status_code, attempt, retries)
                time.sleep(backoff)
                backoff *= 2
                continue
            r.raise_for_status()
            return
        except (requests.RequestException, ValueError) as e:
            last_err = e
            logging.warning("Ошибка отправки в Telegram: %s (попытка %d/%d)", e, attempt, retries)
            time.sleep(backoff)
            backoff *= 2
    if last_err:
        raise RuntimeError(f"Не удалось отправить Telegram-сообщение: {last_err}")


def notify_email(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    email_from: str,
    email_to: str,
    subject: str,
    body: str,
    use_tls: bool = False,
) -> None:
    """Отправка email через SMTP"""
    msg = EmailMessage()
    msg["From"] = email_from
    msg["To"] = email_to
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    if use_tls:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        try:
            server.starttls(context=context)
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        finally:
            server.quit()
    else:
        # SMTPS (465) либо insecure (не рекомендуется)
        server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=15)
        try:
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        finally:
            server.quit()


# -------------------------- Основной цикл -------------------------- #

def build_tasks(args: argparse.Namespace) -> List[MonitorTask]:
    """Формирование полного списка задач из CLI и/или конфига"""
    tasks_cli: List[MonitorTask] = []
    tasks_cfg: List[MonitorTask] = []

    if args.symbol:
        tasks_cli = build_tasks_from_cli(args)

    if args.config:
        tasks_cfg = load_tasks_from_config(args.config)

    tasks = merge_tasks(tasks_cli, tasks_cfg)
    if not tasks:
        raise ValueError("Не найдено ни одной задачи мониторинга.")

    return tasks


def group_tasks_by_vs(tasks: List[MonitorTask]) -> Dict[str, List[MonitorTask]]:
    """Группируем задачи по валюте котировки (vs), чтобы батчить запросы"""
    d: Dict[str, List[MonitorTask]] = {}
    for t in tasks:
        d.setdefault(t.vs.upper(), []).append(t)
    return d


def build_message(symbol: str, vs: str, cond: Condition, price: float, interval: int) -> Tuple[str, str]:
    """Формирует (title, body) для всех каналов"""
    title = format_alert_title(symbol, vs, cond, price)
    lines = [
        f"{title}",
        f"Condition: {cond.describe()}",
        f"Current price: {price:.10g}",
        f"Time (UTC): {now_utc_iso()}",
        f"Interval: {interval}s",
        "Source: CoinGecko /simple/price",
    ]
    return title, "\n".join(lines)


def main():
    try_load_env()

    parser = build_arg_parser()
    args = parser.parse_args()

    # Логи
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    # Подтягиваем дефолты из ENV для нотификаций
    tg_token = args.tg_token or os.getenv("TG_TOKEN")
    tg_chat_id = args.tg_chat_id or os.getenv("TG_CHAT_ID")

    smtp_host = args.smtp_host or os.getenv("SMTP_HOST")
    smtp_port = args.smtp_port or (int(os.getenv("SMTP_PORT")) if os.getenv("SMTP_PORT") else None)
    smtp_user = args.smtp_user or os.getenv("SMTP_USER")
    smtp_pass = args.smtp_pass or os.getenv("SMTP_PASS")
    email_from = args.email_from or os.getenv("EMAIL_FROM")
    email_to = args.email_to or os.getenv("EMAIL_TO")

    try:
        tasks = build_tasks(args)
    except Exception as e:
        logging.error("Ошибка формирования задач: %s", e)
        sys.exit(2)

    # Загружаем state
    state_path = args.state_file or DEFAULT_STATE_FILE
    state = load_state(state_path)

    # Проверка настроек каналов (минимальная)
    notify_channels = set(args.notify or ["console"])
    if "telegram" in notify_channels and (not tg_token or not tg_chat_id):
        logging.warning("Канал telegram выбран, но tg-token/tg-chat-id не заданы. Канал будет пропущен.")
        notify_channels.discard("telegram")
    if "email" in notify_channels:
        missing = [k for k, v in {
            "smtp_host": smtp_host, "smtp_port": smtp_port,
            "email_from": email_from, "email_to": email_to,
        }.items() if not v]
        if missing:
            logging.warning("Канал email выбран, но отсутствуют параметры: %s. Канал будет пропущен.", ", ".join(missing))
            notify_channels.discard("email")
        # Если порт есть, но TLS не задан — это не ошибка, можно без TLS/или SMTPS (465)
        if "email" in notify_channels and not smtp_user:
            logging.info("SMTP_USER не указан — попытаемся отправить без аутентификации (если сервер позволяет).")

    # Основной цикл
    exit_code = 0
    while True:
        try:
            # Группируем по валюте котировки (vs), чтобы минимизировать запросы
            groups = group_tasks_by_vs(tasks)

            for vs, group in groups.items():
                ids = [t.cg_id for t in group]
                if not ids:
                    continue

                try:
                    prices = fetch_prices_batch(ids, vs)
                except Exception as e:
                    logging.error("Сбой получения цен для %s: %s", vs, e)
                    exit_code = max(exit_code, 3)
                    continue

                # Обрабатываем каждую задачу
                for t in group:
                    price = prices.get(t.cg_id)
                    if price is None or not isinstance(price, (int, float)) or math.isnan(price):
                        logging.warning("Нет цены для %s (%s/%s)", t.symbol, t.cg_id, vs)
                        continue

                    key = state_key(t.symbol, t.vs, t.condition)
                    st = state.get(key, {"armed": True})

                    # Если условие выполняется и armed=True — шлём нотификацию
                    if condition_met(price, t.condition) and st.get("armed", True):
                        title, body = build_message(t.symbol, t.vs, t.condition, price, args.interval)

                        # Консоль — всегда, если выбрана
                        if "console" in notify_channels:
                            notify_console(title, body)

                        # Telegram
                        if "telegram" in notify_channels and tg_token and tg_chat_id:
                            try:
                                notify_telegram(tg_token, str(tg_chat_id), f"{title}\n\n{body}")
                            except Exception as e:
                                logging.error("Не удалось отправить Telegram-уведомление: %s", e)
                                exit_code = max(exit_code, 3)

                        # Email
                        if "email" in notify_channels and smtp_host and smtp_port and email_from and email_to:
                            try:
                                notify_email(
                                    smtp_host=smtp_host,
                                    smtp_port=int(smtp_port),
                                    smtp_user=smtp_user or "",
                                    smtp_pass=smtp_pass or "",
                                    email_from=email_from,
                                    email_to=email_to,
                                    subject=title,
                                    body=body,
                                    use_tls=bool(args.smtp_tls),
                                )
                            except Exception as e:
                                logging.error("Не удалось отправить email-уведомление: %s", e)
                                exit_code = max(exit_code, 3)

                        # Обновляем состояние (разармируем) после отправки
                        st.update({
                            "armed": False,
                            "last_trigger": now_utc_iso(),
                            "last_price": price,
                            "mode": t.condition.mode,
                        })
                        state[key] = st
                    else:
                        # Обновляем armed в зависимости от того, вышли ли из "тревожной зоны"
                        update_arm_state(price, t.condition, st)
                        st["last_price"] = price
                        st["mode"] = t.condition.mode
                        state[key] = st

            # Сохраняем состояние на диск
            save_state(state_path, state)

        except KeyboardInterrupt:
            print("\nОстановлено пользователем (Ctrl+C).", file=sys.stderr)
            break
        except Exception as e:
            logging.error("Необработанная ошибка цикла: %s", e)
            exit_code = max(exit_code, 3)

        if args.once:
            break

        # Соблюдаем интервал опроса (не чаще 1 запрос/5с желательно).
        time.sleep(max(1, int(args.interval)))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()