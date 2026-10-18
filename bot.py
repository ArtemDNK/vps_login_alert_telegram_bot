#!/usr/bin/env python3
"""
tg-login-bot — уведомления в Telegram о попытках входа на сервер
(SSH, локальная консоль, su, sudo) + кнопка перезагрузки.

Источник событий — systemd-journald (facility auth/authpriv), поэтому
на Debian 13 не нужен rsyslog и /var/log/auth.log.
"""
import asyncio
import html
import json
import logging
import os
import re
import shutil
import socket
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramRetryAfter
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from dotenv import load_dotenv

# ───────────────────────── настройки ─────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = {int(x) for x in re.split(r"[,\s]+", os.environ["ADMIN_IDS"].strip()) if x}
SERVER_NAME = os.getenv("SERVER_NAME") or socket.gethostname()
# Неудачные SSH-входы сами не приходят — их видно по кнопке «🛡 Попытки входа»
# 1 — присылать каждую выполненную через sudo команду
NOTIFY_SUDO_COMMANDS = os.getenv("NOTIFY_SUDO_COMMANDS", "0") == "1"
REBOOT_CONFIRM_TTL = 60  # секунд на подтверждение перезагрузки

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("tg-login-bot")

E = lambda s: html.escape(str(s or ""))  # имена пользователей приходят от атакующих — экранируем всё


# ───────────────────────── разбор журнала ─────────────────────────
@dataclass
class Event:
    ok: bool
    source: str  # SSH / Консоль / su / sudo
    user: str
    ip: str = ""
    detail: str = ""
    ts: float = field(default_factory=time.time)


RX_SSH_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")
RX_SSH_FAIL = re.compile(r"Failed (\S+) for (invalid user )?(.*?) from (\S+) port (\d+)")
# shadow: FAILED LOGIN (1) on '/dev/tty1' FOR 'root', Authentication failure
# util-linux (Debian 13): FAILED LOGIN 1 ON tty1 FOR root, Authentication failure
RX_LOGIN_FAIL = re.compile(
    r"FAILED LOGIN \(?\d+\)?(?:\s+on\s+'?(?P<tty>[^'\s]+)'?)?(?:\s+FROM\s+'?(?P<host>[^'\s]+)'?)?"
    r"\s+FOR\s+'?(?P<user>[^',]*)'?,\s*(?P<reason>.+)",
    re.I,
)
# ROOT LOGIN ON tty1 / LOGIN ON tty1 BY artem [FROM host]
RX_LOGIN_OK = re.compile(
    r"^(?P<root>ROOT\s+)?LOGIN\s+ON\s+'?(?P<tty>[^'\s]+)'?(?:\s+BY\s+(?P<user>\S+))?"
    r"(?:\s+FROM\s+'?(?P<host>[^'\s]+)'?)?",
    re.I,
)
RX_SU_FAIL = re.compile(r"FAILED SU \(to (\S+)\) (\S+) on (\S+)")
RX_SU_OK = re.compile(r"^\(to (\S+)\) (\S+) on (\S+)")
RX_SUDO_FAIL = re.compile(r"^\s*(\S+) : (\d+) incorrect password attempts?")
RX_SUDO_DENIED = re.compile(r"^\s*(\S+) : (user NOT in sudoers|command not allowed)")
RX_SUDO_CMD = re.compile(r"^\s*(\S+) : .*?USER=(\S+) ; COMMAND=(.+)$")


def parse(ident: str, msg: str) -> Event | None:
    if ident.startswith("sshd"):  # sshd / sshd-session / sshd-auth (OpenSSH 10)
        if m := RX_SSH_OK.search(msg):
            return Event(True, "SSH", m[2], m[3], m[1])
        if m := RX_SSH_FAIL.search(msg):
            detail = m[1] + (", несуществующий пользователь" if m[2] else "")
            return Event(False, "SSH", m[3], m[4], detail)
    elif ident == "login":
        if m := RX_LOGIN_FAIL.search(msg):
            detail = " · ".join(x for x in (m["tty"], m["reason"]) if x)
            return Event(False, "Консоль", m["user"], m["host"] or "", detail)
        if m := RX_LOGIN_OK.search(msg):
            user = m["user"] or ("root" if m["root"] else "?")
            return Event(True, "Консоль", user, m["host"] or "", m["tty"])
    elif ident == "su":
        if m := RX_SU_FAIL.search(msg):
            return Event(False, "su", f"{m[2]} → {m[1]}", "", m[3])
        if m := RX_SU_OK.search(msg):
            return Event(True, "su", f"{m[2]} → {m[1]}", "", m[3])
    elif ident == "sudo":
        if m := RX_SUDO_FAIL.search(msg):
            return Event(False, "sudo", m[1], "", f"неверный пароль × {m[2]}")
        if m := RX_SUDO_DENIED.search(msg):
            return Event(False, "sudo", m[1], "", m[2])
        if NOTIFY_SUDO_COMMANDS and (m := RX_SUDO_CMD.search(msg)):
            return Event(True, "sudo", f"{m[1]} → {m[2]}", "", m[3].strip())
    return None


def _field(entry: dict, key: str) -> str:
    v = entry.get(key, "")
    if isinstance(v, list):  # journald отдаёт не-UTF8 строки массивом байт
        v = bytes(v).decode("utf-8", "replace")
    return v or ""


async def iter_journal(extra_args: list[str]):
    """События входа из journald. SYSLOG_FACILITY=4 (auth) ИЛИ 10 (authpriv)."""
    cmd = ["journalctl", "--no-pager", "-q", "-o", "json", *extra_args,
           "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        limit=1 << 20,
    )
    try:
        async for raw in proc.stdout:
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            ev = parse(_field(entry, "SYSLOG_IDENTIFIER"), _field(entry, "MESSAGE"))
            if not ev:
                continue
            if ts := entry.get("__REALTIME_TIMESTAMP"):
                ev.ts = int(ts) / 1_000_000
            yield ev
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


async def journal_reader(queue: asyncio.Queue) -> None:
    while True:
        log.info("Слежу за журналом")
        async for ev in iter_journal(["-f", "-n", "0"]):  # только новые записи
            try:
                queue.put_nowait(ev)
            except asyncio.QueueFull:
                pass
        log.warning("journalctl завершился, перезапуск через 5 с")
        await asyncio.sleep(5)


# ───────────────────────── форматирование ─────────────────────────
TITLES = {
    ("SSH", True): "Вход по SSH",
    ("SSH", False): "Неудачный вход по SSH",
    ("Консоль", True): "Вход в консоль",
    ("Консоль", False): "Неудачный вход в консоль",
    ("su", True): "su — смена пользователя",
    ("su", False): "Неудачный su",
    ("sudo", True): "Команда sudo",
    ("sudo", False): "Отказ sudo",
}


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S")


def fmt_dur(sec: float) -> str:
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    return f"{d} д {h} ч {m} мин" if d else f"{h} ч {m} мин"


def uptime() -> float:
    with open("/proc/uptime") as f:
        return float(f.read().split()[0])


def format_event(ev: Event) -> str:
    lines = [
        f"{'✅' if ev.ok else '⛔'} <b>{TITLES[(ev.source, ev.ok)]}</b> · <code>{E(SERVER_NAME)}</code>",
        f"👤 <code>{E(ev.user[:64])}</code>",
    ]
    if ev.ip:
        lines.append(f"🌐 <code>{E(ev.ip)}</code>")
    if ev.detail:
        lines.append(f"ℹ️ {E(ev.detail[:500])}")
    lines.append(f"🕒 {fmt_time(ev.ts)}")
    return "\n".join(lines)


async def build_report(hours: int = 24) -> str:
    """Сводка по журналу за последние N часов — переживает перезапуски бота и сервера."""
    ok_src, fail_src = defaultdict(int), defaultdict(int)
    ssh_fails: dict = defaultdict(lambda: {"count": 0, "users": defaultdict(int)})
    async for ev in iter_journal(["--since", f"{hours} hours ago"]):
        if ev.ok:
            ok_src[ev.source] += 1
        else:
            fail_src[ev.source] += 1
            if ev.source == "SSH":
                b = ssh_fails[ev.ip]
                b["count"] += 1
                b["users"][ev.user] += 1

    lines = [f"🛡 <b>Попытки входа</b> · <code>{E(SERVER_NAME)}</code>", f"За последние {hours} ч:", ""]
    for src in ("SSH", "Консоль", "su", "sudo"):
        if ok_src[src] or fail_src[src]:
            lines.append(f"{src}: ✅ {ok_src[src]}  ⛔ {fail_src[src]}")
    if len(lines) == 3:
        lines.append("Событий нет.")

    if ssh_fails:
        lines += ["", f"<b>Неудачные SSH:</b> {fail_src['SSH']} попыток с {len(ssh_fails)} IP"]
        items = sorted(ssh_fails.items(), key=lambda kv: -kv[1]["count"])
        for ip, p in items[:20]:
            users = sorted(p["users"].items(), key=lambda kv: -kv[1])
            names = ", ".join(E(u[:32]) for u, _ in users[:5]) + (" …" if len(users) > 5 else "")
            lines.append(f"<code>{E(ip)}</code> — {p['count']} ({names})")
        if len(items) > 20:
            lines.append(f"…и ещё {len(items) - 20} IP")
    return "\n".join(lines)


# ───────────────────────── клавиатуры ─────────────────────────
BTN_STATUS = "📊 Статус"
BTN_STATS = "🛡 Попытки входа"
BTN_REBOOT = "🔄 Перезагрузка"

MAIN_KB = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text=BTN_STATUS), KeyboardButton(text=BTN_STATS)],
        [KeyboardButton(text=BTN_REBOOT)],
    ],
    resize_keyboard=True,
    is_persistent=True,
)
REBOOT_INLINE = InlineKeyboardMarkup(
    inline_keyboard=[[InlineKeyboardButton(text="🔄 Перезагрузить сервер", callback_data="reboot:ask")]]
)


def confirm_kb() -> InlineKeyboardMarkup:
    ts = int(time.time())
    return InlineKeyboardMarkup(
        inline_keyboard=[[
            InlineKeyboardButton(text="✅ Да, перезагрузить", callback_data=f"reboot:yes:{ts}"),
            InlineKeyboardButton(text="❌ Отмена", callback_data="reboot:no"),
        ]]
    )


# ───────────────────────── уведомления ─────────────────────────
class Notifier:
    def __init__(self, bot: Bot):
        self.bot = bot

    async def send(self, text: str, exclude: int | None = None, **kw) -> None:
        text = text[:4000]
        for chat_id in ADMIN_IDS:
            if chat_id == exclude:
                continue
            for _ in range(3):
                try:
                    await self.bot.send_message(chat_id, text, **kw)
                    break
                except TelegramRetryAfter as e:
                    await asyncio.sleep(e.retry_after + 1)
                except Exception as e:
                    log.warning("Не удалось отправить в %s: %s", chat_id, e)
                    await asyncio.sleep(3)

    async def handle(self, ev: Event) -> None:
        if not ev.ok and ev.source == "SSH":
            return  # неудачные SSH — только по кнопке «🛡 Попытки входа»
        markup = REBOOT_INLINE if ev.ok and ev.source in ("SSH", "Консоль") else None
        await self.send(format_event(ev), reply_markup=markup)


async def status_text() -> str:
    up = uptime()
    l1, l5, l15 = os.getloadavg()
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            mem[k] = int(v.split()[0])
    total, avail = mem["MemTotal"] / 1024, mem["MemAvailable"] / 1024
    du = shutil.disk_usage("/")
    try:
        proc = await asyncio.create_subprocess_exec(
            "loginctl", "list-sessions", "--no-legend", "--no-pager",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        sessions = out.decode(errors="replace").strip() or "нет"
    except FileNotFoundError:
        sessions = "loginctl недоступен"
    return "\n".join([
        f"📊 <b>{E(SERVER_NAME)}</b>",
        f"⏱ Аптайм: {fmt_dur(up)} (загрузка {fmt_time(time.time() - up)})",
        f"⚙️ Load: {l1:.2f} / {l5:.2f} / {l15:.2f} (ядер: {os.cpu_count()})",
        f"🧠 RAM: {total - avail:.0f} / {total:.0f} МБ",
        f"💾 /: {du.used / 2**30:.1f} / {du.total / 2**30:.1f} ГБ",
        "",
        "👥 Активные сессии:",
        f"<pre>{E(sessions[:2500])}</pre>",
    ])


async def do_reboot(notifier: Notifier) -> None:
    await asyncio.sleep(3)  # даём Telegram доставить ответ
    proc = await asyncio.create_subprocess_exec(
        "systemctl", "reboot", stderr=asyncio.subprocess.PIPE
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        await notifier.send(f"❗️ Перезагрузка не удалась:\n<pre>{E(err.decode(errors='replace')[:1000])}</pre>")


# ───────────────────────── обработчики ─────────────────────────
dp = Dispatcher()
# Всё, что пишут не админы, молча игнорируется
dp.message.filter(F.from_user.id.in_(ADMIN_IDS))
dp.callback_query.filter(F.from_user.id.in_(ADMIN_IDS))


@dp.message(CommandStart())
@dp.message(Command("help"))
async def cmd_start(m: Message) -> None:
    await m.answer(
        f"Слежу за входами на <code>{E(SERVER_NAME)}</code>: SSH, консоль, su, sudo.\n\n"
        "/status — состояние сервера\n/stats — попытки входа за 24 ч\n/reboot — перезагрузка",
        reply_markup=MAIN_KB,
    )


@dp.message(Command("status"))
@dp.message(F.text == BTN_STATUS)
async def cmd_status(m: Message) -> None:
    await m.answer(await status_text(), reply_markup=MAIN_KB)


@dp.message(Command("stats"))
@dp.message(F.text == BTN_STATS)
async def cmd_stats(m: Message) -> None:
    await m.answer(await build_report(24), reply_markup=MAIN_KB)


CONFIRM_TEXT = "⚠️ Перезагрузить <code>{}</code>?\nПодтверждение действует {} с."


@dp.message(Command("reboot"))
@dp.message(F.text == BTN_REBOOT)
async def cmd_reboot(m: Message) -> None:
    await m.answer(CONFIRM_TEXT.format(E(SERVER_NAME), REBOOT_CONFIRM_TTL), reply_markup=confirm_kb())


@dp.callback_query(F.data == "reboot:ask")
async def cb_reboot_ask(c: CallbackQuery) -> None:
    await c.message.answer(CONFIRM_TEXT.format(E(SERVER_NAME), REBOOT_CONFIRM_TTL), reply_markup=confirm_kb())
    await c.answer()


@dp.callback_query(F.data == "reboot:no")
async def cb_reboot_no(c: CallbackQuery) -> None:
    await c.message.edit_text("Перезагрузка отменена.")
    await c.answer()


@dp.callback_query(F.data.startswith("reboot:yes:"))
async def cb_reboot_yes(c: CallbackQuery, notifier: Notifier) -> None:
    ts = int(c.data.rsplit(":", 1)[1])
    boot_time = time.time() - uptime()
    if time.time() - ts > REBOOT_CONFIRM_TTL or ts < boot_time:
        await c.message.edit_text("⌛ Подтверждение устарело — нажмите «Перезагрузка» ещё раз.")
        await c.answer()
        return
    u = c.from_user
    log.warning("Перезагрузку запросил %s (id %s, @%s)", u.full_name, u.id, u.username)
    await c.message.edit_text(f"🔄 Перезагружаю <code>{E(SERVER_NAME)}</code>… Напишу, когда поднимется.")
    await c.answer("Перезагрузка…")
    await notifier.send(f"🔄 Перезагрузку <code>{E(SERVER_NAME)}</code> запросил {E(u.full_name)} (id {u.id})", exclude=u.id)
    asyncio.create_task(do_reboot(notifier))


# ───────────────────────── запуск ─────────────────────────
async def consumer(queue: asyncio.Queue, notifier: Notifier) -> None:
    while True:
        ev = await queue.get()
        try:
            await notifier.handle(ev)
        except Exception:
            log.exception("Ошибка обработки события")


async def main() -> None:
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML", link_preview_is_disabled=True))
    notifier = Notifier(bot)
    queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)

    tasks = [
        asyncio.create_task(journal_reader(queue)),
        asyncio.create_task(consumer(queue, notifier)),
    ]

    # Сбрасываем накопившиеся апдейты, чтобы старая кнопка ребута не сработала после загрузки
    await bot.delete_webhook(drop_pending_updates=True)
    await bot.set_my_commands([
        BotCommand(command="status", description="Состояние сервера"),
        BotCommand(command="stats", description="Попытки входа за 24 ч"),
        BotCommand(command="reboot", description="Перезагрузить сервер"),
    ])

    up = uptime()
    if up < 600:
        hello = f"🟢 Сервер <code>{E(SERVER_NAME)}</code> загрузился ({fmt_dur(up)} назад)"
    else:
        hello = f"🤖 Бот запущен на <code>{E(SERVER_NAME)}</code>"
    await notifier.send(hello, reply_markup=MAIN_KB)

    try:
        await dp.start_polling(bot, notifier=notifier)
    finally:
        for t in tasks:
            t.cancel()
        try:
            await asyncio.wait_for(notifier.send(f"🔴 Бот на <code>{E(SERVER_NAME)}</code> остановлен"), 5)
        except Exception:
            pass
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
