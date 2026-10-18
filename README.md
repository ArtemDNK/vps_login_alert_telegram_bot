# VPS Login Alert Telegram Bot

Telegram-бот для сервера на Debian 13. Сразу сообщает о входах на сервер, а также умеет показывать его состояние и перезагружать по кнопке.

## Возможности

**Мгновенные уведомления:**
- ✅ успешный вход по SSH: пользователь, IP, метод (ключ или пароль);
- ✅ / ⛔ вход и неудачная попытка в локальной консоли (tty, VNC-консоль хостера);
- ✅ / ⛔ `su`;
- ⛔ `sudo`: неверный пароль, «user NOT in sudoers». По желанию можно получать каждую команду sudo.

Неудачные попытки SSH (брутфорс) **не присылаются автоматически**, чтобы не засорять чат. Они доступны по кнопке.

**Кнопки:**
| Кнопка | Что делает |
|---|---|
| 📊 Статус | аптайм, load average, RAM, диск, активные сессии |
| 🛡 Попытки входа | сводка из журнала за 24 ч: успешные и неудачные входы по источникам, топ-20 IP брутфорса с подбираемыми логинами |
| 🔄 Перезагрузка | `systemctl reboot` с подтверждением, которое действует 60 с |

Под каждым уведомлением об успешном входе есть кнопка «🔄 Перезагрузить сервер». После загрузки бот сообщает, что сервер поднялся.

События читаются из **systemd-journald** (facility `auth`/`authpriv`), поэтому rsyslog и `/var/log/auth.log` не нужны. Сводка строится прямо из журнала и не теряется при перезапуске бота или сервера.

## Требования

- Debian 13 (подойдут и другие дистрибутивы с systemd)
- Python 3.10+
- root-доступ: он нужен для чтения журнала auth и перезагрузки

## Установка

### 1. Создайте бота и узнайте свой ID

1. В Telegram откройте [@BotFather](https://t.me/BotFather), отправьте `/newbot` и сохраните полученный токен.
2. Узнайте свой числовой ID, например у [@userinfobot](https://t.me/userinfobot).
3. Откройте своего нового бота и нажмите **Start**. Без этого Telegram не даст боту писать вам первым.

### 2. Установите бота на сервер

Все команды выполняются от root:

```bash
apt update && apt install -y git python3-venv

git clone https://github.com/ArtemDNK/vps_login_alert_telegram_bot.git /opt/vps_login_alert_telegram_bot
cd /opt/vps_login_alert_telegram_bot

python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

### 3. Настройте `.env`

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

| Переменная | Описание |
|---|---|
| `BOT_TOKEN` | токен от @BotFather |
| `ADMIN_IDS` | ваш Telegram ID. Несколько ID указываются через запятую. Только эти пользователи получают уведомления и могут перезагружать сервер |
| `SERVER_NAME` | имя сервера в сообщениях (необязательно, по умолчанию hostname) |
| `NOTIFY_SUDO_COMMANDS` | `1`, чтобы присылать каждую команду, выполненную через sudo (по умолчанию `0`) |

### 4. Запустите как службу

```bash
cp vps-login-alert-bot.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vps-login-alert-bot
```

Проверьте, что бот работает:

```bash
systemctl status vps-login-alert-bot
journalctl -u vps-login-alert-bot -f
```

В Telegram должно прийти сообщение «🤖 Бот запущен».

### 5. Проверка

Можно сымитировать события, не входя на сервер по-настоящему:

```bash
logger -t sshd -p auth.info "Accepted publickey for root from 203.0.113.5 port 4242 ssh2"
logger -t sshd -p auth.info "Failed password for invalid user admin from 198.51.100.7 port 5555 ssh2"
```

Первое событие сразу придёт уведомлением. Второе появится в сводке по кнопке «🛡 Попытки входа».

## Обновление

```bash
cd /opt/vps_login_alert_telegram_bot
git pull
venv/bin/pip install -U -r requirements.txt
systemctl restart vps-login-alert-bot
```

## Удаление

```bash
systemctl disable --now vps-login-alert-bot
rm /etc/systemd/system/vps-login-alert-bot.service
systemctl daemon-reload
rm -rf /opt/vps_login_alert_telegram_bot
```

## Безопасность

- Сообщения и нажатия кнопок от пользователей, которых нет в `ADMIN_IDS`, молча игнорируются.
- Перезагрузка требует подтверждения. Кнопка подтверждения перестаёт работать через 60 секунд и после перезагрузки сервера.
- При старте бот сбрасывает накопившиеся апдейты Telegram, поэтому старое нажатие не вызовет повторную перезагрузку.
- Имена пользователей в попытках входа задаёт атакующий, поэтому весь текст в сообщениях экранируется.
- Служба работает от root с ограничениями systemd: `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`.
- Файл `.env` с токеном закрыт правами `600` и исключён из git.

## Если что-то не работает

- **Бот молчит при входе.** Проверьте, что журнал видит события: `journalctl -f SYSLOG_FACILITY=4 SYSLOG_FACILITY=10`, затем войдите по SSH из другого окна.
- **Бот не пишет совсем.** Проверьте `BOT_TOKEN` и `ADMIN_IDS` и убедитесь, что нажали Start у бота. Ошибки смотрите в `journalctl -u vps-login-alert-bot`.
- **Сводка показывает меньше 24 ч.** Значит, журнал не сохраняется между перезагрузками. Включите постоянное хранение: `mkdir -p /var/log/journal && systemctl restart systemd-journald`.
