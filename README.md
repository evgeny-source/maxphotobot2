# optical-max-photo-bot

MAX-бот: сидит в чате, забирает фото заказов и отправляет в инбокс optical
(`POST /api/photo-inbox`, `source=max`). Сохраняются **кто отправил** и **текст/подпись**.

Аналог [optical-telegram-photo-bot](https://github.com/evgeny-source/ozordersfotobot), но для мессенджера MAX.

## SSL / сертификат Минцифры

`platform-api2.max.ru` подписан УЦ Минцифры. В репозитории лежит бандл
`certs/russian_trusted_ca_bundle.pem` — бот подмешивает его к системным CA
автоматически. Если проверка всё равно падает: `SSL_VERIFY=0` (временный обход).

## Что принимает

- Вложения `type=image` (и файлы-картинки)
- Текст сообщения → поле `caption` в инбоксе
- Автор → `sender_id` + `sender_name`

## Фильтр чата

По умолчанию бот слушает только:

- `chat_id=-73114090287804`

Переопределение: `ALLOWED_CHAT_IDS`. Чтобы принимать из всех чатов: `ALLOWED_CHAT_IDS=*`.

На успех бот отвечает текстом «Готово» (реакции у MAX Bot API для этого сценария
не используем). Отключить: `REPLY_ON_SUCCESS=0`.

## Важно для групп / каналов

Чтобы получать события из группового чата или канала, бот должен быть
**администратором**. Иначе `GET /updates` не отдаст `message_created` из группы.

Документация: [dev.max.ru/docs-api](https://dev.max.ru/docs-api),
[GET /updates](https://dev.max.ru/docs-api/methods/GET/updates).

Если на боте уже висит **Webhook**, long polling не работает — снимите подписку
в кабинете / через API `DELETE /subscriptions`.

## Токен

1. Верифицируйте профиль в «MAX для бизнеса» / партнёрской платформе.
2. Создайте чат-бота, дождитесь модерации при необходимости.
3. Токен: расширенные настройки бота или команда «Получить токен» в боте «MAX для бизнеса».
4. В запросах — заголовок `Authorization: {token}` (не query).

## Локальный запуск

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
# заполните BOT_TOKEN и PHOTO_INBOX_TOKEN
```

PowerShell:

```powershell
Get-Content .env | ForEach-Object {
  if ($_ -match '^\s*#' -or $_ -notmatch '=') { return }
  $k,$v = $_.Split('=',2); Set-Item -Path "env:$k" -Value $v.Trim()
}
python main.py
```

## Деплой на [Bothost](https://bothost.ru/docs/)

1. Залейте репозиторий на GitHub.
2. Bothost → **Создать бота** → репозиторий.
3. **Главный файл:** `main.py`.
4. Зависимости из `requirements.txt`.
5. Режим: **long polling** (отдельный HTTPS-домен не нужен).
6. Переменные:

| Переменная | Значение |
|---|---|
| `BOT_TOKEN` | токен MAX-бота |
| `PHOTO_INBOX_URL` | `http://base.401010.ru/api/photo-inbox` |
| `PHOTO_INBOX_TOKEN` | тот же, что на сервере optical |
| `ALLOWED_CHAT_IDS` | `-73114090287804` (или свой id / `*` для всех) |
| `REPLY_ON_SUCCESS` | `1` или `0` |

7. Добавьте бота в рабочий чат как **админа**, отправьте тестовое фото.
8. Инбокс: https://base.401010.ru/photo-inbox — источник `max`.

## Поток

```text
MAX chat  →  этот бот (Bothost, GET /updates)
          →  скачать image payload.url
          →  POST multipart /api/photo-inbox?token=… (source=max)
          →  optical photo-inbox
```

## Команды

- `/start` — справка
- `/chatid` — показать `chat_id` для `ALLOWED_CHAT_IDS`
