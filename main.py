#!/usr/bin/env python3
"""MAX-бот: фото из чата → photo-inbox optical (source=max)."""

from __future__ import annotations

import logging
import os
import re
import ssl
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("max-photo-bot")

BOT_VERSION = "3"
_ROOT = Path(__file__).resolve().parent
_DEFAULT_CA_BUNDLE = _ROOT / "certs" / "russian_trusted_ca_bundle.pem"
DEFAULT_CHAT_ID = "-73114090287804"

API_BASE = (os.environ.get("MAX_API_BASE") or "https://platform-api2.max.ru").rstrip("/")
BOT_TOKEN = (os.environ.get("BOT_TOKEN") or os.environ.get("MAX_BOT_TOKEN") or "").strip()
PHOTO_INBOX_URL = (
    os.environ.get("PHOTO_INBOX_URL") or "http://base.401010.ru/api/photo-inbox"
).strip()
PHOTO_INBOX_TOKEN = (os.environ.get("PHOTO_INBOX_TOKEN") or "").strip()
REPLY_ON_SUCCESS = (os.environ.get("REPLY_ON_SUCCESS") or "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
SHOW_IDS_IN_REPLY = (os.environ.get("SHOW_IDS_IN_REPLY") or "0").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT_SEC") or "60")
POLL_TIMEOUT = int(os.environ.get("POLL_TIMEOUT_SEC") or "30")
POLL_LIMIT = int(os.environ.get("POLL_LIMIT") or "100")
# SSL для platform-api2.max.ru (сертификат Минцифры). По умолчанию — бандл в certs/.
# SSL_VERIFY=0 — отключить проверку (крайний случай).
# SSL_CA_BUNDLE=/path/to.pem — свой бандл.
SSL_VERIFY_RAW = (os.environ.get("SSL_VERIFY") or "1").strip().lower()
SSL_CA_BUNDLE = (os.environ.get("SSL_CA_BUNDLE") or "").strip()

_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic"}
_ID_REQUEST_RE = re.compile(
    r"(?i)^\s*/?(?:chat_?id|where|id|start|help)(?:@\w+)?\s*$"
    r"|^\s*chat\s*id\s*$"
    r"|^\s*айди\s*$"
)
_SSL_VERIFY: ssl.SSLContext | bool | str = True


def _parse_id_set(raw: str) -> set[str]:
    out: set[str] = set()
    for part in (raw or "").replace(";", ",").split(","):
        item = part.strip()
        if item:
            out.add(item)
    return out


# Пустой ALLOWED_CHAT_IDS в env → дефолтный рабочий чат; "*" или "all" → все чаты.
_allowed_raw = (os.environ.get("ALLOWED_CHAT_IDS") or DEFAULT_CHAT_ID).strip()
if _allowed_raw.lower() in {"*", "all", "any"}:
    ALLOWED_CHAT_IDS: set[str] = set()
else:
    ALLOWED_CHAT_IDS = _parse_id_set(_allowed_raw)


def _require_env() -> None:
    missing = [
        n
        for n, v in (
            ("BOT_TOKEN", BOT_TOKEN),
            ("PHOTO_INBOX_TOKEN", PHOTO_INBOX_TOKEN),
            ("PHOTO_INBOX_URL", PHOTO_INBOX_URL),
        )
        if not v
    ]
    if missing:
        logger.error("Не заданы переменные окружения: %s", ", ".join(missing))
        sys.exit(1)


def _build_ssl_verify() -> ssl.SSLContext | bool | str:
    """TLS для MAX API: системные CA + сертификаты Минцифры из бандла."""
    if SSL_VERIFY_RAW in {"0", "false", "no", "off"}:
        logger.warning("SSL_VERIFY=0 — проверка сертификатов отключена")
        return False

    ca_path = Path(SSL_CA_BUNDLE) if SSL_CA_BUNDLE else _DEFAULT_CA_BUNDLE
    if not ca_path.is_file():
        logger.warning(
            "CA bundle не найден (%s) — обычная проверка SSL (может упасть на Минцифре)",
            ca_path,
        )
        return True

    # Bothost/Windows могут отдать CRLF — OpenSSL ждёт LF в PEM.
    raw = ca_path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=raw.decode("ascii"))
    logger.info("SSL: системные CA + %s", ca_path.name)
    return ctx


def _http_client(**kwargs: Any) -> httpx.Client:
    kwargs.setdefault("verify", _SSL_VERIFY)
    return httpx.Client(**kwargs)


def _auth_headers() -> dict[str, str]:
    return {"Authorization": BOT_TOKEN}


def _sender_name(sender: dict[str, Any] | None) -> str:
    if not sender:
        return ""
    name = (sender.get("name") or "").strip()
    if not name:
        first = (sender.get("first_name") or "").strip()
        last = (sender.get("last_name") or "").strip()
        name = f"{first} {last}".strip()
    username = (sender.get("username") or "").strip()
    if username:
        name = f"{name} @{username}".strip()
    return name[:255]


def _chat_id_from_message(message: dict[str, Any]) -> str | None:
    recipient = message.get("recipient") or {}
    chat_id = recipient.get("chat_id")
    if chat_id is not None:
        return str(chat_id)
    # Диалог: иногда chat_id нет, есть user_id получателя
    user_id = recipient.get("user_id")
    if user_id is not None:
        return str(user_id)
    return None


def _message_id(message: dict[str, Any]) -> str:
    body = message.get("body") or {}
    mid = body.get("mid") or message.get("mid") or ""
    return str(mid)


def _message_text(message: dict[str, Any]) -> str:
    body = message.get("body") or {}
    return str(body.get("text") or "").strip()


def _is_allowed_chat(chat_id: str | None) -> bool:
    if not ALLOWED_CHAT_IDS:
        return True
    return chat_id is not None and chat_id in ALLOWED_CHAT_IDS


def _ids_block(chat_id: str | None) -> str:
    lines = [
        f"chat_id={chat_id if chat_id is not None else '—'}",
        f"ALLOWED_CHAT_IDS={chat_id if chat_id is not None else ''}",
        f"bot_v{BOT_VERSION}",
    ]
    return "\n".join(lines)


def _guess_filename(url: str, fallback: str) -> str:
    path = urlparse(url).path
    base = os.path.basename(path) if path else ""
    if base and "." in base:
        return base[:200]
    return fallback


def _looks_like_image(att: dict[str, Any]) -> bool:
    att_type = str(att.get("type") or "").lower()
    if att_type in {"image", "photo"}:
        return True
    if att_type not in {"file", "share"}:
        return False
    payload = att.get("payload") or {}
    mime = str(payload.get("mime_type") or payload.get("mime") or "").lower()
    if mime.startswith("image/"):
        return True
    name = str(payload.get("file_name") or payload.get("filename") or "").lower()
    ext = os.path.splitext(name)[1]
    return ext in _IMAGE_EXTS


def _image_attachments(message: dict[str, Any]) -> list[dict[str, Any]]:
    body = message.get("body") or {}
    attachments = body.get("attachments") or []
    if not isinstance(attachments, list):
        return []
    out: list[dict[str, Any]] = []
    for att in attachments:
        if isinstance(att, dict) and _looks_like_image(att):
            out.append(att)
    return out


def _attachment_url(att: dict[str, Any]) -> str | None:
    payload = att.get("payload") or {}
    url = payload.get("url") or att.get("url")
    if isinstance(url, str) and url.startswith(("http://", "https://")):
        return url
    return None


def _attachment_unique_id(att: dict[str, Any], message_id: str, index: int) -> str:
    payload = att.get("payload") or {}
    for key in ("photo_id", "id", "token", "file_id"):
        val = payload.get(key)
        if val not in (None, "", 0):
            return f"max:{val}"
    return f"max:{message_id}:{index}"


def max_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    with _http_client(timeout=HTTP_TIMEOUT + POLL_TIMEOUT + 5) as client:
        resp = client.get(
            f"{API_BASE}{path}",
            headers=_auth_headers(),
            params=params or {},
        )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected response: {data!r}"[:300])
    return data


def max_post_json(path: str, *, params: dict[str, Any] | None = None, body: dict[str, Any]) -> dict[str, Any]:
    with _http_client(timeout=HTTP_TIMEOUT) as client:
        resp = client.post(
            f"{API_BASE}{path}",
            headers={**_auth_headers(), "Content-Type": "application/json"},
            params=params or {},
            json=body,
        )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected response: {data!r}"[:300])
    return data


def send_message(chat_id: str, text: str) -> None:
    try:
        max_post_json(
            "/messages",
            params={"chat_id": chat_id},
            body={"text": text[:4000]},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("send_message failed chat=%s: %s", chat_id, exc)


def download_bytes(url: str) -> bytes:
    with _http_client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        resp = client.get(url, headers=_auth_headers())
        if resp.status_code >= 400:
            # Часть CDN-ссылок не требует Authorization
            resp = client.get(url)
        resp.raise_for_status()
        return bytes(resp.content)


def upload_to_inbox(
    *,
    data: bytes,
    filename: str,
    chat_id: str,
    message_id: str,
    file_unique_id: str,
    sender_id: str,
    sender_name: str,
    caption: str,
) -> dict[str, Any]:
    url = PHOTO_INBOX_URL
    if "token=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}token={PHOTO_INBOX_TOKEN}"

    files = {"file": (filename, data, "application/octet-stream")}
    form = {
        "source": "max",
        "chat_id": chat_id,
        "message_id": message_id,
        "file_unique_id": file_unique_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "caption": caption,
    }
    with httpx.Client(timeout=HTTP_TIMEOUT) as client:
        resp = client.post(url, data=form, files=files)
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        payload = {"ok": False, "message": (resp.text or "")[:300]}
    if not isinstance(payload, dict):
        payload = {"ok": False, "message": str(payload)[:300]}
    payload.setdefault("status", resp.status_code)
    if resp.status_code >= 400:
        payload["ok"] = False
        payload.setdefault("message", f"HTTP {resp.status_code}")
    return payload


def handle_command(chat_id: str, text: str) -> bool:
    low = text.lower().strip()
    if low in {"/start", "/help", "start", "help"} or low.startswith(("/start@", "/help@")):
        allow = ",".join(sorted(ALLOWED_CHAT_IDS)) if ALLOWED_CHAT_IDS else "(все чаты)"
        send_message(
            chat_id,
            f"Бот фото заказов MAX v{BOT_VERSION}\n"
            f"Слушает: ALLOWED_CHAT_IDS={allow}\n"
            "Фото/картинки → инбокс optical (source=max)\n"
            "/chatid — показать id чата",
        )
        return True
    if _ID_REQUEST_RE.search(text) or low.startswith(("/chatid", "/chat_id", "/id", "/where")):
        send_message(chat_id, _ids_block(chat_id))
        return True
    return False


def process_message_created(update: dict[str, Any]) -> None:
    message = update.get("message") or {}
    if not isinstance(message, dict):
        return

    chat_id = _chat_id_from_message(message)
    text = _message_text(message)
    mid = _message_id(message)

    if chat_id and text and handle_command(chat_id, text):
        return

    if not _is_allowed_chat(chat_id):
        logger.info("Skip chat=%s (not in allowlist)", chat_id)
        return

    images = _image_attachments(message)
    if not images:
        return
    if chat_id is None:
        logger.warning("Image without chat_id, skip mid=%s", mid)
        return

    sender = message.get("sender") if isinstance(message.get("sender"), dict) else None
    sender_id = str((sender or {}).get("user_id") or "")
    sender_name = _sender_name(sender)
    caption = text

    ok_any = False
    last_error = ""
    last_id = ""
    last_dup = False

    for idx, att in enumerate(images):
        url = _attachment_url(att)
        if not url:
            logger.warning("Image without url mid=%s idx=%s", mid, idx)
            continue
        uid = _attachment_unique_id(att, mid, idx)
        filename = _guess_filename(url, f"{uid}.jpg")
        try:
            data = download_bytes(url)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Download failed mid=%s", mid)
            last_error = str(exc)
            continue
        try:
            result = upload_to_inbox(
                data=data,
                filename=filename,
                chat_id=chat_id,
                message_id=mid or str(message.get("timestamp") or ""),
                file_unique_id=uid,
                sender_id=sender_id,
                sender_name=sender_name,
                caption=caption,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Upload failed mid=%s", mid)
            last_error = str(exc)
            continue

        if result.get("ok"):
            ok_any = True
            last_id = str(result.get("id") or "")
            last_dup = bool(result.get("duplicate"))
            logger.info(
                "Inbox ok chat=%s mid=%s duplicate=%s id=%s",
                chat_id,
                mid,
                last_dup,
                last_id,
            )
        else:
            last_error = str(result.get("message") or "ошибка")
            logger.warning("Inbox reject: %s", last_error)

    if ok_any:
        if REPLY_ON_SUCCESS or SHOW_IDS_IN_REPLY:
            if last_dup:
                reply = "Уже было в инбоксе"
            elif last_id:
                reply = f"Готово · {last_id[:8]}"
            else:
                reply = "Готово"
            if SHOW_IDS_IN_REPLY:
                reply += "\n" + _ids_block(chat_id)
            send_message(chat_id, reply)
        return

    if last_error:
        send_message(chat_id, f"Не принято: {last_error}"[:400])


def process_update(update: dict[str, Any]) -> None:
    update_type = update.get("update_type") or update.get("type")
    if update_type == "message_created":
        process_message_created(update)
        return
    logger.debug("Ignore update_type=%s", update_type)


def poll_loop() -> None:
    marker: int | None = None
    logger.info(
        "Starting MAX photo bot v%s → %s | allow=%s | api=%s",
        BOT_VERSION,
        PHOTO_INBOX_URL,
        ",".join(sorted(ALLOWED_CHAT_IDS)) or "(all)",
        API_BASE,
    )
    while True:
        params: dict[str, Any] = {
            "limit": POLL_LIMIT,
            "timeout": POLL_TIMEOUT,
            "types": "message_created",
        }
        if marker is not None:
            params["marker"] = marker
        try:
            data = max_get("/updates", params=params)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            body = (exc.response.text or "")[:300] if exc.response is not None else ""
            logger.error("GET /updates HTTP %s: %s", code, body)
            if code == 401:
                sys.exit(1)
            time.sleep(5)
            continue
        except Exception as exc:  # noqa: BLE001
            logger.error("GET /updates failed: %s", exc)
            time.sleep(5)
            continue

        next_marker = data.get("marker")
        if next_marker is not None:
            try:
                marker = int(next_marker)
            except (TypeError, ValueError):
                pass

        updates = data.get("updates") or []
        if not isinstance(updates, list):
            continue
        for upd in updates:
            if not isinstance(upd, dict):
                continue
            try:
                process_update(upd)
            except Exception:  # noqa: BLE001
                logger.exception("process_update failed")


def main() -> None:
    global _SSL_VERIFY
    _require_env()
    _SSL_VERIFY = _build_ssl_verify()
    poll_loop()


if __name__ == "__main__":
    main()
