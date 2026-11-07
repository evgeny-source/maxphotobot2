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

BOT_VERSION = "6"
_ROOT = Path(__file__).resolve().parent
_DEFAULT_CA_BUNDLE = _ROOT / "certs" / "russian_trusted_ca_bundle.pem"
DEFAULT_CHAT_ID = "-73114090287804"
INBOX_ORIGIN = "https://ostroeclub.ru"

API_BASE = (os.environ.get("MAX_API_BASE") or "https://platform-api2.max.ru").rstrip("/")
BOT_TOKEN = (os.environ.get("BOT_TOKEN") or os.environ.get("MAX_BOT_TOKEN") or "").strip()
_PHOTO_INBOX_URL_RAW = (
    os.environ.get("PHOTO_INBOX_URL") or f"{INBOX_ORIGIN}/api/photo-inbox"
).strip()
PHOTO_INBOX_TOKEN = (os.environ.get("PHOTO_INBOX_TOKEN") or "").strip()
REPLY_ON_SUCCESS = (os.environ.get("REPLY_ON_SUCCESS") or "0").strip().lower() not in {
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
ERROR_REPLY_TEXT = (
    os.environ.get("ERROR_REPLY_TEXT") or "ошибка, загрузка не удалась."
).strip() or "ошибка, загрузка не удалась."


def _env_float(name: str, default: str) -> float:
    raw = (os.environ.get(name) or default).strip()
    try:
        return float(raw)
    except ValueError:
        logger.warning("Некорректное %s=%r, использую %s", name, raw, default)
        return float(default)


def _env_int(name: str, default: str) -> int:
    raw = (os.environ.get(name) or default).strip()
    try:
        return int(raw)
    except ValueError:
        logger.warning("Некорректное %s=%r, использую %s", name, raw, default)
        return int(default)


_LEGACY_HTTP_TIMEOUT = (os.environ.get("HTTP_TIMEOUT_SEC") or "120").strip()
HTTP_CONNECT_TIMEOUT = _env_float("HTTP_CONNECT_TIMEOUT_SEC", "15")
HTTP_READ_TIMEOUT = _env_float("HTTP_READ_TIMEOUT_SEC", _LEGACY_HTTP_TIMEOUT)
HTTP_WRITE_TIMEOUT = _env_float("HTTP_WRITE_TIMEOUT_SEC", _LEGACY_HTTP_TIMEOUT)
HTTP_RETRY_COUNT = max(1, _env_int("HTTP_RETRY_COUNT", "3"))
HTTP_RETRY_BACKOFF = max(0.0, _env_float("HTTP_RETRY_BACKOFF_SEC", "2"))
HEALTH_CHECK_SEC = max(0.0, _env_float("HEALTH_CHECK_SEC", "300"))
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


def _redact_url(url: str) -> str:
    return re.sub(r"(token=)[^&]+", r"\1***", url, flags=re.IGNORECASE)


def _normalize_inbox_url(url: str) -> str:
    """Старый хост base.401010.ru и http://ostroeclub.ru → https://ostroeclub.ru."""
    raw = (url or "").strip() or f"{INBOX_ORIGIN}/api/photo-inbox"
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if host not in {
        "base.401010.ru",
        "www.base.401010.ru",
        "ostroeclub.ru",
        "www.ostroeclub.ru",
    }:
        return raw
    path = parsed.path or "/api/photo-inbox"
    if path in {"", "/"}:
        path = "/api/photo-inbox"
    query = f"?{parsed.query}" if parsed.query else ""
    rewritten = f"{INBOX_ORIGIN}{path}{query}"
    if rewritten != raw:
        logger.warning(
            "PHOTO_INBOX_URL %s заменён на %s",
            _redact_url(raw),
            _redact_url(rewritten),
        )
    return rewritten


PHOTO_INBOX_URL = _normalize_inbox_url(_PHOTO_INBOX_URL_RAW)


def _inbox_timeout() -> httpx.Timeout:
    return httpx.Timeout(
        connect=HTTP_CONNECT_TIMEOUT,
        read=HTTP_READ_TIMEOUT,
        write=HTTP_WRITE_TIMEOUT,
        pool=HTTP_CONNECT_TIMEOUT,
    )


def _retryable_status(code: int) -> bool:
    return code in {408, 425, 429, 500, 502, 503, 504}


def _retryable_exc(exc: BaseException) -> bool:
    return isinstance(
        exc,
        (
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.NetworkError,
            httpx.RemoteProtocolError,
        ),
    )


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
    with _http_client(timeout=HTTP_READ_TIMEOUT + POLL_TIMEOUT + 5) as client:
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
    with _http_client(timeout=_inbox_timeout()) as client:
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


def send_message(
    chat_id: str,
    text: str,
    *,
    reply_to_mid: str | None = None,
) -> None:
    body: dict[str, Any] = {"text": text[:4000]}
    if reply_to_mid:
        body["link"] = {"type": "reply", "mid": reply_to_mid}
    try:
        max_post_json(
            "/messages",
            params={"chat_id": chat_id},
            body=body,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("send_message failed chat=%s: %s", chat_id, exc)


def reply_upload_error(chat_id: str, mid: str) -> None:
    send_message(chat_id, ERROR_REPLY_TEXT, reply_to_mid=mid or None)


def download_bytes(url: str) -> bytes:
    last_exc: BaseException | None = None
    for attempt in range(1, HTTP_RETRY_COUNT + 1):
        try:
            with _http_client(timeout=_inbox_timeout(), follow_redirects=True) as client:
                resp = client.get(url, headers=_auth_headers())
                if resp.status_code >= 400:
                    # Часть CDN-ссылок не требует Authorization
                    resp = client.get(url)
                resp.raise_for_status()
                return bytes(resp.content)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if _retryable_exc(exc) and attempt < HTTP_RETRY_COUNT:
                logger.warning(
                    "Download retry attempt=%s/%s err=%s",
                    attempt,
                    HTTP_RETRY_COUNT,
                    exc,
                )
                time.sleep(HTTP_RETRY_BACKOFF * attempt)
                continue
            raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("download failed")


def _parse_inbox_response(resp: httpx.Response) -> dict[str, Any]:
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
    size_kb = len(data) / 1024
    log_ctx = (
        f"chat={chat_id} mid={message_id} uid={file_unique_id} "
        f"file={filename!r} size={size_kb:.1f}KiB url={_redact_url(url)}"
    )
    last_exc: BaseException | None = None
    last_status: int | None = None
    for attempt in range(1, HTTP_RETRY_COUNT + 1):
        t0 = time.monotonic()
        logger.info("Upload start attempt=%s/%s %s", attempt, HTTP_RETRY_COUNT, log_ctx)
        try:
            with httpx.Client(timeout=_inbox_timeout()) as client:
                resp = client.post(url, data=form, files=files)
            elapsed = time.monotonic() - t0
            last_status = resp.status_code
            payload = _parse_inbox_response(resp)
            if _retryable_status(resp.status_code) and attempt < HTTP_RETRY_COUNT:
                logger.warning(
                    "Upload HTTP %s attempt=%s elapsed=%.2fs %s",
                    resp.status_code,
                    attempt,
                    elapsed,
                    log_ctx,
                )
                time.sleep(HTTP_RETRY_BACKOFF * attempt)
                continue
            logger.info(
                "Upload done attempt=%s elapsed=%.2fs http=%s ok=%s duplicate=%s id=%s",
                attempt,
                elapsed,
                resp.status_code,
                payload.get("ok"),
                payload.get("duplicate"),
                payload.get("id"),
            )
            return payload
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            elapsed = time.monotonic() - t0
            if _retryable_exc(exc) and attempt < HTTP_RETRY_COUNT:
                logger.warning(
                    "Upload retry attempt=%s/%s elapsed=%.2fs err=%s: %s",
                    attempt,
                    HTTP_RETRY_COUNT,
                    elapsed,
                    exc.__class__.__name__,
                    exc,
                )
                time.sleep(HTTP_RETRY_BACKOFF * attempt)
                continue
            logger.error(
                "Upload failed attempt=%s/%s elapsed=%.2fs err=%s: %s",
                attempt,
                HTTP_RETRY_COUNT,
                elapsed,
                exc.__class__.__name__,
                exc,
            )
            raise
    if last_exc is not None:
        raise last_exc
    return {
        "ok": False,
        "status": last_status or 0,
        "message": f"HTTP {last_status}" if last_status else "upload failed",
    }


def _check_vps_health() -> bool:
    parsed = urlparse(PHOTO_INBOX_URL)
    if not parsed.scheme or not parsed.netloc:
        return False
    probe = f"{parsed.scheme}://{parsed.netloc}/login"
    t0 = time.monotonic()
    try:
        with httpx.Client(
            timeout=httpx.Timeout(connect=10.0, read=10.0, write=10.0, pool=10.0),
            follow_redirects=True,
        ) as client:
            resp = client.get(probe)
        ok = resp.status_code < 500
        logger.info(
            "Health ok=%s probe=%s http=%s elapsed=%.2fs",
            ok,
            probe,
            resp.status_code,
            time.monotonic() - t0,
        )
        return ok
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Health failed probe=%s elapsed=%.2fs err=%s: %s",
            probe,
            time.monotonic() - t0,
            exc.__class__.__name__,
            exc,
        )
        return False


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
            last_error = "no url"
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
        # Успех — без сообщения в чат (REPLY_ON_SUCCESS оставлен для отладки).
        if REPLY_ON_SUCCESS or SHOW_IDS_IN_REPLY:
            if last_dup:
                reply = "Уже было в инбоксе"
            elif last_id:
                reply = f"Готово · {last_id[:8]}"
            else:
                reply = "Готово"
            if SHOW_IDS_IN_REPLY:
                reply += "\n" + _ids_block(chat_id)
            send_message(chat_id, reply, reply_to_mid=mid or None)
        return

    logger.warning("Upload failed chat=%s mid=%s err=%s", chat_id, mid, last_error or "unknown")
    reply_upload_error(chat_id, mid)


def process_update(update: dict[str, Any]) -> None:
    update_type = update.get("update_type") or update.get("type")
    if update_type == "message_created":
        process_message_created(update)
        return
    logger.debug("Ignore update_type=%s", update_type)


def poll_loop() -> None:
    marker: int | None = None
    last_health = 0.0
    logger.info(
        "Starting MAX photo bot v%s → %s | allow=%s | api=%s | retries=%s",
        BOT_VERSION,
        _redact_url(PHOTO_INBOX_URL),
        ",".join(sorted(ALLOWED_CHAT_IDS)) or "(all)",
        API_BASE,
        HTTP_RETRY_COUNT,
    )
    if HEALTH_CHECK_SEC > 0:
        _check_vps_health()
        last_health = time.monotonic()
    while True:
        if HEALTH_CHECK_SEC > 0 and time.monotonic() - last_health >= HEALTH_CHECK_SEC:
            _check_vps_health()
            last_health = time.monotonic()
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
