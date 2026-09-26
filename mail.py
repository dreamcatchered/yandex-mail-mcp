"""mail.py — слой IMAP/SMTP для Яндекс Почты.

Один аккаунт, пароль приложения, никакого OAuth: у Яндекса нет скоупа mail:imap,
поэтому XOAUTH2 для личной почты невозможен (см. yandex.com/dev/id/doc/en).

Соединение открывается на каждый вызов и закрывается сразу: MCP-запросы редкие,
а держать пул IMAP на сервере с 700 МБ RAM незачем.
"""

from __future__ import annotations

import base64
import email
import email.header
import email.utils
import html
import imaplib
import re
import smtplib
import socket
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.policy import default as default_policy

TIMEOUT = 30
IDLE_DROP = 900

# РЇРЅРґРµРєСЃ РѕС‚РґР°С‘С‚ РїР°РїРєРё РїРѕ-СЂСѓСЃСЃРєРё; РїРѕР»РµР·РЅС‹Рµ СЃРёРЅРѕРЅРёРјС‹, С‡С‚РѕР±С‹ РјРѕР¶РЅРѕ Р±С‹Р»Рѕ РїРёСЃР°С‚СЊ folder="inbox"
FOLDER_ALIASES = {
    "inbox": "INBOX",
    "in": "INBOX",
    "входящие": "INBOX",
    "входящие письма": "INBOX",
    "sent": "Sent",
    "отправленные": "Sent",
    "отправленные письма": "Sent",
    "drafts": "Drafts",
    "черновики": "Drafts",
    "черновики писем": "Drafts",
    "trash": "Trash",
    "корзина": "Trash",
    "deleted": "Trash",
    "junk": "Junk",
    "spam": "Junk",
    "спам": "Junk",
    "нежелательная почта": "Junk",
    "archive": "Archive",
    "архив": "Archive",
    "all": "[Gmail]/All Mail",
}

# если имя не подошло, ищем папку по назначению — у Яндекса русские названия
ROLE_ALIASES = {
    "inbox": "inbox", "in": "inbox", "входящие": "inbox", "входящие письма": "inbox",
    "sent": "sent", "отправленные": "sent", "отправленные письма": "sent",
    "drafts": "drafts", "черновики": "drafts", "черновики писем": "drafts",
    "trash": "trash", "deleted": "trash", "корзина": "trash", "удаленные": "trash",
    "junk": "junk", "spam": "junk", "спам": "junk", "нежелательная почта": "junk",
    "archive": "archive", "архив": "archive",
}

_TAG_RE = re.compile(rb"[^\s()\"]+")


def decode_mutf7(raw: str) -> str:
    """modified UTF-7 -> обычный текст (RFC 3501). Яндекс отдаёт так русские папки."""
    if not raw or "&" not in raw:
        return raw
    out, buf, i = [], [], 0
    while i < len(raw):
        char = raw[i]
        if char != "&":
            if buf:
                out.append("".join(buf))
                buf = []
            out.append(char)
            i += 1
            continue
        end = raw.find("-", i + 1)
        if end == -1:
            out.append(raw[i:])
            break
        chunk = raw[i + 1:end]
        if not chunk:
            out.append("&")
        else:
            try:
                b64 = chunk.replace(",", "/")
                b64 += "=" * (-len(b64) % 4)
                out.append(base64.b64decode(b64).decode("utf-16-be"))
            except Exception:  # noqa: BLE001
                out.append(raw[i:end + 1])
        if buf:
            out.append("".join(buf))
            buf = []
        i = end + 1
    if buf:
        out.append("".join(buf))
    return "".join(out)


def encode_mutf7(text: str) -> str:
    """обычный текст -> modified UTF-7 для отправки серверу."""
    out, i = [], 0
    while i < len(text):
        char = text[i]
        if char == "&":
            out.append("&-")
            i += 1
            continue
        if 0x20 <= ord(char) <= 0x7E:
            out.append(char)
            i += 1
            continue
        chunk = ""
        while i < len(text) and not (0x20 <= ord(text[i]) <= 0x7E or text[i] == "&"):
            chunk += text[i]
            i += 1
        b64 = base64.b64encode(chunk.encode("utf-16-be")).decode("ascii").rstrip("=").replace("/", ",")
        out.append("&" + b64 + "-")
    return "".join(out)


class MailError(Exception):
    """Ошибка уровня почты — в MCP уходит как isError, а не как 500."""


def _decode_header(value) -> str:
    """Заголовки RFC 2047 вида =?utf-8?B?...?= -> нормальный текст."""
    if not value:
        return ""
    try:
        parts = email.header.decode_header(str(value))
    except Exception:  # noqa: BLE001
        return str(value)
    out = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            out.append(chunk.decode(charset or "utf-8", "replace"))
        else:
            out.append(chunk)
    return "".join(out).strip()


def _strip_html(raw: str) -> str:
    """Читаемый текст из HTML — для LLM html-исходник бесполезен."""
    raw = re.sub(r"(?is)<(script|style|head)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    raw = re.sub(r"(?i)</(p|div|tr|li|h[1-6])>", "\n", raw)
    raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    raw = html.unescape(raw)
    raw = re.sub(r"[ \t\xa0]+", " ", raw)
    raw = re.sub(r"\n\s*\n\s*\n+", "\n\n", raw)
    return raw.strip()


def _to_text(msg) -> str:
    """Достаёт текст письма: сначала text/plain, иначе HTML -> текст."""
    plain, rich = [], []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition.lower():
                continue
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_content()
            except Exception:  # noqa: BLE001
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = payload.decode(part.get_content_charset() or "utf-8", "replace")
            if not isinstance(payload, str):
                continue
            (plain if ctype == "text/plain" else rich).append(payload)
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:  # noqa: BLE001
            payload = ""
        if isinstance(payload, str):
            (plain if ctype == "text/plain" else rich).append(payload)
    body = "\n".join(plain).strip() or _strip_html("\n".join(rich))
    # IMAP-С†РёС‚Р°С‚Р° (">") РІ РѕС‚РІРµС‚Рµ РїРѕР»РµР·РЅР°: РїРѕ РЅРµР№ РІРёРґРЅРѕ, РЅР° С‡С‚Рѕ РѕС‚РІРµС‡Р°РµРј
    lines = [ln for ln in body.splitlines()]
    trimmed = [ln for ln in lines if not ln.startswith(">")]
    quoted = [ln for ln in lines if ln.startswith(">")]
    out = "\n".join(trimmed).strip()
    if quoted and len(quoted) < 80:
        out = (out + "\n\n--- цитата выше ---\n" + "\n".join(quoted)).strip()
    return out or body


def _addresses(msg, header: str) -> list[str]:
    out: list[str] = []
    for name, addr in email.utils.getaddresses([_decode_header(v) for v in msg.get_all(header, [])]):
        if addr:
            out.append(addr)
        elif name:
            out.append(name)
    return out


def _parse_date(raw) -> str:
    try:
        dt = email.utils.parsedate_to_datetime(str(raw))
    except (TypeError, ValueError):
        return ""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().isoformat(timespec="seconds")


class Mailbox:
    """Один почтовый ящик Яндекса."""

    def __init__(self, address: str, password: str, imap_host="imap.yandex.ru", imap_port=993,
                 smtp_host="smtp.yandex.ru", smtp_port=465, display_name: str = ""):
        self.address = address
        self._password = password
        self.imap_host = imap_host
        self.imap_port = int(imap_port)
        self.smtp_host = smtp_host
        self.smtp_port = int(smtp_port)
        self.display_name = display_name or address
        self._lock = threading.RLock()
        self._box = None
        self._box_at = 0.0
        self.timeout = int(TIMEOUT)
        self.IDLE_DROP = int(IDLE_DROP)

    # ---------- РЅРёР·РєРёР№ СѓСЂРѕРІРµРЅСЊ ----------

    def _connect(self):
        """Живое IMAP-соединение, переиспользуемое между вызовами.

        Яндекс отвечает на приветствие НОВОГО соединения с задержкой — после серии
        частых подключений она доходит до 30 секунд, тогда как все команды после
        LOGIN выполняются за миллисекунды. Поэтому держим одно соединение.
        """
        box = self._box
        if box is not None:
            if time.time() - self._box_at > self.IDLE_DROP:
                self._drop_box()
            else:
                try:
                    box.noop()
                    self._box_at = time.time()
                    return box
                except Exception:  # noqa: BLE001
                    self._drop_box()
        try:
            box = imaplib.IMAP4_SSL(self.imap_host, self.imap_port, timeout=self.timeout)
        except (OSError, imaplib.IMAP4.error) as exc:
            raise MailError(
                f"не удалось подключиться к IMAP {self.imap_host}:{self.imap_port} — {exc}. "
                "Проверь, что в настройках Яндекс Почты включён доступ по IMAP."
            ) from exc
        try:
            box.login(self.address, self._password)
        except imaplib.IMAP4.error as exc:
            self._hard_close(box)
            raise MailError(
                f"IMAP отклонил вход: {exc}. Обычно это неверный пароль приложения — "
                "его можно отозвать и создать заново в id.yandex.ru → Безопасность → Пароли приложений."
            ) from exc
        self._box = box
        self._box_at = time.time()
        return box

    def _select(self, box, wire: str, readonly: bool = True) -> str:
        """Выбирает папку, если не выбрана нужная: лишний SELECT — лишний round-trip."""
        wanted = (wire, readonly)
        if getattr(box, "_ycp_sel", None) == wanted:
            return wire
        typ, _ = box.select(f'"{wire}"', readonly=readonly)
        if typ != "OK":
            raise MailError(f"не удалось открыть папку {wire!r}")
        try:
            box._ycp_sel = wanted
        except AttributeError:
            pass
        return wire

    def _drop_box(self) -> None:
        box, self._box = self._box, None
        if box is not None:
            self._hard_close(box)

    @staticmethod
    def _hard_close(box) -> None:
        try:
            if box.sock is not None:
                box.sock.settimeout(2)
        except Exception:  # noqa: BLE001
            pass
        try:
            box.logout()
        except Exception:  # noqa: BLE001
            pass
        try:
            if box.sock is not None:
                box.sock.close()
        except Exception:  # noqa: BLE001
            pass

    def _resolve(self, box, folder: str) -> str:
        return self._resolve_pair(box, folder)[0]

    def _resolve_pair(self, box, folder: str) -> tuple[str, str]:
        """Возвращает (имя для провода, имя для человека). Яндекс отдаёт modified-UTF7."""
        wanted = (folder or "INBOX").strip()
        if not wanted:
            wanted = "INBOX"
        wanted_norm = wanted.lower()

        available = self._list_folders_raw(box)
        if not available:
            return wanted, wanted

        def pick(pred):
            for wire, name, flags in available:
                if pred(wire, name, flags):
                    return wire, name
            return None

        alias = FOLDER_ALIASES.get(wanted_norm)
        found = (
            pick(lambda w, n, f: n == wanted or w == wanted)
            or pick(lambda w, n, f: n.lower() == wanted_norm or w.lower() == wanted_norm)
            or pick(lambda w, n, f: n.split("}")[-1].lower() == wanted_norm)
            or pick(lambda w, n, f: w.split("}")[-1].lower() == wanted_norm)
        )
        if found is None and alias:
            alias_norm = alias.strip().lower()
            found = (
                pick(lambda w, n, f, a=alias_norm: n.lower() == a or w.lower() == a)
                or pick(lambda w, n, f, a=alias_norm: n.split("}")[-1].lower() == a)
            )
        if found is None:
            # по имени не нашли — ищем по назначению: у Яндекса «Черновики», а не «Drafts»
            wanted_role = ROLE_ALIASES.get(wanted_norm)
            if wanted_role:
                found = pick(lambda w, n, f, r=wanted_role: self._role(n, f) == r)
        if found:
            return found
        raise MailError(
            f"папка {wanted!r} не найдена. Доступные: "
            + ", ".join(name for _, name, _ in available[:40])
            + " (посмотри список папок инструментом list_folders)"
        )

    def _list_folders_raw(self, box) -> list[tuple[str, str, str]]:
        """[(имя для провода, читаемое имя, флаги)] из ответа LIST."""
        typ, rows = box.list()
        if typ != "OK":
            return []
        out: list[tuple[str, str, str]] = []
        for row in rows or []:
            raw = row if isinstance(row, bytes) else str(row).encode()
            m = re.match(rb"\((?P<flags>[^)]*)\)\s+(?P<delim>\S+)\s*(?P<name>.+)$", raw.strip())
            if not m:
                parts = _TAG_RE.findall(raw)
                if not parts:
                    continue
                name_raw, flags = parts[-1], b""
            else:
                name_raw, flags = m.group("name").strip(), m.group("flags")
            if name_raw.startswith(b'"') and name_raw.endswith(b'"'):
                name_raw = name_raw[1:-1]
            for enc in ("utf-8", "cp1251", "latin-1"):
                try:
                    wire = name_raw.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            else:
                wire = name_raw.decode("utf-8", "replace")
            out.append((wire, decode_mutf7(wire).strip(), flags.decode("ascii", "replace")))
        return out

    # ---------- С‡С‚РµРЅРёРµ ----------

    def list_folders(self) -> list[dict]:
        with self._lock:
            box = self._connect()
            try:
                out = [{"name": name, "role": self._role(name, flags), "special":
                        [f for f in flags.split() if f.startswith("\\")]}
                       for _, name, flags in self._list_folders_raw(box)]
                out.sort(key=lambda r: {"inbox": 0, "sent": 1, "drafts": 2,
                                        "trash": 3, "junk": 4, "archive": 5}.get(r["role"], 9))
                return out
            finally:
                self._logout(box)

    @staticmethod
    def _role(name: str, flags: str) -> str:
        low = (name or "").strip().lower().split("}")[-1]
        if "\\inbox" in flags.lower() or low == "inbox":
            return "inbox"
        if "\\sent" in flags.lower() or low in ("sent", "отправленные", "отправленные письма"):
            return "sent"
        if "\\drafts" in flags.lower() or low in ("drafts", "черновики", "черновики писем"):
            return "drafts"
        if "\\trash" in flags.lower() or low in ("trash", "deleted", "корзина"):
            return "trash"
        if "\\junk" in flags.lower() or low in ("junk", "spam", "спам", "нежелательная почта"):
            return "junk"
        if low in ("archive", "архив"):
            return "archive"
        return "other"

    def _status_counts(self, box, folder: str) -> dict:
        counts = {"total": None, "unseen": None}
        try:
            typ, status = box.status(folder, "(MESSAGES UNSEEN)")
            if typ == "OK" and status and status[0]:
                nums = re.findall(rb"(?:MESSAGES|UNSEEN)\s+(\d+)", status[0])
                if len(nums) >= 2:
                    counts["total"], counts["unseen"] = int(nums[0]), int(nums[1])
        except Exception:  # noqa: BLE001
            pass
        return counts

    def _envelope(self, box, uid: str, folder: str) -> dict:
        """Читает письмо через BODY.PEEK[] — флаг \\Seen не выставляется, как побочный эффект чтения."""
        typ, data = box.uid("fetch", uid, "(BODY.PEEK[])")
        if typ != "OK" or not data:
            return {}
        raw = b""
        for chunk in data:
            if isinstance(chunk, tuple):
                raw = chunk[1] or b""
        if not raw:
            return {}
        msg = email.message_from_bytes(raw, policy=default_policy)
        summary = self._summarize(msg, uid, folder, body=_to_text(msg))
        summary["attachments"] = self._attachments_meta(msg)
        return summary

    @staticmethod
    def _attachments_meta(msg) -> list[dict]:
        out = []
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disp = str(part.get("Content-Disposition") or "")
            fname = part.get_filename()
            if not fname and "attachment" not in disp.lower():
                continue
            out.append({
                "filename": _decode_header(fname) if fname else "(без имени)",
                "content_type": part.get_content_type(),
                "size_bytes": len(part.get_payload(decode=True) or b""),
            })
        return out

    def _summarize(self, msg, uid: str, folder: str, body: str | None) -> dict:
        rec = {
            "id": uid,
            "folder": folder,
            "subject": _decode_header(msg.get("Subject")) or "(без темы)",
            "from": _addresses(msg, "From"),
            "from_name": _decode_header(email.utils.parseaddr(_decode_header(msg.get("From", "")))[0]),
            "to": _addresses(msg, "To"),
            "cc": _addresses(msg, "Cc"),
            "date": _parse_date(msg.get("Date")),
            "message_id": _decode_header(msg.get("Message-ID")),
        }
        if body is not None:
            rec["body"] = body
        return rec

    def search_emails(self, query: str = "ALL", folder: str = "INBOX", limit: int = 20,
                      snippet_chars: int = 600) -> list[dict]:
        limit = max(1, min(int(limit or 20), 100))
        criteria = (query or "ALL").strip() or "ALL"
        with self._lock:
            box = self._connect()
            try:
                wire, real = self._resolve_pair(box, folder)
                self._select(box, wire, readonly=True)
                # РєСЂРёС‚РµСЂРёР№ СѓС…РѕРґРёС‚ Р±Р°Р№С‚Р°РјРё UTF-8, РёРЅР°С‡Рµ imaplib СѓРїР°РґС‘С‚ РЅР° РєРёСЂРёР»Р»РёС†Рµ
                crit = criteria.encode("utf-8")
                args = [b"CHARSET UTF-8", crit] if _has_non_ascii(criteria) else [crit]
                typ, data = box.uid("search", None, *args)
                if typ != "OK":
                    raise MailError(
                        f"IMAP отклонил поисковый запрос {criteria!r}. Ожидается синтаксис IMAP: "
                        'ALL, UNSEEN, FROM "a@b.c", SUBJECT "hello", SINCE 01-Dec-2024'
                    )
                uids = [u.decode("ascii", "ignore") for u in (data[0] or b"").split() if u]
                picked = list(reversed(uids[-limit:]))
                out = []
                for uid in picked:
                    rec = self._envelope(box, uid, real)
                    if not rec:
                        continue
                    body = rec.pop("body", "") or ""
                    rec["snippet"] = body[:snippet_chars].strip()
                    out.append(rec)
                return out
            finally:
                self._logout(box)

    def read_email(self, uid: str, folder: str = "INBOX") -> dict:
        with self._lock:
            box = self._connect()
            try:
                wire, real = self._resolve_pair(box, folder)
                self._select(box, wire, readonly=True)
                rec = self._envelope(box, str(uid), real)
                if not rec:
                    raise MailError(f"письмо {uid} в папке {real} не найдено")
                return rec
            finally:
                self._logout(box)

    def counts(self, folder: str = "INBOX") -> dict:
        with self._lock:
            box = self._connect()
            try:
                wire, real = self._resolve_pair(box, folder)
                self._select(box, wire, readonly=True)
                return {"folder": real, **self._status_counts(box, wire)}
            finally:
                self._logout(box)

    # ---------- Р·Р°РїРёСЃСЊ ----------

    def mark_seen(self, uids, seen=True, folder="INBOX") -> dict:
        return self._store_flags(folder, uids, "\\Seen", seen)

    def mark_flag(self, uids, flag: str, value=True, folder="INBOX") -> dict:
        if not flag.startswith("\\"):
            flag = "\\" + flag
        return self._store_flags(folder, uids, flag, value)

    @staticmethod
    def _existing_uids(box, uids) -> set:
        """Какие из переданных UID реально есть в выбранной папке.

        STORE/MOVE на несуществующем UID возвращают OK, поэтому «молчаливый успех»
        возможен — проверяем явно через UID SEARCH.
        """
        uids = [str(u) for u in uids if str(u).strip()]
        if not uids:
            return set()
        try:
            typ, data = box.uid("search", None, b"UID", *[u.encode("ascii", "ignore") for u in uids])
            if typ == "OK" and data and data[0] is not None:
                return {u.decode("ascii", "ignore") for u in data[0].split() if u}
        except Exception:  # noqa: BLE001
            pass
        return set(uids)

    def _store_flags(self, folder, uids, flag, value) -> dict:
        uids = [str(u) for u in uids if str(u).strip()]
        if not uids:
            raise MailError("не передано ни одного id письма")
        with self._lock:
            box = self._connect()
            try:
                wire, real = self._resolve_pair(box, folder)
                self._select(box, wire, readonly=False)
                present = self._existing_uids(box, uids)
                missing = [u for u in uids if u not in present]
                done, failed = [], []
                for uid in uids:
                    if uid not in present:
                        continue
                    st, _ = box.uid("store", uid, "+FLAGS" if value else "-FLAGS", f"({flag})")
                    (done if st == "OK" else failed).append(uid)
                return {"ok": not failed, "folder": real, "changed": done, "failed": failed,
                        "missing": missing}
            finally:
                self._logout(box)

    def move(self, uids, destination: str, folder="INBOX") -> dict:
        uids = [str(u) for u in uids if str(u).strip()]
        if not uids:
            raise MailError("не передано ни одного id письма")
        with self._lock:
            box = self._connect()
            try:
                wire, real = self._resolve_pair(box, folder)
                dest_wire, dest_name = self._resolve_pair(box, destination)
                self._select(box, wire, readonly=False)
                _, caps = box.capability()
                caps_bytes = caps[1] if isinstance(caps, tuple) else caps
                if isinstance(caps_bytes, (list, tuple)):
                    caps_bytes = b" ".join(c if isinstance(c, bytes) else str(c).encode()
                                            for c in caps_bytes)
                if caps_bytes and b"MOVE" in caps_bytes.upper():
                    present = self._existing_uids(box, uids)
                    missing = [u for u in uids if u not in present]
                    done, failed = [], []
                    for uid in uids:
                        if uid not in present:
                            continue
                        st, _ = box.uid("move", uid, f'"{dest_wire}"')
                        (done if st == "OK" else failed).append(uid)
                    out = {"ok": not failed, "changed": done, "failed": failed, "via": "MOVE"}
                else:
                    present = self._existing_uids(box, uids)
                    missing = [u for u in uids if u not in present]
                    done, failed = [], []
                    for uid in uids:
                        if uid not in present:
                            continue
                        st, _ = box.uid("copy", uid, f'"{dest_wire}"')
                        if st != "OK":
                            failed.append(uid)
                            continue
                        box.uid("store", uid, "+FLAGS", r"(\Deleted)")
                        done.append(uid)
                    if done:
                        box.expunge()
                    out = {"ok": not failed, "changed": done, "failed": failed, "via": "copy+expunge"}
                out["folder"] = real
                out["destination"] = dest_name
                out["missing"] = missing
                if missing and not done:
                    raise MailError(
                        f"в папке {real!r} нет писем с id {', '.join(missing)}. "
                        "id мог устареть после перемещения — найди письмо заново через search_emails"
                    )
                return out
            finally:
                self._logout(box)

    def delete(self, uids, folder="INBOX", expunge=False) -> dict:
        """expunge=False — перенос в Корзину (восстановимо), expunge=True — удаление безвозвратно."""
        if not expunge:
            out = self.move(uids, "Корзина", folder=folder)
            out["permanent"] = False
            return out
        out = self._store_flags(folder, uids, r"\Deleted", True)
        if out.get("changed"):
            with self._lock:
                box = self._connect()
                try:
                    wire, _ = self._resolve_pair(box, out["folder"])
                    self._select(box, wire, readonly=False)
                    box.expunge()
                finally:
                    self._logout(box)
            out["expunged"] = True
        out["permanent"] = True
        return out

    # ---------- РѕС‚РїСЂР°РІРєР° ----------

    def _build(self, to, subject, body, cc, bcc, html_body, reply_to=None, references=None) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = self.address
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        if bcc:
            msg["Bcc"] = ", ".join(bcc)
        msg["Subject"] = subject or "(без темы)"
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid(domain=self.address.split("@")[-1])
        if reply_to:
            msg["In-Reply-To"] = reply_to
        if references:
            msg["References"] = references
        if html_body:
            msg.set_content(body or "")
            msg.add_alternative(html_body, subtype="html")
        else:
            msg.set_content(body or "")
        return msg

    def _smtp(self):
        try:
            if self.smtp_port == 465:
                return smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=TIMEOUT)
            srv = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=TIMEOUT)
            srv.starttls()
            return srv
        except (OSError, smtplib.SMTPException, socket.error) as exc:
            raise MailError(f"не удалось подключиться к SMTP {self.smtp_host}:{self.smtp_port} — {exc}") from exc

    def _deliver(self, msg: EmailMessage) -> str:
        recipients = [a for a in (_addresses(msg, "To") + _addresses(msg, "Cc") + _addresses(msg, "Bcc")) if a]
        if not recipients:
            raise MailError("не указано ни одного получателя")
        if len(recipients) > 50:
            raise MailError(f"слишком много получателей ({len(recipients)}), максимум 50 за одно письмо")
        with self._smtp() as srv:
            try:
                srv.login(self.address, self._password)
            except smtplib.SMTPAuthenticationError as exc:
                raise MailError(
                    f"SMTP отклонил вход: {exc.smtp_error.decode('utf-8', 'replace') if isinstance(exc.smtp_error, bytes) else exc}. "
                    "Проверь пароль приложения."
                ) from exc
            except (OSError, smtplib.SMTPException) as exc:
                raise MailError(f"ошибка SMTP: {exc}") from exc
            try:
                srv.send_message(msg, from_addr=self.address, to_addrs=recipients)
            except (OSError, smtplib.SMTPException) as exc:
                raise MailError(f"письмо не отправлено: {exc}") from exc
        return msg["Message-ID"]

    def send(self, to, subject, body, cc=None, bcc=None, html_body=None) -> dict:
        to = _as_list(to)
        cc, bcc = _as_list(cc), _as_list(bcc)
        msg = self._build(to, subject, body, cc, bcc, html_body)
        mid = self._deliver(msg)
        return {"ok": True, "message_id": mid, "to": to, "cc": cc, "bcc": bcc,
                "subject": subject, "sent_at": datetime.now().astimezone().isoformat(timespec="seconds")}

    def reply(self, uid, folder, body, to=None, cc=None, all_reply=False, html_body=None) -> dict:
        original = self.read_email(uid, folder)
        orig_from = original.get("from") or []
        orig_to = original.get("to") or []
        if not orig_from:
            raise MailError("у исходного письма нет отправителя — нельзя построить ответ")
        if all_reply:
            targets, seen = [], set()
            for addr in orig_from + orig_to + original.get("cc", []):
                low = addr.lower()
                if low == self.address.lower() or low in seen:
                    continue
                seen.add(low)
                targets.append(addr)
            reply_to_all = targets
        else:
            reply_to_all = to or [orig_from[0]]
        reply_to_mid = original.get("message_id") or ""
        refs = reply_to_mid
        subject = original.get("subject") or ""
        if not subject.lower().startswith("re:"):
            subject = f"Re: {subject}"
        quoted = original.get("body") or ""
        # С€Р°РїРєРё ReferenСЃes: РёСЃС…РѕРґРЅС‹Р№ + РЅР°С€ Р±СѓРґСѓС‰РёР№ Message-ID РЅРµРёР·РІРµСЃС‚РµРЅ Р·Р°СЂР°РЅРµРµ, РїРѕСЌС‚РѕРјСѓ С‚РѕР»СЊРєРѕ РёСЃС…РѕРґРЅС‹Р№
        text = body if not quoted else f"{body}\n\n--- исходное письмо ---\n{quoted}"
        msg = self._build(reply_to_all, subject, text, _as_list(cc), [], html_body,
                          reply_to=reply_to_mid, references=refs)
        mid = self._deliver(msg)
        return {"ok": True, "message_id": mid, "in_reply_to": reply_to_mid, "to": reply_to_all,
                "cc": _as_list(cc), "subject": subject}

    def forward(self, uid, folder, to, body="", cc=None) -> dict:
        original = self.read_email(uid, folder)
        targets = _as_list(to)
        if not targets:
            raise MailError("не указано ни одного получателя для пересылки")
        subject = original.get("subject") or ""
        if not subject.lower().startswith("fwd:"):
            subject = f"Fwd: {subject}"
        origin = (original.get("from") or ["?"])[0]
        head = (f"Пересылаемое сообщение\n"
                f"От: {origin}\n"
                f"Кому: {', '.join(original.get('to') or [])}\n"
                f"Дата: {original.get('date') or ''}\n"
                f"Тема: {original.get('subject') or ''}\n")
        text = (body + "\n\n" + head + (original.get("body") or "")).strip()
        msg = self._build(targets, subject, text, _as_list(cc), [], None)
        mid = self._deliver(msg)
        return {"ok": True, "message_id": mid, "to": targets, "cc": _as_list(cc), "subject": subject,
                "forwarded_from": original.get("id")}

    def create_draft(self, to, subject, body, cc=None, bcc=None, html_body=None) -> dict:
        to, cc, bcc = _as_list(to), _as_list(cc), _as_list(bcc)
        msg = self._build(to, subject, body, cc, bcc, html_body)
        raw = msg.as_bytes(policy=SMTP_POLICY)
        with self._lock:
            box = self._connect()
            try:
                dest_wire, dest_name = self._resolve_pair(box, "Drafts")
                # imaplib ждёт flags строкой (скобки уже в строке) и None вместо даты
                typ, _ = box.append(f'"{dest_wire}"', r"(\Seen)", None, raw)
                if typ != "OK":
                    raise MailError("не удалось сохранить черновик")
            finally:
                self._logout(box)
        return {"ok": True, "folder": dest_name, "subject": subject, "to": to, "cc": cc, "bcc": bcc}

    # ---------- РґРёР°РіРЅРѕСЃС‚РёРєР° ----------

    def verify(self) -> dict:
        with self._lock:
            box = self._connect()
            try:
                self._select(box, "INBOX", readonly=True)
                caps = box.capability()
                if isinstance(caps, tuple):
                    caps = caps[1]
                if isinstance(caps, (list, tuple)):
                    caps = b" ".join(str(x).encode() if not isinstance(x, bytes) else x
                                     for x in caps)
                caps_text = (caps or b"").decode("ascii", "replace")
                inbox = self._status_counts(box, "INBOX")
                smtp_ok, smtp_err, smtp_ext = False, "", False
                try:
                    srv = self._smtp()
                    with srv:
                        srv.login(self.address, self._password)
                        smtp_ext = bool(srv.esmtp_features)
                    smtp_ok = True
                except MailError as exc:
                    smtp_err = str(exc)
                return {
                    "ok": True, "address": self.address,
                    "imap": {"ok": True, "host": self.imap_host,
                             "capabilities": sorted(caps_text.split()),
                             "inbox_total": inbox["total"], "inbox_unseen": inbox["unseen"]},
                    "smtp": {"ok": smtp_ok, "host": self.smtp_host, "port": self.smtp_port,
                             "error": smtp_err, "extensions": smtp_ext},
                }
            finally:
                self._logout(box)

    def _logout(self, box) -> None:
        """Соединение остаётся открытым для следующего вызова — закрывать его дорого.

        Помечаем время последнего использования; по IDLE_DROP соединение снимется само.
        Если после операции протокол разъехался, NOOP при следующем вызове это покажет.
        """
        self._box_at = time.time()


def _has_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in text or "")


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = re.split(r"[,;]", value)
    elif isinstance(value, (list, tuple, set)):
        parts = []
        for item in value:
            parts.extend(re.split(r"[,;]", str(item)))
    else:
        parts = [str(value)]
    out = []
    for part in parts:
        addr = part.strip().strip("<>").strip()
        if addr:
            out.append(addr)
    return out
