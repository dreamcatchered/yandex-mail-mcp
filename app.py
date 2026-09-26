"""app.py — MCP-сервер Яндекс Почты для ChatGPT.

Транспорт: Streamable HTTP (JSON-RPC 2.0 в POST /mcp).
Авторизация: OAuth 2.1 (oauth.py) — так ChatGPT умеет подключать удалённые /mcp.

Почта: IMAP + SMTP Яндекса с паролем приложения (mail.py). У Яндекса нет OAuth-скоупа
mail:imap, поэтому XOAUTH2 недоступен и пароль приложения — единственный путь.
"""

from __future__ import annotations

import functools
import hmac
import json
import logging
import os
import re
import time
from logging.handlers import RotatingFileHandler
from urllib.parse import quote

from flask import Flask, jsonify, request

import mail as mail_mod
import oauth as oauth_mod

HERE = os.path.dirname(os.path.abspath(__file__))
APP_VERSION = "1.0.0"
START_TIME = time.time()
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
_handler = RotatingFileHandler(
    os.path.join(HERE, "yandex-mail-mcp.log"), maxBytes=1_000_000, backupCount=2, encoding="utf-8"
)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
logging.getLogger("yandexmail").addHandler(_handler)
LOG = logging.getLogger("yandexmail.app")


def load_config() -> dict:
    path = os.path.join(HERE, "config.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


CFG = load_config()
PORT = int(CFG.get("port") or 5180)
TOKEN = str(CFG.get("access_code") or "")
MAIL = mail_mod.Mailbox(
    address=CFG["address"],
    password=CFG["app_password"],
    imap_host=CFG.get("imap_host") or "imap.yandex.ru",
    imap_port=CFG.get("imap_port") or 993,
    smtp_host=CFG.get("smtp_host") or "smtp.yandex.ru",
    smtp_port=CFG.get("smtp_port") or 465,
)
PUBLIC_URL = (CFG.get("public_url") or "").rstrip("/")

app = Flask(__name__, static_folder=None)
try:
    app.json.ensure_ascii = False
except Exception:  # noqa: BLE001
    pass

OAUTH = oauth_mod.OAuthProvider(
    TOKEN, PUBLIC_URL, static_clients=CFG.get("oauth_clients") or [], mailbox=MAIL.address
)
app.register_blueprint(OAUTH.blueprint)


def const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode("utf-8", "replace"), (b or "").encode("utf-8", "replace"))


def is_authenticated() -> bool:
    header = request.headers.get("Authorization", "")
    bearer = header[7:].strip() if header.startswith("Bearer ") else ""
    if bearer and (const_eq(bearer, TOKEN) or OAUTH.verify_access(bearer)):
        return True
    return const_eq(request.headers.get("X-Access-Token", ""), TOKEN)


OAUTH.authorized = is_authenticated


def requires_auth(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if is_authenticated():
            return view(*args, **kwargs)
        return jsonify({"status": "error", "message": "нужен access token"}), 401

    wrapper.auth_required = True
    return wrapper


# --------------------------------------------------------------------------- MCP-обвязка


def mcp_result(payload) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, default=str)}],
            "isError": False}


def mcp_error(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _ids(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = re.split(r"[,\s]+", str(value))
    return [str(i).strip() for i in items if str(i).strip()]


def _msg_id(folder: str, uid: str) -> str:
    return f"{folder}|{uid}"


def _split_msg_id(value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if "|" in text:
        folder, _, uid = text.partition("|")
        return folder, uid
    return "INBOX", text


def _group_by_folder(value, default_folder: str = "INBOX") -> dict:
    """{'Черновики': ['144', '145'], 'INBOX': ['7']} — id может быть от разных папок."""
    groups: dict[str, list[str]] = {}
    for raw in _ids(value):
        folder, uid = _split_msg_id(raw)
        groups.setdefault(folder or default_folder, []).append(uid)
    return groups


def _msg_url(folder: str, uid: str) -> str:
    base = PUBLIC_URL or ""
    return f"{base}/message/{quote(folder, safe='')}/{quote(str(uid), safe='')}"


def _snippet(body: str, limit: int = 400) -> str:
    text = re.sub(r"\s+", " ", body or "").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


# --------------------------------------------------------------------------- инструменты

INSTRUCTIONS = (
    "Сервер управляет одной почтой Яндекса. Работай так:\n"
    "1) Начинай с read-only: unread_count или list_folders, потом search_emails, потом read_email.\n"
    "2) id письма — это строка вида 'папка|uid'. Её возвращает search_emails, и её же нужно "
    "передавать в read_email, reply_email, forward_email, move_email, mark_email, delete_email. "
    "Не выдумывай id — бери из результата поиска.\n"
    "3) Папку можно задавать по-русски или по-английски: INBOX/Входящие, Sent/Отправленные, "
    "Drafts/Черновики, Trash/Корзина, Junk/Спам, Archive/Архив. Если сомневаешься — list_folders.\n"
    "4) search_emails принимает синтаксис IMAP в query: ALL, UNSEEN, FROM \"a@b.c\", "
    "SUBJECT счёт, SINCE 01-Dec-2025, комбинации через пробел. Если запрос не в синтаксисе IMAP — "
    "собери его сам из текста запроса пользователя.\n"
    "5) Перед отправкой письма всегда покажи пользователю получателей, тему и текст и дождись "
    "подтверждения. Для черновика используй create_draft — это безопаснее, чем send_email.\n"
    "6) delete_email требует confirm=true. Не удаляй письма, если пользователь не попросил именно об этом, "
    "и предупреди, что действие необратимо.\n"
    "7) search и fetch — обёртки для Deep Research: search возвращает список писем с id и url, "
    "fetch отдаёт полный текст по id из search. Для обычной работы используй search_emails/read_email.\n"
    "8) Письма на кириллице возвращаются в UTF-8 — не перекодируй и не ломай кавычки в теме письма.\n"
)


def _s(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or [],
            "additionalProperties": False}


FOLDER = {"type": "string", "description": "Папка. INBOX/Входящие, Sent/Отправленные, "
                                          "Drafts/Черновики, Trash/Корзина, Junk/Спам. По умолчанию INBOX."}
IDS = {"type": "string", "description": "id письма из search_emails, вида 'папка|uid'. Несколько — через запятую."}
BODY = {"type": "string", "description": "Текст письма на русском."}

MCP_TOOLS = [
    {
        "name": "search",
        "description": "Найти письма в почтовом ящике (обёртка для Deep Research). "
                       "Возвращает id, тему, отправителя, дату и url каждого письма.",
        "inputSchema": _s({
            "query": {"type": "string", "description": "Поисковый запрос. Пусто или 'всё' — все письма."},
            "folder": dict(FOLDER),
            "limit": {"type": "integer", "description": "Сколько писем вернуть, максимум 20.", "default": 10},
        }, ["query"]),
    },
    {
        "name": "fetch",
        "description": "Полный текст письма по id, который вернул search. Используй для цитат и Deep Research.",
        "inputSchema": _s({
            "id": {"type": "string", "description": "id письма из результата search, вида 'папка|uid'."},
        }, ["id"]),
    },
    {
        "name": "unread_count",
        "description": "Сколько всего писем и сколько непрочитанных в папке. Быстрый ответ на «что нового?». "
                       "Работает, даже если детальный поиск не нужен.",
        "inputSchema": _s({"folder": dict(FOLDER)}),
    },
    {
        "name": "list_folders",
        "description": "Список всех папок почтового ящика с их назначением (входящие, отправленные, "
                       "черновики, корзина, спам, архив).",
        "inputSchema": _s({}),
    },
    {
        "name": "search_emails",
        "description": "Поиск писем. query — синтаксис IMAP: ALL, UNSEEN, FROM \"ivan@x.ru\", "
                       "SUBJECT \"счёт\", SINCE 01-Dec-2025, комбинации через пробел. "
                       "Возвращает список с id, темой, отправителем, датой и началом текста.",
        "inputSchema": _s({
            "query": {"type": "string", "description": "Запрос в синтаксисе IMAP. ALL — все письма."},
            "folder": dict(FOLDER),
            "limit": {"type": "integer", "description": "Сколько писем вернуть, максимум 50. По умолчанию 20."},
        }, ["query"]),
    },
    {
        "name": "read_email",
        "description": "Полный текст одного письма: тема, отправитель, получатели, дата, текст, "
                       "список вложений. Не помечает письмо прочитанным.",
        "inputSchema": _s({
            "id": {"type": "string", "description": "id письма вида 'папка|uid' из search_emails."},
        }, ["id"]),
    },
    {
        "name": "send_email",
        "description": "Отправить письмо. Сначала покажи пользователю получателей, тему и текст и дождись "
                       "подтверждения — ChatGPT спросит сам, но текст должен быть готов заранее.",
        "inputSchema": _s({
            "to": {"type": "string", "description": "Кому. Несколько адресов — через запятую."},
            "subject": {"type": "string", "description": "Тема письма."},
            "body": dict(BODY),
            "cc": {"type": "string", "description": "Копия, через запятую."},
            "bcc": {"type": "string", "description": "Скрытая копия, через запятую."},
            "html": {"type": "string", "description": "HTML-версия письма, если нужна."},
        }, ["to", "subject", "body"]),
    },
    {
        "name": "reply_email",
        "description": "Ответить на письмо с сохранением цепочки (тема станет Re:, а письмо останется в треде).",
        "inputSchema": _s({
            "id": {"type": "string", "description": "id письма вида 'папка|uid'."},
            "body": dict(BODY),
            "to": {"type": "string", "description": "Переопределить получателя, через запятую. По умолчанию — автор."},
            "cc": {"type": "string", "description": "Копия, через запятую."},
            "all_reply": {"type": "boolean", "description": "Ответить всем (reply-all), а не только автору.",
                          "default": False},
        }, ["id", "body"]),
    },
    {
        "name": "forward_email",
        "description": "Переслать письмо другому адресу, с исходным текстом в теле.",
        "inputSchema": _s({
            "id": {"type": "string", "description": "id письма вида 'папка|uid'."},
            "to": {"type": "string", "description": "Кому переслать, через запятую."},
            "body": {"type": "string", "description": "Твой комментарий сверху, необязательно."},
            "cc": {"type": "string", "description": "Копия, через запятую."},
        }, ["id", "to"]),
    },
    {
        "name": "create_draft",
        "description": "Сохранить письмо в черновики, не отправляя. Предпочитай это, если пользователь "
                       "просит «подготовь письмо», а не «отправь».",
        "inputSchema": _s({
            "to": {"type": "string", "description": "Кому, через запятую."},
            "subject": {"type": "string", "description": "Тема письма."},
            "body": dict(BODY),
            "cc": {"type": "string", "description": "Копия, через запятую."},
            "bcc": {"type": "string", "description": "Скрытая копия, через запятую."},
            "html": {"type": "string", "description": "HTML-версия письма, если нужна."},
        }, ["to", "subject", "body"]),
    },
    {
        "name": "move_email",
        "description": "Переместить письма в другую папку. Несколько id — через запятую.",
        "inputSchema": _s({
            "id": dict(IDS),
            "destination": {"type": "string", "description": "Куда переместить: Archive/Архив, Trash/Корзина, "
                                                          "Sent/Отправленные, Drafts/Черновики."},
        }, ["id", "destination"]),
    },
    {
        "name": "mark_email",
        "description": "Пометить письма прочитанными или непрочитанными, поставить или снять флаги "
                       "Flagged (важное) и Starred.",
        "inputSchema": _s({
            "id": dict(IDS),
            "seen": {"type": "boolean", "description": "True — прочитано, False — не прочитано."},
            "flagged": {"type": "boolean", "description": "Поставить или снять флаг «важное»."},
            "starred": {"type": "boolean", "description": "Поставить или снять звезду."},
        }, ["id"]),
    },
    {
        "name": "delete_email",
        "description": "Удалить письма. По умолчанию переносит их в Корзину (можно восстановить). "
                       "Для окончательного удаления поставь expunge=true. Обязателен confirm=true.",
        "inputSchema": _s({
            "id": dict(IDS),
            "confirm": {"type": "boolean", "description": "Обязательно true — подтверждение удаления."},
            "expunge": {"type": "boolean", "description": "true — стереть безвозвратно. Опасно."},
        }, ["id", "confirm"]),
    },
    {
        "name": "verify_connection",
        "description": "Проверить, что почта доступна: IMAP и SMTP на связи, сколько писем во входящих. "
                       "Первое, что стоит вызвать, если что-то не работает.",
        "inputSchema": _s({}),
    },
]


def call_tool(name: str, args: dict):
    try:
        return _dispatch(name, args or {})
    except mail_mod.MailError as exc:
        return mcp_error(str(exc))
    except Exception as exc:  # noqa: BLE001
        LOG.exception("tool %s failed", name)
        return mcp_error(f"внутренняя ошибка в {name}: {exc}")


def _dispatch(name: str, args: dict) -> dict:
    if name == "verify_connection":
        return mcp_result(MAIL.verify())

    if name == "list_folders":
        return mcp_result({"folders": MAIL.list_folders()})

    if name == "unread_count":
        return mcp_result(MAIL.counts(args.get("folder") or "INBOX"))

    if name == "search_emails":
        found = MAIL.search_emails(
            query=str(args.get("query") or "ALL"),
            folder=str(args.get("folder") or "INBOX"),
            limit=int(args.get("limit") or 20),
        )
        out = []
        for rec in found:
            uid = rec["id"]
            folder = rec["folder"]
            out.append({
                "id": _msg_id(folder, uid),
                "uid": uid,
                "folder": folder,
                "subject": rec["subject"],
                "from": rec["from"],
                "from_name": rec.get("from_name", ""),
                "date": rec["date"],
                "url": _msg_url(folder, uid),
                "snippet": _snippet(rec.get("snippet") or ""),
            })
        return mcp_result({"folder": args.get("folder") or "INBOX", "count": len(out), "emails": out})

    if name == "search":
        query = str(args.get("query") or "").strip()
        if query.lower() in ("", "всё", "все", "all", "*"):
            query = "ALL"
        found = MAIL.search_emails(
            query=query,
            folder=str(args.get("folder") or "INBOX"),
            limit=min(int(args.get("limit") or 10), 20),
        )
        out = []
        for rec in found:
            uid, folder = rec["id"], rec["folder"]
            sender = (rec.get("from_name") or (rec.get("from") or [""])[0] or "").strip()
            out.append({
                "id": _msg_id(folder, uid),
                "title": rec["subject"],
                "url": _msg_url(folder, uid),
                "text": _snippet(rec.get("snippet") or sender, 200),
                "author": sender,
                "published_date": rec.get("date") or "",
            })
        return mcp_result({"query": query, "results": out})

    if name == "fetch":
        folder, uid = _split_msg_id(args.get("id"))
        rec = MAIL.read_email(uid, folder)
        body = rec.get("body") or ""
        head = [
            f"Тема: {rec.get('subject','')}",
            f"От: {', '.join(rec.get('from') or [])}",
            f"Кому: {', '.join(rec.get('to') or [])}",
            f"Дата: {rec.get('date','')}",
        ]
        if rec.get("cc"):
            head.append(f"Копия: {', '.join(rec['cc'])}")
        if rec.get("attachments"):
            head.append("Вложения: " + ", ".join(
                f"{a.get('filename')} ({a.get('size_bytes')} б)" for a in rec["attachments"]))
        return mcp_result({
            "id": args.get("id"),
            "title": rec.get("subject", ""),
            "url": _msg_url(folder, uid),
            "text": "\n".join(head) + "\n\n" + body,
            "metadata": {
                "from": rec.get("from"), "to": rec.get("to"), "cc": rec.get("cc"),
                "date": rec.get("date"), "folder": folder, "uid": uid,
                "attachments": rec.get("attachments") or [],
            },
        })

    if name == "read_email":
        folder, uid = _split_msg_id(args.get("id"))
        rec = MAIL.read_email(uid, folder)
        rec["url"] = _msg_url(folder, uid)
        return mcp_result(rec)

    if name == "send_email":
        return mcp_result(MAIL.send(
            to=args.get("to"), subject=str(args.get("subject") or ""), body=str(args.get("body") or ""),
            cc=args.get("cc"), bcc=args.get("bcc"), html_body=args.get("html"),
        ))

    if name == "reply_email":
        folder, uid = _split_msg_id(args.get("id"))
        return mcp_result(MAIL.reply(
            uid=uid, folder=folder, body=str(args.get("body") or ""),
            to=mail_mod._as_list(args.get("to")), cc=mail_mod._as_list(args.get("cc")),
            all_reply=bool(args.get("all_reply")), html_body=args.get("html"),
        ))

    if name == "forward_email":
        folder, uid = _split_msg_id(args.get("id"))
        return mcp_result(MAIL.forward(
            uid=uid, folder=folder, to=args.get("to"),
            body=str(args.get("body") or ""), cc=mail_mod._as_list(args.get("cc")),
        ))

    if name == "create_draft":
        return mcp_result(MAIL.create_draft(
            to=args.get("to"), subject=str(args.get("subject") or ""), body=str(args.get("body") or ""),
            cc=args.get("cc"), bcc=args.get("bcc"), html_body=args.get("html"),
        ))

    if name == "move_email":
        default_folder = str(args.get("folder") or "INBOX")
        results = {}
        for folder, uids in _group_by_folder(args.get("id"), default_folder).items():
            results[folder] = MAIL.move(uids=uids, destination=str(args.get("destination") or "Trash"),
                                        folder=folder)
        return mcp_result({"ok": all(r.get("ok") for r in results.values()), "by_folder": results})

    if name == "mark_email":
        default_folder = str(args.get("folder") or "INBOX")
        by_folder = {}
        for folder, uids in _group_by_folder(args.get("id"), default_folder).items():
            ops = {}
            if args.get("seen") is not None:
                ops["seen"] = MAIL.mark_seen(uids, bool(args["seen"]), folder)
            for flag in ("flagged", "starred"):
                if args.get(flag) is not None:
                    ops[flag] = MAIL.mark_flag(uids, flag, bool(args[flag]), folder)
            by_folder[folder] = ops
        if not any(by_folder.values()):
            return mcp_error("нечего менять: укажи хотя бы seen, flagged или starred")
        flat = [r for ops in by_folder.values() for r in ops.values()]
        return mcp_result({"ok": all(r.get("ok") for r in flat), "by_folder": by_folder})

    if name == "delete_email":
        if not args.get("confirm"):
            return mcp_error("удаление не подтверждено: передай confirm=true. "
                             "Предупреди пользователя, что действие необратимо, и спроси подтверждение.")
        default_folder = str(args.get("folder") or "INBOX")
        by_folder = {}
        for folder, uids in _group_by_folder(args.get("id"), default_folder).items():
            by_folder[folder] = MAIL.delete(uids=uids, folder=folder,
                                            expunge=bool(args.get("expunge")))
        return mcp_result({"ok": all(r.get("ok") for r in by_folder.values()), "by_folder": by_folder})

    return mcp_error(f"неизвестный инструмент {name}")


# --------------------------------------------------------------------------- HTTP

@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path in ("/mcp", "/oauth/token", "/oauth/register", "/oauth/revoke"):
        resp.headers["Cache-Control"] = "no-store"
    if resp.status_code == 401 and request.path == "/mcp":
        base = OAUTH.base_url(request.url_root)
        resp.headers["WWW-Authenticate"] = (
            f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'
        )
    return resp


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "app": "yandex-mail-mcp",
        "version": APP_VERSION,
        "mailbox": MAIL.address,
        "mcp": "/mcp",
        "uptime_s": int(time.time() - START_TIME),
        "tools": [t["name"] for t in MCP_TOOLS],
    })


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok", "uptime_s": int(time.time() - START_TIME)})


@app.route("/message/<path:folder>/<path:uid>", methods=["GET"])
@requires_auth
def message_page(folder: str, uid: str):
    try:
        rec = MAIL.read_email(uid, folder)
    except mail_mod.MailError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 502
    rec.pop("url", None)
    return jsonify(rec)


@app.route("/mcp", methods=["POST", "GET", "OPTIONS"])
@requires_auth
def mcp_endpoint():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "GET":
        # Streamable HTTP: поток сервер->клиент не предлагаем, поэтому честный 405
        return ("", 405, {"Allow": "POST"})

    req = request.get_json(silent=True) or {}
    if isinstance(req, list):
        req = req[0] if req else {}
    method = req.get("method", "")
    rpc_id = req.get("id")
    params = req.get("params") or {}

    def wrap(result):
        return jsonify({"jsonrpc": "2.0", "id": rpc_id, "result": result})

    if method == "initialize":
        wanted = str(params.get("protocolVersion") or "")
        version = wanted if wanted in SUPPORTED_PROTOCOLS else "2025-06-18"
        return wrap({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "yandex-mail-mcp", "version": APP_VERSION},
            "instructions": INSTRUCTIONS,
        })

    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return ("", 202)

    if method == "ping":
        return wrap({})

    if method == "tools/list":
        return wrap({"tools": MCP_TOOLS})

    if method == "tools/call":
        name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            args = {}
        result = call_tool(name, args)
        if result.get("isError"):
            return jsonify({"jsonrpc": "2.0", "id": rpc_id,
                            "error": {"code": -32000, "message": result["content"][0]["text"]}})
        return wrap(result)

    if method == "resources/list":
        return wrap({"resources": []})
    if method == "prompts/list":
        return wrap({"prompts": []})

    return jsonify({"jsonrpc": "2.0", "id": rpc_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"}})


@app.errorhandler(404)
def not_found(_):
    return jsonify({"status": "error", "message": "не найдено"}), 404


@app.errorhandler(500)
def server_error(exc):
    LOG.exception("500: %s", exc)
    return jsonify({"status": "error", "message": "внутренняя ошибка"}), 500


if __name__ == "__main__":
    LOG.info("yandex-mail-mcp %s listening on 127.0.0.1:%d, mailbox=%s", APP_VERSION, PORT, MAIL.address)
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False, use_reloader=False)
