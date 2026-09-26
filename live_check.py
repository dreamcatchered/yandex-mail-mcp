"""live_check.py — боевая проверка на реальном ящике.

Требует развёрнутого сервиса и кода доступа. По умолчанию НИЧЕГО не отправляет
и не удаляет: только чтение. Создание черновика и проверка отправки — по флагам.

    YCP_TOKEN=<код> python live_check.py https://yandex-mail-mcp.example.com
    YCP_TOKEN=<код> python live_check.py https://yandex-mail-mcp.example.com --write
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5180"
TOKEN = os.environ.get("YCP_TOKEN", "").strip()
WRITE = "--write" in sys.argv
SELF = os.environ.get("YCP_ADDRESS", "").strip()
TEST_SUBJECT = "Проверка MCP-сервера Яндекс Почты"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(method: str, path: str, body=None, form=None, token=None, timeout=180):
    data, hdrs = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return 0, "EXC %s: %s" % (type(exc).__name__, exc)


def authorize() -> str:
    """Полный OAuth-цикл, как это делает ChatGPT: DCR -> PKCE -> token."""
    _, raw = call("POST", "/oauth/register", body={
        "client_name": "live_check",
        "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"})
    client_id = json.loads(raw).get("client_id")
    if not client_id:
        raise SystemExit("DCR не удался: " + raw[:200])

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "live"})
    req = urllib.request.Request(
        BASE + "/oauth/authorize",
        data=urllib.parse.urlencode({**dict(urllib.parse.parse_qsl(query)),
                                    "password": TOKEN}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        urllib.request.build_opener(_NoRedirect).open(req, timeout=60)
        raise SystemExit("ожидался редирект с кодом, а его не случилось")
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "")
    code = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(location).query)).get("code", "")
    if not code:
        raise SystemExit("код авторизации не вернулся")

    status, raw = call("POST", "/oauth/token", form={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect_uri, "code_verifier": verifier})
    if status != 200:
        raise SystemExit("обмен кода не удался: %s %s" % (status, raw[:200]))
    return json.loads(raw)["access_token"]


def tool(token: str, name: str, arguments: dict):
    t0 = time.time()
    _, raw = call("POST", "/mcp", body={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                        "params": {"name": name, "arguments": arguments}},
                  token=token)
    dt = time.time() - t0
    try:
        doc = json.loads(raw)
    except ValueError:
        return {"_error": raw[:300]}, dt
    if doc.get("error"):
        return {"_error": doc["error"].get("message", "")[:300]}, dt
    result = doc.get("result", {})
    text = result.get("content", [{}])[0].get("text", "")
    if result.get("isError"):
        return {"_error": text[:300]}, dt
    try:
        return json.loads(text), dt
    except ValueError:
        return text[:300], dt


def show(label: str, value, dt: float) -> None:
    rendered = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    print(f"\n--- {label}  ({dt:.1f}s)")
    print(rendered[:700])


def main() -> int:
    if not TOKEN:
        print("Не задан YCP_TOKEN — возьми access_code из config.json\n")
        return 2

    print(f"=== Боевая проверка {BASE} ===")
    token = authorize()
    print("OAuth-цикл пройден, access token получен\n")

    conn, dt = tool(token, "verify_connection", {})
    show("verify_connection", conn, dt)
    if conn.get("_error") or not conn.get("ok"):
        print("\nСервис не видит почту — дальше идти бессмысленно.")
        return 1

    folders, dt = tool(token, "list_folders", {})
    show("list_folders", folders, dt)

    counts, dt = tool(token, "unread_count", {})
    show("unread_count", counts, dt)

    found, dt = tool(token, "search_emails", {"query": "UNSEEN", "folder": "INBOX", "limit": 2})
    show("search_emails (2 непрочитанных)", found, dt)

    emails = found.get("emails") or [] if isinstance(found, dict) else []
    if emails:
        body, dt = tool(token, "read_email", {"id": emails[0]["id"]})
        show("read_email", body, dt)
    else:
        print("\nНепрочитанных писем нет — read_email пропущен.")

    if not WRITE:
        print("\nПроверки записи пропущены (--write не задан).")
        return 0

    if not SELF:
        print("\nДля --write нужен YCP_ADDRESS — адрес своего ящика.")
        return 2

    draft, dt = tool(token, "create_draft", {
        "to": SELF, "subject": TEST_SUBJECT, "body": "Черновик для проверки. Можно удалить."})
    show("create_draft", draft, dt)

    if isinstance(draft, dict) and draft.get("ok"):
        found, _ = tool(token, "search_emails",
                        {"query": 'SUBJECT "%s"' % TEST_SUBJECT, "folder": "Черновики", "limit": 3})
        print("\n--- поиск созданного черновика")
        print(json.dumps(found, ensure_ascii=False)[:500])
        for item in (found.get("emails") or []) if isinstance(found, dict) else []:
            tool(token, "move_email", {"id": item["id"], "destination": "Архив"})
            print("черновик %s перемещён в Архив" % item["id"])

    sent, dt = tool(token, "send_email", {
        "to": SELF, "subject": TEST_SUBJECT + ": отправка",
        "body": "Тестовое письмо, отправленное MCP-сервером. Можно удалить."})
    show("send_email (себе)", sent, dt)
    print("\nГотово. Не забудь удалить тестовые письма и черновики.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
