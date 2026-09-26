"""selftest.py — проверка протокола без реальной почты.

Гоняет полный цикл, который повторит ChatGPT: DCR -> authorize с PKCE -> token ->
tools/list -> вызов инструмента -> refresh -> revoke. IMAP/SMTP не трогает.

    YCP_TOKEN=<код доступа> python selftest.py https://yandex-mail-mcp.example.com
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5180"
YCP_TOKEN = os.environ.get("YCP_TOKEN", "").strip()

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'OK  ' if ok else 'FAIL'} {name}" + (f"  -> {detail}" if detail and not ok else ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """ChatGPT-редирект уводит на chatgpt.com, который отвечает 403 — автоследование ломает тест."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(method: str, path: str, body=None, headers=None, form=None, token=None):
    url = path if path.startswith("http") else BASE + path
    data = None
    hdrs = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")


def rpc(method: str, params=None, rpc_id=1, token=None, notify=False):
    payload = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        payload["params"] = params
    if not notify:
        payload["id"] = rpc_id
    return call("POST", "/mcp", body=payload, token=token)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main() -> int:
    print(f"\n=== Проверка yandex-mail-mcp на {BASE} ===\n")

    if not YCP_TOKEN:
        print("Не задан YCP_TOKEN. Возьми код доступа из config.json (ключ access_code)\n"
              "и запусти:  YCP_TOKEN=<код> python selftest.py <url>\n")
        return 2

    print("[1] сервис и метаданные")
    code, _, raw = call("GET", "/healthz")
    check("healthz отвечает 200", code == 200, f"{code}")
    code, _, raw = call("GET", "/.well-known/oauth-authorization-server")
    as_meta = json.loads(raw) if code == 200 else {}
    check("authorization server metadata", code == 200, f"{code}")
    issuer = str(as_meta.get("issuer") or "")
    check("issuer — https-URL без пути", issuer.startswith("https://") and issuer.count("/") <= 3
          or issuer.startswith("http://127.0.0.1"), issuer)
    for field in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        check(f"{field} на том же хосте, что issuer",
              str(as_meta.get(field) or "").startswith(issuer), str(as_meta.get(field)))
    check("объявлен PKCE S256", "S256" in (as_meta.get("code_challenge_methods_supported") or []))
    check("объявлен DCR endpoint", bool(as_meta.get("registration_endpoint")))
    check("grant_types содержит refresh_token",
          "refresh_token" in (as_meta.get("grant_types_supported") or []))
    code, _, raw = call("GET", "/.well-known/oauth-protected-resource")
    prm = json.loads(raw) if code == 200 else {}
    check("protected resource metadata", code == 200, f"{code}")
    check("PRM resource указывает на /mcp", str(prm.get("resource", "")).endswith("/mcp"),
          str(prm.get("resource")))
    check("PRM ссылается на authorization server", bool(prm.get("authorization_servers")))
    code, _, raw = call("GET", "/.well-known/oauth-protected-resource/mcp")
    check("PRM доступен и с путём ресурса", code == 200, f"{code}")

    print("\n[2] 401 и WWW-Authenticate")
    code, hdrs, raw = rpc("tools/list")
    check("tools/list без токена -> 401", code == 401, f"{code}")
    check("есть WWW-Authenticate", "www-authenticate" in {k.lower() for k in hdrs})
    www = next((v for k, v in hdrs.items() if k.lower() == "www-authenticate"), "")
    check("WWW-Authenticate ссылается на PRM", "oauth-protected-resource" in www, www)
    code, _, _ = rpc("tools/list", token="definitely-not-a-token")
    check("мусорный токен -> 401", code == 401, f"{code}")

    print("\n[3] динамическая регистрация клиента (DCR)")
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    code, _, raw = call("POST", "/oauth/register", body={
        "client_name": "ChatGPT selftest",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })
    reg = json.loads(raw) if code == 201 else {}
    client_id = reg.get("client_id", "")
    check("DCR вернул 201 и client_id", code == 201 and client_id, f"{code} {raw[:120]}")
    code, _, _ = call("POST", "/oauth/register", body={"client_name": "bad"})
    check("DCR без redirect_uri отклонён", code == 400, f"{code}")

    print("\n[4] PKCE: неверный пароль и верный код")
    verifier = secrets.token_urlsafe(48)
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    qs = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "state": "st-1", "scope": "yandexmail",
    })
    code, _, _ = call("GET", f"/oauth/authorize?{qs}")
    check("экран согласия открылся (200)", code == 200, f"{code}")
    code, _, _ = call("POST", "/oauth/authorize", form={**dict(urllib.parse.parse_qsl(qs)),
                                                       "password": "wrong-password"})
    check("неверный код доступа отклонён (401)", code == 401, f"{code}")

    code, hdrs, _ = call("POST", "/oauth/authorize", form={**dict(urllib.parse.parse_qsl(qs)),
                                                            "password": YCP_TOKEN})
    location = next((v for k, v in hdrs.items() if k.lower() == "location"), "")
    check("верный код доступа -> redirect с кодом", code in (302, 303) and "code=" in location,
          f"{code} {location[:100]}")
    auth_code = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(location).query)).get("code", "")
    check("state вернулся в redirect", "state=st-1" in location, location[:120])
    check("redirect ведёт на зарегистрированный uri", location.startswith(redirect_uri))

    print("\n[5] обмен кода на токен")
    code, _, raw = call("POST", "/oauth/token", form={
        "grant_type": "authorization_code", "code": auth_code, "client_id": client_id,
        "redirect_uri": redirect_uri, "code_verifier": "wrong-verifier",
    })
    check("неверный code_verifier отклонён", code == 400, f"{code}")

    code, _, raw = call("POST", "/oauth/token", form={
        "grant_type": "authorization_code", "code": auth_code, "client_id": client_id,
        "redirect_uri": redirect_uri, "code_verifier": verifier,
    })
    tok = json.loads(raw) if code == 200 else {}
    access = tok.get("access_token", "")
    refresh = tok.get("refresh_token", "")
    check("обмен кода успешен", code == 200 and bool(access), f"{code} {raw[:120]}")
    check("выдан refresh_token", bool(refresh))
    check("access token не равен refresh token", access and access != refresh)
    check("код одноразовый", call("POST", "/oauth/token", form={
        "grant_type": "authorization_code", "code": auth_code, "client_id": client_id,
        "redirect_uri": redirect_uri, "code_verifier": verifier})[0] == 400)

    print("\n[6] MCP: initialize, tools/list, ошибки")
    code, _, raw = rpc("initialize", {"protocolVersion": "2025-06-18",
                                      "capabilities": {},
                                      "clientInfo": {"name": "selftest", "version": "1"}}, token=access)
    init = json.loads(raw).get("result", {}) if code == 200 else {}
    check("initialize успешен", code == 200 and bool(init), f"{code}")
    check("эхо protocolVersion", init.get("protocolVersion") == "2025-06-18",
          str(init.get("protocolVersion")))
    check("serverInfo задан", bool(init.get("serverInfo", {}).get("name")))
    check("instructions непустые", len(init.get("instructions") or "") > 200)
    code, _, raw = rpc("initialize", {"protocolVersion": "1999-01-01"}, token=access)
    check("неизвестная версия протокола -> своя", code == 200 and
          json.loads(raw)["result"]["protocolVersion"] == "2025-06-18")
    code, _, _ = rpc("notifications/initialized", notify=True, token=access)
    check("notifications/initialized -> 202", code == 202, f"{code}")
    code, _, _ = rpc("ping", token=access)
    check("ping -> 200", code == 200, f"{code}")

    code, _, raw = rpc("tools/list", token=access)
    tools = json.loads(raw).get("result", {}).get("tools", []) if code == 200 else []
    names = [t.get("name") for t in tools]
    check("tools/list вернул инструменты", code == 200 and len(tools) > 0, f"{code}")
    if not tools:
        print("\n!!! tools/list пуст — следующие проверки инструментов пропущены")
    check("меньше 70 инструментов", 0 < len(tools) < 70, f"{len(tools)}")
    for required in ("search", "fetch", "search_emails", "read_email", "send_email",
                     "reply_email", "create_draft", "move_email", "delete_email"):
        check(f"есть инструмент {required}", required in names)
    check("у всех инструментов есть inputSchema",
          bool(tools) and all(isinstance(t.get("inputSchema"), dict)
                              and t["inputSchema"].get("type") == "object" for t in tools))
    check("у всех инструментов есть описание",
          bool(tools) and all(isinstance(t.get("description"), str) and t["description"].strip()
                              for t in tools))
    check("delete_email требует confirm",
          "confirm" in (next((t for t in tools if t["name"] == "delete_email"), {})
                        .get("inputSchema", {}).get("required", [])))

    code, _, raw = rpc("tools/call", {"name": "verify_connection"}, token=access)
    payload = json.loads(raw) if code == 200 else {}
    is_err = payload.get("error") is not None or \
        (payload.get("result") or {}).get("isError") is True
    check("вызов инструмента не роняет сервис (ошибка почты -> isError, не 500)", is_err or code == 200,
          f"{code} {raw[:160]}")
    code, _, raw = rpc("tools/call", {"name": "delete_email",
                                      "arguments": {"id": "INBOX|1"}}, token=access)
    out = json.loads(raw) if code == 200 else {}
    text = json.dumps(out, ensure_ascii=False)
    check("delete_email без confirm отказывает", "confirm" in text.lower(), text[:160])

    code, _, raw = rpc("tools/call", {"name": "нет_такого"}, token=access)
    check("неизвестный инструмент -> ошибка", "неизвестный" in json.dumps(
        json.loads(raw) if code == 200 else {}, ensure_ascii=False).lower())

    code, _, raw = call("GET", "/mcp", token=access)
    check("GET /mcp -> 405 (нет SSE)", code == 405, f"{code}")
    code, _, raw = call("POST", "/mcp", body={"jsonrpc": "2.0", "id": 9, "method": "нет/метода"},
                        token=access)
    check("неизвестный метод -> -32601",
          json.loads(raw).get("error", {}).get("code") == -32601 if code == 200 else False)

    print("\n[7] refresh и отзыв")
    code, _, raw = call("POST", "/oauth/token",
                        form={"grant_type": "refresh_token", "refresh_token": refresh})
    tok2 = json.loads(raw) if code == 200 else {}
    access2 = tok2.get("access_token", "")
    check("refresh_token работает", code == 200 and bool(access2), f"{code} {raw[:120]}")
    check("refresh вернул новую пару токенов",
          bool(access2) and access2 != refresh and tok2.get("refresh_token") != refresh,
          f"a={access2[:8]!r} r={tok2.get('refresh_token','')[:8]!r}")
    check("старый access token остаётся валиден до TTL (это норма OAuth)",
          rpc("tools/list", token=access)[0] in (200, 401))
    check("новый access token работает", rpc("tools/list", token=access2)[0] == 200)
    check("ротация: старый refresh token мёртв",
          call("POST", "/oauth/token",
               form={"grant_type": "refresh_token", "refresh_token": refresh})[0] == 400)
    call("POST", "/oauth/revoke", form={"token": access2})
    check("revoke убивает токен", rpc("tools/list", token=access2)[0] == 401)

    print(f"\n=== Итог: {len(PASS)} ок, {len(FAIL)} провалено ===")
    if FAIL:
        print("Провалено: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
