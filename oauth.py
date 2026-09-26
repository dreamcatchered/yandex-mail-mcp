"""oauth.py — минимальный OAuth 2.1 провайдер, чтобы удалённый MCP-коннектор ChatGPT подключился сам.

Логика перенесена из dreamHome (smarthome) без изменений по существу — там она уже
проверена и покрыта selftest'ом; здесь переименованы только scope и тексты экрана входа.

Что реализовано:
  * метаданные authorization server и protected resource (well-known);
  * динамическая регистрация клиентов (DCR) — ChatGPT регистрируется сам;
  * authorization code + PKCE (только S256, публичный клиент без секрета);
  * статические клиенты из config.json (oauth_clients) — для клиентов без DCR/PKCE;
  * refresh-токены с ротацией;
  * экран входа: пароль — это access_code из config.json.

Токены непрозрачные и лежат в oauth.json; подписанных JWT здесь намеренно нет.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse

from flask import Blueprint, jsonify, redirect, render_template_string, request

OAUTH_FILE = Path(__file__).with_name("oauth.json")

SCOPE = "yandexmail"
CODE_TTL = 8 * 60
LOGIN_FAIL_LIMIT = 8


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def new_token() -> str:
    return secrets.token_urlsafe(32)


def const_eq(a: str, b: str) -> bool:
    """сравнение только байтами: compare_digest на str падает с не-ASCII из рук клиента."""
    return hmac.compare_digest((a or "").encode("utf-8", "replace"), (b or "").encode("utf-8", "replace"))


def remote_ip() -> str:
    """IP вошедшего. X-Real-IP ставит обратный прокси из $remote_addr, его не подделать."""
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return (
        request.headers.get("X-Real-IP")
        or request.headers.get("CF-Connecting-IP")
        or forwarded
        or request.remote_addr
        or "?"
    )


def _is_https_or_local(uri: str) -> bool:
    try:
        parsed = urlparse(str(uri))
    except Exception:  # noqa: BLE001
        return False
    if parsed.scheme == "https" and parsed.netloc:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}


class OAuthProvider:
    """Хранение клиентов, кодов и токенов + проверка подлинности запросов."""

    def __init__(self, login_password: str, issuer: str, path: Path = OAUTH_FILE,
                 access_ttl: int = 12 * 3600, refresh_ttl: int = 90 * 86400,
                 static_clients: list | None = None, mailbox: str = ""):
        self.login_password = login_password
        self.issuer = issuer.rstrip("/")
        self.path = path
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self.lock = threading.RLock()
        self.data = {"clients": {}, "codes": {}, "tokens": {}, "used_codes": []}
        self.failed: dict[str, list] = {}
        self.static: dict[str, dict] = {}
        for raw in static_clients or []:
            rec = self._static_record(raw or {})
            if rec["client_id"]:
                self.static[rec["client_id"]] = rec
        self.authorized = None
        self.mailbox = mailbox
        self.load()
        self.blueprint = build_blueprint(self, ("/mcp",), mailbox)

    @staticmethod
    def _static_record(raw: dict) -> dict:
        cid = str(raw.get("client_id") or "").strip()
        secret = str(raw.get("client_secret") or "")
        return {
            "client_id": cid,
            "client_name": str(raw.get("client_name") or cid)[:80],
            "redirect_uris": [str(u) for u in (raw.get("redirect_uris") or []) if _is_https_or_local(u)],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic" if secret else "none",
            "scope": str(raw.get("scope") or SCOPE),
            "client_id_issued_at": 0,
            "static": True,
            "require_pkce": bool(raw.get("require_pkce", True)),
            "client_secret": secret,
        }

    def base_url(self, fallback_root: str = "") -> str:
        return self.issuer or fallback_root.rstrip("/")

    def access_label(self) -> str:
        days = self.access_ttl // 86400
        return f"{days} дн." if days else f"{max(1, self.access_ttl // 3600)} ч."

    # ---------- хранение ----------

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                self.data.update({k: saved.get(k, {}) for k in ("clients", "codes", "tokens")})
        except Exception:  # noqa: BLE001
            pass

    def save(self) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def gc(self) -> None:
        now = time.time()
        with self.lock:
            self.data["codes"] = {k: v for k, v in self.data["codes"].items() if v.get("exp", 0) > now}
            self.data["tokens"] = {k: v for k, v in self.data["tokens"].items() if v.get("exp", 0) > now}
            self.data["used_codes"] = self.data["used_codes"][-200:]
            self.failed = {k: v for k, v in self.failed.items() if v[1] > now}
            clients = self.data["clients"]
            if len(clients) > 50:
                newest = sorted(clients, key=lambda k: clients[k].get("client_id_issued_at", 0))[-50:]
                self.data["clients"] = {k: clients[k] for k in newest}

    # ---------- метаданные ----------

    def as_metadata(self, base: str = "") -> dict:
        base = (base or self.issuer).rstrip("/")
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"]
            + (["client_secret_basic"] if any(c.get("client_secret") for c in self.static.values()) else []),
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": [SCOPE],
            "revocation_endpoint": f"{base}/oauth/revoke",
        }

    def protected_resource(self, resource: str) -> dict:
        return {
            "resource": resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
        }

    # ---------- клиенты (DCR) ----------

    def register(self, meta: dict) -> tuple[dict | None, str]:
        uris = [str(u) for u in (meta.get("redirect_uris") or []) if _is_https_or_local(u)]
        if not uris:
            return None, "нужен хотя бы один redirect_uri по https"
        client_id = "c_" + secrets.token_urlsafe(10)
        client = {
            "client_id": client_id,
            "client_name": str(meta.get("client_name") or "")[:80],
            "redirect_uris": uris[:10],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPE,
            "client_id_issued_at": int(time.time()),
        }
        with self.lock:
            self.data["clients"][client_id] = client
            self.save()
        return client, ""

    def client(self, client_id: str) -> dict | None:
        if not client_id:
            return None
        with self.lock:
            rec = self.data["clients"].get(client_id)
        return rec or self.static.get(client_id)

    def redirect_ok(self, client: dict, redirect_uri: str) -> bool:
        if redirect_uri in (client.get("redirect_uris") or []):
            return True
        return bool(client.get("static")) and not client.get("redirect_uris") and _is_https_or_local(redirect_uri)

    def secret_ok(self, client_id: str, secret: str) -> bool:
        client = self.client(client_id) or {}
        if not client.get("static"):
            return False
        want = client.get("client_secret") or ""
        return const_eq(want, secret) if want else bool((secret or "").strip())

    # ---------- вход ----------

    def check_login_busy(self, ip: str) -> bool:
        with self.lock:
            rec = self.failed.get(ip)
            return bool(rec) and rec[1] > time.time() and rec[0] >= LOGIN_FAIL_LIMIT

    def note_login_fail(self, ip: str) -> None:
        with self.lock:
            rec = self.failed.setdefault(ip, [0, 0])
            rec[0] += 1
            rec[1] = time.time() + 120

    def note_login_ok(self, ip: str) -> None:
        with self.lock:
            self.failed.pop(ip, None)

    def verify_password(self, password: str) -> bool:
        return const_eq((password or "").strip(), self.login_password)

    # ---------- authorization code ----------

    def issue_code(self, *, client_id: str, redirect_uri: str, scope: str, challenge: str) -> str:
        code = new_token()
        with self.lock:
            self.data["codes"][code] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "challenge": challenge,
                "exp": time.time() + CODE_TTL,
            }
            self.save()
        return code

    def exchange_code(self, *, code: str, verifier: str, client_id: str, redirect_uri: str,
                      secret: str = "") -> tuple[dict | None, str]:
        with self.lock:
            self.gc()
            rec = self.data["codes"].get(code or "")
            if not rec or code in self.data["used_codes"]:
                return None, "invalid_grant"
            if rec["exp"] < time.time():
                return None, "invalid_grant"
            if rec["client_id"] != client_id or (rec["redirect_uri"] or "") != (redirect_uri or ""):
                return None, "invalid_grant"
            if rec["challenge"]:
                digest = b64url(hashlib.sha256((verifier or "").encode("ascii", "ignore")).digest())
                if not const_eq(digest, rec["challenge"]):
                    return None, "invalid_grant"
            elif not self.secret_ok(rec["client_id"], secret):
                return None, "invalid_grant"
            self.data["used_codes"].append(code)
            self.data["codes"].pop(code, None)
            token = self._mint(rec["client_id"], rec["scope"])
            self.save()
            return token, ""

    def refresh(self, refresh_token: str) -> tuple[dict | None, str]:
        with self.lock:
            self.gc()
            rec = self.data["tokens"].get(refresh_token or "")
            if not rec or not rec.get("is_refresh"):
                return None, "invalid_grant"
            if rec["exp"] < time.time():
                return None, "invalid_grant"
            self.data["tokens"].pop(refresh_token, None)
            token = self._mint(rec["client_id"], rec["scope"])
            self.save()
            return token, ""

    def _mint(self, client_id: str, scope: str) -> dict:
        access, refresh = new_token(), new_token()
        now = time.time()
        self.data["tokens"][access] = {
            "client_id": client_id, "scope": scope, "is_refresh": False, "exp": now + self.access_ttl
        }
        self.data["tokens"][refresh] = {
            "client_id": client_id, "scope": scope, "is_refresh": True, "exp": now + self.refresh_ttl
        }
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
            "refresh_token": refresh,
            "scope": scope or SCOPE,
        }

    def verify_access(self, token: str) -> bool:
        if not token:
            return False
        with self.lock:
            self.gc()
            rec = self.data["tokens"].get(token)
            return bool(rec) and not rec.get("is_refresh") and rec["exp"] > time.time()

    def revoke(self, token: str) -> None:
        with self.lock:
            self.data["tokens"].pop(token or "", None)
            self.save()

    def stats(self) -> dict:
        with self.lock:
            self.gc()
            return {
                "clients": len(self.data["clients"]),
                "access_tokens": sum(1 for v in self.data["tokens"].values() if not v.get("is_refresh")),
                "refresh_tokens": sum(1 for v in self.data["tokens"].values() if v.get("is_refresh")),
            }


# --------------------------------------------------------------------------- Flask blueprint

CONSENT_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Почта — доступ для ChatGPT</title>
<style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#e8ecff;
      font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
 .card{width:min(430px,92vw);background:#141a30cc;border:1px solid #2a3357;border-radius:18px;padding:24px;
       box-shadow:0 20px 60px #0008;backdrop-filter:blur(8px)}
 h1{margin:0 0 6px;font-size:19px} p{margin:0 0 16px;color:#9fb0d8;font-size:13.5px}
 .warn{background:#2a1f10;border:1px solid #6b4a1a;color:#ffd9a0;border-radius:12px;padding:10px 12px;
       margin-bottom:16px;font-size:12.5px}
 .who{background:#0e1428;border-radius:12px;padding:10px 12px;margin-bottom:16px;font-size:13px;color:#c9d4f5;
       border:1px solid #253050;word-break:break-all}
 label{display:block;font-size:12.5px;color:#9fb0d8;margin-bottom:6px}
 input[type=password]{width:100%;box-sizing:border-box;padding:11px 12px;border-radius:11px;border:1px solid #2f3a63;
      background:#0b1020;color:#e8ecff;font-size:15px}
 button{width:100%;margin-top:14px;padding:12px;border:0;border-radius:11px;background:#4c7dff;color:#fff;
        font-size:15px;font-weight:600;cursor:pointer}
 .err{color:#ff9c9c;font-size:13px;margin-top:10px}
 .hint{margin-top:14px;font-size:11.5px;color:#6f7fa8}
</style></head><body>
 <div class="card">
  <h1>Разрешить доступ к почте?</h1>
  <p>Подключение даст ChatGPT возможность читать, искать и отправлять письма
     от твоего имени в ящике {{ mailbox }}.</p>
  <div class="warn">ChatGPT сможет <b>отправлять письма твоим именем</b> и <b>удалять</b> их.
     ChatGPT показывает подтверждение перед такими действиями — но решение всё равно за тобой.</div>
  <div class="who"><b>{{ client_name }}</b><br>перенаправление: {{ redirect_host }}</div>
  <form method="post" action="/oauth/authorize">
   {% for key, value in fields.items() %}<input type="hidden" name="{{ key }}" value="{{ value }}">{% endfor %}
   <label>Код доступа (access_code из config.json)</label>
   <input type="password" name="password" autocomplete="current-password" placeholder="код доступа" autofocus required>
   <button type="submit">Подключить</button>
   {% if error %}<div class="err">{{ error }}</div>{% endif %}
  </form>
  <div class="hint">Один вход = один токен доступа со сроком {{ access_days }};
     ChatGPT обновит его сам через refresh.</div>
 </div></body></html>"""

ERROR_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Почта</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#e8ecff;
font:15px system-ui}div{max-width:520px;padding:24px;border:1px solid #2a3357;border-radius:16px;background:#141a30cc}
</style></head><body><div><b>Нельзя продолжить</b><br>{{ message }}</div></body></html>"""


def build_blueprint(provider: OAuthProvider, resource_paths: tuple[str, ...] = ("/mcp",),
                    mailbox: str = "") -> Blueprint:
    bp = Blueprint("oauth", __name__)

    def issuer() -> str:
        return provider.base_url(request.url_root)

    def authorize_error(message: str, code: int = 400):
        return render_template_string(ERROR_HTML, message=message), code

    # ---- well-known: и корень, и вариант с путём ресурса (требование MCP/auth spec) ----
    @bp.route("/.well-known/oauth-authorization-server", methods=["GET"])
    @bp.route("/.well-known/oauth-authorization-server/<path:extra>", methods=["GET"])
    @bp.route("/.well-known/openid-configuration", methods=["GET"])
    @bp.route("/.well-known/openid-configuration/<path:extra>", methods=["GET"])
    def as_metadata(extra: str = ""):
        return jsonify(provider.as_metadata(issuer()))

    @bp.route("/.well-known/oauth-protected-resource", methods=["GET"])
    @bp.route("/.well-known/oauth-protected-resource/<path:extra>", methods=["GET"])
    def resource_metadata(extra: str = ""):
        path = f"/{extra}" if extra else (resource_paths[0] if resource_paths else "")
        return jsonify(provider.protected_resource(f"{issuer()}{path}"))

    # ---- DCR ----
    @bp.route("/oauth/register", methods=["POST"])
    def register():
        client, error = provider.register(request.get_json(silent=True) or {})
        if not client:
            return jsonify({"error": "invalid_client_metadata", "error_description": error}), 400
        body = dict(client)
        body["client_secret"] = ""
        return jsonify(body), 201

    # ---- authorize ----
    @bp.route("/oauth/authorize", methods=["GET", "POST", "OPTIONS"])
    def authorize():
        if request.method == "OPTIONS":
            return ("", 204)
        src = request.values
        client_id = src.get("client_id", "")
        redirect_uri = src.get("redirect_uri", "")
        state = src.get("state", "")
        challenge = src.get("code_challenge", "")
        scope = src.get("scope", SCOPE)
        hidden = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "state": state,
            "scope": scope,
        }
        if challenge:
            hidden["code_challenge_method"] = src.get("code_challenge_method") or "S256"
        if src.get("nonce"):
            hidden["nonce"] = src["nonce"]

        if src.get("response_type", "code") != "code":
            return authorize_error("поддерживается только response_type=code")
        client = provider.client(client_id)
        if not client:
            return authorize_error(
                "неизвестный client_id: этот клиент не зарегистрирован и не описан в конфигурации сервера"
            )
        if client.get("require_pkce", True) and (not challenge or hidden.get("code_challenge_method") != "S256"):
            return authorize_error("нужен PKCE: code_challenge + code_challenge_method=S256")
        if not provider.redirect_ok(client, redirect_uri):
            return authorize_error("redirect_uri не совпадает с зарегистрированным")

        if request.method == "POST":
            ip = remote_ip()
            if provider.check_login_busy(ip):
                return authorize_error("слишком много неудачных попыток, подожди пару минут", 429)
            if not provider.verify_password(src.get("password", "")):
                provider.note_login_fail(ip)
                return render_template_string(
                    CONSENT_HTML,
                    client_name=client["client_name"] or client_id,
                    redirect_host=urlparse(redirect_uri).netloc or redirect_uri,
                    fields=hidden,
                    error="неверный код доступа",
                    access_days=provider.access_label(),
                    mailbox=mailbox or "вашем",
                ), 401
            provider.note_login_ok(ip)
            code = provider.issue_code(
                client_id=client_id, redirect_uri=redirect_uri, scope=scope, challenge=challenge
            )
            sep = "&" if "?" in redirect_uri else "?"
            location = f"{redirect_uri}{sep}{urlencode({k: v for k, v in (('code', code), ('state', state)) if v})}"
            return redirect(location, code=302)

        return render_template_string(
            CONSENT_HTML,
            client_name=client["client_name"] or client_id,
            redirect_host=urlparse(redirect_uri).netloc or redirect_uri,
            fields=hidden,
            error="",
            access_days=provider.access_label(),
            mailbox=mailbox or "вашем",
        )

    # ---- token ----
    @bp.route("/oauth/token", methods=["POST", "OPTIONS"])
    def token():
        if request.method == "OPTIONS":
            return ("", 204)
        form = request.form or {}
        grant = form.get("grant_type", "")
        client_id = form.get("client_id", "")
        basic = request.authorization
        basic_user = getattr(basic, "username", None) or ""
        basic_pass = getattr(basic, "password", None) or ""
        client_id = client_id or basic_user
        if grant == "authorization_code":
            issued, error = provider.exchange_code(
                code=form.get("code", ""),
                verifier=form.get("code_verifier", ""),
                client_id=client_id,
                redirect_uri=form.get("redirect_uri", ""),
                secret=form.get("client_secret", "") or basic_pass,
            )
        elif grant == "refresh_token":
            issued, error = provider.refresh(form.get("refresh_token", ""))
        else:
            issued, error = None, "unsupported_grant_type"
        if not issued:
            return jsonify({"error": error}), 400
        issued["scope"] = issued.get("scope") or SCOPE
        return jsonify(issued)

    @bp.route("/oauth/revoke", methods=["POST"])
    def revoke():
        provider.revoke((request.form or {}).get("token", ""))
        return ("", 204)

    @bp.route("/oauth/sessions", methods=["GET"])
    def sessions():
        allowed = bool(provider.authorized) and bool(provider.authorized())
        if not allowed:
            return jsonify({"error": "unauthorized"}), 401
        return jsonify({"status": "ok", "mailbox": mailbox, **provider.stats()})

    return bp
