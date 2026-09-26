# Cloudflare Tunnel для MCP-коннектора.

# Зачем туннель, а не nginx + Let's Encrypt:
#   * порт 443 на сервере часто занят (xray, другие сервисы);
#   * не нужен открытый порт и сертификат на каждом хосте;
#   * TLS терминируется на краю Cloudflare, наружу смотрит только localhost.
# Побочный плюс: адрес сервера нигде не светится.

# 1. Создать туннель и получить токен (Dashboard → Zero Trust → Networks → Tunnels,
#    либо API). Токен — это секрет, его не коммитить.

# 2. На сервере:
#      mkdir -p /etc/cloudflared
#      printf '%s' '<ТОКЕН_ТУННЕЛЯ>' > /etc/cloudflared/token
#      chmod 600 /etc/cloudflared/token
#      cloudflared --no-autoupdate service install <ТОКЕН_ТУННЕЛЯ>
#      systemctl enable --now cloudflared

# 3. Привязать адрес к сервису (tunnel id и hostname — свои):
#      cloudflared tunnel route dns <TUNNEL_ID> yandex-mail-mcp.example.com
#      cloudflared tunnel ingress rule <TUNNEL_ID> \
#          --hostname yandex-mail-mcp.example.com --url http://127.0.0.1:5180

# 4. ВАЖНО для этого сервера: исходящая сеть не любит IPv6 и QUIC,
#    поэтому туннель запускается с жёсткими флагами в /etc/systemd/system/cloudflared.service:
#        ExecStart=/usr/bin/cloudflared --no-autoupdate --protocol http2 \
#                  --edge-ip-version 4 --region us tunnel run --token-file /etc/cloudflared/token
#        Type=simple
#        TimeoutStartSec=0
#    Без этого cloudflared уходит в IPv6 и падает по таймауту.

# 5. В зоне Cloudflare обязательно выключить Browser Integrity Check:
#    он отвечает 403 (error 1010) на небраузерные User-Agent, а ChatGPT
#    ходит с бот-агентом. Проверено: curl проходит, Python-urllib — 403.
#    Либо отключить для всей зоны, либо правилом конфигурации для одного хоста.
