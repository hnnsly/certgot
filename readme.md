# certgot

Wildcard ACME certificates via DNS-01. Linux + systemd.

## Use it

Download `certgot` from the release.

```bash
sudo install -m 0755 certgot /usr/local/bin/certgot
certgot init
```

On Linux, `init` writes `~/.config/certgot/config.yml` and state goes to
`~/.local/share/certgot`. Override the config location with `--config` or
`CERTGOT_CONFIG`. Root commands default to `/etc/certgot/config.yml`.

```bash
certgot doctor
certgot setup --setup-interval 2w --yes
```

`setup` asks for sudo, copies config and secrets to `/etc/certgot`, then enables a systemd timer. It renews certificates automatically.

```bash
sudo certgot status --config /etc/certgot/config.yml
systemctl list-timers certgot.timer
```

Telegram reports use explicit fields, not a URL:

```yaml
notifications:
  on: [renewed, error]
  telegram:
    bot_token: "${TELEGRAM_BOT_TOKEN}"
    chat_id: -1001234567890
    topic_id: 42 # optional
```

For non-interactive init, use `--telegram-bot-token-env`,
`--telegram-chat-id`, and optional `--telegram-topic-id`.
The old `telegram_url` fields are not supported.

DNS provider variables: [lego docs](https://go-acme.github.io/lego/dns/).
