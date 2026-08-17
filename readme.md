# certgot

Wildcard ACME certificates via DNS-01. Linux + systemd.

## Use it

Download `certgot` and `config-example.yml` from the release.

```bash
sudo install -m 0755 certgot /usr/local/bin/certgot
cp config-example.yml config.yml
$EDITOR config.yml
$EDITOR cloudflare.env

certgot doctor --config config.yml
certgot setup --config config.yml --setup-interval 2w --yes
```

`setup` asks for sudo, copies config and secrets to `/etc/certgot`, then enables a systemd timer. It renews certificates automatically.

```bash
sudo certgot status --config /etc/certgot/config.yml
systemctl list-timers certgot.timer
```

Need a config from scratch instead? Run `certgot init`.

DNS provider variables: [lego docs](https://go-acme.github.io/lego/dns/).
