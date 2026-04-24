# certgot

Tiny Go app for grabbing wildcard certs for multiple domains.
small go app for grabbing wildcard certs. It uses DNS-01, stores certs, sends notifications, setups timers.

## What it does

- issues and renews wildcard certs
- works with multiple domains from one config
- stores certs locally
- can install itself with systemd setup
- sends status to Telegram

## Setup

```bash
certgot --setup --config config.yml
```

## Run

```bash
certgot --config /etc/certgot/config.yml
```

## Config

Use [`config-example.yml`](/Users/daniil/Code/certgot/config-example.yml) as the base.
For provider env vars, check the lego DNS docs:
[go-acme.github.io/lego/dns](https://go-acme.github.io/lego/dns/)
