# Local ACME integration test

This test starts the local Pebble ACME server only. It never contacts a public
ACME directory and uses a fake in-process DNS-01 provider. Pebble is run with
`PEBBLE_VA_ALWAYS_VALID=1`, so the server accepts the DNS challenge after the
client has called the provider's `Present` and `CleanUp` methods.

```bash
just integration
```

`integration/run.sh` clones the pinned Pebble `v2.10.1` source into a temporary
directory, builds it, starts it on localhost, and cleans it up afterward. Docker
is not required. To reuse an existing Pebble checkout, set `PEBBLE_SOURCE`:

```bash
PEBBLE_SOURCE=/private/tmp/pebble TMPDIR=/private/tmp just integration
```

`integration/compose.yml` remains available for manual Docker-based debugging.

The test covers config loading, account creation, DNS-01 issuance, atomic
release publishing, status and a forced renewal. Lock contention and interrupted
publication remain deterministic unit tests because they depend on local filesystem failure injection rather than ACME behavior.
