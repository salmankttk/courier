# Courier

A shared drop box for your tailnet. Anyone you share Courier with can upload files and download what others uploaded, from any browser, with no passwords.

- **Tailnet-only.** Courier joins Tailscale as its own device (`courier`), so you can share just Courier with a friend without exposing the rest of your server.
- **Knows who you are.** Tailscale tells Courier who each visitor is, so every file shows its uploader. You can delete your own files; admins can delete any.
- **Big files.** Uploads stream straight to disk and downloads support resuming. A disk reserve stops uploads from filling the server.
- **One binary.** The Go backend embeds the Liquid Glass web UI.

## Run locally

```sh
go run . -dev localhost:8080 -data ./data
```

Dev mode skips Tailscale and treats you as an admin.

## Deploy

```sh
deploy/deploy.sh user@server
```

Then, on the server:

1. Set the admins in `/etc/courier/env`, e.g. `COURIER_ADMINS=you@example.com`, and `sudo systemctl restart courier`.
2. On first start Courier prints a Tailscale login link (`journalctl -u courier`). Open it to add the `courier` device to your tailnet.
3. In the Tailscale admin console, disable key expiry for `courier`, and share it with friends (Machines → courier → Share).
4. Optional: enable HTTPS certificates in the Tailscale admin console (DNS page) and add `-https` to `COURIER_FLAGS`.

## Flags

| Flag | Default | |
|---|---|---|
| `-data` | `/srv/courier` | where files and the index live |
| `-hostname` | `courier` | device name on the tailnet |
| `-admins` | | comma-separated logins that may delete any file |
| `-reserve-gb` | `20` | disk space uploads may never use |
| `-https` | `false` | serve HTTPS with a tailnet certificate |
| `-port` | `41642` | UDP port for direct Tailscale connections |
| `-dev` | | run without Tailscale on this address |
