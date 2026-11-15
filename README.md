# Courier

**A private drop box for the people on your tailnet.**

Courier is a small web app for passing big files between friends, without upload limits, cloud storage or accounts. One person drops a file in and everyone else with access can pull it down. It runs on a machine you own and is only reachable over [Tailscale](https://tailscale.com), so the files never leave your hardware and strangers can't even find the page.

It was built for musicians swapping Logic Pro sessions, which are too big for email and awkward for most file-sharing tools because a `.logicx` project is a folder disguised as a file. Courier handles them as single items and they come back out intact.

## How it works

**It joins your tailnet as its own device.** Courier embeds Tailscale ([tsnet](https://tailscale.com/kb/1244/tsnet)), so it appears on your network as a machine called `courier` with its own HTTPS address. You share that one device with a friend, and they can reach Courier and nothing else on your network.

**Tailscale is the login.** Courier asks Tailscale who each visitor is, so there are no accounts, passwords or sign-up screens. Every upload shows who it came from, people can remove what they uploaded, and admins can remove anything. A visitor Tailscale can't identify is turned away.

**Files go straight to disk.** Uploads stream to disk as they arrive, so a 50 GB session needs no more memory than a 5 KB note. There is no per-file limit, only a reserve of free disk space that uploads can't use. Downloads can be resumed.

**Folders stay whole.** A folder or Logic project uploads as one item and downloads as a zip built on the fly, so it takes no extra disk space. Unzipping it gives back exactly what was uploaded, hidden files and empty folders included. Browsers that zip packages themselves (Safari and other WebKit browsers) work too.

**Every upload is scanned for malware.** Courier passes each upload to [ClamAV](https://www.clamav.net) and holds it back until the scan comes back clean. Anything flagged is deleted, stays in the list marked as blocked, and is logged so the server owner can be alerted. Files larger than ClamAV can read in full (about 4 GB) are marked as partly scanned.

## Design

The interface is monochrome, square-cornered, and built around **line weight**. Weight carries information instead of decorating:

- Each file's bar is as thick as the file is big, from a hairline for a note to a heavy stroke for a session.
- Scan states are line styles: dashed while scanning, a fine rule once clean, a heavy strike-through when blocked.
- Things you can act on, like the drop zone, buttons and the search field, get heavier as you interact with them.

It follows the system's light or dark mode, with a toggle that remembers your choice.

## Under the hood

A single Go binary with the web interface (plain HTML, CSS and JavaScript, no build step) embedded inside it. It has no database: metadata lives in one JSON index next to the stored files. It runs as a sandboxed systemd service under its own user.

| | |
|---|---|
| `main.go` | flags, Tailscale (tsnet), HTTP/HTTPS listeners |
| `server.go` | API: list, upload, download, folder zips, delete |
| `store.go` | on-disk storage, folder uploads, disk reserve |
| `scanner.go` | ClamAV scanning queue and quarantine |
| `dev.go` | local dev mode: live reload and a stand-in scanner |
| `web/` | the interface |
| `deploy/` | systemd unit and deploy script |

## Running it

```sh
go run . -dev localhost:8080 -data ./data            # local, no Tailscale, live reload
deploy/deploy.sh user@server                         # build for Linux and install as a service
```

On first start Courier prints a Tailscale login link to add itself to your tailnet. It's configured with flags: `-data`, `-hostname`, `-admins`, `-https`, `-reserve-gb`, `-scan` (see `courier -h`). Scanning expects `clamav-daemon` with `MaxFileSize`, `MaxScanSize` and `StreamMaxLength` raised to about 4000M.
