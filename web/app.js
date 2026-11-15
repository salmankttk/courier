"use strict";

const $ = (id) => document.getElementById(id);
const state = { me: null, admin: false, files: [], query: "" };

const KINDS = {
  image: ["png", "jpg", "jpeg", "gif", "webp", "heic", "svg", "bmp", "tiff", "raw"],
  video: ["mp4", "mov", "mkv", "avi", "webm", "m4v"],
  audio: ["mp3", "wav", "flac", "m4a", "aac", "ogg", "aiff"],
  archive: ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "dmg", "iso"],
  doc: ["pdf", "doc", "docx", "txt", "md", "rtf", "pages", "key", "numbers", "xls", "xlsx", "csv", "ppt", "pptx"],
};

function ext(name) {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(i + 1).toLowerCase() : "";
}

function kind(f) {
  const e = ext(f.name);
  if (f.folder) return e === "logicx" ? "logic" : "folder";
  for (const [k, list] of Object.entries(KINDS)) if (list.includes(e)) return k;
  return "other";
}

function label(f) {
  if (f.folder) return ext(f.name) === "logicx" ? "logic" : "dir";
  return (ext(f.name) || "file").slice(0, 4);
}

// What the scan state means for the person looking at the list.
const SCAN = {
  pending: { text: "Scanning…", cls: "badge-wait", blocked: true },
  clean: { text: "Scanned", cls: "badge-ok" },
  partial: { text: "Partly scanned", cls: "badge-warn", title: "Too big for the virus scanner to read completely; nothing was found in the part it checked." },
  error: { text: "Scan failed", cls: "badge-bad", blocked: true },
  infected: { text: "Blocked", cls: "badge-bad", blocked: true },
};

function bytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

function ago(iso) {
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  node.append(...children.filter((c) => c != null));
  return node;
}

function icon(path) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.innerHTML = path;
  return svg;
}
const ICON_DOWN = '<path d="M12 4v12m0 0-5-5m5 5 5-5"/><path d="M5 20h14"/>';
const ICON_TRASH = '<path d="M4 7h16M10 11v6m4-6v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/>';

function avatar(user) {
  if (user.pic) return el("img", { class: "avatar", src: user.pic, alt: "", referrerpolicy: "no-referrer" });
  const initials = (user.name || user.login || "?").split(/[\s@.]/).filter(Boolean).slice(0, 2).map((w) => w[0]).join("").toUpperCase();
  return el("span", { class: "avatar" }, initials);
}

let toastTimer;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 3500);
}

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Courier": "1", ...(opts.headers || {}) } });
  if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
  return res.status === 204 ? null : res.json();
}

function render() {
  const list = $("files");
  const q = state.query.toLowerCase();
  const shown = state.files.filter((f) => !q || f.name.toLowerCase().includes(q) || (f.uploader.name || "").toLowerCase().includes(q));
  list.replaceChildren(...shown.map(row));
  $("empty").hidden = state.files.length > 0;
  $("count").textContent = state.files.length ? `${state.files.length} file${state.files.length === 1 ? "" : "s"}` : "";
}

function row(f) {
  const mine = state.me && f.uploader.login === state.me.login;
  const scan = SCAN[f.scan];
  const del = mine || state.admin
    ? el("button", { class: "btn btn-danger", title: "Delete", "aria-label": `Delete ${f.name}`, onclick: (e) => remove(f, e.currentTarget) }, icon(ICON_TRASH))
    : null;
  const get = scan?.blocked
    ? el("span", { class: "btn btn-primary btn-disabled", "aria-disabled": "true" }, icon(ICON_DOWN), "Get")
    : el("a", { class: "btn btn-primary", href: `/api/files/${f.id}`, download: f.folder ? `${f.name}.zip` : f.name, "aria-label": `Download ${f.name}` }, icon(ICON_DOWN), "Get");
  const badge = scan
    ? el("span", { class: `badge ${scan.cls}`, title: f.scan === "infected" ? `Malware detected: ${f.threat}. The file was deleted.` : scan.title || "" }, scan.text)
    : null;
  const details = f.folder ? `${bytes(f.size)} · ${f.count} file${f.count === 1 ? "" : "s"}` : bytes(f.size);
  return el("li", { class: `file${f.scan === "infected" ? " file-blocked" : ""}` },
    el("div", { class: `type type-${kind(f)}` }, label(f)),
    el("div", { class: "meta" },
      el("div", { class: "name", title: f.name }, f.name),
      el("div", { class: "sub" }, avatar(f.uploader), `${mine ? "You" : f.uploader.name || f.uploader.login} · ${ago(f.uploadedAt)}`, badge)),
    el("div", { class: "size" }, f.scan === "infected" ? "" : details),
    el("div", { class: "actions" }, f.scan === "infected" ? null : get, del));
}

async function remove(f, button) {
  // Two-step delete: first click arms the button, second click deletes.
  if (!button.classList.contains("confirm")) {
    button.classList.add("confirm");
    button.replaceChildren("Delete?");
    setTimeout(() => { if (button.isConnected) { button.classList.remove("confirm"); button.replaceChildren(icon(ICON_TRASH)); } }, 3000);
    return;
  }
  try {
    await api(`/api/files/${f.id}`, { method: "DELETE" });
    toast(`Deleted ${f.name}`);
    refresh();
  } catch (err) {
    toast(err.message);
  }
}

let refreshTimer;
async function refresh() {
  clearTimeout(refreshTimer);
  try {
    const [files, stats] = await Promise.all([api("/api/files"), api("/api/stats")]);
    state.files = files;
    $("storage").textContent = `${bytes(stats.free)} free`;
    render();
  } catch (err) {
    toast(`Can't reach Courier: ${err.message}`);
  }
  // Poll quickly while something is being scanned, otherwise just to catch others' uploads.
  const scanning = state.files.some((f) => f.scan === "pending");
  refreshTimer = setTimeout(refresh, scanning ? 3000 : 10000);
}

// upload sends one file, or one folder when given { name, files: [{path, file}], dirs }.
function upload(item) {
  const isFolder = !(item instanceof File);
  const total = isFolder ? item.files.reduce((n, f) => n + f.file.size, 0) : item.size;
  const row = el("li", {},
    el("div", { class: "up-name" }, el("span", {}, isFolder ? `${item.name} (${item.files.length} files)` : item.name), el("span", {}, "0%")),
    el("div", { class: "bar" }, el("i")));
  $("upload-list").append(row);
  $("uploads").hidden = false;
  const pct = row.querySelector(".up-name span:last-child");
  const bar = row.querySelector(".bar > i");

  const body = new FormData();
  if (isFolder) {
    body.append("folder", item.name);
    for (const d of item.dirs) body.append("dir", d);
    for (const { path, file } of item.files) {
      body.append("path", path);
      body.append("file", file, file.name);
    }
  } else {
    body.append("file", item, item.name);
  }
  const xhr = new XMLHttpRequest(); // fetch() can't report upload progress
  xhr.open("POST", "/api/files");
  xhr.setRequestHeader("X-Courier", "1");
  xhr.upload.onprogress = (e) => {
    const p = Math.min(100, Math.round((e.loaded / (e.lengthComputable ? e.total : total || 1)) * 100));
    bar.style.width = `${p}%`;
    pct.textContent = `${p}% · ${bytes(e.loaded)}`;
  };
  const finish = (ok, msg) => {
    row.classList.add(ok ? "up-done" : "up-failed");
    pct.textContent = ok ? "Done" : "Failed";
    if (!ok) toast(msg);
    refresh();
    setTimeout(() => {
      row.remove();
      if (!$("upload-list").children.length) $("uploads").hidden = true;
    }, ok ? 2500 : 6000);
  };
  xhr.onload = () => (xhr.status < 300 ? finish(true) : finish(false, xhr.responseText.trim() || `Upload failed (${xhr.status})`));
  xhr.onerror = () => finish(false, `Upload of ${item.name} failed`);
  xhr.send(body);
}

// Folders (and Mac packages like .logicx) arrive as directory entries; walk
// them so every file inside, hidden ones included, gets uploaded.
function readAll(dirEntry) {
  const reader = dirEntry.createReader();
  return new Promise((resolve, reject) => {
    const out = [];
    const next = () => reader.readEntries((batch) => {
      if (!batch.length) return resolve(out);
      out.push(...batch);
      next(); // readEntries returns at most ~100 entries per call
    }, reject);
    next();
  });
}

async function collectFolder(root) {
  const files = [];
  const dirs = [];
  async function walk(entry, rel) {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      files.push({ path: rel, file });
    } else {
      dirs.push(rel);
      for (const child of await readAll(entry)) await walk(child, `${rel}/${child.name}`);
    }
  }
  for (const child of await readAll(root)) await walk(child, child.name);
  return { name: root.name, files, dirs };
}

async function handleDrop(items) {
  // Entries must be grabbed synchronously, before the drop event ends.
  const entries = [...items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  for (const entry of entries) {
    if (entry.isFile) {
      upload(await new Promise((res, rej) => entry.file(res, rej)));
    } else {
      toast(`Reading ${entry.name}…`);
      upload(await collectFolder(entry));
    }
  }
}

// A folder chosen with the picker arrives as a flat list with relative paths.
function folderFromPicker(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  const name = files[0].webkitRelativePath.split("/")[0];
  const dirs = new Set();
  const items = files.map((file) => {
    const path = file.webkitRelativePath.split("/").slice(1).join("/");
    const parts = path.split("/");
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/"));
    return { path, file };
  });
  upload({ name, files: items, dirs: [...dirs] });
}

function setupDrop() {
  const overlay = $("drag-overlay");
  let depth = 0;
  const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes("Files");
  window.addEventListener("dragenter", (e) => { if (hasFiles(e)) { depth++; overlay.hidden = false; } });
  window.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; overlay.hidden = true; } });
  window.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    overlay.hidden = true;
    handleDrop(e.dataTransfer.items).catch((err) => toast(`Couldn't read that: ${err.message || err}`));
  });

  const zone = $("dropzone");
  const picker = $("picker");
  const folderPicker = $("folder-picker");
  zone.addEventListener("click", (e) => {
    if (e.target.closest("#pick-folder")) folderPicker.click();
    else picker.click();
  });
  zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
  picker.addEventListener("change", () => { for (const f of picker.files) upload(f); picker.value = ""; });
  folderPicker.addEventListener("change", () => { folderFromPicker(folderPicker.files); folderPicker.value = ""; });
}

async function init() {
  setupDrop();
  $("search").addEventListener("input", (e) => { state.query = e.target.value; render(); });
  try {
    const me = await api("/api/me");
    state.me = me.user;
    state.admin = me.admin;
    $("me").replaceChildren(avatar(me.user), el("span", {}, me.user.name || me.user.login));
  } catch (err) {
    toast(`Can't identify you: ${err.message}`);
  }
  await refresh(); // keeps polling itself to pick up others' uploads
}

init();
