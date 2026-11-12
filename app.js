/* Мои финансы — телефон.
   Записи хранятся на телефоне (localStorage). «Синхронизировать» шифрует паролем записи с пометкой
   «на компьютер» и кладёт их в ваш приватный репозиторий GitHub (inbox/), затем забирает сводку
   с компьютера (snapshot.enc). Формат шифрования совпадает с phone_sync.py на компьютере:
   PBKDF2-SHA256 (200 000) → AES-256-GCM, у каждого файла своя соль. */
"use strict";

const VERSION = "2026.11.11-c";          // поднимать вместе с version.json и CACHE в sw.js
let newVersion = "";                      // на GitHub лежит версия новее той, что открыта
const FORMAT = "moi-finansy-1";
const ITER = 200000;
const API = "https://api.github.com";
const INBOX = "inbox";
const SNAPSHOT = "snapshot.enc";
const TOKEN_PAGE = "https://github.com/settings/personal-access-tokens/new";

const EXPENSE_DEFAULT = ["Продукты", "Обеды и кафе", "Обеды в офисе", "Транспорт", "Связь", "Подписки", "Одежда и маркетплейсы",
  "Красота и уход", "Здоровье и врачи", "Дом и быт", "Поездки и отпуск", "Подарки", "Переводы близким",
  "Развлечения и прогулки", "Хобби и творчество", "Квартира", "Непредвиденное", "Другое"];
const INCOME_DEFAULT = ["Зарплата", "Аванс", "Премия", "Отпускные", "Кэшбэк", "Подработка", "Подарок",
  "Возврат / отложенное", "Другое"];

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

/* ------------------------------------------------------------------ хранение */
const store = {
  get(key, def) {
    try { const v = localStorage.getItem("mf." + key); return v === null ? def : JSON.parse(v); }
    catch (e) { return def; }
  },
  set(key, val) {
    try { localStorage.setItem("mf." + key, JSON.stringify(val)); return true; }
    catch (e) { toast("Не получилось сохранить на телефоне: " + e.message); return false; }
  },
};
let entries = store.get("entries", []);
let cfg = store.get("cfg", { repo: "", ghToken: "", pw: "", lastMode: "send" });
let snap = store.get("snap", null);
let locked = false;                       // PIN включён и ещё не введён — данные не показываем
let kind = "expense";
let mode = cfg.lastMode || "send";
let filter = "all";        // (старый список «Записи» — теперь часть «Операций»)
const saveEntries = () => store.set("entries", entries);
const saveCfg = () => store.set("cfg", cfg.pinOn ? { ...cfg, ghToken: "", pw: "", srvToken: "" } : cfg);
/* Режим сервера: приложение открыто с вашего сервера (config.js там ставит MF_SERVER). Записи и сводка идут
   напрямую на сервер по HTTPS, ноутбук для этого не нужен. На GitHub Pages — прежний режим через репозиторий. */
const SRV = !!window.MF_SERVER;
function saveSnap(text) {
  /* сводка хранится в том виде, как пришла (зашифрована паролем синхронизации); без PIN — ещё и открытой */
  if (text) store.set("snapBox", text);
  if (cfg.pinOn) { try { localStorage.removeItem("mf.snap"); } catch (e) { /* нет */ } }
  else store.set("snap", snap);
}

/* ------------------------------------------------------------------ мелочи */
function fmt(x) {
  const n = Math.round(Number(x) || 0);
  return n.toLocaleString("ru-RU").replace(/ /g, " ") + " ₽";
}
function fmtExact(x) {
  const n = Number(x) || 0;
  const s = n.toLocaleString("ru-RU", { minimumFractionDigits: n % 1 ? 2 : 0, maximumFractionDigits: 2 });
  return s.replace(/ /g, " ") + " ₽";
}
function todayISO() {
  const d = new Date();
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
}
function ddmm(iso) { return iso ? iso.slice(8, 10) + "." + iso.slice(5, 7) : ""; }
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function uid() {
  if (crypto.randomUUID) return crypto.randomUUID().replace(/-/g, "");
  const a = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
}
let toastTimer = null;
function toast(text, ms = 3200) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}
/* колонка по дате, как на компьютере: 10–24 — с зарплаты, 25–9 — с аванса */
/* колонка по дате: с зарплаты (10-го) до аванса (25-го); выплату на выходных дают раньше — дни берём из сводки.
   Доход «Аванс» — всегда «с аванса», «Зарплата» — «с зарплаты». */
function autoHalf(iso, cat) {
  const c = String(cat || "").toLowerCase();
  if (c.includes("аванс")) return 2;
  if (c.includes("зарплат")) return 1;
  const sh = snap && snap.shift_days && snap.shift_days[iso.slice(0, 10)];
  if (sh) return sh;                  // праздник за 1–2 дня до выплаты — уже её колонка
  const p = snap && snap.paydays && snap.paydays[iso.slice(0, 7)];
  if (p) return iso >= p[1] ? 2 : iso >= p[0] ? 1 : 2;
  const d = Number(iso.slice(8, 10)); return d >= 10 && d <= 24 ? 1 : 2;
}
const HALF_NAME = { 1: "с зарплаты", 2: "с аванса" };

/* ------------------------------------------------------------------ шифрование */
function b64(buf) {
  const b = new Uint8Array(buf); let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) { return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); }
async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptObj(obj, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pw, salt, ITER);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return JSON.stringify({ f: FORMAT, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
}
async function decryptText(text, pw) {
  let box;
  try { box = JSON.parse(text); } catch (e) { throw new Error("Файл сводки повреждён"); }
  const key = await deriveKey(pw, unb64(box.salt), box.iter || ITER);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, key, unb64(box.ct));
    return JSON.parse(dec.decode(plain));
  } catch (e) {
    throw new Error("Пароль не подходит — он должен быть такой же, как в программе на компьютере");
  }
}

/* ------------------------------------------------------------------ GitHub (приватный репозиторий) */
class SyncError extends Error {}
function cleanRepo(t) {
  t = String(t || "").trim().replace(/\/+$/, "").replace(/^https?:\/\//, "").replace(/^(www\.)?github\.com\//, "").replace(/\.git$/, "");
  return t.split("/").filter(Boolean).slice(0, 2).join("/");
}
async function gh(method, path, body) {
  const url = path === null ? `${API}/repos/${cfg.repo}`
    : `${API}/repos/${cfg.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}`;
  const headers = { Authorization: "Bearer " + cfg.ghToken, Accept: "application/vnd.github+json" };
  if (body) headers["Content-Type"] = "application/json";
  let r;
  try {
    r = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store" });
  } catch (e) {
    throw new SyncError(navigator.onLine === false ? "Нет интернета — записи подождут на телефоне"
      : "GitHub не ответил — проверьте интернет. Записи остались на телефоне.");
  }
  if (r.status === 401) throw new SyncError("GitHub не принял токен — вставьте новый во вкладке «Настройки»");
  if (r.status === 403) throw new SyncError("У токена нет права записи — нужен доступ «Contents: Read and write» к репозиторию");
  if (r.status === 404 && path === null) throw new SyncError(`Репозиторий «${cfg.repo}» не найден — проверьте название и доступ токена`);
  let data = {};
  try { data = await r.json(); } catch (e) { /* пусто */ }
  return { status: r.status, data };
}
async function upload(path, text, message) {
  const { status, data } = await gh("PUT", path, { message, content: b64(enc.encode(text)) });
  if (status !== 200 && status !== 201) throw new SyncError("Не получилось отправить на GitHub (" + (data.message || status) + ")");
}
async function download(path) {
  const { status, data } = await gh("GET", path);
  if (status === 404) return null;
  if (status !== 200 || !data.content) throw new SyncError("Не получилось скачать сводку (" + (data.message || status) + ")");
  return dec.decode(unb64(data.content.replace(/\s/g, "")));
}
function needSetup() {
  if (SRV) return cfg.srvToken ? "" : "Войдите на сервер — вкладка «Настройки» → «Вход»";
  if (!cfg.repo || !cfg.repo.includes("/")) return "Укажите репозиторий синхронизации (вкладка «Настройки»)";
  if (!cfg.ghToken) return "Вставьте токен GitHub (вкладка «Настройки»)";
  if (!cfg.pw) return "Введите пароль синхронизации (вкладка «Настройки»)";
  return "";
}

/* ------------------------------------------------------------------ сервер */
async function srv(method, path, body) {
  let r;
  try {
    r = await fetch(path, { method, cache: "no-store",
      headers: { "Content-Type": "application/json", ...(cfg.srvToken ? { Authorization: "Bearer " + cfg.srvToken } : {}) },
      body: body ? JSON.stringify(body) : undefined });
  } catch (e) {
    throw new SyncError(navigator.onLine === false ? "Нет интернета — записи подождут на телефоне"
      : "Сервер не ответил — проверьте интернет. Записи остались на телефоне.");
  }
  let data = {};
  try { data = await r.json(); } catch (e) { /* пусто */ }
  if (r.status === 401 && path !== "/api/login") {
    cfg.srvToken = ""; saveCfg();
    throw new SyncError("Нужно войти заново: «Настройки» → «Вход на сервер»");
  }
  if (!r.ok) throw new SyncError(data.error || ("Сервер ответил ошибкой " + r.status));
  return data;
}
function localKey() {
  /* сводка на телефоне под PIN шифруется случайным ключом этого телефона (не паролем сервера) */
  if (!cfg.pw) { const a = crypto.getRandomValues(new Uint8Array(24)); cfg.pw = b64(a); saveCfg(); }
  return cfg.pw;
}
async function srvLogin(password) {
  const d = await srv("POST", "/api/login", { password, device: "телефон · " + (navigator.platform || "") });
  cfg.srvToken = d.token; localKey(); saveCfg();
}
function pendingPayload(pending) {
  return {
    f: FORMAT, sent: new Date().toISOString(), device: navigator.userAgent.slice(0, 80),
    entries: pending.map((e) => (e.kind === "bank"
      ? { id: e.id, date: e.date, kind: "bank", real: e.real, diff: e.diff, record: e.record, created: e.created }
      : e.kind === "done" ? { id: e.id, date: e.date, kind: "done", row_id: e.row_id, row_name: e.row_name || "", created: e.created }
      : e.kind === "cycle" ? { id: e.id, date: e.date, kind: "cycle", flow: e.flow || 0, created: e.created }
      : e.kind === "mark" ? { id: e.id, date: e.date, kind: "mark", title: e.title, mark_kind: e.mark_kind, created: e.created }
      : e.kind === "markdel" ? { id: e.id, date: e.date, kind: "markdel", mark_id: e.mark_id, created: e.created }
      : e.kind === "rowdel" ? { id: e.id, date: e.date, kind: "rowdel", row_id: e.row_id, row_name: e.row_name || "", created: e.created }
      : e.kind === "rowedit" ? { id: e.id, date: e.date, kind: "rowedit", row_id: e.row_id, row_name: e.row_name || "", amount: e.amount, new_date: e.new_date, half: e.half || null, created: e.created }
      : e.kind === "rowadd" ? { id: e.id, date: e.date, kind: "rowadd", row_kind: e.row_kind, category: e.category, note: e.note,
        amount: e.amount, half: e.half, done: !!e.done, created: e.created }
      : e.kind === "paste" ? { id: e.id, date: e.date, kind: "paste", items: e.items, created: e.created }
      : GENERIC_KINDS.includes(e.kind) ? { ...(e.p || {}), id: e.id, date: e.date, kind: e.kind, created: e.created }
      : e.kind === "fundpay" ? { id: e.id, date: e.date, kind: "fundpay", fund: e.fund, amount: e.amount,
        category: e.category, note: e.note, row_id: e.row_id || null, row_name: e.row_name || "", created: e.created }
      : { id: e.id, date: e.date, kind: e.kind, amount: e.amount, category: e.category,
        note: e.note, half: e.half || null, row_id: e.row_id || null, row_name: e.row_name || "", created: e.created,
        rev: e.rev || 0, deleted: !!e.deleted })),
  };
}
async function syncServer(quiet, pending) {
  let data;
  if (pending.length) {
    data = await srv("POST", "/api/push", { payload: pendingPayload(pending) });
    const now = new Date().toISOString();
    pending.forEach((e) => { e.status = "sent"; e.sent_at = now; });
    entries = entries.filter((e) => !(e.deleted && e.status === "sent"));
    saveEntries();
  } else {
    data = await srv("GET", "/api/snapshot");
  }
  if (data.snapshot) {
    snap = data.snapshot;
    saveSnap(await encryptObj(snap, localKey()));
    const got = new Set(snap.received || []);
    let changed = false;
    entries.forEach((e) => { if (e.status === "sent" && got.has(e.id)) { e.status = "done"; changed = true; } });
    if (changed) saveEntries();
  }
  if (!quiet || pending.length) toast(pending.length ? `Записано в лист: ${pending.length}` : "Данные обновлены ✓", 3500);
}

/* ------------------------------------------------------------------ синхронизация */
let syncing = false;
async function sync(quiet = false) {
  if (syncing || locked) return;
  const why = needSetup();
  if (why) { if (!quiet) { toast(why); showPage("set"); } return; }
  if (quiet && navigator.onLine === false) return;
  syncing = true;
  $("syncBtn").classList.add("busy");
  $("syncText").textContent = "Синхронизирую…";
  try {
    const pending = entries.filter((e) => e.mode === "send" && e.status === "pending");
    if (SRV) { await syncServer(quiet, pending); cfg.lastSync = new Date().toISOString(); saveCfg(); return; }
    if (pending.length) {
      const payload = pendingPayload(pending);
      const name = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14) + "-" + uid().slice(0, 8) + ".enc";
      await upload(`${INBOX}/${name}`, await encryptObj(payload, cfg.pw), "phone: " + pending.length);
      const now = new Date().toISOString();
      pending.forEach((e) => { e.status = "sent"; e.sent_at = now; });
      entries = entries.filter((e) => !(e.deleted && e.status === "sent"));   // удаление ушло на компьютер
      saveEntries();
    }
    const text = await download(SNAPSHOT);
    let note = "";
    if (text) {
      snap = await decryptText(text, cfg.pw);
      saveSnap(text);
      const got = new Set(snap.received || []);
      let changed = false;
      entries.forEach((e) => { if (e.status === "sent" && got.has(e.id)) { e.status = "done"; changed = true; } });
      if (changed) saveEntries();
    } else {
      note = " · сводки с компьютера пока нет: откройте программу на компьютере";
    }
    if (!quiet || pending.length) toast((pending.length ? `Отправлено: ${pending.length}` : "Новых записей для компьютера нет") + note, 4200);
    cfg.lastSync = new Date().toISOString(); saveCfg();
  } catch (e) {
    if (!quiet || !(e instanceof SyncError) || !/интернет/.test(e.message)) toast(e instanceof SyncError ? e.message : "Ошибка: " + e.message, 5200);
  } finally {
    syncing = false;
    $("syncBtn").classList.remove("busy");
    renderAll();
  }
}

let autoTimer = null;
function autoSync(delay = 1500) {
  /* сама отправляет записи и забирает сводку: после записи, при открытии и при возврате в приложение.
     Без интернета — тихо ждёт: записи останутся «ждут отправки», кнопка «Синхронизировать» всегда под рукой. */
  clearTimeout(autoTimer);
  autoTimer = setTimeout(() => sync(true), delay);
}

/* ------------------------------------------------------------------ PIN-код */
const PIN_ITER = 300000;
let pinTries = 0, pinWait = 0, pinBuf = "", hiddenAt = 0;
async function pinKey(pin, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode("mf-pin:" + pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: PIN_ITER, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function pinSet(pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await pinKey(pin, salt),
    enc.encode(JSON.stringify({ ghToken: cfg.ghToken, pw: cfg.pw, srvToken: cfg.srvToken || "" })));
  cfg.pinBox = { salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  cfg.pinLen = pin.length;
  if (snap && !store.get("snapBox", null) && cfg.pw) store.set("snapBox", await encryptObj(snap, cfg.pw));
  cfg.pinOn = true;
  saveCfg();
  saveSnap(null);
}
async function pinOpen(pin) {
  const box = cfg.pinBox;
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, await pinKey(pin, unb64(box.salt)), unb64(box.ct));
    const sec = JSON.parse(dec.decode(plain));
    cfg.ghToken = sec.ghToken; cfg.pw = sec.pw; cfg.srvToken = sec.srvToken || "";
  } catch (e) { return false; }
  const sb = store.get("snapBox", null);
  if (sb && cfg.pw) { try { snap = await decryptText(sb, cfg.pw); } catch (e) { snap = null; } }
  return true;
}
function lockNow() {
  if (!cfg.pinOn) return;
  locked = true;
  cfg.ghToken = ""; cfg.pw = ""; cfg.srvToken = ""; snap = null;           // в памяти — ничего секретного, пока PIN не введён
  pinBuf = "";
  document.querySelectorAll(".sheet-bg").forEach((x) => x.remove());
  $("lock").hidden = false;
  drawPin("");
}
function drawPin(msg) {
  const n = cfg.pinLen || 4;
  $("pinDots").innerHTML = Array.from({ length: n }, (_, i) => `<i class="${i < pinBuf.length ? "on" : ""}"></i>`).join("");
  if (msg !== undefined) $("pinMsg").textContent = msg;
}
async function pinPress(k) {
  if (Date.now() < pinWait) { drawPin(`Подождите ${Math.ceil((pinWait - Date.now()) / 1000)} с`); return; }
  if (k === "del") { pinBuf = pinBuf.slice(0, -1); drawPin(); return; }
  if (pinBuf.length >= (cfg.pinLen || 4)) return;
  pinBuf += k; drawPin();
  if (pinBuf.length === (cfg.pinLen || 4)) {
    drawPin("Проверяю…");
    const ok = await pinOpen(pinBuf);
    if (ok) {
      locked = false; pinTries = 0; pinBuf = "";
      $("lock").hidden = true;
      renderAll();
      autoSync(300);
    } else {
      pinTries += 1; pinBuf = "";
      if (pinTries >= 5) { pinWait = Date.now() + 30000 * (pinTries - 4); drawPin("Неверно. Подождите 30 секунд"); }
      else drawPin(`Неверный PIN-код (попытка ${pinTries} из 5)`);
      const d = $("pinDots"); d.classList.remove("shake"); void d.offsetWidth; d.classList.add("shake");
    }
  }
}
function pinForgot() {
  if (!confirm("Сбросить PIN-код? Токен, пароль и сводка на телефоне сотрутся — их нужно будет ввести заново. " +
    "Записи на телефоне останутся.")) return;
  cfg.pinOn = false; cfg.pinBox = null; cfg.ghToken = ""; cfg.pw = ""; cfg.srvToken = ""; snap = null;
  try { localStorage.removeItem("mf.snap"); localStorage.removeItem("mf.snapBox"); } catch (e) { /* нет */ }
  saveCfg();
  locked = false; $("lock").hidden = true; renderAll(); showPage("set");
}
function pinSetupDialog() {
  if (SRV ? !cfg.srvToken : (!cfg.ghToken || !cfg.pw)) { toast(SRV ? "Сначала войдите на сервер" : "Сначала вставьте токен и пароль синхронизации"); return; }
  sheetDialog(`<h2>${cfg.pinOn ? "Сменить PIN-код" : "Поставить PIN-код"}</h2>
    <p class="hint">Код будет спрашиваться при каждом открытии приложения и через минуту после сворачивания.
    Токен, пароль и сводка на телефоне хранятся зашифрованными этим кодом. Лучше 6 цифр.</p>
    <label class="field"><span>PIN-код (4–6 цифр)</span><input id="pinA" type="password" inputmode="numeric" maxlength="6" autocomplete="off"></label>
    <label class="field"><span>Ещё раз</span><input id="pinB" type="password" inputmode="numeric" maxlength="6" autocomplete="off"></label>
    <button class="primary" data-a="pin">Сохранить PIN-код</button>`, (a) => {
    if (a !== "pin") return;
    const p1 = $("pinA").value.trim(), p2 = $("pinB").value.trim();
    if (!/^\d{4,6}$/.test(p1)) { toast("PIN — от 4 до 6 цифр"); return false; }
    if (p1 !== p2) { toast("PIN-коды не совпадают"); return false; }
    pinSet(p1).then(() => { renderSettings(); toast("PIN-код поставлен ✓"); });
  });
}
function pinRemove() {
  if (!confirm("Убрать PIN-код? Токен и пароль снова будут храниться на телефоне без защиты кодом.")) return;
  cfg.pinOn = false; cfg.pinBox = null; saveCfg(); saveSnap(null); renderSettings(); toast("PIN-код убран");
}

/* ------------------------------------------------------------------ настройки из ссылки */
function readHash() {
  const h = new URLSearchParams(location.hash.slice(1));
  if (h.get("repo")) { cfg.repo = cleanRepo(h.get("repo")); saveCfg(); }
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
}

/* ------------------------------------------------------------------ форма записи */
function categories() {
  const c = snap && snap.categories;
  return kind === "income" ? ((c && c.income) || INCOME_DEFAULT) : ((c && c.expense) || EXPENSE_DEFAULT);
}
function planRows() {
  if (!snap || !snap.halves) return [];
  const out = [];
  snap.halves.forEach((h) => h.rows.forEach((r) => {
    if (!r.credit && !r.fund && r.left > 0.5) out.push({ ...r, half: h.half, htitle: h.title });
  }));
  return out;
}
function fillForm() {
  const cat = $("category"), keep = cat.value;
  cat.innerHTML = categories().map((c) => `<option>${esc(c)}</option>`).join("");
  const last = kind === "income" ? cfg.lastInc : cfg.lastExp;
  const want = [keep, last, kind === "income" ? "Зарплата" : "Продукты"].find((c) => c && categories().includes(c));
  if (want) cat.value = want;
  const rows = planRows();
  $("rowField").hidden = kind !== "expense" || !rows.length;
  const rowSel = $("row"), keepRow = rowSel.value;
  rowSel.innerHTML = `<option value="">— не из плана, новой строкой —</option>` + rows.map((r) =>
    `<option value="${r.id}">${esc(r.name)} · ост. ${fmt(r.left)} (${esc(r.htitle.toLowerCase())})</option>`).join("");
  if (keepRow && rows.some((r) => String(r.id) === keepRow)) rowSel.value = keepRow;
  if (!$("date").value) $("date").value = todayISO();
  document.querySelectorAll("#addForm .seg button").forEach((b) => b.classList.toggle("on", b.dataset.kind === kind));
  document.querySelectorAll(".dest button").forEach((b) => b.classList.toggle("on", b.dataset.mode === mode));
  $("destHint").textContent = mode === "send"
    ? "Уйдёт в лист месяца на компьютере при синхронизации."
    : "Останется только на телефоне — на компьютер не попадёт (можно отправить позже из «Записей»).";
}
function onRowChange() {
  const r = planRows().find((x) => String(x.id) === $("row").value);
  if (r) {
    if (categories().includes(r.category)) $("category").value = r.category;
    $("half").value = String(r.half);
    if (!$("note").value) $("note").placeholder = r.name;
  }
}
function parseAmount(s) {
  const v = Number(String(s).replace(/\s| /g, "").replace(",", "."));
  return Number.isFinite(v) ? Math.round(v * 100) / 100 : NaN;
}
let editingId = null;
function setEditing(id) {
  editingId = id;
  const b = $("editBanner");
  if (b) b.hidden = !id;
  if ($("submitBtn")) $("submitBtn").textContent = id ? "Сохранить" : "Записать";
}
function onSubmit(ev) {
  ev.preventDefault();
  const amount = parseAmount($("amount").value);
  if (!(amount > 0)) { toast("Введите сумму"); $("amount").focus(); return; }
  const rowId = kind === "expense" && $("row").value ? Number($("row").value) : null;
  const row = rowId ? planRows().find((r) => r.id === rowId) : null;
  const e = {
    id: uid(), created: new Date().toISOString(), date: $("date").value || todayISO(), kind, amount,
    category: $("category").value, note: $("note").value.trim() || (row ? row.name : ""),
    half: Number($("half").value) || 0, row_id: rowId, row_name: row ? row.name : "",
    mode, status: mode === "send" ? "pending" : "local",
  };
  const editIdx = editingId ? entries.findIndex((x) => x.id === editingId) : -1;
  let old = null;
  if (editIdx >= 0) {                       // правка записи: тот же id, на том же месте
    old = entries[editIdx];
    e.id = old.id; e.created = old.created;
    if (old.status === "sent") {             // уже отправлена — уходит исправление (rev+1), только на компьютер
      e.rev = (old.rev || 0) + 1; e.mode = "send"; e.status = "pending";
    }
    entries[editIdx] = e;
  } else entries.unshift(e);
  if (!saveEntries()) { if (old) entries[editIdx] = old; else entries.shift(); return; }
  setEditing(null);
  cfg.lastMode = mode;
  if (kind === "income") cfg.lastInc = e.category; else cfg.lastExp = e.category;
  saveCfg();
  $("amount").value = ""; $("note").value = ""; $("row").value = ""; $("note").placeholder = "например: кофе, продукты в Самокате";
  toast((kind === "income" ? "Доход " : "Трата ") + fmtExact(amount) + (mode === "send" ? " — отправляю…" : " — только на телефоне"));
  renderAll();
  if (mode === "send") autoSync();
}

/* ------------------------------------------------------------------ иконки категорий (тонкие линии) */
const ICON = {
  "Продукты": '<path d="M3 4h3l3 11h10"/><path d="M8 8h13l-2 5H9.5"/><circle cx="10" cy="19" r="1.4"/><circle cx="18" cy="19" r="1.4"/>',
  "Обеды и кафе": '<path d="M4 9h12v5a5 5 0 0 1-5 5h-2a5 5 0 0 1-5-5z"/><path d="M16 11h2a2.5 2.5 0 0 1 0 5h-2.5M8 3v3M12 3v3"/>',
  "Обеды в офисе": '<rect x="4" y="9" width="16" height="10" rx="2"/><path d="M4 13h16M9 9V6h6v3"/>',
  "Транспорт": '<rect x="5" y="3" width="14" height="15" rx="3"/><path d="M5 11h14M8 18v3M16 18v3"/>',
  "Связь": '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18h2"/>',
  "Подписки": '<path d="M4 14a8 8 0 0 1 16 0"/><rect x="3" y="13" width="4" height="7" rx="1.5"/><rect x="17" y="13" width="4" height="7" rx="1.5"/>',
  "Одежда и маркетплейсы": '<path d="M9 3 4 6l2 4 2-1v12h8V9l2 1 2-4-5-3a3 3 0 0 1-6 0z"/>',
  "Красота и уход": '<path d="M12 2c.5 6 3.5 9 10 10-6.5 1-9.5 4-10 10-.5-6-3.5-9-10-10 6.5-1 9.5-4 10-10z"/>',
  "Здоровье и врачи": '<path d="M12 2c4 5 7 8 7 12a7 7 0 0 1-14 0c0-4 3-7 7-12z"/><path d="M12 11v6M9 14h6"/>',
  "Дом и быт": '<path d="M3 11 12 3l9 8v10H3z"/><path d="M10 21v-6h4v6"/>',
  "Подарки": '<rect x="4" y="9" width="16" height="12" rx="2"/><path d="M3 7h18v3H3zM12 7v14"/><path d="M12 7c-2-4-6-3-5 0M12 7c2-4 6-3 5 0"/>',
  "Квартира": '<path d="M3 11 12 3l9 8v10H3z"/><path d="M10 21v-6h4v6"/>',
  "Кредиты и платежи": '<rect x="3" y="6" width="18" height="12" rx="2.5"/><path d="M3 10h18M7 15h4"/>',
  "Поездки и отпуск": '<path d="M2.5 13.5 21 6l-4 13-4.5-4.5L9 18l-.5-5z"/>',
  "Хобби и творчество": '<path d="M14.5 4.5l5 5L10 19H5v-5z"/><path d="M12.5 6.5l5 5"/>',
  "Развлечения и прогулки": '<path d="M12 3l2.6 5.6 6 .6-4.5 4 1.3 6L12 16.2 6.6 19.2l1.3-6-4.5-4 6-.6z"/>',
  "Переводы близким": '<path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/>',
  "Непредвиденное": '<path d="M12 3 2.5 20h19z"/><path d="M12 10v4.5M12 17.5v.01"/>',
  "_refund": '<path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-3"/>',
  "_income": '<path d="M12 19V5M6 11l6-6 6 6"/>',
  "_fund": '<ellipse cx="12" cy="13" rx="8" ry="6"/><path d="M9 9h5M7 18v3M17 18v3"/>',
  "_default": '<circle cx="12" cy="12" r="4"/>',
};
const ICON_CHECK = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16.5 9.5"/></svg>';
const ICON_BANK = '<svg viewBox="0 0 24 24"><path d="M3 10 12 4l9 6"/><path d="M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18"/></svg>';
function iconFor(e) {
  const k = e.kind === "income" ? "_income" : (e.category || "").startsWith("В фонд") ? "_fund"
    : ICON[e.category] ? e.category : "_default";
  return `<svg viewBox="0 0 24 24">${ICON[k]}</svg>`;
}

/* ------------------------------------------------------------------ отрисовка */
function badge(e) {
  if (e.deleted) return '<span class="badge pending">удаление ждёт отправки</span>';
  if (e.rev && e.status === "pending") return '<span class="badge pending">исправление ждёт отправки</span>';
  return { pending: '<span class="badge pending">ждёт отправки</span>', sent: '<span class="badge sent">отправлено</span>',
    done: '<span class="badge done">в листе ✓</span>', local: '<span class="badge local">только телефон</span>' }[e.status] || "";
}
function phoneEntryHtml(e) {
  const half = e.half || autoHalf(e.date, e.kind === "income" ? e.category : "");
  if (e.kind === "done" || e.kind === "fundpay") {
    const t = e.kind === "done" ? `Оплачено ● «${esc(e.row_name)}»` : `Из фонда «${esc(e.fund)}» · ${esc(e.note || e.category)}`;
    const sub = e.kind === "done" ? "отметка в листе" : esc(e.category);
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">${e.kind === "done" ? ICON_CHECK : `<svg viewBox="0 0 24 24">${ICON._fund}</svg>`}</div><div class="mid">
      <div class="t">${t}</div><div class="s">${ddmm(e.date)} · ${sub} ${badge(e)}</div></div>
      <div class="sum">${e.kind === "fundpay" ? "−" + fmtExact(e.amount) : ""}</div></div>`;
  }
  if (e.kind === "rowdel" || e.kind === "rowedit") {
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">${e.kind === "rowdel" ? "✕" : "✎"}</div><div class="mid">
      <div class="t">${e.kind === "rowdel" ? "Удалить из листа" : "Изменить строку"}: ${esc(e.row_name)}</div>
      <div class="s">${e.kind === "rowedit" ? `${ddmm(e.new_date)} · ${fmt(e.amount)} ` : ""}${badge(e)}</div></div><div class="sum"></div></div>`;
  }
  if (GENERIC_KINDS.includes(e.kind)) {
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">${esc(e.icon || "•")}</div><div class="mid">
      <div class="t">${esc(e.title || e.kind)}</div><div class="s">${ddmm(e.date)} ${badge(e)}</div></div><div class="sum"></div></div>`;
  }
  if (e.kind === "rowadd") {
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">＋</div><div class="mid">
      <div class="t">Новая строка: ${esc(e.note || e.category)}</div>
      <div class="s">${ddmm(e.date)} · ${esc(e.category)} · ${HALF_NAME[e.half]}${e.done ? " · ●" : ""} ${badge(e)}</div></div>
      <div class="sum ${e.row_kind === "income" ? "green" : ""}">${e.row_kind === "income" ? "+" : ""}${fmt(e.amount)}</div></div>`;
  }
  if (e.kind === "paste") {
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">📋</div><div class="mid">
      <div class="t">Вставка: ${e.items.length} опер.</div>
      <div class="s">${ddmm(e.date)} · ${esc(e.note || "")} ${badge(e)}</div></div>
      <div class="sum">${e.amount ? "−" + fmtExact(e.amount) : ""}</div></div>`;
  }
  if (e.kind === "mark" || e.kind === "markdel") {
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">${e.kind === "mark" ? "📝" : "✕"}</div><div class="mid">
      <div class="t">${e.kind === "mark" ? "В календарь" : "Убрать из календаря"}: ${esc(e.title)}</div>
      <div class="s">${ddmm(e.date)} ${badge(e)}</div></div><div class="sum"></div></div>`;
  }
  if (e.kind === "cycle") {
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">🌸</div><div class="mid">
      <div class="t">Цикл: ${e.flow ? FLOW_NAMES[e.flow] : "без выделений"}</div><div class="s">${ddmm(e.date)} · отметка в «Здоровье» ${badge(e)}</div></div>
      <div class="sum"></div></div>`;
  }
  if (e.kind === "bank") {
    return `<div class="entry tap" data-id="${e.id}"><div class="ic">${ICON_BANK}</div><div class="mid">
      <div class="t">Сверка с банком</div><div class="s">${ddmm(e.date)} · ${esc(e.note)} ${badge(e)}</div></div>
      <div class="sum">${e.record && e.diff ? (e.diff < 0 ? "−" : "+") + fmtExact(Math.abs(e.diff)) : ""}</div></div>`;
  }
  return `<div class="entry tap" data-id="${e.id}"><div class="ic">${iconFor(e)}</div><div class="mid">
    <div class="t">${esc(e.note || e.category)}</div>
    <div class="s">${ddmm(e.date)} · ${esc(e.category)}${e.row_name ? " · из «" + esc(e.row_name) + "»" : ""} · ${HALF_NAME[half]} ${badge(e)}</div></div>
    <div class="sum ${e.kind === "income" ? "green" : ""}">${e.kind === "income" ? "+" : "−"}${fmtExact(e.amount)}</div></div>`;
}
function renderList() {
  /* записи с телефона, которых ещё нет в листе на компьютере (ждут отправки, отправлены, только на телефоне) */
  const q = (($("opsSearch") && $("opsSearch").value) || "").trim().toLowerCase();
  const list = entries.filter((e) => e.status !== "done" && (!q || `${e.note} ${e.category} ${e.row_name || ""} ${e.fund || ""}`.toLowerCase().includes(q)));
  if (!list.length) { $("phoneList").innerHTML = opsKind === "phone" ? `<div class="card empty">Все записи с телефона уже в листе на компьютере ✓</div>` : ""; return; }
  $("phoneList").innerHTML = `<div class="day-head"><div class="sec">📱 С телефона — ещё не в листе</div><div class="tot">${list.length}</div></div>
    <div class="card" style="padding:0">${list.map(phoneEntryHtml).join("")}</div>`;
}

/* ------------------------------------------------------------------ Операции (как выписка) */
let opsIdx = 0, opsKind = "all";
function buildOps(sh) {
  /* операции листа: доходы, траты из строк (каждая отдельно) и оплаченные строки без трат */
  const out = [];
  sh.halves.forEach((hf) => {
    const col = hf.half === 1 ? "з/п" : "аванс";
    hf.incomes.filter((r) => r.date <= todayISO()).forEach((r) => out.push({ date: r.date, title: r.name, sub: `${r.fund ? "из фонда" : r.category} · ${col}`,
      amount: r.amount, inc: true, cat: r.category }));
    hf.rows.forEach((r) => {
      const sp = r.spends || [];
      if (sp.length) {
        sp.forEach((x) => out.push({ date: x.date, title: x.note || r.name, sub: `из «${r.name}» · ${col}`,
          amount: Math.abs(x.amount), inc: x.amount < 0, refund: x.amount < 0, cat: r.category, row: r.id }));
      } else if (r.done) {
        out.push({ date: r.date, title: r.name, sub: `${r.category}${r.from_fund ? " · из фонда" : ""} · ${col}`,
          amount: r.amount, inc: false, cat: r.category, row: r.id, fund: r.fund });
      }
    });
  });
  out.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  return out;
}
function renderOps() {
  renderList();
  const box = $("ops");
  $("opsMonths").innerHTML = snap && snap.sheets ? snap.sheets.map((x, i) =>
    `<button type="button" class="chip ${i === opsIdx ? "on" : ""}" data-opsm="${i}">${esc(x.title)}</button>`).join("") : "";
  if (opsKind === "phone") { box.innerHTML = ""; return; }
  if (!snap || !snap.sheets) { box.innerHTML = `<div class="card empty">Операции появятся после синхронизации с компьютером.</div>`; return; }
  opsIdx = Math.min(opsIdx, snap.sheets.length - 1);
  const q = ($("opsSearch").value || "").trim().toLowerCase();
  let ops = buildOps(snap.sheets[opsIdx]);
  if (opsKind === "out") ops = ops.filter((o) => !o.inc);
  if (opsKind === "in") ops = ops.filter((o) => o.inc);
  if (q) ops = ops.filter((o) => `${o.title} ${o.sub} ${o.cat}`.toLowerCase().includes(q));
  const spent = ops.filter((o) => !o.inc && !o.fund).reduce((a, o) => a + o.amount, 0);
  const got = ops.filter((o) => o.inc && !o.refund).reduce((a, o) => a + o.amount, 0);
  let h = (opsIdx === 0 && !q ? lastSpendsHint() : "") + `<div class="totals"><div class="card"><div class="k">Траты${q ? " (найдено)" : ""}</div><div class="v">${fmt(spent)}</div></div>
    <div class="card"><div class="k">Доходы</div><div class="v green">+${fmt(got)}</div></div></div>`;
  if (!ops.length) { box.innerHTML = h + `<div class="card empty">Ничего не нашлось</div>`; return; }
  let day = "";
  ops.forEach((o, i) => {
    if (o.date !== day) {
      if (day) h += "</div>";
      day = o.date;
      const dayOut = ops.filter((x) => x.date === day && !x.inc && !x.fund).reduce((a, x) => a + x.amount, 0);
      const isToday = day === todayISO();
      h += `<div class="day-head"><div class="sec">${ddmm(day)}${isToday ? " · сегодня" : ""}</div>
        <div class="tot">${dayOut ? "−" + fmt(dayOut) : ""}</div></div><div class="card" style="padding:0">`;
    }
    const icon = o.refund ? ICON._refund : o.inc ? ICON._income
      : ICON[o.cat] || (o.fund || (o.cat || "").startsWith("В фонд") ? ICON._fund : ICON._default);
    h += `<div class="entry tap" data-op="${i}"><div class="ic"><svg viewBox="0 0 24 24">${icon}</svg></div><div class="mid">
      <div class="t">${esc(o.title)}</div><div class="s">${esc(o.sub)}</div></div>
      <div class="sum ${o.inc ? "green" : ""}">${o.inc ? "+" : "−"}${fmtExact(o.amount)}</div></div>`;
  });
  box.innerHTML = h + "</div>";
  box._ops = ops;
}
function openOp(i) {
  const o = ($("ops")._ops || [])[i];
  if (!o) return;
  if (o.row) { openRow(o.row); return; }
  sheetDialog(`<h2>${esc(o.title)} · ${o.inc ? "+" : "−"}${fmtExact(o.amount)}</h2>
    <p class="hint">${ddmm(o.date)} · ${esc(o.sub)}</p>`, () => {});
}

function unsentExpenses() {
  /* Траты «на компьютер», которых ещё нет в сводке. Трата из строки-плана (или той же категории, где план
     ещё не потрачен) свободные деньги не уменьшает — она уже была запланирована; вычитаем только сверх плана. */
  const got = new Set((snap && snap.received) || []);
  const pool = new Map(planRows().map((r) => [r.id, { left: r.left, category: r.category }]));
  let extra = 0;
  entries.filter((e) => e.kind === "expense" && e.mode === "send" && !got.has(e.id) && e.status !== "done" && !e.deleted)
    .slice().reverse().forEach((e) => {
      let id = e.row_id && pool.has(e.row_id) ? e.row_id : null;
      if (!id) for (const [rid, r] of pool) if (r.category === e.category && r.left > 0.5) { id = rid; break; }
      if (!id) { extra += e.amount; return; }
      const r = pool.get(id);
      const take = Math.min(r.left, e.amount);
      r.left -= take;
      extra += e.amount - take;
    });
  return extra;
}
function localSpentThisMonth() {
  const ym = todayISO().slice(0, 7);
  return entries.filter((e) => e.kind === "expense" && e.status === "local" && e.date.startsWith(ym)).reduce((s, e) => s + e.amount, 0);
}
function todayBlock() {
  if (!snap || !snap.today) {
    return `<div class="muted">Сводки с компьютера пока нет. Нажмите «Синхронизировать», когда на компьютере будет настроена синхронизация.</div>`;
  }
  const t = snap.today;
  const extra = unsentExpenses();
  const free = t.free - extra;
  const nextPay = new Date(t.next_pay + "T00:00:00");
  const days = Math.max(1, Math.round((nextPay - new Date(todayISO() + "T00:00:00")) / 86400000));
  const perDay = Math.max(0, free) / days;
  const status = free < 0 ? "red" : perDay < 500 ? "yellow" : "green";
  let html = `<div class="big"><span class="dot ${status}"></span>${free < 0 ? "Не хватает " + fmt(-free) : "Можно ~<b>" + fmt(perDay) + "</b> в день"}</div>
    <div class="hint">свободно до ${ddmm(t.next_pay)}: ${fmt(free)} · ${days} дн. · колонка «${esc(t.column.toLowerCase())}»</div>`;
  if (t.note) html += `<div class="hint">${esc(t.note)}</div>`;
  if (extra > 0) html += `<div class="hint">учтены траты с телефона сверх плана, которых ещё нет на компьютере: −${fmt(extra)}</div>`;
  const loc = localSpentThisMonth();
  if (loc > 0) html += `<div class="hint">только на телефоне в этом месяце: ${fmt(loc)} (в расчёт не входят)</div>`;
  return html;
}
function heroCard() {
  /* главная карта: сколько можно тратить — розово-сиреневая, как банковская карта */
  if (!snap.today) return `<div class="card hero">${todayBlock()}</div>`;
  const t = snap.today, extra = unsentExpenses(), free = t.free - extra;
  const days = Math.max(1, Math.round((new Date(t.next_pay + "T00:00:00") - new Date(todayISO() + "T00:00:00")) / 86400000));
  const perDay = Math.max(0, free) / days;
  const status = free < 0 ? "red" : perDay < 500 ? "yellow" : "green";
  const chips = [`до ${ddmm(t.next_pay)} · ${days} дн.`, `колонка «${t.column.toLowerCase()}»`];
  if (snap.cards != null) chips.push(`на картах ≈ ${fmt(snap.cards)}`);
  chips.push(snap.bank && snap.bank.last_check ? `сверка ${ddmm(snap.bank.last_check)}` : "сверки ещё не было");
  return `<div class="card hero">
    <div class="k"><span class="dot ${status}"></span>${free < 0 ? "До выплаты не хватает" : "Можно потратить сегодня"}</div>
    <div class="big">${free < 0 ? fmt(-free) : "~" + fmt(perDay)}</div>
    <div class="hint">${free < 0 ? "денег колонки не хватает на всё запланированное" : `свободно до выплаты ${fmt(free)}`}</div>
    ${t.note ? `<div class="hint">${esc(t.note)}</div>` : ""}
    ${extra > 0 ? `<div class="hint">учтены траты с телефона сверх плана: −${fmt(extra)}</div>` : ""}
    <div class="chipline">${chips.map((c) => `<span>${esc(c)}</span>`).join("")}</div></div>`;
}
function renderSummary() {
  /* Главная — только то, чего нет на других вкладках: сколько можно тратить, «До зарплаты», важное.
     Строки листа — в «Листе», платежи — в «Кредитах», фонды — в «Ещё». */
  if (!snap) {
    $("summary").innerHTML = updateBanner() + `<div class="card empty">Сводка появится после первой синхронизации.<br>На компьютере: «☰ Ещё → 📲 Телефон → Настроить».</div>`;
    return;
  }
  const imp = importantItems();
  const impLine = (r) => `<div class="line"><span>${esc(r.icon)} ${esc(r.text)}</span></div>`;
  let h = updateBanner() + staleBanner() + heroCard();
  h += `<div class="qa">
    <button type="button" data-go="add"><i><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg></i>Записать</button>
    <button type="button" data-go="bank"><i><svg viewBox="0 0 24 24"><path d="M3 10 12 4l9 6"/><path d="M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18"/></svg></i>Сверка</button>
    <button type="button" data-go="credits"><i><svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="2.5"/><path d="M3 10h18M7 15h4"/></svg></i>Кредиты</button>
    <button type="button" data-go="funds"><i><svg viewBox="0 0 24 24"><path d="M5 11a7 6 0 0 1 13-2h2v4l-2 1v3h-3v-2H9v2H6v-3a6 6 0 0 1-1-3z"/><circle cx="15" cy="10" r=".6"/></svg></i>Фонды</button>
  </div>`;
  h += walletCard();
  h += imp.length ? `<div class="card soft"><h2>🔔 Важное</h2>${imp.slice(0, 4).map(impLine).join("")}` +
    (imp.length > 4 ? `<details><summary>ещё ${imp.length - 4}</summary>${imp.slice(4).map(impLine).join("")}</details>` : "") + `</div>` : "";
  const nx = nextPayments(1)[0];
  if (nx) h += `<div class="card tap" data-go="credits" style="cursor:pointer"><div class="line" style="border:0;padding:0">
    <span>💳 Ближайший платёж: <b>${ddmm(nx.due)}</b> · ${esc(nx.name)}</span><span class="r">${fmt(nx.amount)} ›</span></div></div>`;
  $("summary").innerHTML = h;
  walletCardBind();
}
/* ------------------------------------------------------------------ Лист месяца (как на компьютере) */
let sheetIdx = 0, sheetMode = "cols";
function rowActual(r) { return r.spent ? r.spent : (r.done ? r.amount : 0); }
function phoneUnsentFor(sheet) {
  /* записи с телефона «на компьютер», которых ещё нет в листе, — за этот бюджетный месяц */
  const got = new Set((snap && snap.received) || []);
  const from = `${sheet.year}-${String(sheet.month).padStart(2, "0")}-10`;
  const nm = sheet.month === 12 ? `${sheet.year + 1}-01-09` : `${sheet.year}-${String(sheet.month + 1).padStart(2, "0")}-09`;
  return entries.filter((e) => (e.kind === "expense" || e.kind === "income") && e.mode === "send" && e.status !== "done"
    && !e.deleted && !got.has(e.id) && e.date >= from && e.date <= nm);
}
function viewSeg(on) {
  /* один переключатель вида: колонки · категории · операции */
  const b = (k, t) => `<button type="button" class="${on === k ? "on" : ""}" data-view="${k}">${t}</button>`;
  return `<div class="seg view-seg">${b("cols", "Колонки")}${b("cats", "Категории")}${b("ops", "Операции")}</div>`;
}
function setView(k) {
  if (k === "ops") { showPage("ops"); return; }
  sheetMode = k; renderSheet(); showPage("sheet");
}
function renderSheet() {
  const box = $("sheet");
  if (!snap || !snap.sheets) { box.innerHTML = `<div class="card empty">Лист появится после синхронизации с компьютером.</div>`; return; }
  sheetIdx = Math.min(sheetIdx, snap.sheets.length - 1);
  const sh = snap.sheets[sheetIdx];
  const order = snap.sheets.map((x, i) => i).sort((a, b) => (snap.sheets[a].year * 12 + snap.sheets[a].month) - (snap.sheets[b].year * 12 + snap.sheets[b].month));
  let h = viewSeg(sheetMode);
  h += `<div class="filters">` + order.map((i) => { const x = snap.sheets[i];
    return `<button type="button" class="chip ${i === sheetIdx ? "on" : ""}" data-sheet="${i}">${esc(x.title)}</button>`; }).join("") + `</div>`;
  h += `<p class="hint" style="margin:-4px 4px 10px">${esc(sh.span)}</p>`;
  const pend = phoneUnsentFor(sh);
  if (pend.length) {
    const sum = pend.reduce((a, e) => a + (e.kind === "expense" ? e.amount : 0), 0);
    h += `<div class="card soft"><b>📱 С телефона, ещё не в листе: ${pend.length}</b>${sum ? ` · траты ${fmt(sum)}` : ""}
      <div class="hint">появятся здесь после синхронизации и открытия программы на компьютере</div></div>`;
  }
  if (sheetMode === "cats") {
    const cats = new Map();
    sh.halves.forEach((hf) => hf.rows.forEach((r) => {
      if (r.credit && !cats.has(r.category)) cats.set(r.category, { plan: 0, fact: 0, n: 0 });
      const c = cats.get(r.category) || { plan: 0, fact: 0, n: 0 };
      c.plan += r.amount; c.fact += rowActual(r); c.n += 1; cats.set(r.category, c);
    }));
    pend.filter((e) => e.kind === "expense").forEach((e) => {
      const c = cats.get(e.category) || { plan: 0, fact: 0, n: 0, phone: 0 };
      c.phone = (c.phone || 0) + e.amount; cats.set(e.category, c);
    });
    const list = [...cats.entries()].sort((a, b) => (b[1].fact + (b[1].phone || 0)) - (a[1].fact + (a[1].phone || 0)));
    const totalFact = list.reduce((a, [, c]) => a + c.fact, 0), totalPlan = list.reduce((a, [, c]) => a + c.plan, 0);
    h += `<div class="card"><div class="line"><span><b>Потрачено</b></span><span class="r"><b>${fmt(totalFact)}</b> <span class="muted">из ${fmt(totalPlan)} по плану</span></span></div>`;
    list.forEach(([name, c]) => {
      const pct = c.plan > 0 ? Math.min(100, (c.fact / c.plan) * 100) : 100;
      h += `<div style="padding:6px 0"><div class="line" style="border:0;padding:0"><span>${esc(name)}</span>
        <span class="r">${fmt(c.fact)} <span class="muted">/ ${fmt(c.plan)}</span></span></div>
        <div class="bar"><i style="width:${pct}%"></i></div>
        ${c.phone ? `<div class="hint" style="margin:2px 0 0">+ с телефона ${fmt(c.phone)}</div>` : ""}</div>`;
    });
    h += `</div>`;
    const inc = new Map();
    sh.halves.forEach((hf) => hf.incomes.forEach((r) => { if (!r.fund) inc.set(r.category, (inc.get(r.category) || 0) + r.amount); }));
    if (inc.size) {
      h += `<div class="sec">Доходы</div><div class="card">`;
      [...inc.entries()].sort((a, b) => b[1] - a[1]).forEach(([n, v]) => { h += `<div class="line"><span>${esc(n)}</span><span class="r green">+${fmt(v)}</span></div>`; });
      h += `</div>`;
    }
  } else {
    sh.halves.forEach((hf) => {
      h += `<div class="card"><div class="line" style="border:0"><h2 style="margin:0">${esc(hf.title)}</h2>
        <span class="r ${hf.rest < 0 ? "red" : "green"}">остаток ${fmt(hf.rest)}</span></div>`;
      if (hf.incomes.length) {
        h += `<div class="sec" style="margin-top:6px">доход +${fmt(hf.income)}</div>`;
        hf.incomes.forEach((r) => { h += `<div class="line"><span>${esc(r.name)}${r.fund ? ' <span class="muted">· из фонда</span>' : ""}</span><span class="r green">+${fmt(r.amount)}</span></div>`; });
      }
      h += `<div class="sec">расходы ${fmt(hf.expense)}</div>`;
      if (!hf.rows.length) h += `<div class="hint">пока пусто</div>`;
      hf.rows.forEach((r) => {
        const st = r.done || pendingDone(r.id) ? '<span class="dot green"></span>' : (r.spent ? '<span class="dot yellow"></span>' : '<span class="dot" style="background:#C9D6F8"></span>');
        const extra = r.from_fund ? "из фонда" : (r.spent && !r.done ? `потрачено ${fmt(r.spent)}, ост. ${fmt(r.left)}`
          : (r.spent && r.spent > r.amount + 0.5 ? "перерасход" : ""));
        h += `<div class="line tap" data-row="${r.id}"><span>${st}${esc(r.name)}${pendingDone(r.id) && !r.done ? ' <span class="muted">(● ждёт отправки)</span>' : ""}${extra ? `<div class="hint" style="margin:1px 0 0 16px">${extra}</div>` : ""}</span>
          <span class="rr"><span class="r">${fmt(r.amount)}</span>${rowQuick(r)}</span></div>`;
      });
      const adds = entries.filter((e) => e.kind === "rowadd" && e.status !== "done" && e.half === hf.half && sheetOf(e.date, e.half) === sh.year * 12 + sh.month);
      adds.forEach((e) => { h += `<div class="line"><span><span class="dot" style="background:#C9D6F8"></span>${esc(e.note || e.category)} <span class="muted">(ждёт отправки)</span></span><span class="r">${e.row_kind === "income" ? "+" : ""}${fmt(e.amount)}</span></div>`; });
      h += `<button type="button" class="ghost small" style="margin-top:8px" data-addrow="${hf.half}">＋ строка</button>`;
      h += `</div>`;
    });
    h += `<p class="hint center"><b>＋</b> — записать трату из строки (продукты, обеды, кафе…). <b>○</b> — отметить оплаченной.<br>Нажмите на строку — все действия: из фонда, изменить, перенести, удалить.</p>`;
  }
  box.innerHTML = h;
}

/* ------------------------------------------------------------------ Фонды */
function renderFunds() {
  const box = $("funds");
  if (!snap || !snap.funds) { box.innerHTML = `<div class="card empty">Фонды появятся после синхронизации с компьютером.</div>`; return; }
  const total = snap.funds.reduce((a, f) => a + f.saved, 0);
  const goals = snap.funds.reduce((a, f) => a + (f.goal || 0), 0);
  const need = snap.funds.reduce((a, f) => a + (f.need || 0), 0);
  let h = `<div class="card"><div class="line"><span>Всего накоплено</span><span class="r"><b>${fmt(total)}</b></span></div>
    <div class="line"><span>Сумма целей</span><span class="r">${fmt(goals)}</span></div>
    ${need ? `<div class="line"><span>В месяц на цели со сроком</span><span class="r">${fmt(need)}</span></div>` : ""}</div>`;
  const got = new Set(snap.received || []);
  snap.funds.forEach((f, i) => {
    const pct = f.goal > 0 ? Math.min(100, (f.saved / f.goal) * 100) : 0;
    const cat = `В фонд «${f.name}»`;
    const pend = entries.filter((e) => e.category === cat && e.mode === "send" && e.status !== "done" && !e.deleted && !got.has(e.id))
      .reduce((a, e) => a + e.amount, 0);
    let dl = "";
    if (f.deadline) {
      const d = f.deadline;
      dl = `к ${d.slice(8, 10)}.${d.slice(5, 7)}.${d.slice(0, 4)}` + (f.need != null && f.goal > f.saved ? ` · ≈ ${fmt(f.need)}/мес` : (f.goal && f.saved >= f.goal ? " · цель достигнута ✨" : ""));
    } else dl = "бессрочный";
    h += `<div class="card"><div class="line" style="border:0;padding:0"><h2 style="margin:0">${esc(f.name)}</h2>
        ${f.place ? `<span class="badge sent">${esc(f.place)}</span>` : ""}</div>
      <div class="big" style="margin-top:6px">${fmt(f.saved)}${f.goal ? ` <span class="muted" style="font-size:16px">из ${fmt(f.goal)} · ${Math.round(pct)}%</span>` : ""}</div>
      ${f.goal ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ""}
      <div class="hint">${esc(dl)}${f.auto ? ` · автоплатёж ${fmt(f.auto)} ${f.auto_day}-го` : ""}${f.planned ? ` · запланировано +${fmt(f.planned)}` : ""}</div>
      ${pend ? `<div class="hint">📱 с телефона ждёт: +${fmt(pend)}</div>` : ""}
      <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="ghost" type="button" data-fund="${i}">＋ Пополнить</button>
      ${f.saved > 0 ? `<button class="ghost" type="button" data-fundpay="${i}">Оплатить из фонда</button>` : ""}</div></div>`;
  });
  box.innerHTML = h;
}
function topUpFund(i) {
  const f = snap.funds[i];
  kind = "expense";
  showPage("add");
  fillForm();
  const cat = `В фонд «${f.name}»`;
  if (!categories().includes(cat)) $("category").insertAdjacentHTML("beforeend", `<option>${esc(cat)}</option>`);
  $("category").value = cat;
  $("row").value = "";
  $("note").value = "";
  $("amount").focus();
  toast(`Пополнение фонда «${f.name}» — впишите сумму`);
}

/* ------------------------------------------------------------------ Сверка с банком */
function bankPending() {
  /* траты/доходы с телефона «на компьютер», которых ещё нет в сводке (их нет в «должно быть») */
  const got = new Set((snap && snap.received) || []);
  const ym = todayISO().slice(0, 7);
  let exp = 0, inc = 0, local = 0;
  entries.forEach((e) => {
    if (e.deleted) return;
    if (e.kind === "expense" && e.mode === "send" && e.status !== "done" && !got.has(e.id)) exp += e.amount;
    if (e.kind === "income" && e.mode === "send" && e.status !== "done" && !got.has(e.id) && e.date <= todayISO()) inc += e.amount;
    if (e.kind === "expense" && e.status === "local" && e.date.startsWith(ym)) local += e.amount;
  });
  return { exp, inc, local };
}
function renderBank() {
  const box = $("bank");
  const b = snap && snap.bank;
  if (!b) { box.innerHTML = `<div class="card empty">Сверка появится после синхронизации с компьютером.</div>`; return; }
  const keep = {};
  box.querySelectorAll && box.querySelectorAll("input[data-acc]").forEach((i) => { keep[i.dataset.acc] = i.value; });
  const pend = bankPending();
  let h = `<div class="card"><p class="hint" style="margin-top:0">Впишите, сколько денег сейчас на каждом счёте (как в приложении банка) и сколько наличных.
    Сводка с компьютера от ${ddmm(snap.generated)} ${snap.generated.slice(11, 16)} — перед сверкой лучше синхронизироваться.</p>`;
  b.accounts.forEach((a) => {
    const v = keep[a.key] !== undefined ? keep[a.key] : (a.last ? String(a.last).replace(".", ",") : "");
    h += `<label class="field"><span>${esc(a.name)}</span><input data-acc="${a.key}" inputmode="decimal" placeholder="0" value="${esc(v)}"></label>`;
  });
  const useLocal = $("bankLocal") ? $("bankLocal").checked : false;
  if (pend.local) h += `<label class="hint" style="display:flex;gap:8px;align-items:center;margin-top:12px"><input type="checkbox" id="bankLocal" ${useLocal ? "checked" : ""}>
    учесть траты «только на телефоне» этого месяца (${fmt(pend.local)}) — если платили с этих карт</label>`;
  h += `</div><div id="bankOut"></div>`;
  box.innerHTML = h;
  box.querySelectorAll("input[data-acc], #bankLocal").forEach((i) => i.addEventListener("input", bankCalc));
  if ($("bankLocal")) $("bankLocal").addEventListener("change", bankCalc);
  bankCalc();
}
let bankDiff = 0, bankReal = {};
function bankCalc() {
  const b = snap.bank, pend = bankPending();
  bankReal = {};
  document.querySelectorAll("#bank input[data-acc]").forEach((i) => { bankReal[i.dataset.acc] = parseAmount(i.value || "0") || 0; });
  const useLocal = $("bankLocal") && $("bankLocal").checked;
  const lifeKeys = b.accounts.filter((a) => a.kind === "life").map((a) => a.key);
  const lifeReal = lifeKeys.reduce((a, k) => a + (bankReal[k] || 0), 0);
  const lifeExp = b.life - pend.exp + pend.inc - (useLocal ? pend.local : 0);
  const verdict = (exp, real) => {
    const d = Math.round((real - exp) * 100) / 100;
    if (Math.abs(d) < 1) return '<span class="green">✓ сходится</span>';
    return d < 0 ? `<span class="red">не хватает ${fmt(-d)}</span>` : `<span class="green">лишние ${fmt(d)}</span>`;
  };
  const names = b.accounts.filter((a) => a.kind === "life").map((a) => a.name).join(" + ");
  let h = `<div class="card"><h2>Деньги на жизнь</h2><p class="hint" style="margin-top:0">${esc(names)}</p>
    <div class="line"><span>Должно быть</span><span class="r">${fmt(lifeExp)}</span></div>
    <div class="line"><span>На картах и наличными</span><span class="r">${fmt(lifeReal)}</span></div>
    <div class="line"><span>Итог</span><span class="r">${verdict(lifeExp, lifeReal)}</span></div>
    <details><summary>почему столько должно быть</summary><div class="hint">
      ${b.start ? `было до зарплаты ${fmt(b.start)} + ` : ""}пришедший доход ${fmt(b.income)} − оплачено (● и ◐) ${fmt(b.paid)}
      ${b.life_funds.map((f) => ` + фонд «${esc(f.name)}» (${esc(f.place)}) ${fmt(f.amount)}`).join("")}
      ${b.early ? ` ${b.early > 0 ? "+" : "−"} из листа следующего месяца (пришло или оплачено заранее) ${fmt(Math.abs(b.early))}` : ""}
      ${pend.exp ? ` − траты с телефона, ещё не на компьютере, ${fmt(pend.exp)}` : ""}${pend.inc ? ` + доходы с телефона ${fmt(pend.inc)}` : ""}
      ${useLocal && pend.local ? ` − траты только на телефоне ${fmt(pend.local)}` : ""}</div></details></div>`;
  Object.entries(b.other || {}).forEach(([k, o]) => {
    const acc = b.accounts.find((a) => a.key === k);
    h += `<div class="card"><h2>${esc(acc ? acc.name : k)}</h2>
      <div class="line"><span>Должно быть</span><span class="r">${fmt(o.expected)}</span></div>
      <div class="line"><span>Есть</span><span class="r">${fmt(bankReal[k] || 0)}</span></div>
      <div class="line"><span>Итог</span><span class="r">${verdict(o.expected, bankReal[k] || 0)}</span></div>
      ${o.funds.length ? `<div class="hint">${o.funds.map((f) => `«${esc(f.name)}» ${fmt(f.amount)}`).join(", ")}</div>` : ""}
      ${(bankReal[k] || 0) - o.expected >= 1 ? `<div class="hint">больше, чем в фондах, — наверное, проценты: добавьте их пополнением фонда.</div>` : ""}</div>`;
  });
  if (b.aside) h += `<p class="hint">✉️ В конвертах ${fmt(b.aside)} — не сверяется.</p>`;
  bankDiff = lifeReal ? Math.round((lifeReal - lifeExp) * 100) / 100 : 0;
  const sus = (snap.bank_check && snap.bank_check.suspects) || [];
  if (lifeExp < 0) h += `<p class="hint red">«Должно быть» меньше нуля — по листу оплачено больше, чем пришло денег: что-то отмечено ●, но не списалось, доход стоит будущей датой или записано дважды.</p>`;
  if (sus.length && (Math.abs(bankDiff) >= 1 || lifeExp < 0)) h += `<div class="card"><h2>Где искать разницу</h2>${sus.map((t) => `<div class="hint" style="margin:4px 0">${esc(t)}</div>`).join("")}</div>`;
  h += `<div class="card">`;
  if (Math.abs(bankDiff) >= 1) {
    h += `<p class="hint" style="margin-top:0">${bankDiff < 0 ? "Скорее всего, какие-то траты не записаны. Если не вспомнить — запишите разницу одной строкой."
      : "Денег больше, чем по листу: возможно, что-то отмечено ●, но ещё не списалось, или пришёл доход, которого нет в листе."}</p>
      <button class="primary" type="button" id="bankFix">${bankDiff < 0 ? `Записать ${fmt(-bankDiff)} как неучтённые траты` : `Записать +${fmt(bankDiff)} как неучтённый доход`}</button>`;
  }
  h += `<button class="ghost" type="button" id="bankSave" style="width:100%">Сохранить сверку (без записи разницы)</button>
    <p class="hint">Уйдёт на компьютер при синхронизации: остатки счетов запомнятся, разница — если выбрали — появится в листе строкой ●.</p></div>`;
  $("bankOut").innerHTML = h;
  if ($("bankFix")) $("bankFix").addEventListener("click", () => bankSend(true));
  $("bankSave").addEventListener("click", () => bankSend(false));
}
function bankSend(record) {
  if (!Object.values(bankReal).some((v) => v > 0)) { toast("Впишите остатки счетов"); return; }
  entries = entries.filter((e) => !(e.kind === "bank" && e.status === "pending"));   // одна сверка в очереди
  entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "bank", amount: Math.abs(bankDiff),
    category: "Сверка с банком", note: record && Math.abs(bankDiff) >= 1 ? (bankDiff < 0 ? "неучтённые траты" : "неучтённый доход") : "остатки счетов",
    real: bankReal, diff: record ? bankDiff : 0, record: !!record, half: 0, row_id: null, mode: "send", status: "pending" });
  saveEntries();
  toast("Сверка сохранена — нажмите «Синхронизировать», чтобы отправить на компьютер", 4500);
  renderAll();
  showPage("sum");
}

function renderSettings() {
  if ($("pinStatus")) {
    $("pinStatus").textContent = cfg.pinOn ? "PIN-код включён ✓" : "PIN-код не поставлен";
    $("pinStatus").className = "status " + (cfg.pinOn ? "ok" : "");
    $("pinBtn").textContent = cfg.pinOn ? "Сменить PIN-код" : "Поставить PIN-код";
    $("pinOff").hidden = !cfg.pinOn;
  }
  document.querySelectorAll(".gh-only").forEach((el) => { el.hidden = SRV; });
  document.querySelectorAll(".srv-only").forEach((el) => { el.hidden = !SRV; });
  if (SRV) {
    $("srvHost").textContent = location.host;
    $("srvStatus").textContent = cfg.srvToken ? "Телефон подключён к серверу ✓" : "Ещё не вошли";
    $("srvStatus").className = "status " + (cfg.srvToken ? "ok" : "");
    $("srvLogout").hidden = !cfg.srvToken;
    $("srvLogin").hidden = !!cfg.srvToken;
    $("srvPw").closest("label").hidden = !!cfg.srvToken;
  }
  $("repo").value = cfg.repo || "";
  const st = $("tokenStatus");
  st.textContent = cfg.ghToken ? "Токен сохранён на этом телефоне ✓" : "Токен ещё не вставлен";
  st.className = "status " + (cfg.ghToken ? "ok" : "");
  $("pwStatus").textContent = cfg.pw ? "Пароль сохранён на этом телефоне ✓" : "Пароль не задан";
  $("pwStatus").className = "status " + (cfg.pw ? "ok" : "");
  const n = entries.length, p = entries.filter((e) => e.status === "pending").length, l = entries.filter((e) => e.status === "local").length;
  $("storageInfo").textContent = `На телефоне записей: ${n} (ждут отправки: ${p}, только на телефоне: ${l}). ` +
    "Чтобы iPhone не стёр данные, пользуйтесь приложением с экрана «Домой» (Поделиться → На экран «Домой»).";
  $("ver").textContent = VERSION + (newVersion ? " · есть новая " + newVersion : "");
  $("updBtn").textContent = newVersion ? "Обновить до " + newVersion : "Проверить обновления";
}
function renderCount() {
  const p = entries.filter((e) => e.status === "pending").length;
  $("syncCount").hidden = !p;
  $("syncCount").textContent = p;
  if (!syncing) $("syncText").textContent = "Синхронизировать";
}
/* ------------------------------------------------------------------ «Ещё»: фонды, здоровье, календарь */
const MON_SHORT = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];
const MON_FULL = ["Январь", "Февраль", "Март", "Апрель", "Май", "Июнь", "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"];
const FLOW_NAMES = ["нет", "мажущие", "лёгкие", "средние", "обильные"];
let calYM = null, calSel = null;

function daysTo(iso) { return Math.round((new Date(iso + "T12:00:00") - new Date(todayISO() + "T12:00:00")) / 86400000); }
function whenIn(iso) { const n = daysTo(iso); return n === 0 ? "сегодня" : n === 1 ? "завтра" : n === -1 ? "вчера" : n > 0 ? `через ${n} дн.` : `${-n} дн. назад`; }
function dchip(iso) {
  const soon = daysTo(iso) >= 0 && daysTo(iso) <= 3;
  return `<div class="dchip ${soon ? "soon" : ""}"><b>${Number(iso.slice(8, 10))}</b><span>${MON_SHORT[Number(iso.slice(5, 7)) - 1]}</span></div>`;
}
function moreTab() { return cfg.moreTab || "funds"; }
function renderMore() {
  const t = moreTab();
  document.querySelectorAll("[data-more]").forEach((b) => b.classList.toggle("on", b.dataset.more === t));
  document.querySelectorAll(".more-pane").forEach((p) => { p.hidden = p.id !== t; });
  if (t === "funds") renderFunds();
  if (t === "health") renderHealth();
  if (t === "cal") renderCal();
  if (t === "occ") renderOcc();
  if (t === "wallet") renderWallet();
}

/* ---------- здоровье */
function cycleLocal() {
  /* дни цикла: из сводки + отмеченные на телефоне, но ещё не дошедшие до сервера */
  const days = { ...((snap && snap.health && snap.health.cycle_days) || {}) };
  entries.filter((e) => e.kind === "cycle" && e.status !== "done" && !e.deleted)
    .forEach((e) => { if (e.flow) days[e.date] = { flow: e.flow, sym: "" }; else delete days[e.date]; });
  return days;
}
function logCycle(day, flow) {
  entries = entries.filter((e) => !(e.kind === "cycle" && e.date === day && e.status === "pending"));
  entries.unshift({ id: uid(), kind: "cycle", date: day, flow, amount: 0, category: "", note: "", mode: "send",
    status: "pending", created: new Date().toISOString() });
  saveEntries(); renderHealth(); renderCount(); autoSync(800);
  toast(flow ? `Отмечено: ${ddmm(day)} — ${FLOW_NAMES[flow]}` : `${ddmm(day)}: отметка убрана`);
}
function cycleDialog() {
  const day = prompt("Какой день отметить? (ДД.ММ, пусто — сегодня)", "");
  if (day === null) return;
  let iso = todayISO();
  const m = String(day).trim().match(/^(\d{1,2})\.(\d{1,2})$/);
  if (m) iso = `${todayISO().slice(0, 4)}-${m[2].padStart(2, "0")}-${m[1].padStart(2, "0")}`;
  else if (String(day).trim()) { toast("Дата — как 28.10"); return; }
  const f = prompt("Выделения: 0 — нет, 1 — мажущие, 2 — лёгкие, 3 — средние, 4 — обильные", "3");
  if (f === null) return;
  const flow = Math.max(0, Math.min(4, Number(f) || 0));
  logCycle(iso, flow);
}
function renderHealth() {
  const box = $("health");
  const h = snap && snap.health;
  if (!h) { box.innerHTML = `<div class="card empty">Здоровье появится после синхронизации с новой версией программы.</div>`; return; }
  let html = "";
  // цикл
  const c = h.cycle;
  const days = cycleLocal();
  const today = todayISO();
  html += `<div class="card"><h2>🌸 Цикл</h2>`;
  if (c) {
    const late = c.late > 0;
    const inP = days[today] && days[today].flow > 0;
    html += `<div class="cyc-big">${inP ? "Месячные" : "День " + c.day}</div>
      <div class="hint">${late ? `<span style="color:var(--red)">задержка ${c.late} дн.</span> (ожидались ${ddmm(c.next)})`
        : c.next ? `следующие ≈ ${ddmm(c.next)} · ${whenIn(c.next)}` : ""}${c.fertile ? ` · фертильные ${ddmm(c.fertile[0])}–${ddmm(c.fertile[1])}` : ""}</div>
      <div class="hint">цикл ≈ ${c.cycle} дн. · месячные ≈ ${c.period} дн.</div>`;
  } else {
    html += `<div class="hint">Отметьте первый день месячных — программа начнёт считать цикл.</div>`;
  }
  html += `<div class="cyc-row">`;
  for (let k = -3; k < 18; k++) {
    const d = addDays(today, k);
    const f = days[d] && days[d].flow > 0;
    const p = (h.pred || {})[d];
    const cls = f ? "period" : p === "period" ? "pred" : p || "";
    html += `<div class="cyc-d ${cls} ${d === today ? "today" : ""}"><b>${Number(d.slice(8, 10))}</b>${k === 0 ? "сег." : MON_SHORT[Number(d.slice(5, 7)) - 1]}</div>`;
  }
  html += `</div><div class="legend"><span><i style="background:#F48FB1"></i>месячные</span><span><i style="background:#FCE1EA;border:1px solid #F7B8CC"></i>прогноз</span>
    <span><i style="background:#D9F2EE;border:1px solid #A9DCD3"></i>фертильные</span><span><i style="background:#8FD3C7"></i>овуляция</span></div>
    <div class="btn-row"><button type="button" class="primary" id="cycToday">${days[today] && days[today].flow ? "Сегодня — без выделений" : "🩸 Сегодня месячные"}</button>
    <button type="button" class="ghost" id="cycDay">Отметить день…</button></div></div>`;
  // ближайшие приёмы
  const up = (h.visits || []).filter((v) => !v.went);
  html += `<div class="card"><h2>📅 Приёмы</h2>`;
  if (!up.length) html += `<div class="hint">Запланированных приёмов нет. Этап плана лечения — нажмите на него ниже: «Записалась» или «Сходила».</div>`;
  up.forEach((v) => {
    const pend = pendingOf("visit_done", (p) => p.visit_id === v.id).length;
    html += `<div class="item tap" data-visit="${v.id}">${dchip(v.date)}<div class="tx"><b>${esc(v.title)}</b>
      <div class="s">${v.clinic ? esc(v.clinic) + " · " : ""}${pend ? "✓ отмечено, ждёт отправки" : v.future ? whenIn(v.date) : "<span style='color:var(--red)'>сходили? нажмите, чтобы отметить</span>"}${v.reason ? " · " + esc(v.reason) : ""}</div></div>
      <div class="am">${v.plan ? "≈ " + fmt(v.plan) : ""}</div></div>`;
  });
  html += `</div>`;
  // планы лечения
  (h.plans || []).forEach((p) => {
    const pct = p.all ? Math.round(p.done / p.all * 100) : 0;
    html += `<div class="card"><h2>🦷 ${esc(p.title)}</h2>${p.clinic ? `<div class="hint">${esc(p.clinic)}</div>` : ""}
      ${p.diagnosis ? `<div class="diag">${esc(p.diagnosis)}</div>` : ""}
      <div class="bar"><i style="width:${pct}%"></i></div>
      <div class="hint">пройдено ${p.done} из ${p.all} · потрачено ${fmt(p.spent)} · впереди ${fmt(p.left)}</div>
      ${p.fund ? `<div class="hint" style="margin-top:4px">🐷 копим в фонде «${esc(p.fund.name)}»: накоплено ${fmt(p.fund.saved)}${p.fund.monthly ? ` · откладывать ${fmt(p.fund.monthly)}/мес` : " · хватает ✓"}</div>` : ""}`;
    p.items.forEach((it) => {
      const pb = pendingOf("hp_book", (x) => x.item_id === it.id)[0], pd = pendingOf("hp_done", (x) => x.item_id === it.id)[0];
      if (pd) it = { ...it, status: "done", day: pd.p.day, fact: pd.p.fact, said: pd.p.said };
      else if (pb) it = { ...it, status: "booked", day: pb.p.day };
      const done = it.status === "done", booked = it.status === "booked";
      const when = done ? `✓ ${it.day ? ddmm(it.day) : ""}` : booked && it.day ? `📅 приём ${ddmm(it.day)} · ${whenIn(it.day)}`
        : it.month ? MON_FULL[Number(it.month.slice(5, 7)) - 1].toLowerCase() + " " + it.month.slice(0, 4) : "без месяца";
      html += `<div class="item ${done || !it.id ? "" : "tap"}" ${done || !it.id ? "" : `data-hp="${it.id}"`}><div class="ic ${done ? "done" : booked ? "booked" : ""}">${done ? "✓" : booked ? "•" : ""}</div>
        <div class="tx"><b>${esc(it.title)}</b><div class="s">${when}${it.note ? " · " + esc(it.note) : ""}</div>
        ${done && it.said ? `<div class="said">💬 ${esc(it.said)}</div>` : ""}</div>
        <div class="am">${done && it.fact != null ? `<b style="color:var(--green)">${fmt(it.fact)}</b><div class="s">план ${fmt(it.cost)}</div>` : `${fmt(it.cost)}<div class="s">по плану</div>`}</div></div>`;
    });
    html += `</div>`;
  });
  // история
  const past = (h.visits || []).filter((v) => v.went);
  if (past.length) {
    html += `<div class="card"><h2>🩺 Где была</h2>`;
    past.forEach((v) => {
      html += `<div class="item">${dchip(v.date)}<div class="tx"><b>${esc(v.title)}</b>
        <div class="s">${v.clinic ? esc(v.clinic) : ""}${v.reason ? " · " + esc(v.reason) : ""}</div>
        ${v.said ? `<div class="said">💬 ${esc(v.said)}</div>` : ""}</div><div class="am">${v.fact ? fmt(v.fact) : ""}</div></div>`;
    });
    html += `</div>`;
  }
  box.innerHTML = html;
  $("cycToday").onclick = () => { const on = days[today] && days[today].flow; logCycle(today, on ? 0 : 3); };
  box.querySelectorAll("[data-visit]").forEach((el) => el.addEventListener("click", () => {
    const v = (h.visits || []).find((x) => x.id === Number(el.dataset.visit)); if (v) visitDialog(v);
  }));
  box.querySelectorAll("[data-hp]").forEach((el) => el.addEventListener("click", () => {
    for (const p of h.plans || []) for (const it of p.items) if (it.id === Number(el.dataset.hp)) return stageDialog(it);
  }));
  $("cycDay").onclick = cycleDialog;
}

/* ---------- календарь */
function calEvents(iso) {
  /* события дня: из сводки + записи, добавленные на телефоне (ещё не на сервере); удалённые с телефона — скрыты */
  const d = snap && snap.calendar && snap.calendar.days[iso];
  const gone = new Set(entries.filter((e) => e.kind === "markdel" && e.status !== "done").map((e) => e.mark_id));
  const ev = ((d && d.ev) || []).filter((e) => !(e.mark && gone.has(e.mark)));
  entries.filter((e) => e.kind === "mark" && e.date === iso && e.status !== "done" && !e.deleted)
    .forEach((e) => ev.push({ i: e.mark_kind === "important" ? "⭐" : "📝", t: e.title, imp: e.mark_kind === "important", local: e.id }));
  return ev;
}
function addMarkDialog(iso) {
  const bg = document.createElement("div");
  bg.className = "sheet-bg";
  bg.innerHTML = `<div class="sheet"><h2>На ${Number(iso.slice(8, 10))} ${MON_SHORT[Number(iso.slice(5, 7)) - 1]}</h2>
    <label class="field"><span>Что</span><input id="mkTitle" placeholder="забрать посылку, позвонить маме…" autocomplete="off"></label>
    <div class="seg" style="margin:10px 0"><button type="button" class="on" data-mk="note">📝 Дело / запись</button>
      <button type="button" data-mk="important">⭐ Важная дата</button></div>
    <p class="hint">Появится в календаре на ноутбуке, накануне придёт напоминание.</p>
    <button class="primary" data-a="save">Добавить</button>
    <button class="ghost" data-a="close">Отмена</button></div>`;
  let mk = "note";
  bg.addEventListener("click", (ev) => {
    const k = ev.target.closest("[data-mk]");
    if (k) { mk = k.dataset.mk; bg.querySelectorAll("[data-mk]").forEach((b) => b.classList.toggle("on", b === k)); return; }
    const a = ev.target.closest("[data-a]") && ev.target.closest("[data-a]").dataset.a;
    if (ev.target === bg || a === "close") { bg.remove(); return; }
    if (a === "save") {
      const title = bg.querySelector("#mkTitle").value.trim();
      if (!title) { toast("Напишите, что запланировать"); return; }
      entries.unshift({ id: uid(), kind: "mark", date: iso, title, mark_kind: mk, amount: 0, category: "", note: title,
        mode: "send", status: "pending", created: new Date().toISOString() });
      saveEntries(); bg.remove(); renderCal(); renderCount(); autoSync(800); toast("Добавлено ✓");
    }
  });
  document.body.appendChild(bg);
  setTimeout(() => bg.querySelector("#mkTitle").focus(), 60);
}
function delMark(ev) {
  if (ev.local) { entries = entries.filter((e) => e.id !== ev.local); saveEntries(); renderCal(); renderCount(); return; }
  if (!confirm(`Удалить «${ev.t}» из календаря?`)) return;
  entries.unshift({ id: uid(), kind: "markdel", mark_id: ev.mark, date: todayISO(), title: ev.t, amount: 0, category: "",
    note: ev.t, mode: "send", status: "pending", created: new Date().toISOString() });
  saveEntries(); renderCal(); renderCount(); autoSync(800);
}
function renderCal() {
  const box = $("cal");
  const cal = snap && snap.calendar;
  if (!cal) { box.innerHTML = `<div class="card empty">Календарь появится после синхронизации с новой версией программы.</div>`; return; }
  const today = todayISO();
  if (!calYM) calYM = today.slice(0, 7);
  if (!calSel) calSel = today;
  const y = Number(calYM.slice(0, 4)), m = Number(calYM.slice(5, 7));
  const first = new Date(y, m - 1, 1), n = new Date(y, m, 0).getDate();
  const shift = (first.getDay() + 6) % 7;
  let g = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"].map((w) => `<div class="wd">${w}</div>`).join("");
  for (let i = 0; i < shift; i++) g += `<div class="blank"></div>`;
  for (let d = 1; d <= n; d++) {
    const iso = `${calYM}-${String(d).padStart(2, "0")}`;
    const info = cal.days[iso] || {};
    const wk = (new Date(y, m - 1, d).getDay() + 6) % 7 >= 5;
    let cls = info.vac ? "vac" : info.w === "office" ? "office" : info.w === "remote" ? "remote" : "";
    if (!cls) cls = (info.k === "holiday" || info.k === "off" || info.k === "weekend" || (wk && !info.k)) && info.k !== "work" ? "off" : info.k === "short" ? "short" : "";
    const ev = calEvents(iso);
    const dots = ev.slice(0, 3).map((e) => `<i class="${e.pay ? "pay" : e.debt ? "debt" : ""}"></i>`).join("");
    const imp = ev.some((e) => e.imp);
    g += `<button type="button" class="cd ${cls} ${iso === today ? "today" : ""} ${iso === calSel ? "sel" : ""} ${imp ? "imp" : ""}" data-cal="${iso}">${d}${dots ? `<span class="dots">${dots}</span>` : ""}</button>`;
  }
  const canPrev = `${calYM}-01` > cal.from, canNext = `${calYM}-31` < cal.to;
  let html = icsCard() + `<div class="card"><div class="cal-head"><button type="button" id="calPrev" ${canPrev ? "" : "disabled"}>‹</button>
    <h2 style="margin:0">${MON_FULL[m - 1]} ${y}</h2><button type="button" id="calNext" ${canNext ? "" : "disabled"}>›</button></div>
    <div class="cal-grid">${g}</div>
    <div class="legend"><span><i style="background:#FBE3E8"></i>выходной</span><span><i style="background:#DCE6FD"></i>офис</span>
    <span><i style="background:#FDE6D3"></i>удалёнка</span><span><i style="background:#DDF3E6"></i>отпуск</span>
    <span><i style="background:var(--green)"></i>выплата</span><span><i style="background:var(--red)"></i>кредит</span></div></div>`;
  // выбранный день
  const sel = cal.days[calSel] || {};
  const selEv = calEvents(calSel);
  const wd = ["воскресенье", "понедельник", "вторник", "среда", "четверг", "пятница", "суббота"][new Date(calSel + "T12:00:00").getDay()];
  const mode = sel.vac ? "🌴 отпуск" : sel.w === "office" ? "🏢 офис" : sel.w === "remote" ? "🏠 удалёнка" : "";
  html += `<div class="card"><h2>${Number(calSel.slice(8, 10))} ${MON_SHORT[Number(calSel.slice(5, 7)) - 1]} · ${wd}</h2>
    <div class="hint">${[mode, whenIn(calSel)].filter(Boolean).join(" · ")}</div>`;
  if (!selEv.length) html += `<div class="hint" style="margin-top:6px">Событий нет</div>`;
  selEv.forEach((e, i) => {
    const mine = e.mark || e.local;
    html += `<div class="item"><div class="tx">${esc(e.i)} ${esc(e.t)}${e.local ? ` <span class="badge pending">ждёт отправки</span>` : ""}</div>
      ${mine ? `<button type="button" class="ghost small" data-delev="${i}">✕</button>` : ""}</div>`;
  });
  html += `<button type="button" class="primary" id="calAdd" style="margin-top:10px">+ Добавить на этот день</button></div>`;
  // скоро
  const soon = [];
  Object.keys(cal.days).sort().forEach((iso) => {
    if (iso < today) return;
    (cal.days[iso].ev || []).forEach((e) => { if (!e.pay || daysTo(iso) <= 14) soon.push([iso, e]); });
  });
  html += `<div class="card"><h2>Скоро</h2>`;
  soon.slice(0, 15).forEach(([iso, e]) => {
    html += `<div class="item">${dchip(iso)}<div class="tx">${esc(e.i)} ${esc(e.t)}<div class="s">${whenIn(iso)}</div></div></div>`;
  });
  html += `</div>`;
  box.innerHTML = html;
  box.querySelectorAll("[data-cal]").forEach((b) => b.addEventListener("click", () => { calSel = b.dataset.cal; renderCal(); }));
  box.querySelectorAll("[data-delev]").forEach((b) => b.addEventListener("click", () => delMark(selEv[Number(b.dataset.delev)])));
  $("calAdd").onclick = () => addMarkDialog(calSel);
  const go = (k) => { const d = new Date(y, m - 1 + k, 1); calYM = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`; renderCal(); };
  $("calPrev").onclick = () => go(-1);
  $("calNext").onclick = () => go(1);
}


/* ------------------------------------------------------------------ записи «как есть» (поводы, счётчик, здоровье, рассрочка) */
const GENERIC_KINDS = ["installment", "occ_new", "occ_set", "nocredit", "hp_book", "hp_done", "visit_done",
  "wallet_save", "wallet_del", "wallet_done", "wallet_money", "wallet_move", "pay_set", "pay_extra"];
function pushGeneric(kind, p, title, icon, date) {
  entries.unshift({ id: uid(), created: new Date().toISOString(), date: date || todayISO(), kind, p, title, icon: icon || "•",
    amount: 0, category: "", note: title, mode: "send", status: "pending" });
  saveEntries(); renderAll(); autoSync(600);
}
function pendingOf(kind, test) {
  return entries.filter((e) => e.kind === kind && e.status !== "done" && (!test || test(e.p || {})));
}

/* ------------------------------------------------------------------ 🍩 без новых кредитов */
function nocreditLine() {
  const nc = snap && snap.nocredit;
  if (!nc) return "";
  const reset = pendingOf("nocredit").length > 0, n = reset ? 0 : nc.days;
  const word = (k) => (k % 10 === 1 && k % 100 !== 11 ? "день" : [2, 3, 4].includes(k % 10) && ![12, 13, 14].includes(k % 100) ? "дня" : "дней");
  return `<div class="card nc-line"><span>🕊️ Без новых кредитов: <b>${n} ${word(n)}</b><span class="muted"> · ${nc.best > n ? "рекорд " + nc.best + " · " : ""}цель ${reset ? 7 : nc.goal}${reset ? " · сброс ждёт отправки" : ""}</span></span>
    <button type="button" class="ghost small" id="ncReset">Взяла в долг</button></div>`;
}
function nocreditCard() {
  const nc = snap && snap.nocredit;
  if (!nc) return "";
  const reset = pendingOf("nocredit").length > 0;
  const n = reset ? 0 : nc.days;
  const goal = reset ? 7 : nc.goal, prev = reset ? 0 : nc.prev;
  const pct = Math.max(2, Math.min(100, ((n - prev) / Math.max(1, goal - prev)) * 100));
  const col = n >= 30 ? "#7FC8A9" : "var(--blue)";
  const word = (k) => (k % 10 === 1 && k % 100 !== 11 ? "день" : [2, 3, 4].includes(k % 10) && ![12, 13, 14].includes(k % 100) ? "дня" : "дней");
  return `<div class="card" style="display:flex;gap:14px;align-items:center">
    <div style="width:58px;height:58px;border-radius:50%;flex:0 0 58px;display:grid;place-items:center;background:conic-gradient(${col} ${pct}%, rgba(127,140,190,.18) 0)">
      <div style="width:44px;height:44px;border-radius:50%;background:var(--card, #fff);display:grid;place-items:center;font-weight:700;font-size:18px">${n}</div></div>
    <div style="flex:1;min-width:0"><b>Без новых кредитов: ${n} ${word(n)}</b>
      <div class="hint" style="margin:2px 0 0">${nc.best > n ? `рекорд ${nc.best} · ` : n >= 7 ? "это рекорд 🏆 · " : ""}цель ${goal}${reset ? " · сброс ждёт отправки" : ""}</div></div>
    <button type="button" class="ghost small" id="ncReset">Взяла в долг</button></div>`;
}
function nocreditReset() {
  const why = prompt("Что взяли? (например: Сплит Лавка)", "");
  if (why === null) return;
  pushGeneric("nocredit", { why: why.trim(), date: todayISO() }, `Взяла в долг${why.trim() ? ": " + why.trim() : ""}`, "🍩");
  toast("Счёт «без новых кредитов» начнётся заново, рекорд сохранится");
}

/* ------------------------------------------------------------------ 🛍 Сплит / рассрочка */
function nextPayday() {
  const t = todayISO();
  const all = Object.values((snap && snap.paydays) || {}).flat().filter((d) => d > t).sort();
  return all[0] || addDays(t, 7);
}
function installmentDialog() {
  const bg = sheetDialog(`<h2>🛍 Купила в Сплит / рассрочку</h2>
    <p class="hint">Заведу кредит, платежи и строки в листах — как на ноутбуке.</p>
    <div class="two"><label class="field"><span>Сервис</span><select id="inSvc"><option>Сплит</option><option>Долями</option><option>Рассрочка Озон</option><option>Рассрочка</option></select></label>
      <label class="field"><span>Что купила</span><input id="inWhat" placeholder="Лавка"></label></div>
    <label class="field"><span>Сумма покупки</span><input id="inSum" inputmode="decimal" placeholder="0"></label>
    <div class="two"><label class="field"><span>Платежей</span><input id="inN" inputmode="numeric" value="4"></label>
      <label class="field"><span>Как часто</span><select id="inEvery"><option value="14">раз в 2 недели</option><option value="30">раз в месяц</option></select></label></div>
    <label class="field"><span>Первый платёж</span><input id="inFirst" type="date" value="${todayISO()}"></label>
    <label style="display:flex;gap:10px;align-items:center;margin:2px 2px 8px"><input type="checkbox" id="inPaid" checked> первый платёж уже списали</label>
    <label style="display:flex;gap:10px;align-items:center;margin:2px 2px 8px"><input type="checkbox" id="inPayoff"> закрою остаток разом</label>
    <label class="field" id="inPayoffF" hidden><span>Когда закрою</span><input id="inPayoffD" type="date" value="${nextPayday()}"></label>
    <label style="display:flex;gap:10px;align-items:center;margin:2px 2px 10px"><input type="checkbox" id="inReset" checked> новый долг — счёт «без кредитов» заново</label>
    <p class="hint" id="inPrev"></p>
    <button class="primary" data-a="save">Записать</button>`, (a) => {
    if (a !== "save") return;
    const total = parseAmount($("inSum").value), n = Math.max(1, Math.min(36, parseInt($("inN").value, 10) || 4));
    if (!(total > 0)) { toast("Впишите сумму покупки"); return false; }
    const name = `${$("inSvc").value} ${$("inWhat").value.trim()}`.trim();
    const p = { name, amount: total, n, every: Number($("inEvery").value), first: $("inFirst").value || todayISO(),
      paid: $("inPaid").checked, payoff: $("inPayoff").checked ? $("inPayoffD").value : null, reset: $("inReset").checked };
    pushGeneric("installment", p, `${name} · ${fmt(total)}`, "🛍", p.first);
    toast(`«${name}» ${fmt(total)} — уйдёт на сервер, платежи появятся в листах`);
  });
  const prev = () => {
    const total = parseAmount($("inSum").value), n = Math.max(1, parseInt($("inN").value, 10) || 4);
    $("inPayoffF").hidden = !$("inPayoff").checked;
    if (!(total > 0)) { $("inPrev").textContent = ""; return; }
    const per = Math.round(total / n * 100) / 100;
    const paid = $("inPaid").checked ? per : 0;
    $("inPrev").textContent = `${n} × ${fmtExact(per)}` + (paid ? ` · первый оплачен` : "") +
      ($("inPayoff").checked ? ` · остаток ${fmtExact(total - paid)} разом ${ddmm($("inPayoffD").value)}` : "");
  };
  bg.addEventListener("input", prev); bg.addEventListener("change", prev); prev();
  setTimeout(() => { const i = bg.querySelector("#inWhat"); if (i) i.focus(); }, 150);
}

/* ------------------------------------------------------------------ 🩺 здоровье: записалась / сходила */
function stageDialog(it) {
  const canBook = it.status === "plan";
  sheetDialog(`<h2>${esc(it.title)}</h2><p class="hint">${fmt(it.cost)} по плану${it.day ? ` · приём ${ddmm(it.day)}` : ""}</p>
    ${canBook ? '<button class="primary" data-a="book">📅 Записалась…</button>' : ""}
    <button class="${canBook ? "ghost" : "primary"}" data-a="done">✓ Сходила…</button>`, (a) => {
    if (a === "book") setTimeout(() => bookDialog(it), 50);
    if (a === "done") setTimeout(() => doneDialog(it.title, it.day || todayISO(), it.cost, (p) =>
      pushGeneric("hp_done", { item_id: it.id, ...p }, `Сходила: ${it.title}`, "🦷", p.day)), 50);
  });
}
function bookDialog(it) {
  sheetDialog(`<h2>📅 ${esc(it.title)}</h2>
    <label class="field"><span>Дата приёма</span><input id="bkDay" type="date" value="${todayISO()}"></label>
    <p class="hint">Если в фонде на приём не хватает, в лист встанет строка «В фонд …» на недостающую сумму.</p>
    <button class="primary" data-a="ok">Записалась</button>`, (a) => {
    if (a !== "ok") return;
    const day = $("bkDay").value;
    if (!day) { toast("Укажите дату"); return false; }
    pushGeneric("hp_book", { item_id: it.id, day }, `Записалась: ${it.title} · ${ddmm(day)}`, "📅");
  });
}
function doneDialog(title, day, cost, send) {
  sheetDialog(`<h2>✓ ${esc(title)}</h2>
    <label class="field"><span>Когда</span><input id="dnDay" type="date" value="${esc(day)}"></label>
    <label class="field"><span>Сколько заплатила</span><input id="dnFact" inputmode="decimal" value="${cost ? String(cost).replace(".", ",") : ""}"></label>
    <label class="field"><span>Что сказали на приёме</span><input id="dnSaid" placeholder="необязательно"></label>
    <button class="primary" data-a="ok">Сохранить</button>`, (a) => {
    if (a !== "ok") return;
    const fact = parseAmount($("dnFact").value || "0");
    send({ day: $("dnDay").value || todayISO(), fact: fact > 0 ? fact : 0, said: $("dnSaid").value.trim() });
    toast("Отмечено — уйдёт на сервер");
  });
}
function visitDialog(v) {
  doneDialog(v.title, v.date > todayISO() ? todayISO() : v.date, v.plan, (p) =>
    pushGeneric("visit_done", { visit_id: v.id, ...p }, `Сходила: ${v.title}`, "🩺", p.day));
}

/* ------------------------------------------------------------------ 🎉 поводы */
function occSum(o) {
  return `потрачено <b class="red">${fmt(o.spent)}</b>${o.got ? ` · подарили <b class="green">+${fmt(o.got)}</b> · из своих <b>${fmt(o.net)}</b>` : ""}` +
    (o.budget ? ` · бюджет ${fmt(o.budget)} → ${o.budget - o.net >= 0 ? `<span class="green">осталось ${fmt(o.budget - o.net)}</span>` : `<span class="red">сверх ${fmt(o.net - o.budget)}</span>`}` : "");
}
function renderOcc() {
  const box = $("occ");
  const oc = snap && snap.occasions;
  if (!oc) { box.innerHTML = `<div class="card empty">Поводы появятся после обновления сервера.</div>`; return; }
  let h = `<button type="button" class="primary" id="occNew" style="margin-bottom:12px">+ Новый повод</button>`;
  pendingOf("occ_new").forEach((e) => { h += `<div class="card soft">${esc(e.p.emoji)} <b>${esc(e.p.name)}</b><div class="hint">ждёт отправки — после синхронизации можно отмечать операции</div></div>`; });
  if (!oc.list.length && !pendingOf("occ_new").length) {
    h += `<div class="card empty">Создайте повод — «🎂 День рождения», «🎄 Новый год» — и отметьте операции, которые к нему относятся: посчитаю, сколько всего ушло.</div>`;
  }
  oc.list.forEach((o, i) => {
    const pend = pendingOf("occ_set", (p) => p.occasion_id === o.id).length;
    h += `<div class="card tap" data-occ="${i}"><h2 style="margin:0 0 4px">${esc(o.emoji)} ${esc(o.name)}</h2>
      <div class="hint" style="margin:0">${ddmm(o.start)}–${ddmm(o.end)}.${o.end.slice(0, 4)} · операций ${o.ops.length}${pend ? " · изменения ждут отправки" : ""}</div>
      <div style="margin-top:6px">${occSum(o)}</div></div>`;
  });
  box.innerHTML = h;
  $("occNew").onclick = occNewDialog;
  box.querySelectorAll("[data-occ]").forEach((el) => el.addEventListener("click", () => occDetail(oc.list[Number(el.dataset.occ)])));
}
function occNewDialog() {
  const sug = (snap.occasions && snap.occasions.suggest) || [];
  const bg = sheetDialog(`<h2>Новый повод</h2>
    ${sug.length ? `<div class="filters">${sug.map((s, i) => `<button type="button" class="chip" data-sug="${i}">${esc(s.emoji)} ${esc(s.name)}</button>`).join("")}</div>` : ""}
    <div class="two"><label class="field"><span>Значок</span><select id="ocEmo">${["🎂", "🎄", "💐", "🎁", "✈️", "💍", "🎉"].map((e) => `<option>${e}</option>`).join("")}</select></label>
      <label class="field"><span>Название</span><input id="ocName" placeholder="День рождения 2026"></label></div>
    <div class="two"><label class="field"><span>С</span><input id="ocStart" type="date" value="${todayISO()}"></label>
      <label class="field"><span>По</span><input id="ocEnd" type="date" value="${addDays(todayISO(), 7)}"></label></div>
    <label class="field"><span>Бюджет (необязательно)</span><input id="ocBudget" inputmode="decimal" placeholder="без бюджета"></label>
    <button class="primary" data-a="save">Создать</button>`, (a) => {
    if (a !== "save") return;
    const name = $("ocName").value.trim();
    if (!name) { toast("Впишите название"); return false; }
    let s = $("ocStart").value, e = $("ocEnd").value;
    if (e < s) [s, e] = [e, s];
    pushGeneric("occ_new", { name, emoji: $("ocEmo").value, start: s, end: e, budget: parseAmount($("ocBudget").value || "0") || 0 },
      `Повод: ${$("ocEmo").value} ${name}`, "🎉");
    toast("Повод создастся при синхронизации — потом отметьте операции");
  });
  bg.querySelectorAll("[data-sug]").forEach((b) => b.addEventListener("click", () => {
    const s = sug[Number(b.dataset.sug)];
    $("ocEmo").value = s.emoji; $("ocName").value = s.name; $("ocStart").value = s.start; $("ocEnd").value = s.end;
  }));
}
function occDetail(o) {
  const ops = o.ops.map((x) => `<div class="line"><span>${ddmm(x.date)} · ${esc(x.name)}</span>
    <span class="r ${x.kind === "income" ? "green" : ""}">${x.kind === "income" ? "+" : "−"}${fmtExact(x.amount)}</span></div>`).join("");
  sheetDialog(`<h2>${esc(o.emoji)} ${esc(o.name)}</h2><p class="hint">${ddmm(o.start)}–${ddmm(o.end)}.${o.end.slice(0, 4)}</p>
    <div style="margin-bottom:8px">${occSum(o)}</div>
    ${ops || '<p class="hint">Операций пока нет.</p>'}
    <button class="primary" data-a="pick" style="margin-top:10px">✓ Отметить операции…</button>`, (a) => {
    if (a === "pick") setTimeout(() => occPick(o), 50);
  });
}
function occPick(o) {
  if (!SRV) { toast("Отмечать операции можно, когда телефон подключён к серверу"); return; }
  toast("Загружаю операции…", 1500);
  srv("GET", `/api/occ?id=${o.id}`).then((data) => {
    const list = data.ops || [];
    const bg = sheetDialog(`<h2>${esc(o.emoji)} ${esc(o.name)} — операции</h2>
      <p class="hint">Всё за даты повода и неделю вокруг. Отметьте, что к нему относится, — подарки, фуршет, подаренные деньги.</p>
      <input id="opQ" placeholder="поиск: фуршет, подарок…" style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:12px;margin-bottom:8px">
      <div id="opList">${list.map((x, i) => `<label class="line" data-txt="${esc((x.name + " " + x.category + " " + x.amount).toLowerCase())}" style="gap:10px">
        <span style="display:flex;gap:10px;align-items:flex-start;flex:1;min-width:0"><input type="checkbox" data-oc="${i}" ${x.on ? "checked" : ""} style="margin-top:3px">
        <span>${ddmm(x.date)} · ${esc(x.name)}<div class="hint" style="margin:0">${esc(x.category)}</div></span></span>
        <span class="r ${x.income ? "green" : ""}">${x.income ? "+" : "−"}${fmtExact(x.amount)}</span></label>`).join("") || '<p class="hint">За эти даты операций нет.</p>'}</div>
      <p class="hint" id="opSum"></p>
      <button class="primary" data-a="save">Сохранить</button>`, (a, box) => {
      if (a !== "save") return;
      const refs = [], items = [];
      box.querySelectorAll("[data-oc]").forEach((c) => {
        if (!c.checked) return;
        const x = list[Number(c.dataset.oc)];
        refs.push(x.ref); items.push({ ref: x.ref, name: x.name, amount: x.amount, date: x.date });
      });
      pushGeneric("occ_set", { occasion_id: o.id, refs, items }, `${o.emoji} ${o.name}: отмечено ${refs.length}`, "🎉");
      toast("Сохраняю…");
    });
    const sum = () => {
      let s = 0, g = 0, n = 0;
      bg.querySelectorAll("[data-oc]").forEach((c) => { if (c.checked) { const x = list[Number(c.dataset.oc)]; n++; if (x.income) g += x.amount; else s += x.amount; } });
      $("opSum").innerHTML = `Отмечено ${n}: потрачено <b>${fmtExact(s)}</b>${g ? `, подарили <b>+${fmtExact(g)}</b>, из своих <b>${fmtExact(s - g)}</b>` : ""}`;
    };
    bg.addEventListener("change", sum); sum();
    $("opQ").addEventListener("input", () => {
      const q = $("opQ").value.trim().toLowerCase();
      bg.querySelectorAll("#opList [data-txt]").forEach((el) => { el.style.display = !q || el.dataset.txt.includes(q) ? "" : "none"; });
    });
  }).catch((e) => toast(e.message || String(e), 4500));
}


/* ------------------------------------------------------------------ 💼 До зарплаты */
const W_KINDS = { spend: ["🧾", "трата"], order: ["📦", "заказ, не оплачен"], borrow: ["🤝", "взяла в долг"],
  refund: ["↩", "вернут мне"], dream: ["✨", "мечта — если хватит"] };
function walletItems() {
  /* строки с сервера + то, что ещё ждёт отправки (добавлено, изменено, удалено, отмечено) */
  const w = (snap && snap.wallet) || { items: [] };
  const map = new Map(w.items.map((x) => [x.uid, { ...x }]));
  entries.filter((e) => e.status !== "done" && e.kind && e.kind.startsWith("wallet_")).slice().reverse().forEach((e) => {
    const p = e.p || {};
    if (e.kind === "wallet_save") map.set(p.item.uid, { ...(map.get(p.item.uid) || {}), ...p.item, pending: true });
    if (e.kind === "wallet_del") map.delete(p.wuid);
    if (e.kind === "wallet_done" && map.has(p.wuid)) map.get(p.wuid).done = p.done;
  });
  return [...map.values()].sort((a, b) => (a.done - b.done) || String(a.day || "9").localeCompare(String(b.day || "9")));
}
function walletMoney() {
  const w = (snap && snap.wallet) || {};
  let card = w.card || 0, cash = w.cash || 0;
  entries.filter((e) => e.kind === "wallet_money" && e.status !== "done").slice().reverse().forEach((e) => {
    if (e.p.card != null) card = e.p.card;
    if (e.p.cash != null) cash = e.p.cash;
  });
  return { card, cash };
}
function walletSummary() {
  const w = (snap && snap.wallet) || {};
  const next = w.next || addDays(todayISO(), 7), t = todayISO();
  const { card, cash } = walletMoney();
  const s = { next, card, cash, card_need: 0, cash_need: 0, card_in: 0, after_need: 0, dream: 0, count: 0 };
  walletItems().filter((x) => !x.done).forEach((x) => {
    s.count++;
    const a = Number(x.amount) || 0, before = (x.day || t) < next;
    if (x.kind === "spend" || x.kind === "order") { if (before) s[x.pay === "cash" ? "cash_need" : "card_need"] += a; else s.after_need += a; }
    else if (x.kind === "borrow") { if ((x.day2 || next) < next) s[x.pay === "cash" ? "cash_need" : "card_need"] += a; else s.after_need += a; }
    else if (x.kind === "refund") { if (before) s.card_in += a; }
    else if (x.kind === "dream") s.dream += a;
  });
  s.card_left = card + s.card_in - s.card_need; s.cash_left = cash - s.cash_need; s.left = s.card_left + s.cash_left;
  /* сумма на карте вписана до последней выплаты — устарела (если на телефоне её с тех пор не меняли) */
  const fresh = entries.some((e) => e.kind === "wallet_money" && e.status !== "done" && e.p.card != null) ||
    entries.some((e) => e.kind === "bank" && e.status !== "done");
  s.card_stale = !!w.card_stale && !fresh && s.card_need > 0; s.card_at = w.card_at || "";
  return s;
}
function walletHeadline(s) {
  if (!s.count) return "запишите траты, заказы и долги, которые впереди";
  const nd = ddmm(s.next), bad = [];
  if (s.card_stale)
    return `С карты до ${nd} — ${fmt(s.card_need)}. Сумма на карте вписана${s.card_at ? " " + ddmm(s.card_at) : ""}, до зарплаты — впишите, сколько сейчас` +
      (s.cash_left < 0 ? ` · наличными не хватает ${fmt(-s.cash_left)}` : "") + (s.after_need ? ` · после зарплаты ${fmt(s.after_need)}` : "");
  if (s.card_left < 0) bad.push(`на карте не хватает ${fmt(-s.card_left)}`);
  if (s.cash_left < 0) bad.push(`наличными не хватает ${fmt(-s.cash_left)}`);
  return (bad.length ? `До ${nd}: ${bad.join(", ")}` : `До ${nd} хватает, останется ${fmt(s.left)}`) +
    (s.after_need ? ` · после зарплаты ${fmt(s.after_need)}` : "");
}
function walletCard() {
  /* мини-карточка на «Главной»: сворачивается; убрать — в «Ещё → 💼 До зарплаты» */
  const w = snap && snap.wallet;
  if (!w || cfg.walletHide) return "";
  const s = walletSummary(), bad = (!s.card_stale && s.card_left < 0) || s.cash_left < 0, folded = cfg.walletFold !== false;   /* по умолчанию — одна строка итога */
  const list = folded ? "" : walletItems().filter((x) => !x.done).slice(0, 4).map((x) =>
    `<div class="line"><span>${W_KINDS[x.kind][0]} ${x.kind === "borrow" ? ddmm(x.day2 || s.next) + " вернуть: " : x.day ? ddmm(x.day) + " " : ""}${esc(x.title || W_KINDS[x.kind][1])}</span>
     <span class="r">${x.kind === "refund" ? "+" : ""}${fmt(x.amount)}${x.pay === "cash" && x.kind !== "refund" ? " 💵" : ""}</span></div>`).join("");
  return `<div class="card" id="wCard"><div style="display:flex;gap:8px;align-items:center">
      <button type="button" class="ghost small" id="wFold" style="width:auto;padding:4px 10px">${folded ? "▸" : "▾"}</button>
      <b style="flex:1">💼 До зарплаты</b><button type="button" class="ghost small" id="wOpen" style="width:auto">Открыть →</button></div>
    <div class="hint ${bad ? "red" : s.count ? "green" : ""}" style="margin:6px 0 0">${esc(walletHeadline(s))}</div>${list}</div>`;
}
function walletCardBind() {
  if ($("wFold")) $("wFold").onclick = () => { cfg.walletFold = cfg.walletFold === false; saveCfg(); renderSummary(); };
  if ($("wOpen")) $("wOpen").onclick = () => { cfg.moreTab = "wallet"; saveCfg(); showPage("more"); renderMore(); };
}
function renderWallet() {
  const box = $("wallet");
  if (!snap || !snap.wallet) { box.innerHTML = `<div class="card empty">«До зарплаты» появится после обновления сервера и ноутбука.</div>`; return; }
  const s = walletSummary(), m = walletMoney();
  const tone = (x) => `<b class="${x < 0 ? "red" : "green"}">${fmt(x)}</b>`;
  let h = `<div class="card"><div class="two">
      <label class="field"><span>💳 На карте</span><input id="wCardIn" inputmode="decimal" value="${String(m.card).replace(".", ",")}"></label>
      <label class="field"><span>💵 Наличными</span><input id="wCashIn" inputmode="decimal" value="${String(m.cash).replace(".", ",")}"></label></div>
    <div style="margin-top:4px">До зарплаты ${ddmm(s.next)}: с карты ${fmt(s.card_need)}${s.card_in ? `, придёт ${fmt(s.card_in)}` : ""} → на карте ${tone(s.card_left)}</div>
    ${s.cash || s.cash_need ? `<div>наличными ${fmt(s.cash_need)} → останется ${tone(s.cash_left)}</div>` : ""}
    ${s.after_need ? `<div class="hint" style="margin:6px 0 0">После зарплаты понадобится ${fmt(s.after_need)}</div>` : ""}
    ${s.dream ? `<div class="hint" style="margin:2px 0 0">✨ Мечты ${fmt(s.dream)} — ${s.left >= s.dream ? "до зарплаты хватает" : "ждут зарплаты"}</div>` : ""}</div>`;
  h += `<div class="filters">${Object.entries(W_KINDS).map(([k, v]) => `<button type="button" class="chip" data-wadd="${k}">+ ${v[0]} ${v[1].split(",")[0].split(" —")[0]}</button>`).join("")}</div>`;
  const list = walletItems();
  h += list.length ? `<div class="card">${list.map((x) => `<div class="line tap" data-wi="${esc(x.uid)}" style="${x.done ? "opacity:.5;text-decoration:line-through" : ""}">
      <span>${W_KINDS[x.kind][0]} ${x.kind === "borrow" ? "вернуть " + ddmm(x.day2 || s.next) : x.day ? ddmm(x.day) : ""} · ${esc(x.title || W_KINDS[x.kind][1])}${x.who ? " · " + esc(x.who) : ""}
        <div class="hint" style="margin:1px 0 0">${x.moved ? "✓ в листе" : "ещё не в листе"}${x.pending ? " · ждёт отправки" : ""}</div></span>
      <span class="r">${x.kind === "refund" ? "+" : ""}${fmt(x.amount)}${x.pay === "cash" && x.kind !== "refund" ? " 💵" : ""}</span></div>`).join("")}</div>`
    : `<div class="card empty">Запишите сюда всё, что впереди: фуршет, такси, заказы, которые надо забрать, долг Севе, мечту «если хватит».</div>`;
  h += `<button type="button" class="primary" id="wMove">📋 Перенести в лист</button>
    <label style="display:flex;gap:10px;align-items:center;margin:12px 2px"><input type="checkbox" id="wHome" ${cfg.walletHide ? "" : "checked"}> показывать на «Главной»</label>`;
  box.innerHTML = h;
  const money = () => pushGeneric("wallet_money", { card: parseAmount($("wCardIn").value || "0"), cash: parseAmount($("wCashIn").value || "0") }, "💼 Деньги сейчас", "💼");
  $("wCardIn").onchange = money; $("wCashIn").onchange = money;
  box.querySelectorAll("[data-wadd]").forEach((b) => b.onclick = () => walletItemDialog(null, b.dataset.wadd));
  box.querySelectorAll("[data-wi]").forEach((el) => el.onclick = () => walletItemDialog(list.find((x) => x.uid === el.dataset.wi)));
  $("wMove").onclick = () => {
    if (!list.some((x) => !x.moved)) { toast("Всё уже в листе ✓"); return; }
    if (!confirm("Поставить в лист всё, чего там ещё нет? Траты — в свой месяц и колонку, долг — доходом и в «План погашения».")) return;
    pushGeneric("wallet_move", {}, "💼 Перенести в лист", "📋"); toast("Переношу в лист…");
  };
  $("wHome").onchange = () => { cfg.walletHide = !$("wHome").checked; saveCfg(); };
}
function walletItemDialog(x, kind) {
  const k0 = x ? x.kind : kind || "spend";
  const next = (snap.wallet && snap.wallet.next) || todayISO();
  const cats = ((snap.categories && snap.categories.expense) || EXPENSE_DEFAULT).filter((c) => !c.startsWith("В фонд") && c !== "Кредиты и платежи");
  const bg = sheetDialog(`<h2>${x ? "Изменить" : "Добавить"}</h2>
    <label class="field"><span>Что это</span><select id="wiKind">${Object.entries(W_KINDS).map(([k, v]) => `<option value="${k}" ${k === k0 ? "selected" : ""}>${v[0]} ${v[1]}</option>`).join("")}</select></label>
    <label class="field"><span>Название</span><input id="wiTitle" value="${esc(x ? x.title : "")}" placeholder="фуршет, Озон: коробки…"></label>
    <label class="field"><span>Сумма</span><input id="wiSum" inputmode="decimal" value="${x ? String(x.amount).replace(".", ",") : ""}"></label>
    <div class="two"><label class="field"><span id="wiDayL">Когда</span><input id="wiDay" type="date" value="${esc((x && x.day) || todayISO())}"></label>
      <label class="field" id="wiDay2F"><span>Вернуть до</span><input id="wiDay2" type="date" value="${esc((x && x.day2) || next)}"></label></div>
    <label class="field" id="wiPayF"><span>Как платить</span><select id="wiPay"><option value="card">💳 с карты</option><option value="cash" ${x && x.pay === "cash" ? "selected" : ""}>💵 наличными</option></select></label>
    <label class="field" id="wiCatF"><span>Категория</span><select id="wiCat">${cats.map((c) => `<option ${(x && x.category === c) || (!x && c === "Другое") ? "selected" : ""}>${esc(c)}</option>`).join("")}</select></label>
    <label class="field" id="wiWhoF"><span>Кто</span><input id="wiWho" value="${esc(x ? x.who || "" : "")}" placeholder="Сева, мама…"></label>
    <button class="primary" data-a="save">Сохранить</button>
    ${x ? `<button class="ghost" data-a="done">${x.done ? "↺ Не оплачено" : "✓ Оплачено / вернула / пришли"}</button><button class="ghost" data-a="del">Удалить</button>` : ""}`, (a) => {
    if (a === "done") { pushGeneric("wallet_done", { wuid: x.uid, done: !x.done }, `💼 ${x.title}: ${x.done ? "не оплачено" : "✓"}`, "💼"); return; }
    if (a === "del") { if (!confirm("Убрать из «До зарплаты»?" + (x.moved ? " В листе строка останется." : ""))) return false;
      pushGeneric("wallet_del", { wuid: x.uid }, `💼 убрано: ${x.title}`, "💼"); return; }
    if (a !== "save") return;
    const amount = parseAmount($("wiSum").value);
    if (!(amount > 0)) { toast("Впишите сумму"); return false; }
    const k = $("wiKind").value;
    const item = { uid: x ? x.uid : "p" + uid(), kind: k, title: $("wiTitle").value.trim(), amount, day: $("wiDay").value,
      day2: k === "borrow" ? $("wiDay2").value : null, pay: $("wiPay").value,
      category: k === "borrow" || k === "refund" ? "" : $("wiCat").value, who: $("wiWho").value.trim() };
    pushGeneric("wallet_save", { item }, `💼 ${item.title || W_KINDS[k][1]} · ${fmt(amount)}`, W_KINDS[k][0]);
  });
  const vis = () => {
    const k = $("wiKind").value;
    $("wiDay2F").hidden = k !== "borrow"; $("wiPayF").hidden = !["spend", "order", "borrow"].includes(k);
    $("wiCatF").hidden = k === "borrow" || k === "refund"; $("wiWhoF").hidden = !(k === "borrow" || k === "refund");
    $("wiDayL").textContent = k === "borrow" ? "Когда получила" : k === "refund" ? "Когда придут" : "Когда";
  };
  bg.addEventListener("change", vis); vis();
}

function renderAll() {
  fillForm();
  $("today").innerHTML = "";              // «можно потратить» — только на Главной, без повторов
  renderOps();
  renderSummary();
  renderSheet();
  renderCredits();
  renderMore();
  renderSettings();
  renderCount();
  updateBadge();
  if ($("page-sum").classList.contains("active")) $("subtitle").textContent = syncStamp();
}

/* ------------------------------------------------------------------ действия над записью */
function openEntry(id) {
  const e = entries.find((x) => x.id === id);
  if (!e) return;
  const bg = document.createElement("div");
  bg.className = "sheet-bg";
  const canSend = e.status === "local";
  const canLocal = e.status === "pending";
  const canDelete = true;
  const canEdit = (e.kind === "expense" || e.kind === "income") && (e.status === "pending" || e.status === "local" || e.status === "sent");
  const title = e.kind === "done" ? `Оплачено ● «${esc(e.row_name)}»` : e.kind === "fundpay" ? `Из фонда «${esc(e.fund)}» · ${fmtExact(e.amount)}`
    : e.kind === "rowdel" ? `Удалить из листа: ${esc(e.row_name)}` : e.kind === "rowedit" ? `Изменить: ${esc(e.row_name)}`
    : GENERIC_KINDS.includes(e.kind) ? esc(e.title || e.kind)
    : e.kind === "rowadd" ? `Новая строка: ${esc(e.note || e.category)} · ${fmt(e.amount)}`
    : e.kind === "paste" ? `Вставка: ${e.items.length} опер.`
    : e.kind === "mark" ? `В календарь: ${esc(e.title)}` : e.kind === "markdel" ? `Убрать из календаря: ${esc(e.title)}`
    : e.kind === "bank" ? "Сверка с банком" : e.kind === "cycle" ? `Цикл: ${e.flow ? FLOW_NAMES[e.flow] : "без выделений"}`
    : `${esc(e.note || e.category)} · ${fmtExact(e.amount)}`;
  bg.innerHTML = `<div class="sheet"><h2>${title}</h2>
    <p class="hint">${ddmm(e.date)} · ${esc(e.category || "")}${e.kind === "expense" || e.kind === "income" ? " · " + HALF_NAME[e.half || autoHalf(e.date, e.kind === "income" ? e.category : "")] : ""}</p>
    ${canEdit ? '<button class="primary" data-a="edit">Изменить</button>' : ""}
    ${e.status === "sent" ? '<p class="hint">Отправлена, но ещё не в листе — её можно изменить или удалить: исправление тоже уйдёт на компьютер. Если компьютер успел записать её раньше, он напомнит поправить лист вручную.</p>' : ""}
    ${e.status === "done" ? '<p class="hint">Уже записана в лист на компьютере. Удаление здесь уберёт её только из этого списка.</p>' : ""}
    ${canSend ? '<button class="primary" data-a="send">Отправить на компьютер</button>' : ""}
    ${canLocal ? '<button class="ghost" data-a="local">Оставить только на телефоне</button>' : ""}
    ${canDelete ? '<button class="ghost danger" data-a="del">Удалить</button>' : ""}
    <button class="ghost" data-a="close">Закрыть</button></div>`;
  bg.addEventListener("click", (ev) => {
    const a = ev.target.dataset && ev.target.dataset.a;
    if (ev.target === bg || a === "close") { bg.remove(); return; }
    if (a === "edit") { bg.remove(); editEntry(e); return; }
    if (a === "send") { e.mode = "send"; e.status = "pending"; }
    if (a === "local") { e.mode = "local"; e.status = "local"; }
    if (a === "del") {
      if (!confirm(e.status === "sent" ? "Удалить запись? Компьютер её не запишет." : "Удалить запись?")) return;
      if (e.status === "sent") {             // уже на сервере — отправляем «удалить»
        e.deleted = true; e.rev = (e.rev || 0) + 1; e.status = "pending"; e.mode = "send";
      } else entries = entries.filter((x) => x.id !== e.id);
    }
    if (a) { saveEntries(); bg.remove(); renderAll(); if (a === "del" && e.deleted) autoSync(); }
  });
  document.body.appendChild(bg);
}

function editEntry(e) {
  kind = e.kind; mode = e.mode;
  showPage("add");
  fillForm();
  if (!categories().includes(e.category)) $("category").insertAdjacentHTML("beforeend", `<option>${esc(e.category)}</option>`);
  $("category").value = e.category;
  $("amount").value = String(e.amount).replace(".", ",");
  $("note").value = e.note || "";
  $("date").value = e.date;
  $("half").value = String(e.half || 0);
  $("row").value = e.row_id ? String(e.row_id) : "";
  const mo = document.querySelector(".more-opts");
  if (mo) mo.open = !!(e.half || e.mode === "local");     // нестандартная колонка / только телефон — показать
  setEditing(e.id);
  toast("Измените и нажмите «Сохранить»");
}

/* ------------------------------------------------------------------ лист действий */
function sheetDialog(html, onClick) {
  const bg = document.createElement("div");
  bg.className = "sheet-bg";
  bg.innerHTML = `<div class="sheet">${html}<button class="ghost" data-a="close">Закрыть</button></div>`;
  bg.addEventListener("click", (ev) => {
    const a = ev.target.dataset && ev.target.dataset.a;
    if (ev.target === bg || a === "close") { bg.remove(); return; }
    if (a && onClick(a, bg) !== false) bg.remove();
  });
  document.body.appendChild(bg);
  return bg;
}
function findRow(id) {
  for (const sh of (snap && snap.sheets) || []) for (const h of sh.halves) for (const r of h.rows) if (r.id === id) return { r, half: h.half };
  return null;
}
function pendingDone(rowId) {
  return entries.some((e) => (e.kind === "done" || e.kind === "fundpay") && e.row_id === rowId && e.status !== "done" && !e.deleted);
}
const SPEND_CATS = ["Продукты", "Обеды и кафе", "Обеды в офисе", "Кафе и рестораны", "Маркетплейсы", "Одежда и маркетплейсы",
  "Развлечения и прогулки", "Другое", "Хобби и творчество", "Красота и уход", "Дом и быт", "Транспорт"];
function isSpendRow(r) {
  /* из строки тратят понемногу: продукты, обеды… (или из неё уже тратили) — у неё ＋; разовые (подписка, квартира) — ○ */
  if ((r.spends || []).length) return true;
  const one = /подписк|квартир|проездн|связь|налог|автоплат|маникюр|косметолог/i.test(r.name || "");
  return SPEND_CATS.includes(r.category) && !one;
}
function rowQuick(r) {
  if (r.done || pendingDone(r.id)) return "";
  if (canSpendRow(r) && isSpendRow(r)) return `<button type="button" class="row-plus" data-spend="${r.id}" aria-label="Потратить из строки">＋</button>`;
  if (r.from_fund) return "";
  return `<button type="button" class="row-plus ring" data-quickdone="${r.id}" aria-label="Отметить оплаченной">○</button>`;
}
function quickDone(id) {
  const f = findRow(id);
  if (!f) return;
  entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "done", amount: 0,
    category: f.r.category, note: "", row_id: id, row_name: f.r.name, half: f.half, mode: "send", status: "pending" });
  saveEntries(); renderAll(); autoSync(800);
  toast(`«${f.r.name}» — оплачено ●. Отменить: «Операции → С телефона» → запись → Удалить`, 4200);
}
function canSpendRow(r) { return !r.credit && !r.from_fund && !r.fund && !String(r.category || "").startsWith("В фонд") && !r.done && r.left > 0.5; }
function spendFromRow(id) {
  kind = "expense"; mode = "send"; setEditing(null);
  showPage("add"); fillForm();
  $("row").value = String(id); onRowChange(); $("amount").focus();
}
function openRow(id) {
  const f = findRow(id);
  if (!f) return;
  const r = f.r;
  const canSpend = canSpendRow(r);
  const canDone = !r.done && !pendingDone(id);
  const sp = r.spends || [];
  const funds = ((snap && snap.funds) || []).map((x, i) => ({ ...x, i })).filter((x) => x.saved > 0.5);
  const canFund = !r.credit && !r.from_fund && !r.done && !sp.length && funds.length;
  const spHtml = sp.length ? `<div class="spend-list">${sp.map((x) => `<div class="line"><span>${ddmm(x.date)} · ${esc(x.note || (x.amount < 0 ? "вернули" : "трата"))}</span>
      <span class="r ${x.amount < 0 ? "green" : ""}">${x.amount < 0 ? "↩ +" : "−"}${fmtExact(Math.abs(x.amount))}</span></div>`).join("")}</div>` : "";
  const canEdit = !r.credit && !r.from_fund;
  sheetDialog(`<h2>${esc(r.name)} · ${fmt(r.amount)}</h2>
    <p class="hint">${esc(r.category)} · ${f.half === 1 ? "с зарплаты" : "с аванса"}${r.date ? " · " + ddmm(r.date) : ""}${r.spent ? ` · потрачено ${fmt(r.spent)}, осталось ${fmt(Math.max(0, r.left))}` : ""}${r.done ? " · оплачено ●" : ""}${pendingDone(id) ? " · отметка ● ждёт синхронизации" : ""}${r.from_fund ? " · оплачено из фонда" : ""}</p>
    ${spHtml}
    <div class="acts">
      ${canSpend ? '<button class="primary wide" data-a="spend">＋ Потратила из этой строки</button>' : ""}
      ${canDone ? `<button class="ghost ${canFund ? "" : "wide"}" data-a="done">● Оплачено</button>` : ""}
      ${canFund ? '<button class="ghost" data-a="fund">🐷 Из фонда…</button>' : ""}
      ${r.credit ? '<button class="ghost wide" data-a="credit">💳 Открыть в «Кредитах»</button>' : ""}
      ${canEdit ? '<button class="ghost" data-a="edit">✏️ Изменить</button>' : ""}
      ${canEdit ? '<button class="ghost" data-a="move">📅 Перенести</button>' : ""}
      ${canEdit && !sp.length ? '<button class="ghost danger wide" data-a="del">Удалить строку</button>' : ""}
    </div>`, (a) => {
    if (a === "del") {
      if (!confirm(`Удалить «${r.name}» ${fmt(r.amount)} из листа?`)) return false;
      entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "rowdel", amount: 0,
        category: r.category, note: r.name, row_id: id, row_name: r.name, mode: "send", status: "pending" });
      saveEntries(); renderAll(); autoSync(800);
      toast(`«${r.name}» удалится из листа при синхронизации`);
    }
    if (a === "edit" || a === "move") { setTimeout(() => editRowDialog(id, r, f.half, a === "move"), 50); }
    if (a === "spend") spendFromRow(id);
    if (a === "credit") showPage("credits");
    if (a === "fund") { setTimeout(() => rowFundDialog(id, r, f.half, funds), 50); }
    if (a === "done") {
      entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "done", amount: 0,
        category: r.category, note: "", row_id: id, row_name: r.name, half: f.half, mode: "send", status: "pending" });
      saveEntries(); renderAll(); autoSync(800);
      toast(`«${r.name}» отмечено ● — уйдёт на компьютер при синхронизации`);
    }
  });
}
function rowFundDialog(id, r, half, funds) {
  /* строку листа оплатили деньгами фонда: в колонку встанет снятие «Из фонда …», строка — ● */
  sheetDialog(`<h2>«${esc(r.name)}» ${fmt(r.amount)} — из какого фонда?</h2>
    <p class="hint">Для месяца это ноль: в колонке появится «Из фонда …» на ту же сумму, строка станет оплаченной ●, фонд уменьшится.</p>
    ${funds.map((x) => `<button class="ghost" data-a="f${x.i}">${esc(x.name)} · в фонде ${fmt(x.saved)}</button>`).join("")}`, (a) => {
    if (!a.startsWith("f")) return;
    const fund = snap.funds[Number(a.slice(1))];
    if (r.amount > fund.saved + 0.5 && !confirm(`В фонде ${fmt(fund.saved)}, а строка ${fmt(r.amount)} — фонд уйдёт в минус. Всё равно?`)) return false;
    entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "fundpay", fund: fund.name,
      amount: r.amount, category: r.category, note: r.name, half, row_id: id, row_name: r.name, mode: "send", status: "pending" });
    saveEntries(); renderAll(); autoSync(800);
    toast(`«${r.name}» — из фонда «${fund.name}», уйдёт при синхронизации`);
  });
}
function editRowDialog(id, r, half, moving) {
  sheetDialog(`<h2>${moving ? "Перенести: " : ""}${esc(r.name)}</h2>
    <p class="hint">Новая дата — строка переедет в нужный месяц (1–9 число в колонке «С аванса» — это лист прошлого месяца).</p>
    <label class="field"><span>Дата</span><input id="reDate" type="date" value="${esc(r.date || todayISO())}"></label>
    <label class="field"><span>Сумма</span><input id="reAmount" inputmode="decimal" value="${String(r.amount).replace(".", ",")}"></label>
    <label class="field"><span>Колонка</span><select id="reHalf"><option value="1" ${half === 1 ? "selected" : ""}>С зарплаты</option>
      <option value="2" ${half === 2 ? "selected" : ""}>С аванса</option></select></label>
    <button class="primary" data-a="save">Сохранить</button>`, (a) => {
    if (a !== "save") return;
    const nd = $("reDate").value, amount = parseAmount($("reAmount").value), nh = Number($("reHalf").value);
    if (!nd) { toast("Укажите дату"); return false; }
    if (!(amount > 0)) { toast("Введите сумму"); return false; }
    entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "rowedit", amount,
      new_date: nd, half: nh !== half ? nh : null, category: r.category, note: r.name, row_id: id, row_name: r.name,
      mode: "send", status: "pending" });
    saveEntries(); renderAll(); autoSync(800);
    toast(`«${r.name}»: ${ddmm(nd)}, ${fmt(amount)}${nh !== half ? ", " + HALF_NAME[nh] : ""} — уйдёт при синхронизации`);
  });
}

/* ------------------------------------------------------------------ новая строка в лист */
function sheetOf(iso, half) {
  /* в какой лист попадёт строка (год*12+месяц): 1–9 число в колонке «С аванса» — лист прошлого месяца */
  const y = Number(iso.slice(0, 4)), m = Number(iso.slice(5, 7));
  return y * 12 + m - (half === 2 && Number(iso.slice(8, 10)) < 10 ? 1 : 0);
}
function addRowDialog(si, half) {
  const sh = snap.sheets[si];
  const ym = `${sh.year}-${String(sh.month).padStart(2, "0")}`;
  const cats = (k) => k === "income" ? ((snap.categories && snap.categories.income) || INCOME_DEFAULT)
    : ((snap.categories && snap.categories.expense) || EXPENSE_DEFAULT).filter((c) => !c.startsWith("В фонд") && c !== "Кредиты и платежи");
  let rk = "expense";
  const bg = sheetDialog(`<h2>Новая строка · ${esc(sh.title)}</h2>
    <div class="seg" id="arKind"><button type="button" class="on" data-k="expense">Расход</button><button type="button" data-k="income">Доход</button></div>
    <label class="field"><span>Что</span><input id="arNote" placeholder="например: маникюр, подарок маме"></label>
    <label class="field"><span>Сумма</span><input id="arAmount" inputmode="decimal" placeholder="0"></label>
    <label class="field"><span>Категория</span><select id="arCat"></select></label>
    <div class="two"><label class="field"><span>Колонка</span><select id="arHalf"><option value="1">С зарплаты</option><option value="2">С аванса</option></select></label>
      <label class="field"><span>Дата</span><input id="arDate" type="date"></label></div>
    <label style="display:flex;gap:10px;align-items:center;margin:4px 2px 10px"><input type="checkbox" id="arDone"> уже оплачено ●</label>
    <p class="hint">Это строка-план: из неё потом можно тратить. Обязательные траты месяца сервер поставит сам.</p>
    <button class="primary" data-a="add">Добавить в лист</button>`, (a) => {
    if (a !== "add") return;
    const amount = parseAmount($("arAmount").value), h = Number($("arHalf").value), d = $("arDate").value;
    const note = $("arNote").value.trim(), cat = $("arCat").value;
    if (!(amount > 0)) { toast("Введите сумму"); return false; }
    if (!d) { toast("Укажите дату"); return false; }
    if (sheetOf(d, h) !== sh.year * 12 + sh.month && !confirm("С такой датой строка попадёт в лист другого месяца. Всё равно добавить?")) return false;
    entries.unshift({ id: uid(), created: new Date().toISOString(), date: d, kind: "rowadd", row_kind: rk, amount,
      category: cat, note, half: h, done: $("arDone").checked, mode: "send", status: "pending" });
    saveEntries(); renderAll(); autoSync(800);
    toast(`«${note || cat}» ${fmt(amount)} → ${sh.title}, ${HALF_NAME[h]}`);
  });
  const fill = () => {
    bg.querySelectorAll("#arKind button").forEach((b) => b.classList.toggle("on", b.dataset.k === rk));
    $("arCat").innerHTML = cats(rk).map((c) => `<option>${esc(c)}</option>`).join("");
    if (rk === "expense" && cats(rk).includes("Другое")) $("arCat").value = "Другое";
  };
  const setDate = () => {
    const h = Number($("arHalf").value);
    const iso = `${ym}-${h === 1 ? "10" : "25"}`;
    const t = todayISO();
    // сегодня — если сегодняшний день как раз в этой колонке этого листа, иначе день выплаты
    const inCol = h === 1 ? (t >= `${ym}-10` && t < `${ym}-25`)
      : (sheetOf(t, 2) === sh.year * 12 + sh.month && (t >= `${ym}-25` || t.slice(0, 7) !== ym));
    $("arDate").value = inCol ? t : iso;
  };
  bg.querySelectorAll("#arKind button").forEach((b) => b.addEventListener("click", () => { rk = b.dataset.k; fill(); }));
  $("arHalf").value = String(half);
  $("arHalf").addEventListener("change", setDate);
  fill(); setDate();
  setTimeout(() => { const i = bg.querySelector("#arNote"); if (i) i.focus(); }, 150);
}

/* ------------------------------------------------------------------ вставка текста из банка / заметок */
function pasteDialog() {
  if (!SRV) { toast("Вставка работает, когда телефон подключён к серверу"); return; }
  sheetDialog(`<h2>📋 Вставить операции</h2>
    <p class="hint">Скопируйте текст выписки Сбера или напишите траты, каждую с новой строки: «продукты 1257,30», «12.10 такси 450».
      Возврат: «Сева возврат купер продукты 1650». Дальше покажу, что уже есть в листе и куда записать остальное.</p>
    <textarea id="pzText" rows="8" placeholder="продукты 1257,30&#10;вб 2386&#10;12.10 такси 450"
      style="width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:14px;font:inherit;resize:vertical;margin-bottom:10px"></textarea>
    <button class="primary" data-a="go">Разобрать →</button>`, (a, bg) => {
    if (a !== "go") return;
    const text = $("pzText").value;
    if (!text.trim()) { toast("Вставьте текст"); return false; }
    const btn = bg.querySelector('[data-a="go"]');
    btn.disabled = true; btn.textContent = "Разбираю…";
    srv("POST", "/api/parse", { text }).then((data) => {
      if (!data.ops || !data.ops.length) {
        btn.disabled = false; btn.textContent = "Разобрать →";
        toast("Не нашла ни одной операции. Формат: «продукты 1257,30»", 4500); return;
      }
      bg.remove(); pastePreview(data);
    }).catch((e) => { btn.disabled = false; btn.textContent = "Разобрать →"; toast(e.message || String(e), 4500); });
    return false;
  });
  setTimeout(() => { const t = $("pzText"); if (t) t.focus(); }, 150);
}
function pastePreview(data) {
  const ops = data.ops;
  const list = (o) => data.choices[o.ym + (o.op.income ? "|i" : "|e")] || [];
  const card = (o, i) => {
    const want = JSON.stringify(o.want);
    const opts = list(o).map((c, j) => `<option value="${j}" ${JSON.stringify(c[1]) === want ? "selected" : ""}>${esc(c[0])}</option>`).join("");
    return `<div style="padding:8px 0;border-bottom:1px solid var(--line)">
      <label style="display:flex;gap:10px;align-items:flex-start"><input type="checkbox" data-pz="${i}" ${o.on ? "checked" : ""} style="margin-top:4px">
        <span style="flex:1;min-width:0">${ddmm(o.op.date)} · ${esc(o.op.text)}${o.note ? `<div class="hint" style="margin:2px 0 0">${esc(o.note)}</div>` : ""}</span>
        <b class="${o.op.income ? "green" : ""}" style="white-space:nowrap">${o.op.income ? "+" : "−"}${fmtExact(o.op.amount)}</b></label>
      <select data-pzs="${i}" style="width:100%;max-width:100%;margin-top:6px;padding:8px 10px;border:1px solid var(--line);border-radius:12px;font-size:14px;background:var(--card, #fff)">${opts}</select></div>`;
  };
  const all = ops.map((o, i) => [o, i]);
  const main = all.filter(([o]) => o.on), quiet = all.filter(([o]) => !o.on);
  const bg = sheetDialog(`<h2>Проверьте · ${ops.length} опер.</h2>
    <p class="hint">Отмечено то, чего нет в листе. «➖ из строки» — спишется из строки-плана, «➕ новой строкой» — отдельной строкой с ●. Куда записать — можно поменять.</p>
    ${data.bad && data.bad.length ? `<p class="hint">Не поняла и пропущу: ${data.bad.map(esc).join(" · ")}</p>` : ""}
    ${main.map(([o, i]) => card(o, i)).join("") || '<p class="hint">Новых операций нет — всё уже в листе ✓</p>'}
    ${quiet.length ? `<details style="margin-top:8px"><summary class="hint">Уже в листе, переводы и доходы (${quiet.length})</summary>${quiet.map(([o, i]) => card(o, i)).join("")}</details>` : ""}
    <p class="hint" id="pzSum" style="margin-top:10px"></p>
    <button class="primary" data-a="save">Записать отмеченное</button>`, (a, box) => {
    if (a !== "save") return;
    const items = [];
    let out = 0;
    box.querySelectorAll("[data-pz]").forEach((c) => {
      if (!c.checked) return;
      const i = Number(c.dataset.pz), o = ops[i];
      const ch = list(o)[Number(box.querySelector(`[data-pzs="${i}"]`).value)];
      if (!ch) return;
      items.push({ op: o.op, t: ch[1] });
      if (!o.op.income) out += o.op.amount;
    });
    if (!items.length) { toast("Ничего не отмечено"); return false; }
    entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "paste", items,
      amount: Math.round(out * 100) / 100, category: "",
      note: items.map((x) => x.op.text).slice(0, 3).join(", ") + (items.length > 3 ? "…" : ""),
      mode: "send", status: "pending" });
    saveEntries(); renderAll(); autoSync(500);
    toast(`Записываю ${items.length} опер.${out ? " на " + fmtExact(out) : ""}…`);
  });
  const recount = () => {
    let n = 0, out = 0, inc = 0;
    bg.querySelectorAll("[data-pz]").forEach((c) => {
      if (!c.checked) return;
      const o = ops[Number(c.dataset.pz)]; n++;
      if (o.op.income) inc += o.op.amount; else out += o.op.amount;
    });
    $("pzSum").innerHTML = `Отмечено: ${n} — трат на <b>${fmtExact(out)}</b>${inc ? `, доходов и возвратов на <b>${fmtExact(inc)}</b>` : ""}`;
  };
  bg.addEventListener("change", recount);
  recount();
}
function payFromFund(i) {
  const f = snap.funds[i];
  const cats = ((snap.categories && snap.categories.expense) || EXPENSE_DEFAULT).filter((c) => !c.startsWith("В фонд"));
  const guess = { "здоров": "Здоровье и врачи", "подар": "Подарки", "отпуск": "Поездки и отпуск", "очки": "Здоровье и врачи",
    "новый год": "Подарки", "танц": "Хобби и творчество", "йог": "Хобби и творчество", "вокал": "Хобби и творчество" };
  const want = Object.entries(guess).find(([k]) => f.name.toLowerCase().includes(k));
  const def = want ? want[1] : "Другое";
  const bg = sheetDialog(`<h2>Оплатить из фонда «${esc(f.name)}»</h2>
    <p class="hint">В фонде ${fmt(f.saved)}. В листе появится «Из фонда …» и сама трата — для месяца это ноль, фонд уменьшится.</p>
    <label class="field"><span>Сумма</span><input id="fpAmount" inputmode="decimal" placeholder="0"></label>
    <label class="field"><span>На что (категория)</span><select id="fpCat">${cats.map((c) => `<option ${c === def ? "selected" : ""}>${esc(c)}</option>`).join("")}</select></label>
    <label class="field"><span>Комментарий</span><input id="fpNote" placeholder="например: стоматолог"></label>
    <label class="field"><span>Дата</span><input id="fpDate" type="date" value="${todayISO()}"></label>
    <button class="primary" data-a="pay">Оплатить из фонда</button>`, (a) => {
    if (a !== "pay") return;
    const amount = parseAmount($("fpAmount").value);
    if (!(amount > 0)) { toast("Введите сумму"); return false; }
    if (amount > f.saved + 0.5 && !confirm(`В фонде ${fmt(f.saved)}, а оплата ${fmt(amount)} — фонд уйдёт в минус. Всё равно оплатить?`)) return false;
    entries.unshift({ id: uid(), created: new Date().toISOString(), date: $("fpDate").value || todayISO(), kind: "fundpay",
      fund: f.name, amount, category: $("fpCat").value, note: $("fpNote").value.trim(), half: 0, row_id: null,
      mode: "send", status: "pending" });
    saveEntries(); renderAll();
    toast(`Из «${f.name}» ${fmtExact(amount)} — уйдёт на компьютер при синхронизации`);
  });
  setTimeout(() => { const i2 = bg.querySelector("#fpAmount"); if (i2) i2.focus(); }, 150);
}

/* ------------------------------------------------------------------ 💳 Кредиты: ближайшие платежи и погашение */
function icsCard() {
  return `<div class="card"><div class="line" style="border:0;padding:0;align-items:center"><span><b>📅 Напоминания в Календаре iPhone</b>
    <div class="hint" style="margin:2px 0 0">платежи и дни рождения — накануне в 10:00, о подарке — за 2 недели</div></span>
    <button class="ghost small" type="button" data-go="ics">Добавить</button></div></div>`;
}
function payKey(d, p) { return `${d.id}:${p.id}`; }
function payPending(d, p) {
  /* последняя неотправленная правка этого платежа с телефона */
  const list = pendingOf("pay_set", (x) => x.debt_name === d.name && (x.pay_id === p.id || (x.due === p.due && Math.abs((x.old_amount || 0) - p.amount) < 0.01)));
  return list.length ? list[0].p : null;
}
function payView(d, p) {
  const e = payPending(d, p);
  return e ? { ...p, amount: e.new_amount != null ? e.new_amount : p.amount, due: e.new_due || p.due,
    paid: p.paid || !!e.paid, waiting: true } : p;
}
function debtsList() { return ((snap && snap.debts) || []); }
function nextPayments(n = 12, days = 75) {
  const t = todayISO(), until = addDays(t, days), out = [];
  if (!snap || !snap.debts) {
    return ((snap && snap.payments) || []).slice(0, n).map((p) => ({ due: p.date, name: p.name, amount: p.amount }));
  }
  debtsList().filter((d) => d.kind !== "owed").forEach((d) => d.payments.forEach((p0) => {
    const p = payView(d, p0);
    if (!p.paid && p.due <= until) out.push({ ...p, name: d.name, debt: d });
  }));
  out.sort((a, b) => (a.due < b.due ? -1 : a.due > b.due ? 1 : 0));
  return out.slice(0, n);
}
function renderCredits() {
  const box = $("credits");
  if (!box) return;
  if (!snap) { box.innerHTML = `<div class="card empty">Кредиты появятся после синхронизации.</div>`; return; }
  let h = nocreditLine();
  if (!snap.debts) {
    h += `<div class="card soft">Обновите программу на ноутбуке и сервере — тогда здесь появятся все кредиты и их можно будет менять с телефона.</div>`;
  }
  const debts = debtsList().filter((d) => d.kind !== "owed");
  const left = debts.reduce((a, d) => a + (d.closed ? 0 : d.left), 0);
  const t = todayISO();
  const next = nextPayments(40, 75);
  h += `<div class="card"><div class="line" style="border:0;padding:0"><h2 style="margin:0">Ближайшие платежи</h2>
    <span class="r muted">2,5 мес.</span></div>`;
  if (!next.length) h += `<div class="hint">В ближайшие 2,5 месяца платежей нет 🎉</div>`;
  let day = "";
  next.forEach((p) => {
    if (p.due !== day) {
      day = p.due;
      const tot = next.filter((x) => x.due === day).reduce((a, x) => a + x.amount, 0);
      const late = day < t;
      h += `<div class="pay-day"><span>${ddmm(day)} · ${late ? '<span class="red">срок прошёл</span>' : whenIn(day)}</span><span>итого ${fmt(tot)}</span></div>`;
    }
    h += p.debt ? `<div class="line tap" data-pay="${payKey(p.debt, p)}"><span>${esc(p.name)}${p.extra ? ' <span class="muted">· досрочно</span>' : ""}${p.waiting ? ' <span class="badge pending">ждёт отправки</span>' : ""}</span>
      <span class="r">${fmtExact(p.amount)} ›</span></div>`
      : `<div class="line"><span>${esc(p.name)}</span><span class="r">${fmt(p.amount)}</span></div>`;
  });
  h += `<p class="hint" style="margin:8px 0 0">Нажмите на платёж — отметить оплаченным ●, поменять сумму или дату.</p></div>`;
  if (debts.length) h += `<div class="sec">Кредиты и долги · осталось ${fmt(left)}</div>`;
  debts.forEach((d) => {
    const extras = pendingOf("pay_extra", (x) => x.debt_name === d.name);
    const pays = d.payments.map((p) => payView(d, p));
    const nx = pays.find((p) => !p.paid);
    const opened = (cfg.debtOpen || []).includes(d.id);
    h += `<details class="card debt" data-debt="${d.id}" ${opened ? "open" : ""}><summary><div class="line" style="border:0;padding:0"><b>${esc(d.name)}</b>
        <span class="r ${d.closed ? "green" : ""}">${d.closed ? "закрыт ✓" : "осталось " + fmt(d.left)}</span></div>
      <div class="hint" style="margin:2px 0 0">${nx ? `следующий ${ddmm(nx.due)} — ${fmtExact(nx.amount)}` : "платежей больше нет"}</div>
      ${d.total > 0 ? `<div class="bar"><i style="width:${Math.min(100, (d.paid / d.total) * 100)}%"></i></div>` : ""}</summary>
      <div class="hint">${d.regular ? `платёж по графику ${fmtExact(d.regular)}${d.pay_day ? ` ${d.pay_day}-го` : ""} · ` : ""}${d.total ? `внесено ${fmt(d.paid)} из ${fmt(d.total)}` : ""}</div>`;
    pays.forEach((p) => {
      h += `<div class="line tap" data-pay="${payKey(d, p)}"><span>${p.paid ? '<span class="dot green"></span>' : '<span class="dot" style="background:#C9D6F8"></span>'}${ddmm(p.due)}${p.extra ? ' <span class="muted">· досрочно</span>' : ""}${p.waiting ? ' <span class="badge pending">ждёт отправки</span>' : ""}</span>
        <span class="r ${p.paid ? "muted" : ""}">${fmtExact(p.amount)}</span></div>`;
    });
    extras.forEach((x) => { h += `<div class="line"><span><span class="dot green"></span>${ddmm(x.p.date)} <span class="muted">· досрочно</span> <span class="badge pending">ждёт отправки</span></span><span class="r">${fmtExact(x.p.sum)}</span></div>`; });
    if (!d.closed) h += `<button class="ghost small" type="button" style="margin-top:8px" data-extra="${d.id}">＋ Внести досрочно</button>`;
    h += `</details>`;
  });
  const owed = debtsList().filter((d) => d.kind === "owed" && !d.closed);
  if (owed.length) {
    h += `<div class="sec">Мне должны</div><div class="card">`;
    owed.forEach((d) => { const nx = d.payments.find((p) => !p.paid);
      h += `<div class="line"><span>${esc(d.name)}${nx ? ` · ${ddmm(nx.due)}` : ""}</span><span class="r green">${fmt(d.left)}</span></div>`; });
    h += `</div>`;
  }
  box.innerHTML = h;
  if ($("ncReset")) $("ncReset").onclick = nocreditReset;
  box.querySelectorAll("details.debt").forEach((el) => el.addEventListener("toggle", () => {
    const id = Number(el.dataset.debt), set = new Set(cfg.debtOpen || []);
    if (el.open) set.add(id); else set.delete(id);
    cfg.debtOpen = [...set]; saveCfg();
  }));
}
function findPay(key) {
  const [did, pid] = String(key).split(":").map(Number);
  const d = debtsList().find((x) => x.id === did);
  const p0 = d && d.payments.find((x) => x.id === pid);
  return d && p0 ? { d, p0, p: payView(d, p0) } : null;
}
function payDialog(key) {
  const f = findPay(key);
  if (!f) return;
  const { d, p0, p } = f;
  const bg = sheetDialog(`<h2>${esc(d.name)} · ${ddmm(p.due)}</h2>
    <p class="hint">${p.paid ? "оплачен ●" : "ещё не оплачен"}${p.extra ? " · досрочный" : ""} · в листе встанет к выплате: 11-е → 10-е, 26-е → 25-е, как у всех кредитов${p.waiting ? " · есть неотправленная правка" : ""}</p>
    <label class="field"><span>Сумма</span><input id="pdAmount" inputmode="decimal" value="${String(p.amount).replace(".", ",")}"></label>
    <label class="field"><span>Дата платежа</span><input id="pdDate" type="date" value="${esc(p.due)}"></label>
    <div class="acts">
      ${p.paid ? "" : '<button class="primary wide" data-a="paid">● Оплачено (с этой суммой)</button>'}
      <button class="ghost wide" data-a="save">Сохранить сумму и дату</button>
    </div>
    <p class="hint">Внесли больше графика — лучше «＋ Внести досрочно» у кредита: лишнее само уйдёт из будущих платежей.</p>`, (a) => {
    if (a !== "paid" && a !== "save") return;
    const amount = parseAmount(bg.querySelector("#pdAmount").value), nd = bg.querySelector("#pdDate").value;
    if (!(amount > 0)) { toast("Введите сумму"); return false; }
    if (!nd) { toast("Укажите дату"); return false; }
    const paid = a === "paid" ? true : null;
    if (a === "save" && Math.abs(amount - p.amount) < 0.005 && nd === p.due) return;
    pushGeneric("pay_set", { debt_id: d.id, debt_name: d.name, pay_id: p0.id, due: p0.due, old_amount: p0.amount,
      new_amount: amount, new_due: nd, paid, paid_on: paid ? todayISO() : null },
      `${d.name}: ${paid ? "оплачено ● " : ""}${ddmm(nd)} ${fmtExact(amount)}`, "💳");
    toast(`«${d.name}» — уйдёт на компьютер при синхронизации`);
  });
}
function extraDialog(did) {
  const d = debtsList().find((x) => x.id === did);
  if (!d) return;
  const bg = sheetDialog(`<h2>Досрочно · ${esc(d.name)}</h2>
    <p class="hint">Осталось ${fmt(d.left)}. В листе встанет строка «${esc(d.name)} (досрочно)», а лишнее уйдёт из будущих платежей
      с конца графика — как на ноутбуке. Если банк после этого поменял ближайший платёж (например, стал 41,85), поправьте его — нажмите на платёж.</p>
    <label class="field"><span>Сумма</span><input id="exAmount" inputmode="decimal" placeholder="0"></label>
    <label class="field"><span>Дата</span><input id="exDate" type="date" value="${todayISO()}"></label>
    <label style="display:flex;gap:10px;align-items:center;margin:4px 2px 10px"><input type="checkbox" id="exPaid" checked> уже внесла ●</label>
    <button class="primary" data-a="go">Записать досрочное</button>`, (a) => {
    if (a !== "go") return;
    const amount = parseAmount(bg.querySelector("#exAmount").value), day = bg.querySelector("#exDate").value;
    if (!(amount > 0)) { toast("Введите сумму"); return false; }
    pushGeneric("pay_extra", { debt_id: d.id, debt_name: d.name, sum: amount, date: day || todayISO(), paid: bg.querySelector("#exPaid").checked },
      `${d.name}: досрочно ${fmtExact(amount)}`, "💳", day || todayISO());
    toast(`Досрочно «${d.name}» ${fmtExact(amount)} — уйдёт при синхронизации`);
  });
  setTimeout(() => { const i = bg.querySelector("#exAmount"); if (i) i.focus(); }, 150);
}

/* ------------------------------------------------------------------ напоминания и Календарь */
/* Ноутбук присылает напоминания на 2 недели вперёд по дням — телефон берёт список на свой «сегодня»,
   даже если ноутбук давно спит. «Сегодня можно потратить» не берём: это считает карточка сверху. */
function todayReminders() {
  if (!snap) return [];
  let list = snap.reminders || [];
  if (snap.reminders_by_day) list = snap.reminders_by_day[todayISO()] || [];
  return list.filter((r) => !r.text.startsWith("Сегодня можно потратить"));
}
function dupReminder(text) {
  /* уже видно в другом месте: «не хватает / можно потратить» — розовая карта, платежи и внесения — «Кредиты» */
  const t = String(text || "").toLowerCase();
  return t.includes("не хватает") || t.includes("можно потратить") || t.includes("не отмечены оплаченными")
    || t.includes("внесени") || t.includes("платёж") || t.includes("платеж") || t.includes("кредит");
}
function creditsAlert() {
  /* просроченный или сегодняшний/завтрашний платёж — точка на вкладке «Кредиты» */
  const t = todayISO(), tm = addDays(t, 1);
  return nextPayments(40, 2).some((p) => p.due <= tm);
}
function importantItems() {
  const out = [];
  todayReminders().filter((r) => !dupReminder(r.text)).forEach((r) => out.push({ icon: r.icon, text: r.text }));
  const old = entries.filter((e) => e.status === "pending" && Date.now() - new Date(e.created).getTime() > 86400000).length;
  if (old) out.push({ icon: "📤", text: `${old} запис${old === 1 ? "ь ждёт" : "и ждут"} отправки больше суток — нажмите «Синхронизировать»` });
  const bc = snap && snap.bank_check;
  if (bc && bc.days && !todayReminders().some((r) => r.text.startsWith("Сверка с банком"))) {
    const now = new Date();
    for (let back = 0; back < 3; back++) {
      const d = new Date(now); d.setDate(d.getDate() - back);
      if (bc.days.includes(d.getDate())) {
        const prev = new Date(d); prev.setDate(prev.getDate() - 1);
        if ((bc.last || "") < prev.toISOString().slice(0, 10))
          out.push({ icon: "🏦", text: `Сверка с банком ${d.getDate() < 15 ? "перед зарплатой" : "перед авансом"}: на ноутбуке — выписки Сбера и Альфы, или «Сверить с банком» здесь` });
        break;
      }
    }
  }
  (snap && snap.pending_refunds || []).forEach((p) => {
    const days = Math.round((Date.now() - new Date(p.date + "T12:00:00").getTime()) / 86400000);
    if (days >= 7 && !todayReminders().some((r) => r.text.startsWith("Ждёте возврат")))
      out.push({ icon: "↩", text: `Ждёте возврат ${fmtExact(p.amount)} (${p.note || "без подписи"}) уже ${days} дн.` });
  });
  return out;
}
function updateBadge() {
  const n = importantItems().length;
  const tab = document.querySelector('.tabs button[data-page="sum"]');
  if (tab) tab.classList.toggle("has-dot", n > 0);
  const ct = document.querySelector('.tabs button[data-page="credits"]');
  if (ct) ct.classList.toggle("has-dot", !!(snap && creditsAlert()));
  try { if (navigator.setAppBadge) (n ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(() => {}); } catch (e) { /* нет */ }
}
function icsEscape(t) { return String(t).replace(/[\\;,]/g, (c) => "\\" + c).replace(/\n/g, "\\n"); }
function icsDate(iso) { return iso.replace(/-/g, "").slice(0, 8); }
function addDays(iso, k) { const d = new Date(iso + "T12:00:00"); d.setDate(d.getDate() + k); return d.toISOString().slice(0, 10); }
function exportCalendar() {
  if (!snap) { toast("Сначала синхронизируйтесь"); return; }
  const done = new Set(cfg.icsDone || []);
  const ev = [];
  (snap.payments || []).forEach((p) => ev.push({ key: `pay:${p.date}:${p.name}:${p.amount}`, date: p.date,
    title: `💳 ${p.name} — ${fmt(p.amount)}`, note: "Внесение по плану погашения (Мои финансы)" }));
  const y = new Date().getFullYear();
  (snap.birthdays || []).forEach((b) => {
    let d = `${y}-${String(b.month).padStart(2, "0")}-${String(b.day).padStart(2, "0")}`;
    if (d < todayISO()) d = `${y + 1}` + d.slice(4);
    ev.push({ key: `bd:${b.name}:${b.month}-${b.day}`, date: d, title: `🎂 ${b.name}`, note: "День рождения / праздник (Мои финансы)", yearly: true });
  });
  const bc = snap.bank_check;
  if (bc && bc.days) bc.days.forEach((day) => {
    const d = new Date(); if (d.getDate() > day) d.setMonth(d.getMonth() + 1);
    d.setDate(day);
    const iso = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
    ev.push({ key: `check:${day}`, date: iso, title: `🏦 Сверка с банком ${day < 15 ? "перед зарплатой" : "перед авансом"}`,
      note: "Выписки Сбера и Альфы → «Загрузить траты» на ноутбуке, потом «Сверить с банком» (Мои финансы)",
      rrule: `RRULE:FREQ=MONTHLY;BYMONTHDAY=${day}`, alarm: "PT10H" });
  });
  const fresh = ev.filter((e) => !done.has(e.key));
  if (!fresh.length) { toast("Новых платежей и дат для Календаря нет — всё уже добавлено"); return; }
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Moi finansy//RU\r\nCALSCALE:GREGORIAN\r\n";
  fresh.forEach((e, i) => {
    ics += "BEGIN:VEVENT\r\n" + `UID:${Date.now()}-${i}@moi-finansy\r\nDTSTAMP:${stamp}\r\n` +
      `DTSTART;VALUE=DATE:${icsDate(e.date)}\r\nDTEND;VALUE=DATE:${icsDate(addDays(e.date, 1))}\r\n` +
      (e.yearly ? "RRULE:FREQ=YEARLY\r\n" : e.rrule ? e.rrule + "\r\n" : "") +
      `SUMMARY:${icsEscape(e.title)}\r\nDESCRIPTION:${icsEscape(e.note)}\r\n` +
      `BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Напоминание\r\nTRIGGER:${e.alarm || "-PT14H"}\r\nEND:VALARM\r\n` +
      (e.yearly ? "BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Подарок\r\nTRIGGER:-P13DT14H\r\nEND:VALARM\r\n" : "") +
      "END:VEVENT\r\n";
  });
  ics += "END:VCALENDAR\r\n";
  const blob = new Blob([ics], { type: "text/calendar;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "moi-finansy.ics";
  document.body.appendChild(a); a.click(); a.remove();
  cfg.icsDone = [...done, ...fresh.map((e) => e.key)].slice(-400); saveCfg();
  toast(`В файле ${fresh.length} событий — нажмите «Добавить все», напомнит накануне в 10:00`, 6000);
}

/* ------------------------------------------------------------------ навигация */
const TITLES = { add: ["Записать", "трата или доход"],
  sheet: ["Лист месяца", "как на компьютере"], funds: ["Фонды", "копилки на цели"],
  more: ["Ещё", "фонды, здоровье, календарь"],
  bank: ["Сверка", "с банком: карты и наличные"], ops: ["Операции", "всё, что записано, новые сверху"],
  credits: ["Кредиты", "платежи и погашение"],
  sum: ["Главная", ""], set: ["Настройки", "синхронизация, PIN, уведомления"] };
function whenText(iso) {
  /* «сегодня в 13:40», «вчера в 21:05», «19.10 в 08:30» */
  const d = new Date(iso);
  if (isNaN(d)) return "";
  const t = d.toTimeString().slice(0, 5);
  const day = new Date(d); day.setHours(0, 0, 0, 0);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const diff = Math.round((today - day) / 86400000);
  if (diff === 0) return `сегодня в ${t}`;
  if (diff === 1) return `вчера в ${t}`;
  return `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")} в ${t}`;
}
function snapAgeH() { return snap && snap.generated ? (Date.now() - new Date(snap.generated).getTime()) / 3600000 : null; }
function ageText(h) {
  if (h < 1) return "меньше часа назад";
  if (h < 24) return `${Math.floor(h)} ч назад`;
  const d = Math.floor(h / 24);
  return `${d} ${d === 1 ? "день" : d < 5 ? "дня" : "дней"} назад`;
}
function syncStamp() {
  /* под заголовком «Главной»: когда ноутбук обновил данные и когда телефон синхронизировался */
  const parts = [];
  if (snap && snap.generated) parts.push(`данные ноутбука ${whenText(snap.generated)}`);
  if (cfg.lastSync) parts.push(`синхр. ${new Date(cfg.lastSync).toTimeString().slice(0, 5)}`);
  return parts.length ? parts.join(" · ") : "ещё не синхронизировано";
}
/* ------------------------------------------------------------------ обновление приложения */
async function checkUpdate(manual) {
  try {
    const r = await fetch("version.json?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error(r.status);
    const v = String((await r.json()).v || "");
    const was = newVersion;
    newVersion = v && v !== VERSION ? v : "";
    if (newVersion !== was) renderAll();
    if (manual) toast(newVersion ? "Есть новая версия " + newVersion : "У вас последняя версия ✓");
  } catch (e) {
    if (manual) toast("Не получилось проверить — нет интернета?");
  }
}
async function applyUpdate() {
  toast("Обновляю…");
  try {
    if ("caches" in window) for (const k of await caches.keys()) await caches.delete(k);
    if ("serviceWorker" in navigator) {
      const reg = await navigator.serviceWorker.getRegistration();
      if (reg) await reg.update().catch(() => {});
    }
  } catch (e) { /* всё равно перезагрузим */ }
  location.replace(location.pathname + "?u=" + Date.now());
}
function updateBanner() {
  if (!newVersion) return "";
  return `<div class="card warn"><b>✨ Вышла новая версия приложения — ${esc(newVersion)}</b>
    <div class="hint" style="margin-top:4px">У вас открыта ${esc(VERSION)}. Записи и настройки останутся на месте.</div>
    <button type="button" style="margin-top:8px" onclick="applyUpdate()">Обновить сейчас</button></div>`;
}
/* ------------------------------------------------------------------ последние записанные траты */
function shortName(t) { return String(t || "").split(" · ")[0].trim(); }   // «обеды в офисе · 6 дн. · …» → «обеды в офисе»
function lastSpends(n = 4) {
  /* траты в листе (из сводки ноутбука) + траты с телефона, которые ещё не в листе; новые по дате сверху */
  let out = ((snap && snap.last_spends) || []).map((x) => ({ ...x, name: shortName(x.name), phone: false }));
  if (!out.length && snap && snap.sheets) {
    /* ноутбук ещё старой версии и не прислал список — берём траты из листов (без времени записи) */
    const today = todayISO();
    snap.sheets.slice(0, 2).forEach((sh) => buildOps(sh).filter((o) => !o.inc && !o.fund && o.date <= today)
      .forEach((o) => out.push({ date: o.date, name: o.title, amount: o.amount, created: "", phone: false })));
  }
  entries.filter((e) => e.kind === "expense" && !e.deleted && e.status !== "done")
    .forEach((e) => out.push({ date: e.date, name: shortName(e.note || e.row_name || e.category), amount: e.amount,
      created: String(e.created || "").replace("T", " ").slice(0, 16), phone: true }));
  out.sort((a, b) => (a.date !== b.date ? (a.date < b.date ? 1 : -1) : (a.created < b.created ? 1 : a.created > b.created ? -1 : 0)));
  return out.slice(0, n);
}
function lastSpendsHint() {
  const f = lastSpends(1)[0];
  return f ? `<p class="hint" style="margin:0 4px 10px">🧾 В банке смотрите операции после <b>${ddmm(f.date)} — «${esc(f.name)}» ${fmt(f.amount)}</b>: что раньше, уже записано.</p>` : "";
}
function lastSpendsCard() {
  const list = lastSpends();
  if (!list.length) return "";
  const f = list[0];
  const when = (x) => (x.created && x.created.slice(0, 10) !== x.date ? ` · внесено ${ddmm(x.created.slice(0, 10))}` : "") +
    (x.created && x.created.length >= 16 ? ` в ${x.created.slice(11, 16)}` : "");
  let h = `<div class="card"><h2>🧾 Последнее, что записано</h2>
    <p class="hint">В банке смотрите операции <b>после ${ddmm(f.date)} — «${esc(f.name)}» ${fmt(f.amount)}</b>: что раньше, уже записано.</p>`;
  list.forEach((x) => {
    h += `<div class="line"><span>${ddmm(x.date)} · ${esc(x.name)}<span class="hint">${x.phone ? " · 📱 с телефона" : ""}${when(x)}</span></span>
      <span class="r">−${fmt(x.amount)}</span></div>`;
  });
  return h + "</div>";
}
function staleBanner() {
  const h = snapAgeH();
  if (h == null || h < 24) return "";
  return `<div class="card warn"><b>🕰 Данные ноутбука — ${whenText(snap.generated)}</b>
    <div class="hint" style="margin-top:4px">Даты, напоминания и «можно в день» телефон считает на сегодня сам и учитывает ваши
    новые траты. По состоянию ноутбука — только остатки строк. Обновится, когда откроете программу на ноутбуке.</div></div>`;
}
function showPage(p) {
  document.querySelectorAll(".page").forEach((s) => s.classList.toggle("active", s.id === "page-" + p));
  /* «Операции» — часть «Листа», «Сверка» — часть «Главной»: подсвечиваем их вкладки */
  const tab = p === "ops" ? "sheet" : p === "bank" ? "sum" : p;
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.page === tab));
  if (p === "bank") renderBank();
  if (p === "credits") renderCredits();
  $("title").textContent = TITLES[p][0];
  $("subtitle").textContent = p === "sum" ? syncStamp() : TITLES[p][1];
  if (p === "ops") renderOps();
  if (p === "more") renderMore();
  window.scrollTo(0, 0);
}

/* ------------------------------------------------------------------ запуск */
function init() {
  readHash();
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
  document.querySelectorAll("[data-more]").forEach((b) => b.addEventListener("click", () => {
    cfg.moreTab = b.dataset.more; saveCfg(); renderMore(); window.scrollTo(0, 0); }));
  document.querySelectorAll("#addForm .seg button").forEach((b) => b.addEventListener("click", () => { kind = b.dataset.kind; $("row").value = ""; fillForm(); }));
  document.querySelectorAll(".dest button").forEach((b) => b.addEventListener("click", () => { mode = b.dataset.mode; fillForm(); }));
  document.querySelectorAll("#opsKinds .chip").forEach((b) => b.addEventListener("click", () => {
    opsKind = b.dataset.k;
    document.querySelectorAll("#opsKinds .chip").forEach((x) => x.classList.toggle("on", x === b));
    renderOps();
  }));
  $("opsSearch").addEventListener("input", () => renderOps());
  $("row").addEventListener("change", onRowChange);
  $("setBtn").addEventListener("click", () => showPage("set"));
  $("editCancel").addEventListener("click", (ev) => {
    ev.preventDefault(); setEditing(null);
    $("amount").value = ""; $("note").value = ""; $("row").value = ""; $("date").value = todayISO();
    toast("Изменение отменено — запись осталась как была");
  });
  $("badgeBtn").addEventListener("click", async () => {
    const st = $("badgeStatus");
    if (!("Notification" in window) || !navigator.setAppBadge) {
      st.textContent = "Здесь это не поддерживается — откройте приложение с иконки на экране «Домой» (iOS 16.4 и новее)."; st.className = "status bad"; return;
    }
    const res = await Notification.requestPermission();
    st.textContent = res === "granted" ? "Готово ✓ На иконке будет число важных дел." : "iPhone не дал разрешение — можно включить в Настройках iPhone → Уведомления.";
    st.className = "status " + (res === "granted" ? "ok" : "bad");
    updateBadge();
  });
  $("icsReset").addEventListener("click", () => { cfg.icsDone = []; saveCfg(); exportCalendar(); });
  document.addEventListener("click", (ev) => {
    const t = ev.target.closest ? ev.target.closest("[data-quickdone],[data-view],[data-spend],[data-pay],[data-extra],[data-sheet],[data-mode2],[data-fund],[data-fundpay],[data-go],[data-row],[data-addrow],[data-op],[data-opsm]") : null;
    if (!t) return;
    if (t.dataset.quickdone !== undefined) { ev.stopPropagation(); quickDone(Number(t.dataset.quickdone)); }
    else if (t.dataset.view !== undefined) setView(t.dataset.view);
    else if (t.dataset.spend !== undefined) { ev.stopPropagation(); spendFromRow(Number(t.dataset.spend)); }
    else if (t.dataset.pay !== undefined) payDialog(t.dataset.pay);
    else if (t.dataset.extra !== undefined) extraDialog(Number(t.dataset.extra));
    else if (t.dataset.sheet !== undefined) { sheetIdx = Number(t.dataset.sheet); renderSheet(); }
    else if (t.dataset.mode2) { sheetMode = t.dataset.mode2; renderSheet(); }
    else if (t.dataset.fund !== undefined) topUpFund(Number(t.dataset.fund));
    else if (t.dataset.fundpay !== undefined) payFromFund(Number(t.dataset.fundpay));
    else if (t.dataset.row !== undefined) openRow(Number(t.dataset.row));
    else if (t.dataset.addrow !== undefined) addRowDialog(sheetIdx, Number(t.dataset.addrow));
    else if (t.dataset.op !== undefined) openOp(Number(t.dataset.op));
    else if (t.dataset.opsm !== undefined) { opsIdx = Number(t.dataset.opsm); renderOps(); }
    else if (t.dataset.go === "ics") exportCalendar();
    else if (t.dataset.go === "funds") { cfg.moreTab = "funds"; saveCfg(); showPage("more"); }
    else if (t.dataset.go) showPage(t.dataset.go);
  });
  $("addForm").addEventListener("submit", onSubmit);
  $("syncBtn").addEventListener("click", sync);
  if ($("pasteBtn")) $("pasteBtn").addEventListener("click", pasteDialog);
  if ($("instBtn")) $("instBtn").addEventListener("click", installmentDialog);
  setTimeout(() => {                         // при открытии — коротко о важном (раз в день)
    const n = importantItems().length;
    if (n && cfg.impSeen !== todayISO()) { toast(`🔔 Важное: ${n} — загляните в «Сводку»`, 4500); cfg.impSeen = todayISO(); saveCfg(); }
  }, 800);
  $("phoneList").addEventListener("click", (ev) => { const el = ev.target.closest(".entry"); if (el) openEntry(el.dataset.id); });
  $("tokenPage").addEventListener("click", (ev) => { ev.preventDefault(); window.open(TOKEN_PAGE, "_blank"); });
  $("ghSave").addEventListener("click", () => {
    const repo = cleanRepo($("repo").value);
    const tok = $("ghToken").value.trim();
    if (!repo.includes("/")) { toast("Репозиторий — в виде «логин/finance-sync»"); return; }
    cfg.repo = repo;
    if (tok) {
      if (tok.length < 20) { toast("Это не похоже на токен GitHub"); return; }
      cfg.ghToken = tok;
    }
    saveCfg(); $("ghToken").value = ""; renderSettings(); toast("Сохранено");
  });
  $("pwSave").addEventListener("click", () => {
    const v = $("pw").value;
    if (v.length < 6) { toast("Пароль — хотя бы 6 символов, такой же как на компьютере"); return; }
    cfg.pw = v; saveCfg(); $("pw").value = ""; renderSettings(); toast("Пароль сохранён");
  });
  $("testBtn").addEventListener("click", async () => {
    const s = $("testStatus");
    if (SRV) {
      s.textContent = "Проверяю…"; s.className = "status";
      try {
        const d = await srv("GET", "/api/ping");
        s.textContent = d.has_db ? "Всё работает ✓ Сервер на связи, база на месте." : "Сервер на связи ✓ Базы ещё нет — подключите ноутбук.";
        s.className = "status ok";
      } catch (e) { s.textContent = e.message; s.className = "status bad"; }
      return;
    }
    const why = needSetup();
    if (why && !(cfg.repo && cfg.ghToken)) { s.textContent = why; s.className = "status bad"; return; }
    s.textContent = "Проверяю…"; s.className = "status";
    try {
      const { status, data } = await gh("GET", null);
      if (status !== 200) throw new SyncError("GitHub ответил ошибкой (" + (data.message || status) + ")");
      if (!data.private) throw new SyncError("Репозиторий публичный — сделайте его приватным на GitHub");
      const text = await download(SNAPSHOT);
      if (text && cfg.pw) { await decryptText(text, cfg.pw); s.textContent = "Всё работает ✓ GitHub на связи, сводка открывается паролем."; }
      else if (text) s.textContent = "GitHub на связи ✓ Введите пароль, чтобы открыть сводку.";
      else s.textContent = "GitHub на связи ✓ Сводки ещё нет — откройте программу на компьютере.";
      s.className = "status ok";
    } catch (e) { s.textContent = e.message; s.className = "status bad"; }
  });
  $("srvLogin").addEventListener("click", async () => {
    const v = $("srvPw").value;
    if (!v) { toast("Введите пароль, который задавали на сервере"); return; }
    try { await srvLogin(v); $("srvPw").value = ""; renderSettings(); toast("Вошли ✓"); sync(true); }
    catch (e) { toast(e.message, 5000); }
  });
  $("srvLogout").addEventListener("click", async () => {
    if (!confirm("Отключить этот телефон от сервера? Записи, которые ещё не отправлены, останутся на телефоне.")) return;
    try { await srv("POST", "/api/logout"); } catch (e) { /* всё равно забываем ключ */ }
    cfg.srvToken = ""; saveCfg(); renderSettings();
  });
  $("clearSent").addEventListener("click", () => {
    const n = entries.filter((e) => e.status === "done").length;
    if (!n) { toast("Дошедших до компьютера записей нет"); return; }
    if (!confirm(`Убрать из списка ${n} записей, которые уже есть в листе на компьютере?`)) return;
    entries = entries.filter((e) => e.status !== "done"); saveEntries(); renderAll();
  });
  $("date").value = todayISO();
  document.querySelectorAll("#lock [data-k]").forEach((b) => b.addEventListener("click", () => pinPress(b.dataset.k)));
  $("pinForgot").addEventListener("click", (ev) => { ev.preventDefault(); pinForgot(); });
  $("pinBtn").addEventListener("click", pinSetupDialog);
  $("pinOff").addEventListener("click", pinRemove);
  $("updBtn").addEventListener("click", () => (newVersion ? applyUpdate() : checkUpdate(true)));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { hiddenAt = Date.now(); return; }
    if (cfg.pinOn && !locked && hiddenAt && Date.now() - hiddenAt > 60000) { lockNow(); return; }
    if (!locked && hiddenAt && Date.now() - hiddenAt > 30000) { autoSync(500); checkUpdate(false); }   // вернулись — обновим
  });
  window.addEventListener("online", () => autoSync(800));
  if (cfg.pinOn) { snap = null; lockNow(); }
  renderAll();
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  setTimeout(() => checkUpdate(false), 1500);
  if (!locked) { if (needSetup()) showPage("set"); else { showPage("sum"); autoSync(600); } }
}
document.addEventListener("DOMContentLoaded", init);
