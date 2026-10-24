/* Мои финансы — телефон.
   Записи хранятся на телефоне (localStorage). «Синхронизировать» шифрует паролем записи с пометкой
   «на компьютер» и кладёт их в ваш приватный репозиторий GitHub (inbox/), затем забирает сводку
   с компьютера (snapshot.enc). Формат шифрования совпадает с phone_sync.py на компьютере:
   PBKDF2-SHA256 (200 000) → AES-256-GCM, у каждого файла своя соль. */
"use strict";

const VERSION = "2026.10.24-d";          // поднимать вместе с version.json и CACHE в sw.js
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
const saveCfg = () => store.set("cfg", cfg.pinOn ? { ...cfg, ghToken: "", pw: "" } : cfg);
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
  if (!cfg.repo || !cfg.repo.includes("/")) return "Укажите репозиторий синхронизации (вкладка «Настройки»)";
  if (!cfg.ghToken) return "Вставьте токен GitHub (вкладка «Настройки»)";
  if (!cfg.pw) return "Введите пароль синхронизации (вкладка «Настройки»)";
  return "";
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
    if (pending.length) {
      const payload = {
        f: FORMAT, sent: new Date().toISOString(), device: navigator.userAgent.slice(0, 80),
        entries: pending.map((e) => (e.kind === "bank"
          ? { id: e.id, date: e.date, kind: "bank", real: e.real, diff: e.diff, record: e.record, created: e.created }
          : e.kind === "done" ? { id: e.id, date: e.date, kind: "done", row_id: e.row_id, created: e.created }
          : e.kind === "fundpay" ? { id: e.id, date: e.date, kind: "fundpay", fund: e.fund, amount: e.amount,
            category: e.category, note: e.note, created: e.created }
          : { id: e.id, date: e.date, kind: e.kind, amount: e.amount, category: e.category,
            note: e.note, half: e.half || null, row_id: e.row_id || null, created: e.created,
            rev: e.rev || 0, deleted: !!e.deleted })),
      };
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
    enc.encode(JSON.stringify({ ghToken: cfg.ghToken, pw: cfg.pw })));
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
    cfg.ghToken = sec.ghToken; cfg.pw = sec.pw;
  } catch (e) { return false; }
  const sb = store.get("snapBox", null);
  if (sb && cfg.pw) { try { snap = await decryptText(sb, cfg.pw); } catch (e) { snap = null; } }
  return true;
}
function lockNow() {
  if (!cfg.pinOn) return;
  locked = true;
  cfg.ghToken = ""; cfg.pw = ""; snap = null;           // в памяти — ничего секретного, пока PIN не введён
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
  cfg.pinOn = false; cfg.pinBox = null; cfg.ghToken = ""; cfg.pw = ""; snap = null;
  try { localStorage.removeItem("mf.snap"); localStorage.removeItem("mf.snapBox"); } catch (e) { /* нет */ }
  saveCfg();
  locked = false; $("lock").hidden = true; renderAll(); showPage("set");
}
function pinSetupDialog() {
  if (!cfg.ghToken || !cfg.pw) { toast("Сначала вставьте токен и пароль синхронизации"); return; }
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
  let h = (opsIdx === 0 && !q ? lastSpendsCard() : "") + `<div class="totals"><div class="card"><div class="k">Траты${q ? " (найдено)" : ""}</div><div class="v">${fmt(spent)}</div></div>
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
  if (extra > 0) html += `<div class="hint">учтены траты с телефона сверх плана, которых ещё нет на компьютере: −${fmt(extra)}</div>`;
  const loc = localSpentThisMonth();
  if (loc > 0) html += `<div class="hint">только на телефоне в этом месяце: ${fmt(loc)} (в расчёт не входят)</div>`;
  html += `<div class="hint">данные ноутбука ${whenText(snap.generated)}</div>`;
  return html;
}
function renderSummary() {
  if (!snap) {
    $("summary").innerHTML = updateBanner() + `<div class="card empty">Сводка появится после первой синхронизации.<br>На компьютере: «☰ Ещё → 📲 Телефон → Настроить».</div>`;
    return;
  }
  const imp = importantItems();
  const impLine = (r) => `<div class="line"><span>${esc(r.icon)} ${esc(r.text)}</span></div>`;
  let h = updateBanner() + staleBanner() + lastSpendsCard();
  h += imp.length ? `<div class="card soft"><h2>🔔 Важное</h2>${imp.slice(0, 4).map(impLine).join("")}` +
    (imp.length > 4 ? `<details><summary>ещё ${imp.length - 4}</summary>${imp.slice(4).map(impLine).join("")}</details>` : "") + `</div>` : "";
  h += `<div class="card">${todayBlock()}${snap.cards != null ? `<div class="line"><span>На картах должно быть</span><span class="r">${fmt(snap.cards)}</span></div>` : ""}</div>`;
  if (snap.month) h += `<div class="sec">${esc(snap.month.title)} · ${esc(snap.month.span)}</div>`;
  (snap.halves || []).forEach((half) => {
    h += `<div class="card"><h2>${esc(half.title)}</h2>
      <div class="line"><span>Доход</span><span class="r green">+${fmt(half.income)}</span></div>
      <div class="line"><span>Расходы по листу</span><span class="r">${fmt(half.expense)}</span></div>
      <div class="line"><span>Остаток</span><span class="r ${half.rest < 0 ? "red" : ""}">${fmt(half.rest)}</span></div>`;
    const open = half.rows.filter((r) => !r.done && r.left > 0.5 && !r.credit);
    if (open.length) {
      h += `<div class="sec" style="margin-top:12px">ещё не потрачено по плану</div>`;
      open.forEach((r, i) => {
        if (i === 5 && open.length > 6) h += `<details><summary>ещё ${open.length - 5} строк</summary>`;
        const pct = r.amount > 0 ? Math.min(100, Math.max(0, (r.spent / r.amount) * 100)) : 0;
        h += `<div style="padding:4px 0"><div class="line" style="border:0;padding:0"><span>${esc(r.name)}</span><span class="r">${fmt(r.left)} <span class="muted">из ${fmt(r.amount)}</span></span></div>
          <div class="bar"><i style="width:${pct}%"></i></div></div>`;
      });
      if (open.length > 6) h += `</details>`;
    }
    h += `</div>`;
  });
  h += `<div class="card"><h2>Сверка с банком</h2><p class="hint">${snap.bank && snap.bank.last_check ? "последняя — " + ddmm(snap.bank.last_check) : "ещё не делали"}</p>
    <button class="ghost" type="button" data-go="bank">🏦 Сверить с банком</button></div>`;
  if (snap.payments && snap.payments.length) {
    h += `<div class="sec">Ближайшие платежи</div><div class="card">`;
    snap.payments.forEach((p) => { h += `<div class="line"><span>${ddmm(p.date)} · ${esc(p.name)}</span><span class="r">${fmt(p.amount)}</span></div>`; });
    h += `</div>`;
  }
  h += `<div class="card"><h2>Напоминания в Календаре iPhone</h2>
    <p class="hint" style="margin-top:0">Платежи и дни рождения добавятся в Календарь с напоминанием накануне в 10:00 (о подарке — за 2 недели).
    Повторно добавляются только новые.</p>
    <button class="ghost" type="button" data-go="ics">📅 Добавить в Календарь</button></div>`;
  $("summary").innerHTML = h;
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
function renderSheet() {
  const box = $("sheet");
  if (!snap || !snap.sheets) { box.innerHTML = `<div class="card empty">Лист появится после синхронизации с компьютером.</div>`; return; }
  sheetIdx = Math.min(sheetIdx, snap.sheets.length - 1);
  const sh = snap.sheets[sheetIdx];
  let h = `<div class="filters">` + snap.sheets.map((x, i) =>
    `<button type="button" class="chip ${i === sheetIdx ? "on" : ""}" data-sheet="${i}">${esc(x.title)}</button>`).join("") +
    `</div><div class="seg" style="margin:-2px 0 10px"><button type="button" class="${sheetMode === "cols" ? "on" : ""}" data-mode2="cols">По колонкам</button>` +
    `<button type="button" class="${sheetMode === "cats" ? "on" : ""}" data-mode2="cats">По категориям</button></div>`;
  h += `<p class="hint" style="margin:-4px 4px 10px">${esc(sh.span)} · сводка от ${ddmm(snap.generated)} ${snap.generated.slice(11, 16)}</p>`;
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
      let left = hf.income;
      hf.rows.forEach((r) => {
        if (!r.from_fund) left -= r.amount;
        const fact = rowActual(r);
        const st = r.done || pendingDone(r.id) ? '<span class="dot green"></span>' : (r.spent ? '<span class="dot yellow"></span>' : '<span class="dot" style="background:#C9D6F8"></span>');
        const extra = r.from_fund ? "из фонда" : (r.spent && !r.done ? `потрачено ${fmt(r.spent)}, ост. ${fmt(r.left)}`
          : (r.spent && r.spent > r.amount + 0.5 ? "перерасход" : ""));
        h += `<div class="line tap" data-row="${r.id}"><span>${st}${esc(r.name)}${pendingDone(r.id) && !r.done ? ' <span class="muted">(● ждёт отправки)</span>' : ""}${extra ? `<div class="hint" style="margin:1px 0 0 16px">${extra}</div>` : ""}</span>
          <span class="r">${fmt(r.amount)}<div class="hint" style="margin:1px 0 0;text-align:right">${left < 0 ? '<span class="red">' + fmt(left) + "</span>" : fmt(left)}</div></span></div>`;
      });
      h += `</div>`;
    });
    h += `<p class="hint center">● оплачено · ◐ тратится · ○ ещё нет. Справа под суммой — остаток колонки после строки.<br>Нажмите на строку — «Потратила из неё» или «Отметить оплаченной ●».</p>`;
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
  let h = `<div class="card"><p class="hint" style="margin-top:0">Впишите, сколько денег сейчас на каждом счёте (как в приложении банка).
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
    <div class="line"><span>На картах сейчас</span><span class="r">${fmt(lifeReal)}</span></div>
    <div class="line"><span>Итог</span><span class="r">${verdict(lifeExp, lifeReal)}</span></div>
    <details><summary>почему столько должно быть</summary><div class="hint">
      ${b.start ? `было до зарплаты ${fmt(b.start)} + ` : ""}пришедший доход ${fmt(b.income)} − оплачено (● и ◐) ${fmt(b.paid)}
      ${b.life_funds.map((f) => ` + фонд «${esc(f.name)}» (${esc(f.place)}) ${fmt(f.amount)}`).join("")}
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
function renderAll() {
  fillForm();
  $("today").innerHTML = todayBlock();
  renderOps();
  renderSummary();
  renderSheet();
  renderFunds();
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
    : e.kind === "bank" ? "Сверка с банком" : `${esc(e.note || e.category)} · ${fmtExact(e.amount)}`;
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
  return entries.some((e) => e.kind === "done" && e.row_id === rowId && e.status !== "done");
}
function openRow(id) {
  const f = findRow(id);
  if (!f) return;
  const r = f.r;
  const canSpend = !r.credit && !r.from_fund && !r.done && r.left > 0.5;
  const canDone = !r.done && !pendingDone(id);
  const sp = r.spends || [];
  const spHtml = sp.length ? `<div class="spend-list">${sp.map((x) => `<div class="line"><span>${ddmm(x.date)} · ${esc(x.note || (x.amount < 0 ? "вернули" : "трата"))}</span>
      <span class="r ${x.amount < 0 ? "green" : ""}">${x.amount < 0 ? "↩ +" : "−"}${fmtExact(Math.abs(x.amount))}</span></div>`).join("")}</div>` : "";
  sheetDialog(`<h2>${esc(r.name)} · ${fmt(r.amount)}</h2>
    <p class="hint">${esc(r.category)} · ${f.half === 1 ? "с зарплаты" : "с аванса"}${r.spent ? ` · потрачено ${fmt(r.spent)}, осталось ${fmt(Math.max(0, r.left))}` : ""}${r.done ? " · оплачено ●" : ""}${pendingDone(id) ? " · отметка ● ждёт синхронизации" : ""}</p>
    ${spHtml}
    ${canSpend ? '<button class="primary" data-a="spend">Потратила из этой строки…</button>' : ""}
    ${canDone ? '<button class="ghost" data-a="done">Отметить оплаченной ●</button>' : ""}`, (a) => {
    if (a === "spend") {
      kind = "expense"; mode = "send"; setEditing(null);
      showPage("add"); fillForm();
      $("row").value = String(id); onRowChange(); $("amount").focus();
    }
    if (a === "done") {
      entries.unshift({ id: uid(), created: new Date().toISOString(), date: todayISO(), kind: "done", amount: 0,
        category: r.category, note: "", row_id: id, row_name: r.name, half: f.half, mode: "send", status: "pending" });
      saveEntries(); renderAll();
      toast(`«${r.name}» отмечено ● — уйдёт на компьютер при синхронизации`);
    }
  });
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

/* ------------------------------------------------------------------ напоминания и Календарь */
function importantItems() {
  const out = [];
  if (snap && snap.reminders) snap.reminders.forEach((r) => out.push({ icon: r.icon, text: r.text }));
  const old = entries.filter((e) => e.status === "pending" && Date.now() - new Date(e.created).getTime() > 86400000).length;
  if (old) out.push({ icon: "📤", text: `${old} запис${old === 1 ? "ь ждёт" : "и ждут"} отправки больше суток — нажмите «Синхронизировать»` });
  const age = snapAgeH();
  if (age != null && age > 24)
    out.push({ icon: "🕰", text: `Данные с ноутбука ${whenText(snap.generated)} (${ageText(age)}) — разбудите ноутбук или откройте программу` });
  const bc = snap && snap.bank_check;
  if (bc && bc.days && !(snap.reminders || []).some((r) => r.text.startsWith("Сверка с банком"))) {
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
    if (days >= 7 && !(snap.reminders || []).some((r) => r.text.startsWith("Ждёте возврат")))
      out.push({ icon: "↩", text: `Ждёте возврат ${fmtExact(p.amount)} (${p.note || "без подписи"}) уже ${days} дн.` });
  });
  return out;
}
function updateBadge() {
  const n = importantItems().length;
  const tab = document.querySelector('.tabs button[data-page="sum"]');
  if (tab) tab.classList.toggle("has-dot", n > 0);
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
  bank: ["Сверка", "с банком: сколько на картах"], ops: ["Операции", "всё, что записано, новые сверху"],
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
function lastSpends(n = 4) {
  /* траты в листе (из сводки ноутбука) + траты с телефона, которые ещё не в листе; новые по дате сверху */
  let out = ((snap && snap.last_spends) || []).map((x) => ({ ...x, phone: false }));
  if (!out.length && snap && snap.sheets) {
    /* ноутбук ещё старой версии и не прислал список — берём траты из листов (без времени записи) */
    const today = todayISO();
    snap.sheets.slice(0, 2).forEach((sh) => buildOps(sh).filter((o) => !o.inc && !o.fund && o.date <= today)
      .forEach((o) => out.push({ date: o.date, name: o.title, amount: o.amount, created: "", phone: false })));
  }
  entries.filter((e) => e.kind === "expense" && !e.deleted && e.status !== "done")
    .forEach((e) => out.push({ date: e.date, name: e.note || e.row_name || e.category, amount: e.amount,
      created: String(e.created || "").replace("T", " ").slice(0, 16), phone: true }));
  out.sort((a, b) => (a.date !== b.date ? (a.date < b.date ? 1 : -1) : (a.created < b.created ? 1 : a.created > b.created ? -1 : 0)));
  return out.slice(0, n);
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
  if (h == null || h < 6) return "";
  return `<div class="card warn"><b>⚠️ Данные с ноутбука ${whenText(snap.generated)} — ${ageText(h)}.</b>
    <div class="hint" style="margin-top:4px">Ноутбук спит или выключен. Остатки и «можно в день» могут быть неточными —
    новые траты записывайте как обычно, они дождутся. Обновится, когда ноутбук проснётся (он сам просыпается раз в полчаса,
    если стоит на зарядке и не выключен).</div></div>`;
}
function showPage(p) {
  document.querySelectorAll(".page").forEach((s) => s.classList.toggle("active", s.id === "page-" + p));
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.page === p));
  if (p === "bank") renderBank();
  $("title").textContent = TITLES[p][0];
  $("subtitle").textContent = p === "sum" ? syncStamp() : TITLES[p][1];
  if (p === "ops") renderOps();
  window.scrollTo(0, 0);
}

/* ------------------------------------------------------------------ запуск */
function init() {
  readHash();
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
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
    const t = ev.target.closest ? ev.target.closest("[data-sheet],[data-mode2],[data-fund],[data-fundpay],[data-go],[data-row],[data-op],[data-opsm]") : null;
    if (!t) return;
    if (t.dataset.sheet !== undefined) { sheetIdx = Number(t.dataset.sheet); renderSheet(); }
    else if (t.dataset.mode2) { sheetMode = t.dataset.mode2; renderSheet(); }
    else if (t.dataset.fund !== undefined) topUpFund(Number(t.dataset.fund));
    else if (t.dataset.fundpay !== undefined) payFromFund(Number(t.dataset.fundpay));
    else if (t.dataset.row !== undefined) openRow(Number(t.dataset.row));
    else if (t.dataset.op !== undefined) openOp(Number(t.dataset.op));
    else if (t.dataset.opsm !== undefined) { opsIdx = Number(t.dataset.opsm); renderOps(); }
    else if (t.dataset.go === "ics") exportCalendar();
    else if (t.dataset.go) showPage(t.dataset.go);
  });
  $("addForm").addEventListener("submit", onSubmit);
  $("syncBtn").addEventListener("click", sync);
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
