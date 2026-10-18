/* Мои финансы — телефон.
   Записи хранятся на телефоне (localStorage). «Синхронизировать» шифрует паролем записи с пометкой
   «на компьютер» и кладёт их в папку приложения на Яндекс Диске (app:/inbox), затем забирает сводку
   с компьютера (app:/snapshot.enc). Формат шифрования совпадает с phone_sync.py на компьютере:
   PBKDF2-SHA256 (200 000) → AES-256-GCM, у каждого файла своя соль. */
"use strict";

const VERSION = "1.0";
const FORMAT = "moi-finansy-1";
const ITER = 200000;
const API = "https://cloud-api.yandex.net/v1/disk";
const INBOX = "app:/inbox";
const SNAPSHOT = "app:/snapshot.enc";

const EXPENSE_DEFAULT = ["Продукты", "Обеды и кафе", "Транспорт", "Связь", "Подписки", "Одежда и маркетплейсы",
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
let cfg = store.get("cfg", { cid: "", token: "", tokenUntil: 0, pw: "", lastMode: "send" });
let snap = store.get("snap", null);
let kind = "expense";
let mode = cfg.lastMode || "send";
let filter = "all";
const saveEntries = () => store.set("entries", entries);
const saveCfg = () => store.set("cfg", cfg);

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
function autoHalf(iso) { const d = Number(iso.slice(8, 10)); return d >= 10 && d <= 24 ? 1 : 2; }
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

/* ------------------------------------------------------------------ Яндекс Диск */
class DiskError extends Error {}
async function http(method, url, opts = {}) {
  let r;
  try {
    r = await fetch(url, { method, headers: opts.headers || {}, body: opts.body, cache: "no-store" });
  } catch (e) {
    throw new DiskError(navigator.onLine === false ? "Нет интернета — записи подождут на телефоне"
      : "Яндекс Диск не ответил (сеть или ограничение браузера). Записи остались на телефоне.");
  }
  if (r.status === 401) throw new DiskError("Яндекс не принял вход — нажмите «Войти через Яндекс» в настройках");
  if (r.status === 403) throw new DiskError("Нет доступа к Диску — проверьте права приложения на oauth.yandex.ru");
  if (r.status === 507) throw new DiskError("На Яндекс Диске закончилось место");
  return r;
}
async function api(method, path, params) {
  const q = new URLSearchParams(params).toString();
  const r = await http(method, `${API}${path}?${q}`, { headers: { Authorization: "OAuth " + cfg.token, Accept: "application/json" } });
  let data = {};
  try { data = await r.json(); } catch (e) { /* пусто */ }
  return { status: r.status, data };
}
async function ensureFolder(path) {
  const { status, data } = await api("PUT", "/resources", { path });
  if (status !== 201 && status !== 409) throw new DiskError("Не получилось создать папку на Диске (" + (data.message || status) + ")");
}
async function upload(path, text) {
  const { status, data } = await api("GET", "/resources/upload", { path, overwrite: "true" });
  if (status !== 200 || !data.href) throw new DiskError("Диск не дал загрузить файл (" + (data.message || status) + ")");
  const r = await http(data.method || "PUT", data.href, { body: new Blob([text], { type: "application/octet-stream" }) });
  if (![200, 201, 202].includes(r.status)) throw new DiskError("Не загрузилось на Диск (" + r.status + ")");
}
async function download(path) {
  const { status, data } = await api("GET", "/resources/download", { path });
  if (status === 404) return null;
  if (status !== 200 || !data.href) throw new DiskError("Диск не дал скачать файл (" + (data.message || status) + ")");
  const r = await http("GET", data.href);
  if (r.status !== 200) throw new DiskError("Не скачалось с Диска (" + r.status + ")");
  return await r.text();
}
function needSetup() {
  if (!cfg.token) return "Сначала войдите через Яндекс (вкладка «Настройки»)";
  if (cfg.tokenUntil && Date.now() > cfg.tokenUntil) return "Вход в Яндекс истёк — войдите заново в «Настройках»";
  if (!cfg.pw) return "Сначала введите пароль синхронизации (вкладка «Настройки»)";
  return "";
}

/* ------------------------------------------------------------------ синхронизация */
let syncing = false;
async function sync() {
  if (syncing) return;
  const why = needSetup();
  if (why) { toast(why); showPage("set"); return; }
  syncing = true;
  $("syncBtn").classList.add("busy");
  $("syncText").textContent = "Синхронизирую…";
  try {
    await ensureFolder("app:/");
    await ensureFolder(INBOX);
    const pending = entries.filter((e) => e.mode === "send" && e.status === "pending");
    if (pending.length) {
      const payload = {
        f: FORMAT, sent: new Date().toISOString(), device: navigator.userAgent.slice(0, 80),
        entries: pending.map((e) => ({ id: e.id, date: e.date, kind: e.kind, amount: e.amount, category: e.category,
          note: e.note, half: e.half || null, row_id: e.row_id || null, created: e.created })),
      };
      const name = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14) + "-" + uid().slice(0, 8) + ".enc";
      await upload(`${INBOX}/${name}`, await encryptObj(payload, cfg.pw));
      const now = new Date().toISOString();
      pending.forEach((e) => { e.status = "sent"; e.sent_at = now; });
      saveEntries();
    }
    const text = await download(SNAPSHOT);
    let note = "";
    if (text) {
      snap = await decryptText(text, cfg.pw);
      store.set("snap", snap);
      const got = new Set(snap.received || []);
      let changed = false;
      entries.forEach((e) => { if (e.status === "sent" && got.has(e.id)) { e.status = "done"; changed = true; } });
      if (changed) saveEntries();
    } else {
      note = " · сводки с компьютера пока нет: откройте программу на компьютере";
    }
    toast((pending.length ? `Отправлено: ${pending.length}` : "Новых записей для компьютера нет") + note, 4200);
  } catch (e) {
    toast(e instanceof DiskError ? e.message : "Ошибка: " + e.message, 5200);
  } finally {
    syncing = false;
    $("syncBtn").classList.remove("busy");
    renderAll();
  }
}

/* ------------------------------------------------------------------ вход через Яндекс */
function readAuthFromHash() {
  const h = new URLSearchParams(location.hash.slice(1));
  let changed = false;
  if (h.get("cid")) { cfg.cid = h.get("cid"); changed = true; }
  if (h.get("access_token")) {
    cfg.token = h.get("access_token");
    const sec = Number(h.get("expires_in") || 0);
    cfg.tokenUntil = sec ? Date.now() + sec * 1000 : 0;
    changed = true;
    setTimeout(() => toast("Вход в Яндекс выполнен ✓"), 300);
  }
  if (h.get("error")) setTimeout(() => toast("Яндекс: " + (h.get("error_description") || h.get("error"))), 300);
  if (changed) saveCfg();
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
}
function login() {
  const cid = $("cid").value.trim();
  if (cid.length < 10) { toast("Вставьте номер приложения (ClientID) с oauth.yandex.ru"); return; }
  cfg.cid = cid; saveCfg();
  /* Яндекс показывает токен на своей странице (адрес возврата у приложения — отладочный, его не меняют):
     открываем её, а здесь раскрываем поле, куда токен вставить. */
  window.open("https://oauth.yandex.ru/authorize?" + new URLSearchParams({
    response_type: "token", client_id: cid, force_confirm: "yes" }).toString(), "_blank");
  const d = document.querySelector("#page-set details");
  if (d) d.open = true;
  toast("Разрешите доступ, скопируйте токен со страницы Яндекса и вставьте в поле «Токен»", 6000);
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
  document.querySelectorAll(".seg button").forEach((b) => b.classList.toggle("on", b.dataset.kind === kind));
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
  entries.unshift(e);
  if (!saveEntries()) { entries.shift(); return; }
  cfg.lastMode = mode;
  if (kind === "income") cfg.lastInc = e.category; else cfg.lastExp = e.category;
  saveCfg();
  $("amount").value = ""; $("note").value = ""; $("row").value = ""; $("note").placeholder = "например: кофе, продукты в Самокате";
  toast((kind === "income" ? "Доход " : "Трата ") + fmtExact(amount) + (mode === "send" ? " — ждёт синхронизации" : " — только на телефоне"));
  renderAll();
}

/* ------------------------------------------------------------------ иконки категорий (тонкие линии) */
const ICON = {
  "Продукты": '<path d="M3 4h3l3 11h10"/><path d="M8 8h13l-2 5H9.5"/><circle cx="10" cy="19" r="1.4"/><circle cx="18" cy="19" r="1.4"/>',
  "Обеды и кафе": '<path d="M4 9h12v5a5 5 0 0 1-5 5h-2a5 5 0 0 1-5-5z"/><path d="M16 11h2a2.5 2.5 0 0 1 0 5h-2.5M8 3v3M12 3v3"/>',
  "Транспорт": '<rect x="5" y="3" width="14" height="15" rx="3"/><path d="M5 11h14M8 18v3M16 18v3"/>',
  "Связь": '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18h2"/>',
  "Подписки": '<path d="M4 14a8 8 0 0 1 16 0"/><rect x="3" y="13" width="4" height="7" rx="1.5"/><rect x="17" y="13" width="4" height="7" rx="1.5"/>',
  "Одежда и маркетплейсы": '<path d="M9 3 4 6l2 4 2-1v12h8V9l2 1 2-4-5-3a3 3 0 0 1-6 0z"/>',
  "Красота и уход": '<path d="M12 2c.5 6 3.5 9 10 10-6.5 1-9.5 4-10 10-.5-6-3.5-9-10-10 6.5-1 9.5-4 10-10z"/>',
  "Здоровье и врачи": '<path d="M12 2c4 5 7 8 7 12a7 7 0 0 1-14 0c0-4 3-7 7-12z"/><path d="M12 11v6M9 14h6"/>',
  "Дом и быт": '<path d="M3 11 12 3l9 8v10H3z"/><path d="M10 21v-6h4v6"/>',
  "Подарки": '<rect x="4" y="9" width="16" height="12" rx="2"/><path d="M3 7h18v3H3zM12 7v14"/><path d="M12 7c-2-4-6-3-5 0M12 7c2-4 6-3 5 0"/>',
  "Квартира": '<path d="M3 11 12 3l9 8v10H3z"/><path d="M10 21v-6h4v6"/>',
  "_income": '<path d="M12 19V5M6 11l6-6 6 6"/>',
  "_fund": '<ellipse cx="12" cy="13" rx="8" ry="6"/><path d="M9 9h5M7 18v3M17 18v3"/>',
  "_default": '<circle cx="12" cy="12" r="4"/>',
};
function iconFor(e) {
  const k = e.kind === "income" ? "_income" : (e.category || "").startsWith("В фонд") ? "_fund"
    : ICON[e.category] ? e.category : "_default";
  return `<svg viewBox="0 0 24 24">${ICON[k]}</svg>`;
}

/* ------------------------------------------------------------------ отрисовка */
function badge(e) {
  return { pending: '<span class="badge pending">ждёт отправки</span>', sent: '<span class="badge sent">на Диске</span>',
    done: '<span class="badge done">в листе ✓</span>', local: '<span class="badge local">только телефон</span>' }[e.status] || "";
}
function renderList() {
  const list = entries.filter((e) => filter === "all" || (filter === "pending" ? e.status === "pending" : e.status === "local"));
  if (!list.length) {
    $("list").innerHTML = `<div class="card empty">${filter === "all" ? "Записей пока нет — добавьте на вкладке «Записать»" : "Здесь пусто"}</div>`;
    return;
  }
  let html = "", day = "";
  list.forEach((e) => {
    if (e.date !== day) {
      if (day) html += "</div>";
      day = e.date;
      html += `<div class="sec">${ddmm(day)}${day === todayISO() ? " · сегодня" : ""}</div><div class="card" style="padding:0">`;
    }
    const half = e.half || autoHalf(e.date);
    html += `<div class="entry" data-id="${e.id}"><div class="ic">${iconFor(e)}</div><div class="mid">
      <div class="t">${esc(e.note || e.category)}</div>
      <div class="s">${esc(e.category)}${e.row_name ? " · из «" + esc(e.row_name) + "»" : ""} · ${HALF_NAME[half]} ${badge(e)}</div></div>
      <div class="sum ${e.kind === "income" ? "green" : ""}">${e.kind === "income" ? "+" : "−"}${fmtExact(e.amount)}</div></div>`;
  });
  $("list").innerHTML = html + "</div>";
}
function unsentExpenses() {
  /* Траты «на компьютер», которых ещё нет в сводке. Трата из строки-плана (или той же категории, где план
     ещё не потрачен) свободные деньги не уменьшает — она уже была запланирована; вычитаем только сверх плана. */
  const got = new Set((snap && snap.received) || []);
  const pool = new Map(planRows().map((r) => [r.id, { left: r.left, category: r.category }]));
  let extra = 0;
  entries.filter((e) => e.kind === "expense" && e.mode === "send" && !got.has(e.id) && e.status !== "done")
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
  html += `<div class="hint">сводка от ${snap.generated.slice(8, 10)}.${snap.generated.slice(5, 7)} ${snap.generated.slice(11, 16)}</div>`;
  return html;
}
function renderSummary() {
  if (!snap) {
    $("summary").innerHTML = `<div class="card empty">Сводка появится после первой синхронизации.<br>На компьютере: «☰ Ещё → 📲 Телефон → Настроить».</div>`;
    return;
  }
  let h = `<div class="card">${todayBlock()}${snap.cards != null ? `<div class="line"><span>На картах должно быть</span><span class="r">${fmt(snap.cards)}</span></div>` : ""}</div>`;
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
  if (snap.funds && snap.funds.length) {
    h += `<div class="sec">Фонды</div><div class="card">`;
    snap.funds.forEach((f) => {
      const pct = f.goal > 0 ? Math.min(100, (f.saved / f.goal) * 100) : 0;
      h += `<div style="padding:5px 0"><div class="line" style="border:0;padding:0"><span>${esc(f.name)}</span><span class="r">${fmt(f.saved)}${f.goal ? ` <span class="muted">из ${fmt(f.goal)}</span>` : ""}</span></div>
        ${f.goal ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ""}</div>`;
    });
    h += `</div>`;
  }
  if (snap.payments && snap.payments.length) {
    h += `<div class="sec">Ближайшие платежи</div><div class="card">`;
    snap.payments.forEach((p) => { h += `<div class="line"><span>${ddmm(p.date)} · ${esc(p.name)}</span><span class="r">${fmt(p.amount)}</span></div>`; });
    h += `</div>`;
  }
  $("summary").innerHTML = h;
}
function renderSettings() {
  $("cid").value = cfg.cid || "";
  const st = $("tokenStatus");
  if (cfg.token && !(cfg.tokenUntil && Date.now() > cfg.tokenUntil)) {
    const until = cfg.tokenUntil ? " до " + new Date(cfg.tokenUntil).toLocaleDateString("ru-RU") : "";
    st.textContent = "Вход в Яндекс выполнен ✓" + until; st.className = "status ok";
  } else {
    st.textContent = cfg.token ? "Вход истёк — войдите снова" : "Ещё не вошли"; st.className = "status " + (cfg.token ? "bad" : "");
  }
  $("pwStatus").textContent = cfg.pw ? "Пароль сохранён на этом телефоне ✓" : "Пароль не задан";
  $("pwStatus").className = "status " + (cfg.pw ? "ok" : "");
  const n = entries.length, p = entries.filter((e) => e.status === "pending").length, l = entries.filter((e) => e.status === "local").length;
  $("storageInfo").textContent = `На телефоне записей: ${n} (ждут отправки: ${p}, только на телефоне: ${l}). ` +
    "Чтобы iPhone не стёр данные, пользуйтесь приложением с экрана «Домой» (Поделиться → На экран «Домой»).";
  $("ver").textContent = VERSION;
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
  renderList();
  renderSummary();
  renderSettings();
  renderCount();
}

/* ------------------------------------------------------------------ действия над записью */
function openEntry(id) {
  const e = entries.find((x) => x.id === id);
  if (!e) return;
  const bg = document.createElement("div");
  bg.className = "sheet-bg";
  const canSend = e.status === "local";
  const canLocal = e.status === "pending";
  const canDelete = e.status !== "sent";
  bg.innerHTML = `<div class="sheet"><h2>${esc(e.note || e.category)} · ${fmtExact(e.amount)}</h2>
    <p class="hint">${ddmm(e.date)} · ${esc(e.category)} · ${HALF_NAME[e.half || autoHalf(e.date)]}</p>
    ${e.status === "sent" ? '<p class="hint">Уже на Яндекс Диске — компьютер заберёт её при следующем запуске. Удалить отсюда нельзя: исправьте в программе на компьютере.</p>' : ""}
    ${e.status === "done" ? '<p class="hint">Уже записана в лист на компьютере. Удаление здесь уберёт её только из этого списка.</p>' : ""}
    ${canSend ? '<button class="primary" data-a="send">Отправить на компьютер</button>' : ""}
    ${canLocal ? '<button class="ghost" data-a="local">Оставить только на телефоне</button>' : ""}
    ${canDelete ? '<button class="ghost danger" data-a="del">Удалить</button>' : ""}
    <button class="ghost" data-a="close">Закрыть</button></div>`;
  bg.addEventListener("click", (ev) => {
    const a = ev.target.dataset && ev.target.dataset.a;
    if (ev.target === bg || a === "close") { bg.remove(); return; }
    if (a === "send") { e.mode = "send"; e.status = "pending"; }
    if (a === "local") { e.mode = "local"; e.status = "local"; }
    if (a === "del") {
      if (!confirm("Удалить запись?")) return;
      entries = entries.filter((x) => x.id !== e.id);
    }
    if (a) { saveEntries(); bg.remove(); renderAll(); }
  });
  document.body.appendChild(bg);
}

/* ------------------------------------------------------------------ навигация */
const TITLES = { add: ["Записать", "трата уйдёт на компьютер по кнопке «Синхронизировать»"],
  list: ["Записи", "что записано на телефоне"], sum: ["Сводка", "с компьютера, после последней синхронизации"],
  set: ["Настройки", "Яндекс Диск и пароль"] };
function showPage(p) {
  document.querySelectorAll(".page").forEach((s) => s.classList.toggle("active", s.id === "page-" + p));
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.page === p));
  $("title").textContent = TITLES[p][0];
  $("subtitle").textContent = TITLES[p][1];
  window.scrollTo(0, 0);
}

/* ------------------------------------------------------------------ запуск */
function init() {
  readAuthFromHash();
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
  document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => { kind = b.dataset.kind; $("row").value = ""; fillForm(); }));
  document.querySelectorAll(".dest button").forEach((b) => b.addEventListener("click", () => { mode = b.dataset.mode; fillForm(); }));
  document.querySelectorAll(".filters .chip").forEach((b) => b.addEventListener("click", () => {
    filter = b.dataset.f;
    document.querySelectorAll(".filters .chip").forEach((x) => x.classList.toggle("on", x === b));
    renderList();
  }));
  $("row").addEventListener("change", onRowChange);
  $("addForm").addEventListener("submit", onSubmit);
  $("syncBtn").addEventListener("click", sync);
  $("list").addEventListener("click", (ev) => { const el = ev.target.closest(".entry"); if (el) openEntry(el.dataset.id); });
  $("loginBtn").addEventListener("click", login);
  $("tokenGet").addEventListener("click", () => {
    const cid = $("cid").value.trim();
    if (cid.length < 10) { toast("Сначала вставьте номер приложения (ClientID)"); return; }
    cfg.cid = cid; saveCfg();
    window.open("https://oauth.yandex.ru/authorize?" + new URLSearchParams({ response_type: "token", client_id: cid,
      force_confirm: "yes" }).toString(), "_blank");
  });
  $("tokenSave").addEventListener("click", () => {
    let t = $("tokenManual").value.trim();
    const m = t.match(/access_token=([^&]+)/);
    if (m) t = decodeURIComponent(m[1]);
    if (t.length < 20) { toast("Это не похоже на токен"); return; }
    cfg.token = t; cfg.tokenUntil = 0; saveCfg(); $("tokenManual").value = ""; renderSettings(); toast("Токен сохранён");
  });
  $("pwSave").addEventListener("click", () => {
    const v = $("pw").value;
    if (v.length < 6) { toast("Пароль — хотя бы 6 символов, такой же как на компьютере"); return; }
    cfg.pw = v; saveCfg(); $("pw").value = ""; renderSettings(); toast("Пароль сохранён");
  });
  $("testBtn").addEventListener("click", async () => {
    const s = $("testStatus");
    const why = needSetup();
    if (why && !cfg.token) { s.textContent = why; s.className = "status bad"; return; }
    s.textContent = "Проверяю…"; s.className = "status";
    try {
      await ensureFolder("app:/");
      await ensureFolder(INBOX);
      const text = await download(SNAPSHOT);
      if (text && cfg.pw) { await decryptText(text, cfg.pw); s.textContent = "Всё работает ✓ Диск на связи, сводка открывается паролем."; }
      else if (text) s.textContent = "Диск на связи ✓ Введите пароль, чтобы открыть сводку.";
      else s.textContent = "Диск на связи ✓ Сводки ещё нет — откройте программу на компьютере.";
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
  renderAll();
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  if (!cfg.token || !cfg.pw) showPage(cfg.cid ? "set" : "add");
}
document.addEventListener("DOMContentLoaded", init);
