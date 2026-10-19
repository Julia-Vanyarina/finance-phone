/* Мои финансы — телефон.
   Записи хранятся на телефоне (localStorage). «Синхронизировать» шифрует паролем записи с пометкой
   «на компьютер» и кладёт их в ваш приватный репозиторий GitHub (inbox/), затем забирает сводку
   с компьютера (snapshot.enc). Формат шифрования совпадает с phone_sync.py на компьютере:
   PBKDF2-SHA256 (200 000) → AES-256-GCM, у каждого файла своя соль. */
"use strict";

const VERSION = "1.0";
const FORMAT = "moi-finansy-1";
const ITER = 200000;
const API = "https://api.github.com";
const INBOX = "inbox";
const SNAPSHOT = "snapshot.enc";
const TOKEN_PAGE = "https://github.com/settings/personal-access-tokens/new";

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
let cfg = store.get("cfg", { repo: "", ghToken: "", pw: "", lastMode: "send" });
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
async function sync() {
  if (syncing) return;
  const why = needSetup();
  if (why) { toast(why); showPage("set"); return; }
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
          : { id: e.id, date: e.date, kind: e.kind, amount: e.amount, category: e.category,
            note: e.note, half: e.half || null, row_id: e.row_id || null, created: e.created })),
      };
      const name = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14) + "-" + uid().slice(0, 8) + ".enc";
      await upload(`${INBOX}/${name}`, await encryptObj(payload, cfg.pw), "phone: " + pending.length);
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
    toast(e instanceof SyncError ? e.message : "Ошибка: " + e.message, 5200);
  } finally {
    syncing = false;
    $("syncBtn").classList.remove("busy");
    renderAll();
  }
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
const ICON_BANK = '<svg viewBox="0 0 24 24"><path d="M3 10 12 4l9 6"/><path d="M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18"/></svg>';
function iconFor(e) {
  const k = e.kind === "income" ? "_income" : (e.category || "").startsWith("В фонд") ? "_fund"
    : ICON[e.category] ? e.category : "_default";
  return `<svg viewBox="0 0 24 24">${ICON[k]}</svg>`;
}

/* ------------------------------------------------------------------ отрисовка */
function badge(e) {
  return { pending: '<span class="badge pending">ждёт отправки</span>', sent: '<span class="badge sent">отправлено</span>',
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
    if (e.kind === "bank") {
      html += `<div class="entry" data-id="${e.id}"><div class="ic">${ICON_BANK}</div><div class="mid">
        <div class="t">Сверка с банком</div><div class="s">${esc(e.note)} ${badge(e)}</div></div>
        <div class="sum">${e.record && e.diff ? (e.diff < 0 ? "−" : "+") + fmtExact(Math.abs(e.diff)) : ""}</div></div>`;
      return;
    }
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
  h += `<div class="card"><h2>Сверка с банком</h2><p class="hint">${snap.bank && snap.bank.last_check ? "последняя — " + ddmm(snap.bank.last_check) : "ещё не делали"}</p>
    <button class="ghost" type="button" data-go="bank">🏦 Сверить с банком</button></div>`;
  if (snap.payments && snap.payments.length) {
    h += `<div class="sec">Ближайшие платежи</div><div class="card">`;
    snap.payments.forEach((p) => { h += `<div class="line"><span>${ddmm(p.date)} · ${esc(p.name)}</span><span class="r">${fmt(p.amount)}</span></div>`; });
    h += `</div>`;
  }
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
    && !got.has(e.id) && e.date >= from && e.date <= nm);
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
        const st = r.done ? '<span class="dot green"></span>' : (r.spent ? '<span class="dot yellow"></span>' : '<span class="dot" style="background:#C9D6F8"></span>');
        const extra = r.from_fund ? "из фонда" : (r.spent && !r.done ? `потрачено ${fmt(r.spent)}, ост. ${fmt(r.left)}`
          : (r.spent && r.spent > r.amount + 0.5 ? "перерасход" : ""));
        h += `<div class="line"><span>${st}${esc(r.name)}${extra ? `<div class="hint" style="margin:1px 0 0 16px">${extra}</div>` : ""}</span>
          <span class="r">${fmt(r.amount)}<div class="hint" style="margin:1px 0 0;text-align:right">${left < 0 ? '<span class="red">' + fmt(left) + "</span>" : fmt(left)}</div></span></div>`;
      });
      h += `</div>`;
    });
    h += `<p class="hint center">● оплачено · ◐ тратится · ○ ещё нет. Справа под суммой — остаток колонки после строки.</p>`;
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
    const pend = entries.filter((e) => e.category === cat && e.mode === "send" && e.status !== "done" && !got.has(e.id))
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
      <button class="ghost" type="button" data-fund="${i}">＋ Пополнить</button></div>`;
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
  $("repo").value = cfg.repo || "";
  const st = $("tokenStatus");
  st.textContent = cfg.ghToken ? "Токен сохранён на этом телефоне ✓" : "Токен ещё не вставлен";
  st.className = "status " + (cfg.ghToken ? "ok" : "");
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
  renderSheet();
  renderFunds();
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
    ${e.status === "sent" ? '<p class="hint">Уже отправлена — компьютер заберёт её при следующем запуске. Удалить отсюда нельзя: исправьте в программе на компьютере.</p>' : ""}
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
  sheet: ["Лист месяца", "как на компьютере"], funds: ["Фонды", "копилки на цели"],
  bank: ["Сверка", "с банком: сколько на картах"],
  list: ["Записи", "что записано на телефоне"], sum: ["Сводка", "с компьютера, после последней синхронизации"],
  set: ["Настройки", "синхронизация и пароль"] };
function showPage(p) {
  document.querySelectorAll(".page").forEach((s) => s.classList.toggle("active", s.id === "page-" + p));
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.page === p));
  if (p === "bank") renderBank();
  $("title").textContent = TITLES[p][0];
  $("subtitle").textContent = TITLES[p][1];
  window.scrollTo(0, 0);
}

/* ------------------------------------------------------------------ запуск */
function init() {
  readHash();
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
  document.querySelectorAll("#addForm .seg button").forEach((b) => b.addEventListener("click", () => { kind = b.dataset.kind; $("row").value = ""; fillForm(); }));
  document.querySelectorAll(".dest button").forEach((b) => b.addEventListener("click", () => { mode = b.dataset.mode; fillForm(); }));
  document.querySelectorAll(".filters .chip").forEach((b) => b.addEventListener("click", () => {
    filter = b.dataset.f;
    document.querySelectorAll(".filters .chip").forEach((x) => x.classList.toggle("on", x === b));
    renderList();
  }));
  $("row").addEventListener("change", onRowChange);
  $("setBtn").addEventListener("click", () => showPage("set"));
  document.addEventListener("click", (ev) => {
    const t = ev.target.closest ? ev.target.closest("[data-sheet],[data-mode2],[data-fund],[data-go]") : null;
    if (!t) return;
    if (t.dataset.sheet !== undefined) { sheetIdx = Number(t.dataset.sheet); renderSheet(); }
    else if (t.dataset.mode2) { sheetMode = t.dataset.mode2; renderSheet(); }
    else if (t.dataset.fund !== undefined) topUpFund(Number(t.dataset.fund));
    else if (t.dataset.go) showPage(t.dataset.go);
  });
  $("addForm").addEventListener("submit", onSubmit);
  $("syncBtn").addEventListener("click", sync);
  $("list").addEventListener("click", (ev) => { const el = ev.target.closest(".entry"); if (el) openEntry(el.dataset.id); });
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
  renderAll();
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  if (needSetup()) showPage("set");
}
document.addEventListener("DOMContentLoaded", init);
