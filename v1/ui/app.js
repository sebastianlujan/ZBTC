// ZBTC demo wallet. The main area is the wallet; the side panel has three
// terminal-styled tabs: terminal (every command, streamed), explorer (what
// anyone sees on the chain) and debug (the decoded OP_RETURN and node state).
'use strict';

// ---- DOM helpers ----

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...children) {
  const { attrs, ...rest } = props;
  const el = document.createElement(tag);
  Object.assign(el, rest);
  for (const [k, v] of Object.entries(attrs ?? {})) el.setAttribute(k, v);
  el.append(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
  return el;
}

// Static markup only: none of these strings carry data.
const ICONS = {
  shield: '<svg viewBox="0 0 20 20"><path d="M10 2l6.5 2.5v5c0 4-2.8 7-6.5 8.5C6.3 16.5 3.5 13.5 3.5 9.5v-5z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>',
  eye: '<svg viewBox="0 0 20 20"><path d="M1.5 10S5 4 10 4s8.5 6 8.5 6-3.5 6-8.5 6-8.5-6-8.5-6z" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="10" cy="10" r="2.5" fill="currentColor"/></svg>',
  up: '<svg viewBox="0 0 20 20"><path d="M6 14L14 6M7 6h7v7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  down: '<svg viewBox="0 0 20 20"><path d="M14 6L6 14M13 14H6V7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  spark: '<svg viewBox="0 0 20 20"><path d="M10 2.5l1.8 5.7 5.7 1.8-5.7 1.8L10 17.5l-1.8-5.7L2.5 10l5.7-1.8z" fill="currentColor"/></svg>',
  check: '<svg viewBox="0 0 16 16"><path d="M3.5 8.5l3 3 6-7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  x: '<svg viewBox="0 0 16 16"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  copy: '<svg viewBox="0 0 16 16"><rect x="5" y="5" width="8.5" height="8.5" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M3 10.5V3.5A1 1 0 0 1 4 2.5h6.5" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>',
  terminal: '<svg viewBox="0 0 20 20"><rect x="2" y="3.5" width="16" height="13" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M5.5 8l2.5 2-2.5 2M10 12.5h4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  cube: '<svg viewBox="0 0 20 20"><path d="M10 2.5l6.5 3.5v8L10 17.5 3.5 14V6z M3.5 6L10 9.5l6.5-3.5M10 9.5v8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  logo: '<svg viewBox="0 0 16 16"><path d="M3 3.5h10L3.5 12.5h9.5" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};
const icon = (name) => h('span', { className: 'icon', innerHTML: ICONS[name], attrs: { 'aria-hidden': 'true' } });

// ---- Formatting ----

const PEOPLE = ['alice', 'bob'];
const MAX_PAYMENT_BTC = 0.9;
const cap = (p) => p[0].toUpperCase() + p.slice(1);
const BTC_FORMAT = new Intl.NumberFormat('es', { minimumFractionDigits: 8, maximumFractionDigits: 8 });
const btc = (v) => `${BTC_FORMAT.format(v)} BTC`;
const zbtc = (n) => `${n} ZBTC`;
const sum = (xs) => xs.reduce((a, b) => a + b, 0);
const shortHex = (s) => (s && s.length > 18 ? `${s.slice(0, 8)}…${s.slice(-8)}` : s ?? '');
const shortAddr = (a) => (a && a.length > 24 ? `${a.slice(0, 12)}…${a.slice(-8)}` : a ?? '');
const decimal = (s) => s.trim().replace(',', '.');
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const RELATIVE = new Intl.RelativeTimeFormat('es', { numeric: 'auto' });

function timeAgo(ms) {
  // Regtest stamps blocks mined in a burst a few seconds ahead of the clock; never say "in N seconds".
  const seconds = Math.min(0, Math.round((ms - Date.now()) / 1000));
  if (Math.abs(seconds) < 60) return RELATIVE.format(seconds, 'second');
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return RELATIVE.format(minutes, 'minute');
  return RELATIVE.format(Math.round(minutes / 60), 'hour');
}

const UNITS_TIP = 'ZBTC son unidades de prueba de esta demo: no son sats ni BTC. Las crea el génesis y viajan como notas protegidas dentro de transacciones Bitcoin; Bitcoin solo las ordena y las fecha.';

// ---- State ----

/** Everything the page knows. `chain` comes from the server; the rest is what the viewer opened. */
const S = {
  chain: null,
  loaded: false,
  account: 'alice',
  busy: null,
  progress: [],
  toast: null,
  tab: 'terminal',
  panelOpen: window.matchMedia('(min-width: 1200px)').matches,
  panelMax: false,
  commands: 0,
  explorer: { view: 'home', ref: null, home: null, txs: new Map(), blocks: new Map(), opened: new Map(), decryptAs: new Map(), loading: false },
  debug: { txid: null, confirmReset: false },
  send: null,
  receive: null,
};

const wallet = (name) => S.chain?.wallets.find((w) => w.name === name);
const other = (name) => PEOPLE.find((p) => p !== name);

/** Units the wallet holds once the next block confirms what is in flight: notes being spent drop out, incoming ones count. */
function afterNextBlock(w) {
  return sum(w.notes.filter((n) => n.state !== 'spent' && n.state !== 'pending-spend').map((n) => n.units));
}

// ---- Terminal tab: every command, streamed as it runs ----

function setPanelOpen(open) {
  S.panelOpen = open;
  if (!open) S.panelMax = false;
  renderPanelFrame();
}

function appendScrolling(parent, child, force = false) {
  const body = $('tab-terminal');
  const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 48;
  parent.append(child);
  if (force || atBottom) body.scrollTop = body.scrollHeight;
}

function termGroup(label, quiet) {
  const body = $('tab-terminal');
  body.querySelector('.term-empty')?.remove();
  if (!quiet) for (const g of body.querySelectorAll('details.tgroup')) g.open = false;
  const status = h('span', { className: 'tg-status run' });
  const count = h('span', { className: 'count', textContent: '0' });
  const list = h('div', { className: 'tg-body' });
  const el = h('details', { className: quiet ? 'tgroup quiet' : 'tgroup', open: !quiet },
    h('summary', {}, status, h('span', { className: 'tg-label', textContent: label }), count), list);
  appendScrolling(body, el, !quiet);
  return { list, status, count, entries: new Map(), n: 0 };
}

function termStart(g, e) {
  const out = h('div', {});
  const entry = h('div', { className: 'tentry running' },
    h('div', { className: 'tcomment', textContent: `# ${e.why}` }),
    h('div', { className: 'tline' }, h('span', { className: 'tprompt', textContent: '$' }), h('span', { className: 'tcmd', textContent: e.cmd })),
    out);
  g.entries.set(e.id, { entry, out });
  g.n += 1;
  g.count.textContent = String(g.n);
  S.commands += 1;
  renderNav();
  appendScrolling(g.list, entry);
}

function termEnd(g, e) {
  const x = g.entries.get(e.id);
  if (!x) return;
  x.entry.classList.remove('running');
  if (!e.ok) x.entry.classList.add('failed');
  if (e.out) appendScrolling(x.out, outputBlock(e.out));
  if (!e.ok) appendScrolling(x.out, h('div', { className: 'texit', textContent: 'el comando terminó con error' }));
}

const OUTPUT_PREVIEW_LINES = 14;

function outputBlock(text) {
  const json = isJson(text);
  const lines = text.split('\n');
  const pre = h('pre', { className: 'tpre' });
  if (lines.length <= OUTPUT_PREVIEW_LINES) {
    pre.append(highlight(text, json));
    return pre;
  }
  pre.append(highlight(lines.slice(0, OUTPUT_PREVIEW_LINES).join('\n'), json));
  const more = h('button', { type: 'button', className: 'tmore', textContent: `… ${lines.length - OUTPUT_PREVIEW_LINES} líneas más` });
  more.onclick = () => {
    pre.replaceChildren(highlight(text, json));
    more.remove();
  };
  return h('div', {}, pre, more);
}

// ---- Syntax colors: JSON from bitcoin-cli, "key: value" lines and tables from zbtc ----

function isJson(text) {
  const t = text.trim();
  if (!t.startsWith('{') && !t.startsWith('[')) return false;
  try {
    JSON.parse(t);
    return true;
  } catch {
    return false;
  }
}

const tok = (kind, text) => h('span', { className: `tok-${kind}`, textContent: text });
const JSON_TOKEN = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([{}[\],])/g;
const KV_LINE = /^(\s*)([A-Za-z][\w ()/|.-]*?)(:)(?=\s|$)/;
const VALUE_TOKEN = /([0-9a-f]{16,})|(\b\d+(?:[.,]\d+)?\b)|(\b(?:spendable|candidate|spent|pending-spend|confirmed\(\d+\)))/g;

function highlight(text, json) {
  const frag = document.createDocumentFragment();
  if (json) {
    let last = 0;
    for (const m of text.matchAll(JSON_TOKEN)) {
      if (m.index > last) frag.append(text.slice(last, m.index));
      if (m[1] && m[2]) frag.append(tok('key', m[1]), tok('punct', m[2]));
      else if (m[1]) frag.append(tok(/^"[0-9a-f]{16,}"$/.test(m[1]) ? 'hex' : 'str', m[1]));
      else if (m[3]) frag.append(tok('num', m[3]));
      else if (m[4]) frag.append(tok('bool', m[4]));
      else frag.append(tok('punct', m[5]));
      last = m.index + m[0].length;
    }
    frag.append(text.slice(last));
    return frag;
  }
  text.split('\n').forEach((line, i) => {
    if (i) frag.append('\n');
    let rest = line;
    const kv = KV_LINE.exec(line);
    if (kv) {
      frag.append(kv[1], tok('key', kv[2]), tok('punct', kv[3]));
      rest = line.slice(kv[0].length);
    }
    frag.append(valueTokens(rest));
  });
  return frag;
}

/** Colors hex runs, numbers and note states inside a value. */
function valueTokens(text) {
  const frag = document.createDocumentFragment();
  let last = 0;
  for (const m of text.matchAll(VALUE_TOKEN)) {
    if (m.index > last) frag.append(text.slice(last, m.index));
    frag.append(tok(m[1] ? 'hex' : m[2] ? 'num' : 'str', m[0]));
    last = m.index + m[0].length;
  }
  frag.append(text.slice(last));
  return frag;
}

// ---- Server actions: each streams its commands into the terminal tab ----

/** Runs one action. Quiet calls (background reads) get a dimmed, folded group; hooks see each command. */
async function call(label, action, body, { quiet = false, onStart, onEnd } = {}) {
  const g = termGroup(label, quiet);
  let result = { ok: false, error: 'la respuesta del servidor se cortó' };
  try {
    const res = await fetch(`/api/${action}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}),
    });
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (value) buffer += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        const event = JSON.parse(line);
        if (event.type === 'start') {
          termStart(g, event);
          onStart?.(event);
        } else if (event.type === 'end') {
          termEnd(g, event);
          onEnd?.(event);
        } else if (event.type === 'done') {
          result = event;
        }
      }
      if (done) break;
    }
  } catch {
    result = { ok: false, error: 'el servidor de la demo no responde. ¿Sigue corriendo pnpm ui?' };
  }
  g.status.className = `tg-status ${result.ok ? 'ok' : 'bad'}`;
  return result;
}

/** Progress hooks that mirror an action's commands as plain-words steps. */
function progressHooks(steps, render) {
  return {
    onStart: (e) => {
      steps.push({ id: e.id, why: e.why, state: 'run' });
      render();
    },
    onEnd: (e) => {
      const step = steps.find((s) => s.id === e.id);
      if (step) step.state = e.ok ? 'done' : 'failed';
      render();
    },
  };
}

async function refresh() {
  const r = await call('estado: leer la red y las billeteras', 'state', {}, { quiet: true });
  S.chain = r.ok ? r.result : null;
  S.loaded = true;
}

/** After anything that changes the chain, cached explorer views are stale. */
function invalidateExplorer() {
  S.explorer.home = null;
  S.explorer.txs.clear();
  S.explorer.blocks.clear();
}

async function busy(label, fn) {
  if (S.busy) return;
  S.busy = label;
  S.progress = [];
  renderAll();
  try {
    await fn();
  } finally {
    S.busy = null;
    renderAll();
    reloadPanel();
  }
}

function toast(text, tone = 'good') {
  S.toast = { text, tone, at: Date.now() };
  renderToast();
  const at = S.toast.at;
  setTimeout(() => {
    if (S.toast?.at === at) {
      S.toast = null;
      renderToast();
    }
  }, 5000);
}

function createNetwork() {
  return busy('Creando la red', async () => {
    const r = await call('crear la red de prueba', 'reset', {}, progressHooks(S.progress, renderWallet));
    invalidateExplorer();
    S.explorer.opened.clear();
    S.explorer.decryptAs.clear();
    S.debug.txid = null;
    await refresh();
    if (r.ok) toast(`Red lista en el bloque ${S.chain?.height}. Alice tiene 100 ZBTC.`);
    else toast(`No se pudo crear la red: ${r.error}`, 'bad');
  });
}

function mine() {
  return busy('Minando un bloque', async () => {
    const r = await call('minar un bloque', 'mine');
    invalidateExplorer();
    await refresh();
    if (r.ok) toast(`Bloque ${S.chain?.height} minado: las transacciones pendientes quedaron confirmadas.`);
    else toast(`No se pudo minar: ${r.error}`, 'bad');
  });
}

// ---- Navbar ----

function renderNav() {
  const c = S.chain;
  $('accounts').replaceChildren(...PEOPLE.map((p) => {
    const b = h('button', { type: 'button', attrs: { role: 'radio', 'aria-checked': String(p === S.account) } },
      h('span', { className: `avatar ${p}`, textContent: cap(p)[0] }), cap(p));
    b.onclick = () => {
      S.account = p;
      renderAll();
    };
    return b;
  }));
  const pill = $('chain-pill');
  pill.classList.toggle('up', Boolean(c));
  pill.replaceChildren(h('span', { className: 'dot' }), h('span', { className: 'label', textContent: c ? `bloque ${c.height}` : 'sin red' }));
  const waiting = c?.mempool.length ?? 0;
  $('mine').disabled = Boolean(S.busy) || !c;
  $('mine').replaceChildren(icon('cube'), waiting ? `Minar bloque · ${waiting}` : 'Minar bloque');
  const toggle = $('panel-toggle');
  toggle.setAttribute('aria-expanded', String(S.panelOpen));
  toggle.classList.toggle('is-busy', Boolean(S.busy));
  toggle.replaceChildren(icon('terminal'), 'terminal', h('span', { className: 'count', textContent: String(S.commands) }), h('span', { className: 'live' }));
}

// ---- Wallet ----

function progressList(steps) {
  return h('ol', { className: 'progress' }, ...steps.map((s) => h('li', { className: s.state === 'run' ? '' : s.state },
    s.state === 'run' ? h('span', { className: 'spinner' }) : icon(s.state === 'done' ? 'check' : 'x'), s.why)));
}

function onboarding() {
  const creating = S.busy === 'Creando la red';
  return h('section', { className: 'onboard' },
    h('span', { className: 'logo', innerHTML: ICONS.logo }),
    h('h1', { textContent: 'Wallet ZBTC' }),
    h('p', { textContent: 'Una wallet protegida sobre Bitcoin. Para probarla, se crea una red Bitcoin local (regtest) con dos cuentas: Alice, que empieza con 100 ZBTC, y Bob.' }),
    creating
      ? progressList(S.progress)
      : h('button', { type: 'button', className: 'btn btn-primary btn-lg', textContent: 'Crear red de prueba', onclick: createNetwork, disabled: Boolean(S.busy) }));
}

function activityRows(person) {
  const entries = S.chain.activity.filter((e) => e.from === person || e.to === person).slice().reverse();
  return entries.map((e) => {
    const outgoing = e.from === person;
    const isPrivate = e.kind !== 'transparent';
    let title;
    let amount;
    let sub;
    if (e.kind === 'genesis') {
      title = 'Saldo inicial';
      amount = `+${zbtc(e.amount)}`;
      sub = 'génesis de la demo';
    } else if (e.kind === 'shielded') {
      title = outgoing ? `Enviado a ${cap(e.to)}` : 'Recibido';
      amount = outgoing ? `−${zbtc(e.amount)}` : `+${zbtc(sum((e.opened ?? []).map((o) => o.units)))}`;
      sub = outgoing ? `privado · ${timeAgo(e.time)}` : `privado · remitente oculto · ${timeAgo(e.time)}`;
    } else {
      title = outgoing ? `Enviado a ${cap(e.to)}` : 'Recibido';
      amount = `${outgoing ? '−' : '+'}${btc(Number(e.amount))}`;
      sub = outgoing ? `público · ${timeAgo(e.time)}` : `público · de ${shortAddr(e.senderAddresses?.[0])} · ${timeAgo(e.time)}`;
    }
    const status = e.kind === 'genesis' ? null : e.pending ? h('span', { className: 'tag amber', textContent: 'Pendiente' }) : h('span', { className: 'tag green', textContent: 'Confirmada' });
    const row = h('button', { type: 'button', className: 'row', disabled: !e.txid, title: e.txid ? 'Ver en el explorer' : '' },
      h('span', { className: `row-icon ${e.kind === 'genesis' ? 'gray' : isPrivate ? 'green' : 'red'}` }, icon(e.kind === 'genesis' ? 'spark' : isPrivate ? 'shield' : 'eye')),
      h('span', { className: 'row-main' }, h('span', { className: 'row-title', textContent: title }), h('span', { className: 'row-sub', textContent: sub })),
      h('span', { className: 'row-end' }, h('span', { className: `row-amount ${outgoing ? 'out' : 'in'}`, textContent: amount }), status));
    if (e.txid) row.onclick = () => openExplorer('tx', e.txid);
    return row;
  });
}

function renderWallet() {
  const main = $('main');
  if (!S.loaded) {
    return main.replaceChildren(h('div', { className: 'wallet' }, h('div', { className: 'skeleton-line tall' }), h('div', { className: 'skeleton-line' })));
  }
  if (!S.chain) return main.replaceChildren(h('div', { className: 'wallet' }, onboarding()));

  const w = wallet(S.account);
  const after = afterNextBlock(w);
  const waiting = S.chain.mempool.length;
  const sendBtn = h('button', { type: 'button', className: 'btn btn-primary btn-lg', disabled: Boolean(S.busy) }, icon('up'), 'Enviar');
  sendBtn.onclick = openSend;
  const receiveBtn = h('button', { type: 'button', className: 'btn btn-lg', disabled: Boolean(S.busy) }, icon('down'), 'Recibir');
  receiveBtn.onclick = openReceive;
  const rows = activityRows(S.account);
  const transfersMade = S.chain.activity.some((e) => e.kind !== 'genesis');

  main.replaceChildren(h('div', { className: 'wallet' },
    h('section', { className: 'hero' },
      h('div', { className: 'hero-label' }, icon('shield'), `Saldo protegido · ${cap(S.account)}`),
      h('div', { className: 'balance' },
        h('span', { className: 'amount', textContent: String(after) }),
        h('span', { className: 'unit', textContent: 'ZBTC' }),
        h('span', { className: 'info', tabIndex: 0, textContent: '?', attrs: { 'data-tip': UNITS_TIP, 'aria-label': UNITS_TIP } })),
      h('p', { className: 'hero-sub', textContent: w.spendable === after ? 'Todo disponible para enviar' : `${zbtc(w.spendable)} disponibles ahora · el resto se confirma con el próximo bloque` }),
      h('div', { className: 'hero-actions' }, sendBtn, receiveBtn)),
    waiting ? h('div', { className: 'banner' },
      h('span', { textContent: `${waiting} ${waiting === 1 ? 'transacción espera' : 'transacciones esperan'} un bloque para confirmarse.` }),
      h('button', { type: 'button', className: 'btn btn-sm', textContent: 'Minar bloque', onclick: mine, disabled: Boolean(S.busy) })) : null,
    h('section', { className: 'cards' },
      h('div', { className: 'card' },
        h('div', { className: 'card-head' }, h('span', { className: 'who' }, icon('shield'), 'ZBTC protegido'), h('span', { className: 'tag green' }, 'privado')),
        h('div', { className: 'card-value', textContent: zbtc(after) }),
        h('div', { className: 'card-sub', textContent: `Notas que solo abre la clave de ${cap(S.account)}.` })),
      h('div', { className: 'card' },
        h('div', { className: 'card-head' }, h('span', { className: 'who' }, icon('eye'), 'Bitcoin · comisiones'), h('span', { className: 'tag red' }, 'público')),
        h('div', { className: 'card-value', textContent: btc(w.fee.confirmed + w.fee.unconfirmed) }),
        h('div', { className: 'card-sub', textContent: w.fee.unconfirmed ? `${btc(w.fee.unconfirmed)} sin confirmar. Cualquiera ve sus movimientos.` : 'Paga las comisiones de red. Cualquiera ve sus movimientos.' }))),
    h('section', {},
      h('div', { className: 'section-title' }, h('h2', { textContent: 'Actividad' })),
      rows.length ? h('div', { className: 'list' }, ...rows) : null,
      transfersMade ? null : h('p', { className: 'empty', textContent: 'Para empezar: enviar ZBTC a la otra cuenta en modo privado y BTC en modo público, y comparar las dos transacciones en el explorer del panel.' }))));
}

// ---- Send dialog ----

function openSend() {
  S.send = { to: other(S.account), mode: 'private', amounts: { private: '17', public: '0,3' }, phase: 'form', steps: [], entry: null, error: null };
  renderSend();
  $('send-dialog').showModal();
}

function sendCheck() {
  const { mode, amounts } = S.send;
  const w = wallet(S.account);
  if (!w) return { ok: false, hint: 'No hay red.' };
  const v = mode === 'private' ? amounts.private.trim() : decimal(amounts.public);
  if (mode === 'private') {
    if (w.spendable === 0) return { ok: false, hint: afterNextBlock(w) ? 'No hay ZBTC disponible todavía: hay que minar un bloque para confirmar.' : 'Esta cuenta no tiene ZBTC.', mine: afterNextBlock(w) > 0 };
    if (!/^[1-9][0-9]*$/.test(v)) return { ok: false, bad: true, hint: 'El monto debe ser un número entero de ZBTC.' };
    if (Number(v) > w.spendable) return { ok: false, bad: true, hint: `Disponible: ${zbtc(w.spendable)}.` };
    return { ok: true, hint: `Disponible: ${zbtc(w.spendable)}. Armar la prueba tarda unos segundos.` };
  }
  if (!/^[0-9]+(\.[0-9]{1,8})?$/.test(v) || Number(v) <= 0 || Number(v) > MAX_PAYMENT_BTC) {
    return { ok: false, bad: true, hint: `Entre 0 y ${String(MAX_PAYMENT_BTC).replace('.', ',')} BTC, con 8 decimales como máximo.` };
  }
  return { ok: true, hint: `Saldo: ${btc(w.fee.confirmed + w.fee.unconfirmed)}, más una pequeña comisión de red.` };
}

/** What the network will see, row by row, for the chosen mode. */
function previewRows(mode) {
  const to = cap(S.send.to);
  return mode === 'private'
    ? [['Quién envía', 'amber', 'Vinculado: la comisión sale de tu fee wallet'], ['Quién recibe', 'green', 'Oculto'], ['Monto', 'green', 'Oculto']]
    : [['Quién envía', 'red', 'Visible: tu dirección'], ['Quién recibe', 'red', `Visible: la dirección de ${to}`], ['Monto', 'red', 'Visible']];
}

function renderSend() {
  const d = $('send-dialog');
  const s = S.send;
  if (!s) return;
  const close = h('button', { type: 'button', className: 'icon-btn', attrs: { 'aria-label': 'Cerrar' }, disabled: s.phase === 'sending' }, icon('x'));
  close.onclick = () => d.close();
  const head = h('div', { className: 'sheet-head' }, h('h2', { textContent: `Enviar desde ${cap(S.account)}` }), close);

  if (s.phase === 'sending') {
    return d.replaceChildren(head, h('div', { className: 'sheet-body' },
      h('p', { className: 'muted', textContent: s.mode === 'private' ? 'Armando la prueba de conocimiento cero y difundiendo la transacción…' : 'Firmando y difundiendo la transacción…' }),
      progressList(s.steps)));
  }
  if (s.phase === 'done' || s.phase === 'error') {
    const ok = s.phase === 'done';
    const view = h('button', { type: 'button', className: 'btn', textContent: 'Ver en el explorer' });
    view.onclick = () => {
      d.close();
      openExplorer('tx', s.entry.txid);
    };
    const done = h('button', { type: 'button', className: 'btn btn-primary', textContent: ok ? 'Listo' : 'Cerrar' });
    done.onclick = () => d.close();
    return d.replaceChildren(head,
      h('div', { className: 'sheet-body' }, h('div', { className: 'result' },
        h('span', { className: `big-icon${ok ? '' : ' bad'}` }, icon(ok ? 'check' : 'x')),
        h('h3', { textContent: ok ? 'Enviado' : 'No se pudo enviar' }),
        h('p', { className: 'muted', textContent: ok ? 'Queda pendiente hasta el próximo bloque.' : s.error }))),
      h('div', { className: 'sheet-foot' }, ok ? view : null, done));
  }

  const modeButton = (mode, title, sub, iconName) => {
    const b = h('button', { type: 'button', className: `mode ${mode}`, attrs: { role: 'radio', 'aria-checked': String(s.mode === mode) } },
      h('span', { className: 'mode-title' }, icon(iconName), title), h('span', { className: 'mode-sub', textContent: sub }));
    b.onclick = () => {
      s.mode = mode;
      renderSend();
    };
    return b;
  };
  const to = h('select', {}, ...PEOPLE.filter((p) => p !== S.account).map((p) => h('option', { value: p, textContent: cap(p) })));
  to.value = s.to;
  to.addEventListener('input', () => {
    s.to = to.value;
    renderSend();
  });
  const amount = h('input', { value: s.amounts[s.mode], inputMode: s.mode === 'private' ? 'numeric' : 'decimal', autocomplete: 'off', attrs: { 'aria-label': 'Monto' } });
  amount.addEventListener('input', () => {
    s.amounts[s.mode] = amount.value;
    updateSend();
  });
  const submit = h('button', { type: 'button', className: 'btn btn-primary', id: 'send-submit' });
  submit.onclick = submitSend;
  const cancel = h('button', { type: 'button', className: 'btn', textContent: 'Cancelar' });
  cancel.onclick = () => d.close();

  d.replaceChildren(head,
    h('div', { className: 'sheet-body' },
      h('div', { className: 'field' }, h('label', { textContent: 'Para' }), h('div', { className: 'input-wrap' }, to)),
      h('div', { className: 'field' }, h('span', { className: 'label', textContent: 'Modo' }),
        h('div', { className: 'modes', attrs: { role: 'radiogroup', 'aria-label': 'Modo' } },
          modeButton('private', 'Privado', 'ZBTC protegido', 'shield'),
          modeButton('public', 'Público', 'Bitcoin transparente', 'eye'))),
      h('div', { className: 'field' }, h('label', { textContent: 'Monto' }),
        h('div', { className: 'input-wrap', id: 'send-amount' }, amount, h('span', { className: 'suffix', textContent: s.mode === 'private' ? 'ZBTC' : 'BTC' })),
        h('p', { className: 'field-hint', id: 'send-hint' })),
      h('div', { className: 'preview' },
        h('div', { className: 'preview-head', textContent: 'Lo que verá cualquiera en la red' }),
        ...previewRows(s.mode).map(([what, tone, text]) => h('div', { className: 'preview-row' }, h('span', { className: 'what', textContent: what }), h('span', { className: `tag ${tone}`, textContent: text })))),
      h('div', { id: 'send-mine' })),
    h('div', { className: 'sheet-foot' }, cancel, submit));
  updateSend();
}

/** Updates hint, button and amount state without rebuilding the form, so the input keeps focus. */
function updateSend() {
  const s = S.send;
  const r = sendCheck();
  const hint = $('send-hint');
  if (!hint) return;
  hint.textContent = r.hint;
  hint.className = r.bad ? 'field-hint bad' : 'field-hint';
  $('send-amount').classList.toggle('bad', Boolean(r.bad));
  const submit = $('send-submit');
  submit.disabled = !r.ok || Boolean(S.busy);
  const value = s.mode === 'private' ? zbtc(s.amounts.private.trim() || '0') : `${s.amounts.public.trim() || '0'} BTC`;
  submit.textContent = `Enviar ${value} ${s.mode === 'private' ? 'en privado' : 'en público'}`;
  $('send-mine').replaceChildren(r.mine ? h('button', { type: 'button', className: 'btn btn-sm', textContent: 'Minar bloque ahora', onclick: async () => { await mine(); renderSend(); } }) : '');
}

async function submitSend() {
  const s = S.send;
  if (!sendCheck().ok) return;
  const from = S.account;
  const amount = s.mode === 'private' ? s.amounts.private.trim() : decimal(s.amounts.public);
  s.phase = 'sending';
  s.steps = [];
  renderSend();
  await busy('Enviando', async () => {
    const label = s.mode === 'private' ? `enviar ${amount} ZBTC en privado: ${from} → ${s.to}` : `enviar ${amount} BTC en público: ${from} → ${s.to}`;
    const r = await call(label, s.mode === 'private' ? 'shielded' : 'transparent', { from, to: s.to, amount }, progressHooks(s.steps, renderSend));
    if (r.ok) {
      s.phase = 'done';
      s.entry = r.result;
    } else {
      s.phase = 'error';
      s.error = r.error;
      setPanelOpen(true);
      showTab('terminal');
    }
    invalidateExplorer();
    await refresh();
  });
  renderSend();
}

// ---- Receive dialog ----

async function openReceive() {
  S.receive = { mode: 'private', data: null, copied: null };
  renderReceive();
  $('receive-dialog').showModal();
  const person = S.account;
  const r = await call(`direcciones de ${person}`, 'address', { person }, { quiet: true });
  if (S.receive && r.ok && r.result.person === S.account) {
    S.receive.data = r.result;
    renderReceive();
  }
}

function renderReceive() {
  const d = $('receive-dialog');
  const s = S.receive;
  if (!s) return;
  const close = h('button', { type: 'button', className: 'icon-btn', attrs: { 'aria-label': 'Cerrar' } }, icon('x'));
  close.onclick = () => d.close();
  const tab = (mode, label, iconName) => {
    const b = h('button', { type: 'button', attrs: { role: 'radio', 'aria-checked': String(s.mode === mode) } }, icon(iconName), label);
    b.onclick = () => {
      s.mode = mode;
      s.copied = null;
      renderReceive();
    };
    return b;
  };
  const address = s.data ? (s.mode === 'private' ? s.data.shielded : s.data.transparent) : null;
  const copy = h('button', { type: 'button', className: 'btn btn-sm', disabled: !address }, icon(s.copied ? 'check' : 'copy'), s.copied ? 'Copiada' : 'Copiar');
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(address);
      s.copied = true;
    } catch {
      s.copied = null;
    }
    renderReceive();
  };
  d.replaceChildren(
    h('div', { className: 'sheet-head' }, h('h2', { textContent: `Recibir en ${cap(S.account)}` }), close),
    h('div', { className: 'sheet-body' },
      h('div', { className: 'tabs-pill', attrs: { role: 'radiogroup', 'aria-label': 'Tipo de dirección' } }, tab('private', 'Privada · ZBTC', 'shield'), tab('public', 'Pública · BTC', 'eye')),
      h('div', { className: 'address' },
        address ? h('code', { textContent: address }) : h('div', { className: 'skeleton-line' }),
        h('div', {}, copy)),
      h('p', { className: 'field-hint', textContent: s.mode === 'private'
        ? 'Dirección protegida: quien te paga a esta dirección no deja en la cadena ni tu dirección ni el monto.'
        : 'Dirección Bitcoin común: cada pago a esta dirección queda a la vista de cualquiera.' })));
}

// ---- Side panel frame ----

function renderPanelFrame() {
  const panel = $('panel');
  panel.classList.toggle('open', S.panelOpen);
  panel.classList.toggle('max', S.panelOpen && S.panelMax);
  panel.classList.toggle('is-busy', Boolean(S.busy));
  for (const b of document.querySelectorAll('#panel .tabs [role="tab"]')) b.setAttribute('aria-selected', String(b.dataset.tab === S.tab));
  for (const name of ['terminal', 'explorer', 'debug']) $(`tab-${name}`).hidden = name !== S.tab;
  $('panel-max').textContent = S.panelMax ? 'restaurar' : 'maximizar';
  renderNav();
}

function showTab(name) {
  S.tab = name;
  renderPanelFrame();
  reloadPanel();
}

function openExplorer(view, ref) {
  S.explorer.view = view;
  S.explorer.ref = ref;
  S.panelOpen = true;
  showTab('explorer');
}

/** Loads whatever the visible tab needs, then draws it. */
async function reloadPanel() {
  if (!S.panelOpen) return;
  if (S.tab === 'explorer') {
    renderExplorer();
    await loadExplorer();
    renderExplorer();
  } else if (S.tab === 'debug') {
    renderDebug();
    await loadDebug();
    renderDebug();
  }
}

// ---- Terminal-styled documents (explorer and debug) ----

const doc = (...children) => h('div', { className: 'tdoc' }, ...children);
const th = (text, sub = false) => h('div', { className: sub ? 'th sub' : 'th', textContent: text });
const comment = (text) => h('div', { className: 'tl tc', textContent: `# ${text}` });
const gap = () => h('div', { className: 'gap' });
const loading = (text) => h('div', { className: 'loading' }, h('span', { className: 'spinner' }), text);

/** A "key: value" line; value can be a string (colored by its content), a node, or [text, colorClass]. */
function kv(key, value, note) {
  let v;
  if (value instanceof Node) v = value;
  else if (Array.isArray(value)) v = tok(value[1], value[0]);
  else v = valueTokens(String(value));
  return h('div', { className: 'tl' }, tok('key', key), tok('punct', ': '), v, note ? tok('dim', `  # ${note}`) : null);
}

const tlink = (text, onclick) => h('button', { type: 'button', className: 'tlink', textContent: text, onclick });
const KIND_LABEL = { zbtc: ['zbtc', 'green'], transparent: ['transparente', 'red'], coinbase: ['coinbase', 'dim'] };

// ---- Explorer tab ----

/** The fetch the current explorer view still needs, or null when it has its data. */
function missingExplorerData() {
  const ex = S.explorer;
  const { view, ref } = ex;
  if (view === 'home' && !ex.home) {
    return async () => {
      const r = await call('explorer: últimos bloques y mempool', 'blocks', {}, { quiet: true });
      ex.home = r.ok ? r.result : { error: r.error };
    };
  }
  if (view === 'tx' && !ex.txs.has(ref)) {
    return async () => {
      const r = await call(`explorer: transacción ${shortHex(ref)}`, 'tx', { txid: ref }, { quiet: true });
      ex.txs.set(ref, r.ok ? r.result : { error: r.error });
    };
  }
  if (view === 'block' && !ex.blocks.has(ref)) {
    return async () => {
      const r = await call(`explorer: bloque ${shortHex(String(ref))}`, 'block', { ref: String(ref) }, { quiet: true });
      ex.blocks.set(ref, r.ok ? r.result : { error: r.error });
    };
  }
  return null;
}

/** Fetches until the view on screen has its data; a view changed mid-fetch is fetched next. */
async function loadExplorer() {
  const ex = S.explorer;
  if (!S.chain || ex.loading) return;
  ex.loading = true;
  try {
    for (let fetch = missingExplorerData(); fetch; fetch = missingExplorerData()) {
      await fetch();
      renderExplorer();
    }
  } finally {
    ex.loading = false;
  }
}

function explorerNav(view, ref) {
  S.explorer.view = view;
  S.explorer.ref = ref;
  reloadPanel();
}

function searchBox() {
  const input = h('input', { placeholder: 'txid o altura de bloque', attrs: { 'aria-label': 'Buscar en el explorer', spellcheck: 'false' } });
  const go = () => {
    const q = input.value.trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(q)) explorerNav('tx', q);
    else if (/^\d+$/.test(q)) explorerNav('block', q);
    else input.value = '';
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') go();
  });
  return h('div', { className: 'tsearch' }, tok('green', 'explorer>'), input);
}

function txRow(t, blockLabel) {
  const [label, color] = KIND_LABEL[t.kind];
  const amount = t.kind === 'zbtc' ? tok('green', 'monto oculto') : h('span', {}, tok('dim', 'salidas '), tok('num', btc(t.btcOut)));
  const b = h('button', { type: 'button', className: 'trow' }, tok(color, label), h('span', {}, tok('hex', shortHex(t.txid)), tok('dim', `  ${t.vsize} vB${blockLabel ? `  ${blockLabel}` : ''}`)), amount);
  b.onclick = () => explorerNav('tx', t.txid);
  return b;
}

function renderExplorerHome(home) {
  const recentTxs = home.blocks.flatMap((b) => b.txs.filter((t) => t.kind !== 'coinbase').map((t) => ({ ...t, height: b.height })));
  return doc(
    searchBox(),
    comment('Lo que ve cualquiera: bloques, transacciones y direcciones. Nadie ve las billeteras.'),
    th(`mempool (${home.mempool.length})`),
    home.mempool.length ? h('div', {}, ...home.mempool.map((t) => txRow(t, 'sin confirmar'))) : comment('vacía: no hay transacciones esperando'),
    th('transacciones recientes'),
    recentTxs.length ? h('div', {}, ...recentTxs.map((t) => txRow(t, `#${t.height}`))) : comment('todavía no hay transferencias en los últimos bloques'),
    th('bloques'),
    h('div', {}, ...home.blocks.map((b) => {
      const kinds = ['zbtc', 'transparent'].map((k) => [k, b.txs.filter((t) => t.kind === k).length]).filter(([, n]) => n);
      const row = h('button', { type: 'button', className: 'trow block' },
        tok('num', `#${b.height}`),
        h('span', {}, tok('hex', shortHex(b.hash)), tok('dim', `  ${timeAgo(b.time * 1000)}`)),
        h('span', {}, tok('dim', `${b.txs.length} tx`), ...kinds.map(([k, n]) => tok(KIND_LABEL[k][1], `  ${n} ${KIND_LABEL[k][0]}`))));
      row.onclick = () => explorerNav('block', b.hash);
      return row;
    })));
}

// ---- Sankey charts (Apache ECharts); band width follows the amount ----

/** Amounts below this share of the total still get a visible band; labels and tooltips keep the real amount. */
const MIN_BAND_SHARE = 0.04;
/** Room for the labels left and right of the chart, as a share of its width, within these bounds. */
const LABEL_SHARE = 0.25;
const LABEL_MIN_PX = 110;
const LABEL_MAX_PX = 220;
/** Average width of one Geist Mono character at the label sizes, for cutting labels to fit. */
const LABEL_CHAR_PX = 6.8;
const TONE_VARS = { exposed: '--red', linked: '--amber', hidden: '--green', opened: '--blue', neutral: '--gray' };
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/** Inputs -> one middle node -> outputs; each box holds its label (title, value, detail), tone and real `amount`. */
function sankeyModel(inputs, middle, outputs) {
  const total = Math.max(sum(inputs.map((b) => b.amount)), sum(outputs.map((b) => b.amount)));
  const band = (amount) => Math.max(amount, total * MIN_BAND_SHARE);
  return {
    nodes: [
      ...inputs.map((box, i) => ({ name: `in${i}`, box, side: 'in' })),
      { name: 'mid', box: middle, side: 'mid' },
      ...outputs.map((box, i) => ({ name: `out${i}`, box, side: 'out' })),
    ],
    links: [
      ...inputs.map((b, i) => ({ source: `in${i}`, target: 'mid', value: band(b.amount), text: b.flow ?? b.value, color: 'source' })),
      ...outputs.map((b, i) => ({ source: 'mid', target: `out${i}`, value: band(b.amount), text: b.flow ?? b.value, color: 'target' })),
    ],
  };
}

const feeOf = (tx) => sum(tx.inputs.map((i) => i.btc)) - sum(tx.outputs.map((o) => o.btc));

/**
 * Who the demo knows an address belongs to; the network itself sees only addresses. Inputs of a
 * transfer made here come from the sender's fee wallet; outputs are the payment or the change.
 */
function addressOwner(detail, side, address) {
  const e = detail.entry;
  if (!e || !address) return null;
  if (side === 'in') return `fee wallet de ${cap(e.from)}`;
  return e.kind === 'transparent' && address === e.recipientAddress ? `pago a ${cap(e.to)}` : `vuelto a ${cap(e.from)}`;
}

function outerModel(detail) {
  const { tx, envelope } = detail;
  const tone = tx.kind === 'zbtc' ? 'linked' : 'exposed';
  const fee = feeOf(tx);
  return sankeyModel(
    tx.inputs.map((i, n) => ({ tone, title: addressOwner(detail, 'in', i.address) ?? `entrada ${n + 1}`, value: btc(i.btc), detail: shortAddr(i.address), full: i.address, amount: i.btc })),
    { tone: 'neutral', title: `tx ${shortHex(tx.txid)}`, value: `${tx.vsize} vB`, full: tx.txid },
    [
      ...tx.outputs.map((o, n) => (envelope && n === envelope.vout
        ? { tone: 'hidden', title: 'OP_RETURN · sobre zbtc', value: `0 BTC · ${envelope.hex.length / 2} B`, detail: 'monto y destino cifrados', amount: 0 }
        : { tone, title: addressOwner(detail, 'out', o.address) ?? `salida ${n + 1}`, value: btc(o.btc), detail: shortAddr(o.address), full: o.address, amount: o.btc })),
      ...(tx.kind === 'coinbase' ? [] : [{ tone: 'neutral', title: 'comisión de red', value: btc(fee), detail: 'para el minero', amount: fee }]),
    ]);
}

/** The value transfer inside the envelope: spent notes (nullifiers) -> proof -> new notes (commitments). */
function innerModel(detail, person, opened) {
  const { envelope } = detail;
  const confirmed = Boolean(detail.block);
  return sankeyModel(
    envelope.nullifiers.map((nf, i) => ({ tone: 'hidden', title: `nullifier ${i + 1}`, value: 'nota gastada: no dice cuál', detail: shortHex(nf), full: nf, amount: 1, flow: 'monto oculto' })),
    { tone: 'neutral', title: 'prueba zk · groth16', value: confirmed ? 'verificada por el replay' : 'se verifica al confirmarse', full: '256 bytes' },
    envelope.commitments.map((cm, i) => {
      const mine = person && opened ? opened.find((o) => o.index === i) : null;
      if (mine) return { tone: 'opened', title: `nota para ${cap(person)}`, value: zbtc(mine.units), detail: `abierta con la clave de ${cap(person)}`, amount: 1, flow: `${zbtc(mine.units)}, visible solo para ${cap(person)}` };
      return { tone: 'hidden', title: `nota nueva ${i + 1}`, value: person ? `cerrada para ${cap(person)}` : 'cerrada', detail: shortHex(cm), full: cm, amount: 1, flow: 'monto oculto' };
    }));
}

function nodeTooltip(b) {
  const lines = [`<b>${escapeHtml(b.title)}</b>`, escapeHtml(b.value)];
  const extra = b.full ?? b.detail;
  if (extra) lines.push(`<span style="opacity:.75;word-break:break-all">${escapeHtml(extra)}</span>`);
  return lines.join('<br>');
}

function edgeTooltip(link, model) {
  const titleOf = (name) => model.nodes.find((n) => n.name === name).box.title;
  return `${escapeHtml(titleOf(link.source))} → ${escapeHtml(titleOf(link.target))}<br><b>${escapeHtml(link.text)}</b>`;
}

/** Left and right margins for labels, from the chart's width. */
function labelRoom(width) {
  return Math.round(Math.min(LABEL_MAX_PX, Math.max(LABEL_MIN_PX, width * LABEL_SHARE)));
}

function fit(text, chars) {
  return text.length > chars ? `${text.slice(0, chars - 1)}…` : text;
}

function sankeyOption(model, room) {
  const color = (tone) => cssVar(TONE_VARS[tone] ?? '--gray');
  const mono = cssVar('--mono');
  const chars = Math.floor((room - 14) / LABEL_CHAR_PX);
  const rich = {
    v: { fontSize: 12, fontWeight: 600, color: cssVar('--term-text'), lineHeight: 17, fontFamily: mono },
    d: { fontSize: 11, color: cssVar('--term-dim'), lineHeight: 15, fontFamily: mono },
  };
  for (const tone of Object.keys(TONE_VARS)) rich[`t_${tone}`] = { fontSize: 11, color: color(tone), lineHeight: 16, fontFamily: mono };
  const position = { in: 'left', mid: 'top', out: 'right' };
  return {
    animationDuration: 700,
    animationDurationUpdate: 500,
    textStyle: { fontFamily: mono },
    tooltip: {
      trigger: 'item',
      confine: true,
      borderWidth: 1,
      borderColor: cssVar('--border-strong'),
      padding: [8, 10],
      backgroundColor: cssVar('--bg-soft'),
      textStyle: { color: cssVar('--text'), fontSize: 12, fontFamily: mono },
      extraCssText: 'max-width: 320px; white-space: normal; border-radius: 8px;',
      formatter: (p) => (p.dataType === 'edge' ? edgeTooltip(p.data, model) : nodeTooltip(p.data.box)),
    },
    series: [{
      type: 'sankey',
      left: room,
      right: room,
      top: 50,
      bottom: 40,
      nodeWidth: 12,
      nodeGap: 50,
      nodeAlign: 'justify',
      layoutIterations: 0,
      draggable: false,
      emphasis: { focus: 'adjacency', lineStyle: { opacity: 0.6 } },
      lineStyle: { curveness: 0.5, opacity: 0.32 },
      label: {
        rich,
        formatter: (p) => {
          const b = p.data.box;
          // The middle node's label sits above it, with the whole chart's width to use.
          const cut = (s) => (p.data.name === 'mid' ? s : fit(s, chars));
          return [`{t_${b.tone}|${cut(b.title)}}`, `{v|${cut(b.value)}}`, b.detail ? `{d|${cut(b.detail)}}` : null].filter(Boolean).join('\n');
        },
      },
      data: model.nodes.map((n) => ({ name: n.name, box: n.box, itemStyle: { color: color(n.box.tone) }, label: { position: position[n.side] } })),
      links: model.links.map((l) => ({ source: l.source, target: l.target, value: l.value, text: l.text, lineStyle: { color: l.color } })),
    }],
  };
}

function describeModel(model) {
  const list = (side) => model.nodes.filter((n) => n.side === side).map((n) => `${n.box.title}: ${n.box.value}`).join('; ');
  return `Entradas: ${list('in')}. ${model.nodes.find((n) => n.side === 'mid').box.title}. Salidas: ${list('out')}.`;
}

// Chart hosts live across renders: moving a host keeps its ECharts instance.
const chartHost = (key) => h('div', { className: 'chart', attrs: { 'data-chart': key, role: 'img' } });
const HOSTS = { outer: chartHost('outer'), inner: chartHost('inner') };
const charts = new Map();
/** The model and layout each chart last drew, so unchanged charts only resize. */
const drawn = new Map();

const resizer = new ResizeObserver((entries) => {
  for (const entry of entries) {
    const key = entry.target.dataset.chart;
    const last = drawn.get(key);
    if (!last || entry.contentRect.width === 0) continue;
    if (last.room !== labelRoom(entry.contentRect.width)) drawSankey(key, last.model);
    else charts.get(key)?.resize();
  }
});

/** Draws or updates one Sankey; call it after its host is in the page, so the host has a size. */
function drawSankey(key, model) {
  const host = HOSTS[key];
  host.setAttribute('aria-label', describeModel(model));
  if (!window.echarts) {
    host.classList.add('offline');
    host.replaceChildren(comment('no se pudo cargar ECharts: el diagrama necesita conexión a internet'));
    return;
  }
  let chart = charts.get(key);
  if (!chart) {
    chart = window.echarts.init(host, null, { renderer: 'svg' });
    charts.set(key, chart);
    resizer.observe(host);
  }
  const room = labelRoom(host.clientWidth);
  const signature = JSON.stringify([model, room]);
  chart.resize();
  if (drawn.get(key)?.signature === signature) return;
  drawn.set(key, { signature, room, model });
  // Replace, not merge: options a previous layout set must not leak into this one.
  chart.setOption(sankeyOption(model, room), { notMerge: true });
}

// ---- Explorer: one transaction ----

async function decryptWith(txid, person) {
  const ex = S.explorer;
  ex.decryptAs.set(txid, person);
  renderExplorer();
  const key = `${txid}:${person}`;
  if (!person || ex.opened.has(key)) return;
  const r = await call(`explorer: descifrar con la clave de ${person}`, 'decrypt', { txid, person });
  if (r.ok) ex.opened.set(key, r.result.opened);
  renderExplorer();
}

/** What anyone learns from the transaction, as tone-colored "key: value" lines. */
function privacyLines(detail) {
  const { tx } = detail;
  const addresses = (list) => [...new Set(list.map((x) => x.address).filter(Boolean))].map(shortAddr).join(', ');
  if (tx.kind === 'zbtc') {
    return [
      kv('remitente', ['vinculado', 'amber'], `la comisión sale de ${addresses(tx.inputs)}`),
      kv('destinatario', ['oculto', 'green'], 'no hay ninguna dirección de destino'),
      kv('monto', ['oculto', 'green'], 'viaja cifrado en el OP_RETURN'),
      kv('validez', ['verificable', 'blue'], 'cualquiera verifica la prueba zk sin abrirla'),
    ];
  }
  if (tx.kind === 'coinbase') return [comment('coinbase: la recompensa del minero, sin remitente')];
  return [
    kv('remitente', ['visible', 'red'], addresses(tx.inputs)),
    kv('destinatario', ['visible', 'red'], `una de: ${addresses(tx.outputs)}`),
    kv('monto', ['visible', 'red'], tx.outputs.map((o) => btc(o.btc)).join(' + ')),
    kv('validez', ['verificable', 'blue'], 'cada nodo verifica firmas y montos'),
  ];
}

function renderExplorerTx(detail) {
  const { tx, block, envelope } = detail;
  const [label, color] = KIND_LABEL[tx.kind];
  const back = tlink('← explorer', () => explorerNav('home', null));
  const parts = [
    h('div', { className: 'tl' }, back),
    th('transacción'),
    kv('txid', tx.txid),
    kv('tipo', [tx.kind === 'zbtc' ? 'zbtc · protegida (shielded)' : label, color]),
    kv('estado', block ? [`confirmada · ${block.confirmations} ${block.confirmations === 1 ? 'confirmación' : 'confirmaciones'}`, 'green'] : ['en la mempool', 'amber']),
    kv('tamaño', `${tx.vsize} vB`),
    tx.kind === 'coinbase' ? null : kv('comisión', btc(feeOf(tx))),
    th('flujo'),
    comment('el ancho de cada banda sigue al monto; la comisión y el OP_RETURN tienen un ancho mínimo para que se vean'),
    detail.entry ? comment('las etiquetas con nombres las agrega la demo: la red solo ve direcciones') : null,
    HOSTS.outer,
    th('qué puede saber cualquiera'),
    ...privacyLines(detail),
    th('entradas'),
    ...tx.inputs.map((i, n) => kv(String(n + 1), i.address ? `${btc(i.btc)}  ${i.address}` : 'coinbase (moneda nueva)', addressOwner(detail, 'in', i.address))),
    th('salidas'),
    ...tx.outputs.map((o, n) => kv(String(n + 1), envelope && n === envelope.vout ? `${btc(o.btc)}  OP_RETURN · ${o.data.length / 2} bytes` : `${btc(o.btc)}  ${o.address ?? o.type}`,
      envelope && n === envelope.vout ? 'sobre zbtc cifrado' : addressOwner(detail, 'out', o.address))),
  ];

  let innerArgs = null;
  if (envelope) {
    const person = S.explorer.decryptAs.get(tx.txid) ?? null;
    const opened = person ? S.explorer.opened.get(`${tx.txid}:${person}`) : null;
    const keyButton = (p, text) => {
      const b = h('button', { type: 'button', className: 'tbtn', textContent: text, attrs: { 'aria-pressed': String(person === p) } });
      b.onclick = () => decryptWith(tx.txid, p);
      return b;
    };
    parts.push(
      th('dentro del OP_RETURN'),
      comment('2 nullifiers gastan notas sin decir cuáles; 2 commitments crean las notas nuevas, cerradas; la prueba zk garantiza que entradas y salidas suman lo mismo'),
      h('div', { className: 'tl' }, tok('key', 'descifrar con la clave de'), tok('punct', ': '), keyButton(null, 'nadie'), ' ', ...PEOPLE.flatMap((p) => [keyButton(p, p), ' '])),
      person && !opened ? loading(`probando la clave de ${person}…`) : null,
      person && opened ? comment(opened.length ? `la clave de ${person} abre ${opened.length === 1 ? 'una nota' : `${opened.length} notas`}; la otra sigue cerrada` : `la clave de ${person} no abre ninguna nota`) : null,
      HOSTS.inner,
      h('div', { className: 'tl' }, tlink('→ debug: ver los 572 bytes del sobre', () => {
        S.debug.txid = tx.txid;
        showTab('debug');
      })));
    innerArgs = [detail, person, opened];
  }
  if (block) {
    parts.push(
      th('bloque'),
      kv('altura', tlink(`#${block.height}`, () => explorerNav('block', block.hash))),
      kv('hash', block.hash),
      kv('hora', `${new Date(block.time * 1000).toLocaleString('es')}`, timeAgo(block.time * 1000)),
      kv('confirmaciones', String(block.confirmations)));
  }
  $('tab-explorer').replaceChildren(doc(...parts));
  drawSankey('outer', outerModel(detail));
  if (innerArgs) drawSankey('inner', innerModel(...innerArgs));
}

function renderExplorerBlock(b) {
  $('tab-explorer').replaceChildren(doc(
    h('div', { className: 'tl' }, tlink('← explorer', () => explorerNav('home', null))),
    th(`bloque #${b.height}`),
    kv('hash', b.hash),
    kv('anterior', b.previous ? tlink(shortHex(b.previous), () => explorerNav('block', b.previous)) : ['génesis', 'dim']),
    kv('siguiente', b.next ? tlink(shortHex(b.next), () => explorerNav('block', b.next)) : ['todavía no hay', 'dim']),
    kv('hora', new Date(b.time * 1000).toLocaleString('es'), timeAgo(b.time * 1000)),
    kv('tamaño', `${b.size} bytes`),
    kv('confirmaciones', String(b.confirmations)),
    th(`transacciones (${b.txs.length})`),
    h('div', {}, ...b.txs.map((t) => txRow(t)))));
}

function renderExplorer() {
  // A closed panel has no size, and charts need one.
  if (S.tab !== 'explorer' || !S.panelOpen) return;
  const body = $('tab-explorer');
  const ex = S.explorer;
  if (!S.chain) return body.replaceChildren(doc(comment('no hay red: la wallet la crea')));
  const failed = (d) => doc(h('div', { className: 'tl' }, tlink('← explorer', () => explorerNav('home', null))), h('div', { className: 'tl tok-red', textContent: `error: ${d.error}` }));
  if (ex.view === 'home' && ex.home?.error) return body.replaceChildren(failed(ex.home));
  if (ex.view === 'tx') {
    const d = ex.txs.get(ex.ref);
    if (!d) return body.replaceChildren(doc(loading(`leyendo la transacción ${shortHex(ex.ref)}…`)));
    return d.error ? body.replaceChildren(failed(d)) : renderExplorerTx(d);
  }
  if (ex.view === 'block') {
    const d = ex.blocks.get(ex.ref);
    if (!d) return body.replaceChildren(doc(loading('leyendo el bloque…')));
    return d.error ? body.replaceChildren(failed(d)) : renderExplorerBlock(d);
  }
  body.replaceChildren(ex.home ? renderExplorerHome(ex.home) : doc(searchBox(), loading('leyendo los últimos bloques…')));
}

// ---- Debug tab ----

const FIELDS = {
  header: { name: 'encabezado', what: '"zbtc", versión 1 y tipo transfer: marcan este OP_RETURN como transferencia ZBTC' },
  anchor: { name: 'anchor', what: 'bloque cuyo árbol de notas usa la prueba' },
  counts: { name: 'cantidades', what: 'siempre 2 entradas y 2 salidas' },
  nullifiers: { name: 'nullifiers', tags: ['entrada 1', 'entrada 2'], what: 'uno por nota gastada; marca la nota como gastada sin decir cuál; repetirlo es doble gasto y el replay lo rechaza' },
  commitments: { name: 'commitments', tags: ['salida 1', 'salida 2'], what: 'hashes de las notas nuevas (pago y vuelto); ocultan dueño y monto' },
  ephemeralKeys: { name: 'claves efímeras', tags: ['salida 1', 'salida 2'], what: 'una clave X25519 nueva por nota; solo la clave privada del dueño reconstruye la clave de descifrado' },
  ciphertexts: { name: 'notas cifradas', tags: ['salida 1', 'salida 2'], what: 'monto (8 B) y semilla (32 B) más etiqueta (16 B), con ChaCha20-Poly1305 para el dueño' },
  proof: { name: 'prueba zk', tags: ['A', 'A', 'B', 'B', 'B', 'B', 'C', 'C'], what: 'Groth16 sobre BN254: notas en el árbol, dueño correcto, nullifiers correctos, montos de 64 bits, entradas = salidas; no revela nada de eso' },
};

const LEAK_LABELS = { amount: 'monto', 'recipient owner key': 'clave de dueño del destinatario', 'recipient encryption key': 'clave de cifrado del destinatario' };

function shieldedEntries() {
  return (S.chain?.activity ?? []).filter((e) => e.kind === 'shielded');
}

async function loadDebug() {
  const entries = shieldedEntries();
  if (!S.debug.txid && entries.length) S.debug.txid = entries[entries.length - 1].txid;
  const txid = S.debug.txid;
  if (!txid || S.explorer.txs.has(txid)) return;
  const r = await call(`debug: decodificar el sobre ${shortHex(txid)}`, 'tx', { txid }, { quiet: true });
  S.explorer.txs.set(txid, r.ok ? r.result : { error: r.error });
}

function highlightSegment(box, key) {
  box.classList.toggle('has-hl', Boolean(key));
  for (const el of box.querySelectorAll('[data-seg]')) el.classList.toggle('hl', el.dataset.seg === key);
}

function bytesView(env) {
  const range = (seg) => `bytes ${seg.offset}–${seg.offset + seg.length - 1}`;
  const values = (seg) => {
    if (seg.key === 'anchor') return [`bloque ${env.anchorHeight}`];
    if (seg.key === 'header' || seg.key === 'counts') return [env.hex.slice(seg.offset * 2, (seg.offset + seg.length) * 2)];
    return env[seg.key];
  };
  const box = h('div', { className: 'bytes' },
    comment('pasar el mouse por un campo ilumina sus bytes, y al revés'),
    h('div', { className: 'seg-legend' }, ...env.segments.map((seg) => h('button', { type: 'button', attrs: { 'data-seg': seg.key } },
      h('span', { className: `swatch seg-${seg.key}` }), `${FIELDS[seg.key].name} ${seg.length}B`))),
    h('pre', { className: 'bytemap' }, ...env.segments.map((seg) => h('span', {
      className: `seg-${seg.key}`,
      title: `${FIELDS[seg.key].name}: ${range(seg)}`,
      textContent: env.hex.slice(seg.offset * 2, (seg.offset + seg.length) * 2),
      attrs: { 'data-seg': seg.key },
    }))),
    ...env.segments.map((seg) => {
      const info = FIELDS[seg.key];
      return h('div', { className: 'field', attrs: { 'data-seg': seg.key } },
        h('div', { className: 'tl' }, h('span', { className: `swatch seg-${seg.key}` }), tok('key', info.name), tok('dim', `  ${range(seg)} · ${seg.length} B`)),
        comment(info.what),
        ...values(seg).map((v, i) => kv(info.tags?.[i] ?? 'valor', v)));
    }));
  box.addEventListener('mouseover', (e) => highlightSegment(box, e.target.closest('[data-seg]')?.dataset.seg ?? null));
  box.addEventListener('mouseleave', () => highlightSegment(box, null));
  return box;
}

function resetZone() {
  if (!S.debug.confirmReset) {
    return h('div', { className: 'tl' }, h('button', { type: 'button', className: 'tbtn danger', textContent: 'reiniciar red', disabled: Boolean(S.busy), onclick: () => {
      S.debug.confirmReset = true;
      renderDebug();
    } }));
  }
  return h('div', {},
    comment('borra la cadena, las billeteras y la actividad de la demo'),
    h('div', { className: 'tl' },
      h('button', { type: 'button', className: 'tbtn danger', textContent: 'sí, reiniciar', onclick: () => {
        S.debug.confirmReset = false;
        showTab('terminal');
        createNetwork();
      } }), ' ',
      h('button', { type: 'button', className: 'tbtn', textContent: 'cancelar', onclick: () => {
        S.debug.confirmReset = false;
        renderDebug();
      } })));
}

function renderDebug() {
  if (S.tab !== 'debug') return;
  const body = $('tab-debug');
  const c = S.chain;
  if (!c) return body.replaceChildren(doc(comment('no hay red: la wallet la crea'), th('peligro'), resetZone()));

  const parts = [
    th('red'),
    kv('altura', String(c.height)),
    kv('mejor_bloque', c.bestHash),
    kv('mempool', `${c.mempool.length} transacciones`),
    kv('replay', `${c.accepted} aceptadas · ${c.rejected} rechazadas`, 'cada billetera reproduce la cadena y verifica cada prueba'),
    kv('digest', c.digest, 'resumen del estado: dos billeteras honestas llegan al mismo'),
    th('billeteras'),
  ];
  for (const w of c.wallets) {
    parts.push(
      th(w.name, true),
      kv('zbtc', `${w.total} (gastable ${w.spendable} · pendiente ${w.pending} · entrante ${w.incoming})`),
      kv('fee_wallet', `${btc(w.fee.confirmed)}${w.fee.unconfirmed ? ` + ${btc(w.fee.unconfirmed)} sin confirmar` : ''}`),
      h('div', { className: 'ttable' },
        h('div', { className: 'tr head' }, ...['estado', 'unidades', 'altura'].map((t) => h('span', { textContent: t }))),
        ...w.notes.map((n) => h('div', { className: 'tr' }, tok('str', n.state), tok('num', String(n.units)), tok('num', n.height === null ? '-' : String(n.height))))));
  }

  const entries = shieldedEntries();
  parts.push(th('op_return'));
  if (!entries.length) parts.push(comment('todavía no hay transacciones protegidas'));
  else {
    parts.push(h('div', { className: 'tl' }, tok('key', 'tx'), tok('punct', ': '), ...entries.slice().reverse().flatMap((e) => {
      const b = h('button', { type: 'button', className: 'tbtn', textContent: `${shortHex(e.txid)} (${e.amount} → ${e.to})`, attrs: { 'aria-pressed': String(e.txid === S.debug.txid) } });
      b.onclick = () => {
        S.debug.txid = e.txid;
        reloadPanel();
      };
      return [b, ' '];
    })));
    const detail = S.explorer.txs.get(S.debug.txid);
    const entry = entries.find((e) => e.txid === S.debug.txid);
    if (!detail) parts.push(loading('decodificando el sobre…'));
    else if (detail.error) parts.push(h('div', { className: 'tl tok-red', textContent: `error: ${detail.error}` }));
    else {
      if (entry?.checks) {
        parts.push(th('búsqueda de fugas', true), comment(`¿aparecen en claro en los bytes públicos? (monto enviado: ${entry.amount})`),
          ...entry.checks.map((ch) => kv(LEAK_LABELS[ch.label] ?? ch.label, ch.inClear ? ['sí: fuga', 'red'] : ['no', 'green'])));
      }
      parts.push(th('bytes del sobre', true), bytesView(detail.envelope));
      const raw = h('details', {}, h('summary', { className: 'tc', textContent: `# json crudo: bitcoin-cli getrawtransaction ${shortHex(S.debug.txid)} 2` }), h('pre', { className: 'tpre' }, highlight(detail.json, true)));
      parts.push(th('json', true), raw);
    }
  }
  parts.push(th('peligro'), resetZone());
  body.replaceChildren(doc(...parts));
}

// ---- Toast ----

function renderToast() {
  $('toast-slot').replaceChildren(S.toast ? h('div', { className: `toast${S.toast.tone === 'bad' ? ' bad' : ''}`, attrs: { role: 'status' } }, icon(S.toast.tone === 'bad' ? 'x' : 'check'), S.toast.text) : '');
}

function renderAll() {
  renderNav();
  renderWallet();
  renderPanelFrame();
  if (S.send && $('send-dialog').open) updateSendIfForm();
  renderExplorer();
  renderDebug();
}

/** Keeps the send form's button state in sync with busy changes, without rebuilding the form. */
function updateSendIfForm() {
  if (S.send.phase === 'form') updateSend();
}

// ---- Wiring ----

$('mine').onclick = mine;
$('panel-toggle').onclick = () => {
  setPanelOpen(!S.panelOpen);
  reloadPanel();
};
$('panel-close').onclick = () => setPanelOpen(false);
$('panel-max').onclick = () => {
  S.panelMax = !S.panelMax;
  renderPanelFrame();
};
for (const b of document.querySelectorAll('#panel .tabs [role="tab"]')) b.onclick = () => showTab(b.dataset.tab);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && S.panelMax && !document.querySelector('dialog[open]')) {
    S.panelMax = false;
    renderPanelFrame();
  }
});
// A send in flight cannot be cancelled, so Esc must not hide its progress.
$('send-dialog').addEventListener('cancel', (e) => {
  if (S.send?.phase === 'sending') e.preventDefault();
});
$('send-dialog').addEventListener('close', () => {
  if (S.send?.phase !== 'sending') S.send = null;
});
$('receive-dialog').addEventListener('close', () => {
  S.receive = null;
});

renderAll();
refresh().then(() => {
  renderAll();
  reloadPanel();
});
