// Minimal DOM harness that runs static/script.js outside a browser and checks
// that every decoded value ends up in its own field.
//
// Run with:  node tests/widget_test.js
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'templates/index.html'), 'utf8');
const js = fs.readFileSync(path.join(ROOT, 'static/script.js'), 'utf8');

class ClassList {
  constructor(el) { this.el = el; this.set = new Set(); }
  add(c) { this.set.add(c); }
  remove(c) { this.set.delete(c); }
  contains(c) { return this.set.has(c); }
}

class Element {
  constructor(id, tag) {
    this.id = id || '';
    this.tagName = (tag || 'div').toUpperCase();
    this.children = [];
    this._text = '';
    this._html = '';
    this.style = {};
    this.attributes = {};
    this.classList = new ClassList(this);
    this.listeners = {};
  }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = String(v); }
  querySelector(sel) {
    if (sel !== 'code') throw new Error('unsupported selector ' + sel);
    return this._code || null;
  }
  appendChild(child) { this.children.push(child); return child; }
  removeChild(child) { this.children = this.children.filter((c) => c !== child); }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type, event) { (this.listeners[type] || []).forEach((fn) => fn(event || {})); }
  setAttribute(k, v) { this.attributes[k] = v; }
  select() {}
  focus() { this.focused = true; }
  scrollIntoView() {}
}

// Build an element for every id in the template.
const elements = {};
for (const m of html.matchAll(/id="([A-Za-z0-9_-]+)"/g)) {
  const id = m[1];
  const el = new Element(id);
  // <pre ...><code></code></pre> fields expose an inner <code>.
  if (html.includes(`id="${id}"><code>`)) el._code = new Element('', 'code');
  elements[id] = el;
}

const created = [];
const document = {
  getElementById: (id) => elements[id] || null,
  addEventListener: (type, fn) => { if (type === 'DOMContentLoaded') document._ready = fn; },
  createElement: (tag) => { const el = new Element('', tag); created.push(el); return el; },
  execCommand: () => true,
  body: { appendChild: () => {}, removeChild: () => {} },
};

const copied = [];
const window = { location: { origin: 'http://localhost:8080' } };
const navigator = { clipboard: { writeText: (t) => { copied.push(t); return Promise.resolve(); }, readText: () => Promise.resolve('') } };

// Evaluate the widget script with our stubs.
const run = new Function('document', 'window', 'navigator', 'console', 'setTimeout', 'setInterval', 'clearInterval', js);
run(document, window, navigator, console, () => {}, () => 1, () => {});

document._ready();

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

const now = Math.floor(Date.now() / 1000);
const token = [
  b64url({ alg: 'HS256', typ: 'JWT' }),
  b64url({ sub: '1234567890', name: 'John Doe', iat: now - 60, exp: now + 3600, lock_region_time: 1750000000 }),
  'c2lnbmF0dXJl',
].join('.');

const results = [];
function check(name, actual, expected) {
  const ok = actual === expected;
  results.push({ name, ok, actual, expected });
}

// --- happy path -----------------------------------------------------------
elements.tokenInput.value = token;
elements.decodeBtn.dispatch('click');

check('results visible', elements.resultsContainer.classList.contains('is-hidden'), false);
check('error hidden', elements.errorMessage.classList.contains('is-hidden'), true);
check('header field', elements.headerContent._code.textContent, JSON.stringify({ alg: 'HS256', typ: 'JWT' }, null, 2));
check('payload field', elements.payloadContent._code.textContent, JSON.stringify(JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString()), null, 2));
check('signature field', elements.signatureContent._code.textContent, 'c2lnbmF0dXJl');
check('algorithm', elements.algorithmValue.textContent, 'HS256');
check('token type', elements.tokenTypeValue.textContent, 'JWT');
check('token status', elements.tokenStatus.textContent, 'Active');
check('status card class', elements.statusCard.className, 'status-card valid');
check('api url', elements.apiUrl.textContent, 'http://localhost:8080/decode_jwt?token=' + encodeURIComponent(token));
check('api link', elements.openApiLink.attributes.href, elements.apiUrl.textContent);
check('claims html highlighted', elements.jsonDisplay._code.innerHTML.includes('json-key'), true);
check('issued at not empty', elements.issuedAtValue.textContent !== '-', true);
check('expires at not empty', elements.expiresValue.textContent !== '-', true);

// --- expired token --------------------------------------------------------
const expired = [b64url({ alg: 'HS256', typ: 'JWT' }), b64url({ exp: now - 10 }), 'sig'].join('.');
elements.tokenInput.value = expired;
elements.decodeBtn.dispatch('click');
check('expired status', elements.tokenStatus.textContent, 'Expired');
check('expired card class', elements.statusCard.className, 'status-card expired');
check('expired countdown', elements.expiryCountdown.textContent, 'Expired');

// --- no exp claim ---------------------------------------------------------
const noExp = [b64url({ alg: 'HS256' }), b64url({ sub: 'x' }), 'sig'].join('.');
elements.tokenInput.value = noExp;
elements.decodeBtn.dispatch('click');
check('unknown status', elements.tokenStatus.textContent, 'Unknown');
check('no expiration text', elements.expiresValue.textContent, 'No expiration');
check('no issued time', elements.issuedAtValue.textContent, 'No issued time');

// --- invalid exp claim ----------------------------------------------------
const badExp = [b64url({ alg: 'HS256' }), b64url({ exp: 'tomorrow' }), 'sig'].join('.');
elements.tokenInput.value = badExp;
elements.decodeBtn.dispatch('click');
check('invalid exp text', elements.expiresValue.textContent, 'Invalid "exp" claim');
check('invalid exp status', elements.tokenStatus.textContent, 'Unknown');

// --- malformed tokens -----------------------------------------------------
elements.tokenInput.value = 'not.a.jwt';
elements.decodeBtn.dispatch('click');
check('malformed hides results', elements.resultsContainer.classList.contains('is-hidden'), true);
check('malformed shows error', elements.errorMessage.classList.contains('is-hidden'), false);

const jwe = [b64url({ alg: 'dir' }), 'a', 'b', 'c', 'd'].join('.');
elements.tokenInput.value = jwe;
elements.decodeBtn.dispatch('click');
check('jwe error mentions JWE', elements.errorDescription.textContent.includes('JWE'), true);

// --- whitespace / Bearer prefix ------------------------------------------
elements.tokenInput.value = '  Bearer ' + token.slice(0, 20) + '\n' + token.slice(20) + '  ';
elements.decodeBtn.dispatch('click');
check('bearer + whitespace decodes', elements.resultsContainer.classList.contains('is-hidden'), false);

// --- unicode --------------------------------------------------------------
const uni = [b64url({ alg: 'HS256' }), b64url({ name: 'سعید 🚀 ünïcode' }), 'sig'].join('.');
elements.tokenInput.value = uni;
elements.decodeBtn.dispatch('click');
check('unicode payload', elements.payloadContent._code.textContent.includes('سعید 🚀 ünïcode'), true);

// --- clear ----------------------------------------------------------------
elements.clearBtn.dispatch('click');
check('clear empties input', elements.tokenInput.value, '');
check('clear hides results', elements.resultsContainer.classList.contains('is-hidden'), true);

// --- copy claims ----------------------------------------------------------
elements.tokenInput.value = token;
elements.decodeBtn.dispatch('click');
elements.copyClaimsBtn.dispatch('click');
setTimeout(() => {
  check('copy claims payload', JSON.parse(copied[copied.length - 1]).sub, '1234567890');
  elements.copyApiBtn.dispatch('click');
  setTimeout(() => {
    check('copy api url', copied[copied.length - 1], elements.apiUrl.textContent);
    elements.clearBtn.dispatch('click');
    check('api actions hidden after clear', elements.apiActions.classList.contains('is-hidden'), true);
    check('api url reset after clear', elements.apiUrl.textContent, 'GET /decode_jwt?token=YOUR_JWT_TOKEN');
    elements.tokenInput.value = token;
    elements.decodeBtn.dispatch('click');
    check('api actions visible after decode', elements.apiActions.classList.contains('is-hidden'), false);

    let failed = 0;
    results.forEach((r) => {
      if (!r.ok) { failed++; console.log('FAIL', r.name, '=>', JSON.stringify(r.actual), 'expected', JSON.stringify(r.expected)); }
      else console.log('ok  ', r.name);
    });
    console.log(failed === 0 ? `\nALL ${results.length} WIDGET CHECKS PASSED` : `\n${failed}/${results.length} CHECKS FAILED`);
    process.exit(failed === 0 ? 0 : 1);
  }, 0);
}, 0);
