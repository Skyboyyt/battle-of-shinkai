// Battle of Shinkai — connect a phone's wallet APP while the game keeps running in Safari / Chrome.
//
// Official Phantom / Solflare deeplink "connect" (https://phantom.app/ul/v1/connect, https://solflare.com/ul/v1/connect):
//  1. CONNECT WALLET on a phone whose browser has no wallet → a small chooser (PHANTOM / SOLFLARE).
//  2. Tapping one creates a NEW one-time x25519 keypair, keeps it for at most 10 minutes (this site's localStorage) and
//     opens the wallet app with app_url, dapp_encryption_public_key, cluster and redirect_link = this exact game page.
//  3. The wallet asks the player to approve, then opens redirect_link in the browser with
//     <wallet>_encryption_public_key + nonce + data (NaCl box, base58), or errorCode + errorMessage.
//  4. This page (usually reloaded in a new tab) reads those parameters before the game starts and removes them from the
//     address bar. It decrypts `data` with the stored one-time key (only the answer to OUR request can be decrypted),
//     keeps the public address, and throws away the one-time key and the wallet's session token. The game then verifies
//     AxoRonin ownership on-chain as usual.
//  5. The connected address is remembered for this browser TAB only (sessionStorage), so a reload never reopens the wallet.
//
// A public address is an identifier, not proof of anything; it is never treated as authentication.
// Never: seed phrases, private keys, signatures, transactions. Nothing here is logged.
(function (global) {
  'use strict';

  var PENDING_KEY = 'shinkai.walletapp.pending';   // localStorage: the one-time request while the wallet app is open
  var SESSION_KEY = 'shinkai.walletapp.session';   // sessionStorage: this tab's connected app wallet {wallet, address}
  var PENDING_TTL_MS = 10 * 60 * 1000;
  var CHANNEL = 'shinkai-wallet';
  var CALLBACK_PARAMS = ['phantom_encryption_public_key', 'solflare_encryption_public_key', 'nonce', 'data', 'errorCode', 'errorMessage'];

  var WALLETS = {
    phantom: { key: 'phantom', name: 'Phantom', connectUrl: 'https://phantom.app/ul/v1/connect', keyParam: 'phantom_encryption_public_key', downloadUrl: 'https://phantom.com/download' },
    solflare: { key: 'solflare', name: 'Solflare', connectUrl: 'https://solflare.com/ul/v1/connect', keyParam: 'solflare_encryption_public_key', downloadUrl: 'https://solflare.com/download' }
  };

  // ================================================================== base58 (Bitcoin alphabet, as used by Solana)
  var ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function base58Encode(bytes) {
    var digits = [];
    for (var i = 0; i < bytes.length; i++) {
      var carry = bytes[i];
      for (var j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
    }
    var out = '';
    for (var k = 0; k < bytes.length && bytes[k] === 0; k++) out += '1';
    for (var d = digits.length - 1; d >= 0; d--) out += ALPHABET[digits[d]];
    return out;
  }

  function base58Decode(text) {
    if (typeof text !== 'string' || text.length === 0 || text.length > 4096) return null;
    var bytes = [];
    for (var i = 0; i < text.length; i++) {
      var carry = ALPHABET.indexOf(text[i]);
      if (carry < 0) return null;
      for (var j = 0; j < bytes.length; j++) {
        carry += bytes[j] * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    var zeros = 0;
    while (zeros < text.length && text[zeros] === '1') zeros++;
    var out = new Uint8Array(zeros + bytes.length);
    for (var k = 0; k < bytes.length; k++) out[out.length - 1 - k] = bytes[k];
    return out;
  }

  // ================================================================== NaCl box: x25519 + XSalsa20-Poly1305
  // The exact construction TweetNaCl's nacl.box.before / nacl.box.open.after use (what Phantom / Solflare document).
  // Verified byte-for-byte against libsodium's official test vectors (scalarmult, core1, onetimeauth, box, box2).
  var P = (BigInt(1) << BigInt(255)) - BigInt(19);
  var A24 = BigInt(121665);
  var ZERO = BigInt(0), ONE = BigInt(1);

  function leToBig(bytes) {
    var n = ZERO;
    for (var i = bytes.length - 1; i >= 0; i--) n = (n << BigInt(8)) | BigInt(bytes[i]);
    return n;
  }

  function bigToLe(n, length) {
    var out = new Uint8Array(length);
    for (var i = 0; i < length; i++) { out[i] = Number(n & BigInt(255)); n >>= BigInt(8); }
    return out;
  }

  function mod(a) { a %= P; return a < ZERO ? a + P : a; }

  function powMod(b, e) {
    var r = ONE;
    b = mod(b);
    while (e > ZERO) {
      if (e & ONE) r = (r * b) % P;
      b = (b * b) % P;
      e >>= ONE;
    }
    return r;
  }

  // RFC 7748 X25519.
  function x25519(scalar, uBytes) {
    var k = new Uint8Array(scalar);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
    var kn = leToBig(k);
    var u = new Uint8Array(uBytes);
    u[31] &= 127;
    var x1 = mod(leToBig(u)), x2 = ONE, z2 = ZERO, x3 = x1, z3 = ONE, swap = ZERO, t;
    for (var i = 254; i >= 0; i--) {
      var bit = (kn >> BigInt(i)) & ONE;
      swap ^= bit;
      if (swap) { t = x2; x2 = x3; x3 = t; t = z2; z2 = z3; z3 = t; }
      swap = bit;
      var A = mod(x2 + z2), AA = (A * A) % P, B = mod(x2 - z2), BB = (B * B) % P, E = mod(AA - BB);
      var C = mod(x3 + z3), D = mod(x3 - z3), DA = (D * A) % P, CB = (C * B) % P;
      x3 = mod((DA + CB) * (DA + CB));
      z3 = mod(x1 * mod((DA - CB) * (DA - CB)));
      x2 = (AA * BB) % P;
      z2 = mod(E * mod(AA + A24 * E));
    }
    if (swap) { t = x2; x2 = x3; x3 = t; t = z2; z2 = z3; z3 = t; }
    return bigToLe((x2 * powMod(z2, P - BigInt(2))) % P, 32);
  }

  var BASEPOINT = new Uint8Array(32); BASEPOINT[0] = 9;
  function scalarMultBase(oneTimeSecret) { return x25519(oneTimeSecret, BASEPOINT); }

  // Salsa20 / HSalsa20 (20 rounds), "expand 32-byte k".
  var SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

  function load32(b, i) { return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0; }
  function store32(b, i, v) { b[i] = v & 255; b[i + 1] = (v >>> 8) & 255; b[i + 2] = (v >>> 16) & 255; b[i + 3] = (v >>> 24) & 255; }
  function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }

  function salsaRounds(x) {
    for (var i = 0; i < 20; i += 2) {
      x[4] ^= rotl((x[0] + x[12]) >>> 0, 7); x[8] ^= rotl((x[4] + x[0]) >>> 0, 9);
      x[12] ^= rotl((x[8] + x[4]) >>> 0, 13); x[0] ^= rotl((x[12] + x[8]) >>> 0, 18);
      x[9] ^= rotl((x[5] + x[1]) >>> 0, 7); x[13] ^= rotl((x[9] + x[5]) >>> 0, 9);
      x[1] ^= rotl((x[13] + x[9]) >>> 0, 13); x[5] ^= rotl((x[1] + x[13]) >>> 0, 18);
      x[14] ^= rotl((x[10] + x[6]) >>> 0, 7); x[2] ^= rotl((x[14] + x[10]) >>> 0, 9);
      x[6] ^= rotl((x[2] + x[14]) >>> 0, 13); x[10] ^= rotl((x[6] + x[2]) >>> 0, 18);
      x[3] ^= rotl((x[15] + x[11]) >>> 0, 7); x[7] ^= rotl((x[3] + x[15]) >>> 0, 9);
      x[11] ^= rotl((x[7] + x[3]) >>> 0, 13); x[15] ^= rotl((x[11] + x[7]) >>> 0, 18);
      x[1] ^= rotl((x[0] + x[3]) >>> 0, 7); x[2] ^= rotl((x[1] + x[0]) >>> 0, 9);
      x[3] ^= rotl((x[2] + x[1]) >>> 0, 13); x[0] ^= rotl((x[3] + x[2]) >>> 0, 18);
      x[6] ^= rotl((x[5] + x[4]) >>> 0, 7); x[7] ^= rotl((x[6] + x[5]) >>> 0, 9);
      x[4] ^= rotl((x[7] + x[6]) >>> 0, 13); x[5] ^= rotl((x[4] + x[7]) >>> 0, 18);
      x[11] ^= rotl((x[10] + x[9]) >>> 0, 7); x[8] ^= rotl((x[11] + x[10]) >>> 0, 9);
      x[9] ^= rotl((x[8] + x[11]) >>> 0, 13); x[10] ^= rotl((x[9] + x[8]) >>> 0, 18);
      x[12] ^= rotl((x[15] + x[14]) >>> 0, 7); x[13] ^= rotl((x[12] + x[15]) >>> 0, 9);
      x[14] ^= rotl((x[13] + x[12]) >>> 0, 13); x[15] ^= rotl((x[14] + x[13]) >>> 0, 18);
    }
  }

  function salsaInput(key, sixteen) {
    var x = new Uint32Array(16);
    x[0] = SIGMA[0]; x[5] = SIGMA[1]; x[10] = SIGMA[2]; x[15] = SIGMA[3];
    for (var i = 0; i < 4; i++) { x[1 + i] = load32(key, 4 * i); x[11 + i] = load32(key, 16 + 4 * i); x[6 + i] = load32(sixteen, 4 * i); }
    return x;
  }

  function hsalsa20(key, input16) {
    var x = salsaInput(key, input16);
    salsaRounds(x);
    var out = new Uint8Array(32), idx = [0, 5, 10, 15, 6, 7, 8, 9];
    for (var i = 0; i < 8; i++) store32(out, 4 * i, x[idx[i]]);
    return out;
  }

  // XSalsa20 keystream of `length` bytes.
  function xsalsa20Stream(key, nonce24, length) {
    var subkey = hsalsa20(key, nonce24.subarray(0, 16));
    var block = new Uint8Array(16), out = new Uint8Array(length);
    block.set(nonce24.subarray(16, 24), 0);
    for (var offset = 0, counter = 0; offset < length; offset += 64, counter++) {
      store32(block, 8, counter >>> 0);
      store32(block, 12, Math.floor(counter / 4294967296) >>> 0);
      var x = salsaInput(subkey, block), z = new Uint32Array(x);
      salsaRounds(z);
      var bytes = new Uint8Array(64);
      for (var i = 0; i < 16; i++) store32(bytes, 4 * i, (z[i] + x[i]) >>> 0);
      out.set(bytes.subarray(0, Math.min(64, length - offset)), offset);
    }
    return out;
  }

  // Poly1305 one-time authenticator (RFC 8439 arithmetic).
  var P1305 = (BigInt(1) << BigInt(130)) - BigInt(5);
  var CLAMP = BigInt('0x0ffffffc0ffffffc0ffffffc0fffffff');
  var MASK128 = (BigInt(1) << BigInt(128)) - ONE;

  function poly1305(message, key32) {
    var r = leToBig(key32.subarray(0, 16)) & CLAMP, s = leToBig(key32.subarray(16, 32)), h = ZERO;
    for (var i = 0; i < message.length; i += 16) {
      var chunk = message.subarray(i, Math.min(i + 16, message.length));
      h = ((h + leToBig(chunk) + (ONE << BigInt(8 * chunk.length))) * r) % P1305;
    }
    return bigToLe((h + s) & MASK128, 16);
  }

  function equal16(a, b) { var d = 0; for (var i = 0; i < 16; i++) d |= a[i] ^ b[i]; return d === 0; }

  // nacl.box.before: HSalsa20(X25519(secret, theirPublic), 0). Null for a small-order (all-zero) shared point.
  function boxBefore(theirPublicKey, mySecret) {
    var shared = x25519(mySecret, theirPublicKey), any = 0;
    for (var i = 0; i < 32; i++) any |= shared[i];
    return any ? hsalsa20(shared, new Uint8Array(16)) : null;
  }

  // nacl.secretbox / box.after: output = tag(16) || ciphertext.
  function boxAfter(message, nonce24, key) {
    var stream = xsalsa20Stream(key, nonce24, 32 + message.length), out = new Uint8Array(16 + message.length);
    for (var i = 0; i < message.length; i++) out[16 + i] = message[i] ^ stream[32 + i];
    out.set(poly1305(out.subarray(16), stream.subarray(0, 32)), 0);
    return out;
  }

  // nacl.box.open.after: null when the tag does not verify.
  function boxOpenAfter(boxed, nonce24, key) {
    if (!boxed || boxed.length < 16 || !nonce24 || nonce24.length !== 24 || !key) return null;
    var stream = xsalsa20Stream(key, nonce24, 32 + boxed.length - 16);
    if (!equal16(poly1305(boxed.subarray(16), stream.subarray(0, 32)), boxed.subarray(0, 16))) return null;
    var out = new Uint8Array(boxed.length - 16);
    for (var i = 0; i < out.length; i++) out[i] = boxed[16 + i] ^ stream[32 + i];
    return out;
  }

  function utf8Encode(text) { return new TextEncoder().encode(text); }
  function utf8Decode(bytes) { return new TextDecoder().decode(bytes); }

  // ================================================================== the wallet-app connection
  // env: { location, history, localStorage, sessionStorage, random(n) -> Uint8Array, now() -> ms, channel (optional) }
  function createLink(env) {
    var listeners = [], queue = [], ui = null;

    function emit(evt) {
      if (listeners.length) listeners.forEach(function (fn) { try { fn(evt); } catch (e) {} });
      else queue.push(evt);
    }

    function read(store, key) {
      try { var raw = store && store.getItem(key); return raw ? JSON.parse(raw) : null; } catch (e) { return null; }
    }
    function write(store, key, value) { try { if (store) store.setItem(key, JSON.stringify(value)); } catch (e) {} }
    function remove(store, key) { try { if (store) store.removeItem(key); } catch (e) {} }

    // The game page itself (origin + path + any existing query), without callback parameters or fragment.
    function pageUrl() {
      var loc = env.location, params = new URLSearchParams(loc.search || '');
      CALLBACK_PARAMS.forEach(function (name) { params.delete(name); });
      var query = params.toString();
      return loc.origin + loc.pathname + (query ? '?' + query : '');
    }

    // One fresh request: a new x25519 keypair, nothing stored until the player actually taps the wallet.
    function prepare(walletKey) {
      var wallet = WALLETS[walletKey];
      if (!wallet) return null;
      var oneTimeSecret = env.random(32), publicKey = scalarMultBase(oneTimeSecret);
      var query = [
        ['app_url', env.location.origin + env.location.pathname],
        ['dapp_encryption_public_key', base58Encode(publicKey)],
        ['redirect_link', pageUrl()],
        ['cluster', 'mainnet-beta']
      ].map(function (p) { return p[0] + '=' + encodeURIComponent(p[1]); }).join('&');
      return {
        wallet: wallet,
        url: wallet.connectUrl + '?' + query,
        pending: { v: 1, wallet: wallet.key, sk: base58Encode(oneTimeSecret), created: env.now() }
      };
    }

    // Called synchronously from the tap on a wallet link (just before the browser opens the wallet app).
    function remember(request) { write(env.localStorage, PENDING_KEY, request.pending); }

    function fail(code, walletName) {
      return { type: 'error', code: code, app: true, wallet: walletName || '' };
    }

    // Reads a wallet's answer from the page address (if any). Always cleans the address bar first.
    function handleReturn() {
      var loc = env.location, params = new URLSearchParams(loc.search || '');
      var answerKey = params.has(WALLETS.phantom.keyParam) ? 'phantom' : params.has(WALLETS.solflare.keyParam) ? 'solflare' : null;
      var isError = params.has('errorCode');
      if (!answerKey && !isError) return null;
      try { env.history.replaceState(null, '', pageUrl().slice(loc.origin.length) + (loc.hash || '')); } catch (e) {}

      var pending = read(env.localStorage, PENDING_KEY);
      remove(env.localStorage, PENDING_KEY); // one-time: a second callback can never use it
      if (!pending || !WALLETS[pending.wallet]) return answerKey ? fail('expired') : null;
      var wallet = WALLETS[pending.wallet];
      if (!(env.now() - pending.created >= 0 && env.now() - pending.created <= PENDING_TTL_MS)) return fail('expired', wallet.name);
      if (isError) {
        var code = String(params.get('errorCode') || '');
        return fail(code === '4001' || /reject|cancel|declin|denied/i.test(String(params.get('errorMessage') || '')) ? 'rejected' : 'failed', wallet.name);
      }
      // Phantom and Solflare name their key parameter differently; accept whichever the answer carries.
      var walletPublicKey = base58Decode(params.get(wallet.keyParam) || params.get(WALLETS[answerKey].keyParam) || '');
      var nonce = base58Decode(params.get('nonce') || ''), data = base58Decode(params.get('data') || '');
      var oneTimeSecret = base58Decode(pending.sk || '');
      if (!walletPublicKey || walletPublicKey.length !== 32 || !nonce || nonce.length !== 24 || !data || data.length < 17 || !oneTimeSecret || oneTimeSecret.length !== 32)
        return fail('callbackFailed', wallet.name);
      var shared = boxBefore(walletPublicKey, oneTimeSecret);
      var plain = shared ? boxOpenAfter(data, nonce, shared) : null;
      if (!plain) return fail('mismatch', wallet.name); // not an answer to THIS request (or tampered)
      var payload;
      try { payload = JSON.parse(utf8Decode(plain)); } catch (e) { return fail('callbackFailed', wallet.name); }
      var address = payload && typeof payload.public_key === 'string' ? payload.public_key : '';
      var addressBytes = base58Decode(address);
      if (!addressBytes || addressBytes.length !== 32) return fail('callbackFailed', wallet.name);
      // The wallet's session token is only needed for signing requests, which this game never makes: not kept.
      write(env.sessionStorage, SESSION_KEY, { wallet: wallet.key, address: address });
      return { type: 'connected', wallet: wallet.name, address: address, via: 'app', restored: false };
    }

    function restore() {
      var session = read(env.sessionStorage, SESSION_KEY);
      if (!session || !WALLETS[session.wallet]) return null;
      var bytes = base58Decode(session.address || '');
      if (!bytes || bytes.length !== 32) { remove(env.sessionStorage, SESSION_KEY); return null; }
      return { type: 'connected', wallet: WALLETS[session.wallet].name, address: session.address, via: 'app', restored: true };
    }

    // Another tab of this site finished the connection this tab started (the wallet usually returns in a new tab).
    function onChannelMessage(message) {
      if (!message || message.type !== 'connected' || !ui || !ui.waiting) return;
      var bytes = base58Decode(message.address || '');
      if (!bytes || bytes.length !== 32 || !WALLETS[message.walletKey]) return;
      write(env.sessionStorage, SESSION_KEY, { wallet: message.walletKey, address: message.address });
      closeChooser();
      emit({ type: 'connected', wallet: WALLETS[message.walletKey].name, address: message.address, via: 'app', restored: false });
    }

    function start() {
      var result = handleReturn() || restore();
      if (result) {
        if (result.type === 'connected' && !result.restored && env.channel) {
          try { env.channel.postMessage({ type: 'connected', walletKey: read(env.sessionStorage, SESSION_KEY).wallet, address: result.address }); } catch (e) {}
        }
        emit(result);
      }
      if (env.channel) env.channel.onmessage = function (e) { onChannelMessage(e && e.data); };
    }

    // ---------------------------------------------------------------- chooser (real <a> links: a tap on a link is
    // what reliably opens the wallet app through its universal / app link)
    function closeChooser() {
      if (ui && ui.root && ui.root.parentNode) ui.root.parentNode.removeChild(ui.root);
      ui = null;
    }

    function showChooser() {
      var doc = env.document;
      if (!doc) return false;
      closeChooser();
      injectStyle(doc);
      var root = doc.createElement('div');
      root.id = 'shinkai-wallet';
      root.setAttribute('role', 'dialog');
      var card = doc.createElement('div');
      card.className = 'sw-card';
      root.appendChild(card);
      var title = el(doc, 'div', 'sw-title', 'CONNECT WALLET');
      var text = el(doc, 'div', 'sw-text', 'Choose your wallet app. It opens, asks you to approve, then brings you back here to keep playing.');
      var buttons = el(doc, 'div', 'sw-buttons', '');
      card.appendChild(title); card.appendChild(text); card.appendChild(buttons);
      ui = { root: root, text: text, waiting: false };
      ['phantom', 'solflare'].forEach(function (key) {
        var request = prepare(key);
        var link = el(doc, 'a', 'sw-button', request.wallet.name.toUpperCase());
        link.href = request.url;
        link.id = 'shinkai-wallet-' + key;
        link.addEventListener('click', function () {
          remember(request);
          if (ui) {
            ui.waiting = true;
            ui.text.textContent = 'Opening ' + request.wallet.name + '… Approve the connection there; you will come back here automatically. '
              + request.wallet.name + ' did not open? Install it, then tap ' + request.wallet.name.toUpperCase() + ' again.';
          }
        });
        buttons.appendChild(link);
      });
      card.appendChild(el(doc, 'div', 'sw-note', 'Read-only: the game only reads your public address. No signatures, no transactions, never your seed phrase.'));
      var get = el(doc, 'div', 'sw-note', 'No wallet app? ');
      ['phantom', 'solflare'].forEach(function (key, i) {
        var a = el(doc, 'a', 'sw-get', 'Get ' + WALLETS[key].name);
        a.href = WALLETS[key].downloadUrl;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        if (i) get.appendChild(doc.createTextNode(' · '));
        get.appendChild(a);
      });
      card.appendChild(get);
      var cancel = el(doc, 'button', 'sw-cancel', 'CANCEL');
      cancel.type = 'button';
      cancel.id = 'shinkai-wallet-cancel';
      cancel.addEventListener('click', function () {
        remove(env.localStorage, PENDING_KEY);
        closeChooser();
        emit(fail('cancelled'));
      });
      card.appendChild(cancel);
      doc.body.appendChild(root);
      return true;
    }

    function forget() {
      remove(env.sessionStorage, SESSION_KEY);
      remove(env.localStorage, PENDING_KEY);
      closeChooser();
    }

    return {
      start: start,
      subscribe: function (fn) {
        listeners.push(fn);
        var pending = queue; queue = [];
        pending.forEach(function (evt) { try { fn(evt); } catch (e) {} });
      },
      showChooser: showChooser,
      closeChooser: closeChooser,
      forget: forget,
      isChooserOpen: function () { return !!ui; },
      // for tests
      _prepare: prepare,
      _remember: remember,
      _handleReturn: handleReturn,
      _restore: restore
    };
  }

  function el(doc, tag, className, text) {
    var node = doc.createElement(tag);
    node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function injectStyle(doc) {
    if (doc.getElementById('shinkai-wallet-style')) return;
    var style = doc.createElement('style');
    style.id = 'shinkai-wallet-style';
    style.textContent = [
      '#shinkai-wallet{position:fixed;inset:0;z-index:2147483000;display:flex;align-items:center;justify-content:center;',
      'background:rgba(4,6,16,.78);font-family:Arial,Helvetica,sans-serif;padding:max(10px,env(safe-area-inset-top)) max(14px,env(safe-area-inset-right)) max(10px,env(safe-area-inset-bottom)) max(14px,env(safe-area-inset-left));box-sizing:border-box}',
      '#shinkai-wallet .sw-card{width:min(560px,100%);max-height:100%;overflow:auto;background:#0b1424;border:2px solid #ff6454;border-radius:14px;padding:16px 18px;box-sizing:border-box;color:#eef3ff;text-align:center}',
      '#shinkai-wallet .sw-title{font-weight:bold;font-size:20px;letter-spacing:1px;margin-bottom:6px}',
      '#shinkai-wallet .sw-text{font-size:14px;color:#b9c4d8;margin-bottom:12px;line-height:1.35}',
      '#shinkai-wallet .sw-buttons{display:flex;gap:10px;justify-content:center;margin-bottom:10px}',
      '#shinkai-wallet .sw-button{flex:1;display:block;padding:14px 8px;border-radius:10px;background:#ff6454;color:#fff;font-weight:bold;font-size:17px;text-decoration:none;letter-spacing:1px}',
      '#shinkai-wallet .sw-note{font-size:12px;color:#8fa0bb;margin:6px 0;line-height:1.3}',
      '#shinkai-wallet .sw-get{color:#59dbe8}',
      '#shinkai-wallet .sw-cancel{margin-top:6px;background:#15263b;color:#fff;border:0;border-radius:8px;padding:9px 22px;font-weight:bold;font-size:14px}'
    ].join('');
    doc.head.appendChild(style);
  }

  var api = {
    WALLETS: WALLETS,
    createLink: createLink,
    _crypto: { x25519: x25519, scalarMultBase: scalarMultBase, hsalsa20: hsalsa20, poly1305: poly1305, boxBefore: boxBefore, boxAfter: boxAfter, boxOpenAfter: boxOpenAfter, xsalsa20Stream: xsalsa20Stream },
    _base58: { encode: base58Encode, decode: base58Decode },
    _utf8: { encode: utf8Encode, decode: utf8Decode }
  };

  if (typeof module !== 'undefined' && module.exports) { module.exports = api; return; }

  // ---------------------------------------------------------------- the game page: start right away (before Unity)
  var channel = null;
  try { if (typeof BroadcastChannel !== 'undefined') channel = new BroadcastChannel(CHANNEL); } catch (e) {}
  var link = createLink({
    location: global.location,
    history: global.history,
    localStorage: (function () { try { return global.localStorage; } catch (e) { return null; } })(),
    sessionStorage: (function () { try { return global.sessionStorage; } catch (e) { return null; } })(),
    document: global.document,
    channel: channel,
    random: function (n) { var b = new Uint8Array(n); global.crypto.getRandomValues(b); return b; },
    now: function () { return Date.now(); }
  });
  link.WALLETS = WALLETS;
  global.ShinkaiWalletLink = link;
  link.start();
})(typeof window !== 'undefined' ? window : this);
