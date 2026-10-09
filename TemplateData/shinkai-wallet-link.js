// Battle of Shinkai — wallet connection and wallet SIGN-IN while the game keeps running in Safari / Chrome.
//
// Phones (no wallet in the browser) use the official Phantom / Solflare deeplinks:
//  1. CONNECT / SIGN IN → a small chooser (PHANTOM / SOLFLARE). Tapping one creates a NEW one-time x25519 keypair, keeps
//     it for at most 10 minutes (this site's localStorage) and opens /ul/v1/connect with app_url, cluster, the
//     dapp_encryption_public_key and redirect_link = this exact game page.
//  2. The wallet approves and opens redirect_link in the browser (usually a new tab) with
//     <wallet>_encryption_public_key + nonce + data (NaCl box, base58), or errorCode + errorMessage. This page reads it
//     before the game starts, removes it from the address bar and decrypts it with the one-time key: only the answer to
//     OUR request can be decrypted.
//  3. Sign-in (Phase 15): this page asks the game server for its one-time sign-in message, then one tap opens
//     /ul/v1/signMessage (payload encrypted with the connect session). This in-between tab does not load the game.
//  4. The wallet signs and sends the player back again; the signature goes to the server, which verifies it and returns
//     a session. The session {token, expiry, address} is kept in this TAB's sessionStorage only (V1.0 Phase 7: never in
//     localStorage; it survives a reload, not a new visit), and handed in memory to the tab that started the sign-in
//     (BroadcastChannel, this site only). The wallet's own session token is used only for that one request and never
//     stored afterwards.
// Home Screen app / another browser (2026-10-08): iPhone keeps a game opened from the Home Screen apart from Safari, but the
// wallet always answers in Safari (likewise, a phone may answer in its default browser, not the one the game runs in).
// So each wallet trip also carries a random hand-off id (shinkai_handoff=…) in redirect_link. A page that receives an
// answer it did not ask for (no matching one-time request here) only forwards the wallet's parameters, still encrypted,
// to the hand-off mailbox on the multiplayer server and asks the player to switch back. The page that did ask (it holds
// the one-time key) fetches them from the mailbox and continues as if the wallet had come back to it. The mailbox can
// neither read nor forge an answer (NaCl box to the one-time key); each id is used once and kept 10 minutes at most.
// Desktop wallets (extensions) sign the same server message through ShinkaiSolanaWallet.jslib (signIn below).
// A public address is an identifier, not proof of anything: only a server-verified signature signs a player in.
// Never: seed phrases, private keys, transactions. Nothing here is logged.
(function (global) {
  'use strict';

  var PENDING_KEY = 'shinkai.walletapp.pending';   // localStorage: the one-time request while the wallet app is open
  var SESSION_KEY = 'shinkai.walletapp.session';   // sessionStorage: this tab's connected app wallet {wallet, address}
  var AUTH_KEY = 'shinkai.auth';                   // sessionStorage: the game server's sign-in session {token, expiresAt, address, wallet}
  var PENDING_TTL_MS = 10 * 60 * 1000;
  var CHANNEL = 'shinkai-wallet';
  var CALLBACK_PARAMS = ['phantom_encryption_public_key', 'solflare_encryption_public_key', 'nonce', 'data', 'errorCode', 'errorMessage'];
  var HANDOFF_PARAM = 'shinkai_handoff';
  var HANDOFF_ID = /^[1-9A-HJ-NP-Za-km-z]{16,32}$/;
  var DEFAULT_RELAY = 'https://shinkai-rooms.fahadsani440.workers.dev'; // the hand-off mailbox (multiplayer/src/handoff.js)
  var POLL_MS = 2000, SLOW_POLL_MS = 6000, FAST_POLLS = 45;           // only while a wallet answer is awaited and the page is visible

  var WALLETS = {
    phantom: { key: 'phantom', name: 'Phantom', connectUrl: 'https://phantom.app/ul/v1/connect', signUrl: 'https://phantom.app/ul/v1/signMessage', keyParam: 'phantom_encryption_public_key', downloadUrl: 'https://phantom.com/download' },
    solflare: { key: 'solflare', name: 'Solflare', connectUrl: 'https://solflare.com/ul/v1/connect', signUrl: 'https://solflare.com/ul/v1/signMessage', keyParam: 'solflare_encryption_public_key', downloadUrl: 'https://solflare.com/download' }
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

  // ================================================================== wallet-app connection + wallet sign-in
  // env: { location, history, localStorage, sessionStorage, document, channel, random(n), now(), fetch(url, init),
  //        homeScreenApp (iPhone: opened from the Home Screen), relayUrl (hand-off mailbox; empty = none),
  //        timer(fn, ms), isHidden(), onVisible(fn) (optional: automatic mailbox checks) }
  function createLink(env) {
    var listeners = [], queue = [], ui = null, held = false, heldWaiters = [];
    var signInStarted = false; // this tab opened the wallet to SIGN IN: it takes the session another tab finishes
    var relayTimer = null, relayBusy = false, relayHooked = false, polls = 0;

    function emit(evt) {
      if (listeners.length) listeners.forEach(function (fn) { try { fn(evt); } catch (e) {} });
      else queue.push(evt);
    }

    function read(store, key) {
      try { var raw = store && store.getItem(key); return raw ? JSON.parse(raw) : null; } catch (e) { return null; }
    }
    function write(store, key, value) { try { if (store) store.setItem(key, JSON.stringify(value)); } catch (e) {} }
    function remove(store, key) { try { if (store) store.removeItem(key); } catch (e) {} }
    function isAddress(text) { var b = base58Decode(typeof text === 'string' ? text : ''); return !!b && b.length === 32; }

    // The game page itself (origin + path + any existing query), without callback parameters or fragment; with a hand-off
    // id when given (the wallet's redirect_link).
    function pageUrl(handoff) {
      var loc = env.location, params = new URLSearchParams(loc.search || '');
      CALLBACK_PARAMS.forEach(function (name) { params.delete(name); });
      params.delete(HANDOFF_PARAM);
      if (handoff) params.set(HANDOFF_PARAM, handoff);
      var query = params.toString();
      return loc.origin + loc.pathname + (query ? '?' + query : '');
    }

    function query(pairs) { return pairs.map(function (p) { return p[0] + '=' + encodeURIComponent(p[1]); }).join('&'); }

    // ---------------------------------------------------------------- the game server's sign-in session
    // {token, expiresAt, address, wallet} in this tab's sessionStorage (≤ 7 days; the server can end it any time).
    // V1.0 Phase 7 (brief 7.7): never in localStorage. A session an older version left there is moved into this tab once
    // and removed from localStorage.
    function validAuth(a) {
      return !!a && typeof a.token === 'string' && /^[A-Za-z0-9_-]{40,64}$/.test(a.token) && a.expiresAt > env.now() && isAddress(a.address);
    }

    function loadAuth() {
      var old = read(env.localStorage, AUTH_KEY);
      if (old) remove(env.localStorage, AUTH_KEY);
      var a = read(env.sessionStorage, AUTH_KEY);
      if (!a && validAuth(old)) { a = old; write(env.sessionStorage, AUTH_KEY, a); }
      if (!a) return null;
      if (!validAuth(a)) { remove(env.sessionStorage, AUTH_KEY); return null; }
      return a;
    }

    function api(backendUrl, path, body, token) {
      var headers = { 'Content-Type': 'application/json' };
      if (token) headers.Authorization = 'Bearer ' + token;
      return env.fetch(backendUrl.replace(/\/+$/, '') + path, { method: body ? 'POST' : 'GET', headers: headers, body: body ? JSON.stringify(body) : undefined })
        .then(function (res) { return res.json().catch(function () { return {}; }).then(function (json) { return { status: res.status, json: json || {} }; }); });
    }

    function authError(code, walletName, message) { emit({ type: 'authError', code: code, wallet: walletName || '', message: message || '' }); }

    // Sends a signature to the server; on success stores and announces the session.
    function verify(backendUrl, challengeId, address, walletName, walletKey, signature) {
      return api(backendUrl, '/v1/auth/verify', { challengeId: challengeId, address: address, signature: signature }).then(function (r) {
        if (r.status !== 200 || typeof r.json.token !== 'string') { authError(r.status === 401 ? 'rejectedByServer' : 'server', walletName, r.json.message); return false; }
        var auth = { token: r.json.token, expiresAt: r.json.expiresAt, address: address, wallet: walletName };
        write(env.sessionStorage, AUTH_KEY, auth);
        remove(env.localStorage, AUTH_KEY);
        signInStarted = false;
        emit({ type: 'session', token: auth.token, expiresAt: auth.expiresAt, address: address, wallet: walletName, restored: false });
        // The tab that started the sign-in (wallets usually come back in a new tab) gets the session in memory: this
        // site's tabs only, nothing stored on the way.
        if (env.channel) { try { env.channel.postMessage({ type: 'signedIn', address: address, auth: auth }); } catch (e) {} }
        return true;
      }, function () { authError('network', walletName); return false; });
    }

    // Desktop / in-wallet browsers: the extension signs the server's message (a popup in the wallet).
    // opts: { backendUrl, address, wallet, signer(bytes) -> Promise<Uint8Array> }
    function signIn(opts) {
      if (!opts || !isAddress(opts.address) || typeof opts.signer !== 'function') { authError('failed', opts && opts.wallet); return Promise.resolve(false); }
      return api(opts.backendUrl, '/v1/auth/challenge', { address: opts.address }).then(function (c) {
        if (c.status !== 200 || typeof c.json.message !== 'string') { authError(c.status === 429 ? 'busy' : 'server', opts.wallet, c.json.message); return false; }
        return Promise.resolve().then(function () { return opts.signer(utf8Encode(c.json.message)); }).then(function (signature) {
          if (!signature || signature.length !== 64) { authError('failed', opts.wallet); return false; }
          return verify(opts.backendUrl, c.json.challengeId, opts.address, opts.wallet, null, base58Encode(signature));
        }, function (e) {
          var text = String((e && (e.message || e.name)) || '');
          authError((e && e.code === 4001) || /reject|denied|declin|cancel/i.test(text) ? 'rejected' : /support/i.test(text) ? 'unsupported' : 'failed', opts.wallet);
          return false;
        });
      }, function () { authError('network', opts.wallet); return false; });
    }

    function signOut(backendUrl) {
      var auth = loadAuth();
      remove(env.sessionStorage, AUTH_KEY);
      remove(env.localStorage, AUTH_KEY);
      remove(env.sessionStorage, SESSION_KEY);
      remove(env.localStorage, PENDING_KEY);
      if (auth && backendUrl) api(backendUrl, '/v1/auth/logout', {}, auth.token).catch(function () {});
    }

    // ---------------------------------------------------------------- phone: connect (and sign-in) through the wallet APP
    // One fresh request: a new x25519 keypair, nothing stored until the player actually taps the wallet.
    function prepare(walletKey, backendUrl) {
      var wallet = WALLETS[walletKey];
      if (!wallet) return null;
      var oneTimeSecret = env.random(32), publicKey = scalarMultBase(oneTimeSecret), handoff = newHandoff();
      var pending = { v: 2, kind: 'connect', wallet: wallet.key, sk: base58Encode(oneTimeSecret), created: env.now() };
      if (backendUrl) pending.signIn = backendUrl;
      if (handoff) pending.handoff = handoff;
      return {
        wallet: wallet,
        url: wallet.connectUrl + '?' + query([['app_url', env.location.origin + env.location.pathname], ['dapp_encryption_public_key', base58Encode(publicKey)],
          ['redirect_link', pageUrl(handoff)], ['cluster', 'mainnet-beta']]),
        pending: pending
      };
    }

    // A random id for one wallet trip (16 bytes), or '' without a hand-off mailbox.
    function newHandoff() { return env.relayUrl ? base58Encode(env.random(16)) : ''; }

    // Called synchronously from the tap on a wallet link (just before the browser opens the wallet app).
    function remember(request) { write(env.localStorage, PENDING_KEY, request.pending); watchRelay(); }

    function fail(code, walletName) { return { type: 'error', code: code, app: true, wallet: walletName || '' }; }

    // Reads a wallet's answer from the page address (if any) and cleans the address bar. Returns
    //   {type:'connected', ..., signStep?}  connect approved (signStep: data for the sign-in step that follows)
    //   {type:'signed', ...}                 sign-in message signed (still to be verified by the server)
    //   {type:'error' | 'authError', ...}
    //   {type:'forward', handoff, params}    an answer to a request made elsewhere (Home Screen app / other browser)
    //   or null (nothing to do)
    function handleReturn() {
      var loc = env.location, search = new URLSearchParams(loc.search || ''), p = {};
      CALLBACK_PARAMS.forEach(function (name) { var v = search.get(name); if (v) p[name] = v; });
      var handoff = search.get(HANDOFF_PARAM) || '', pending = read(env.localStorage, PENDING_KEY);
      var cleanAddressBar = function () { try { env.history.replaceState(null, '', pageUrl().slice(loc.origin.length) + (loc.hash || '')); } catch (e) {} };
      if (handoff && env.relayUrl && HANDOFF_ID.test(handoff) && (p.nonce && p.data || p.errorCode) && !(pending && pending.handoff === handoff)) {
        cleanAddressBar(); // the one-time key is not here: pass the (still encrypted) answer on
        return { type: 'forward', handoff: handoff, params: p };
      }
      return settle(p, pending, cleanAddressBar);
    }

    // Opens a wallet answer (callback parameters p) with the one-time request it answers.
    function settle(p, pending, onAnswer) {
      var answerKey = p[WALLETS.phantom.keyParam] ? 'phantom' : p[WALLETS.solflare.keyParam] ? 'solflare' : null;
      var isError = !!p.errorCode, hasData = !!(p.nonce && p.data);
      var signAnswer = !answerKey && (hasData || isError) && pending && pending.kind === 'sign';
      if (!answerKey && !signAnswer && !(isError && pending)) return null; // stray parameters: ignored
      if (onAnswer) onAnswer();
      remove(env.localStorage, PENDING_KEY); // one-time: a second callback can never use it
      var params = { get: function (name) { return p[name] || null; } };
      if (!pending || !WALLETS[pending.wallet]) return fail('expired');
      var wallet = WALLETS[pending.wallet];
      var expired = !(env.now() - pending.created >= 0 && env.now() - pending.created <= PENDING_TTL_MS);
      var rejectedCode = function () {
        return String(params.get('errorCode') || '') === '4001' || /reject|cancel|declin|denied/i.test(String(params.get('errorMessage') || '')) ? 'rejected' : 'failed';
      };

      if (pending.kind === 'sign') {
        var signFail = function (code) { return { type: 'authError', code: code, wallet: wallet.name, message: '' }; };
        if (expired) return signFail('expired');
        if (isError) return signFail(rejectedCode());
        var nonceS = base58Decode(params.get('nonce') || ''), dataS = base58Decode(params.get('data') || ''), sharedS = base58Decode(pending.shared || '');
        if (!nonceS || nonceS.length !== 24 || !dataS || dataS.length < 17 || !sharedS || sharedS.length !== 32) return signFail('callbackFailed');
        var plainS = boxOpenAfter(dataS, nonceS, sharedS);
        if (!plainS) return signFail('mismatch');
        var signed;
        try { signed = JSON.parse(utf8Decode(plainS)); } catch (e) { return signFail('callbackFailed'); }
        var sig = base58Decode(signed && typeof signed.signature === 'string' ? signed.signature : '');
        if (!sig || sig.length !== 64 || !isAddress(pending.address) || typeof pending.challengeId !== 'string') return signFail('callbackFailed');
        return { type: 'signed', wallet: wallet.name, walletKey: wallet.key, address: pending.address, challengeId: pending.challengeId, signature: signed.signature, backendUrl: pending.backendUrl };
      }

      if (expired) return fail('expired', wallet.name);
      if (isError) return fail(rejectedCode(), wallet.name);
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
      if (!isAddress(address)) return fail('callbackFailed', wallet.name);
      write(env.sessionStorage, SESSION_KEY, { wallet: wallet.key, address: address });
      var result = { type: 'connected', wallet: wallet.name, address: address, via: 'app', restored: false };
      // The wallet's session token is only kept (in memory, then in the one-time sign request) to ask for the sign-in
      // signature; it is never stored afterwards.
      if (pending.signIn && typeof payload.session === 'string' && payload.session.length > 0 && payload.session.length < 4096) {
        result.signStep = { wallet: wallet.key, address: address, shared: base58Encode(shared), dappPublic: base58Encode(scalarMultBase(oneTimeSecret)), session: payload.session, backendUrl: pending.signIn };
      }
      return result;
    }

    function restoreAppConnection() {
      var session = read(env.sessionStorage, SESSION_KEY);
      if (!session || !WALLETS[session.wallet]) return null;
      if (!isAddress(session.address)) { remove(env.sessionStorage, SESSION_KEY); return null; }
      return { type: 'connected', wallet: WALLETS[session.wallet].name, address: session.address, via: 'app', restored: true };
    }

    // Another tab of this site finished what this tab started (wallets usually come back in a new tab).
    function onChannelMessage(message) {
      if (!message) return;
      if (message.type === 'connected' && ui && ui.waiting && isAddress(message.address) && WALLETS[message.walletKey]) {
        write(env.sessionStorage, SESSION_KEY, { wallet: message.walletKey, address: message.address });
        closeOverlay();
        emit({ type: 'connected', wallet: WALLETS[message.walletKey].name, address: message.address, via: 'app', restored: false });
      } else if (message.type === 'signedIn' && ((ui && ui.waiting) || signInStarted)) {
        // (the 'connected' message from the in-between tab may already have closed this tab's overlay)
        if (held) { showMessage('Signed in', 'You are signed in. Continue in the new tab; you can close this one.'); return; }
        signInStarted = false;
        // The session comes with the message (it lives in the other tab's sessionStorage, which this tab cannot read).
        var auth = validAuth(message.auth) && message.auth.address === message.address ? message.auth : loadAuth();
        if (auth && auth === message.auth) write(env.sessionStorage, AUTH_KEY, { token: auth.token, expiresAt: auth.expiresAt, address: auth.address, wallet: auth.wallet });
        closeOverlay();
        if (auth) {
          emit({ type: 'connected', wallet: auth.wallet, address: auth.address, via: 'session', restored: true });
          emit({ type: 'session', token: auth.token, expiresAt: auth.expiresAt, address: auth.address, wallet: auth.wallet, restored: true });
        }
      }
    }

    // ---------------------------------------------------------------- hand-off mailbox (see the top of this file)
    function relayBase() { return String(env.relayUrl || '').replace(/\/+$/, ''); }

    // The one-time request this browser is waiting on, if it can be answered through the mailbox.
    function waitingHandoff() {
      var p = read(env.localStorage, PENDING_KEY), age = p ? env.now() - p.created : -1;
      return p && typeof p.handoff === 'string' && HANDOFF_ID.test(p.handoff) && age >= 0 && age <= PENDING_TTL_MS ? p : null;
    }

    // Checks the mailbox every few seconds while an answer is awaited and the page is visible, and at once when the
    // player switches back to it.
    function watchRelay() {
      if (!env.relayUrl || !env.timer) return;
      if (!relayHooked && env.onVisible) { relayHooked = true; env.onVisible(function () { pollRelay(); }); }
      polls = 0;
      if (!relayTimer) relayTimer = env.timer(tick, POLL_MS);
    }
    function tick() {
      relayTimer = null;
      if (!waitingHandoff()) return; // answered, cancelled or expired: stop
      if (!(env.isHidden && env.isHidden())) { polls++; pollRelay(); }
      relayTimer = env.timer(tick, polls < FAST_POLLS ? POLL_MS : SLOW_POLL_MS);
    }

    function pollRelay() {
      var pending = waitingHandoff();
      if (!pending || relayBusy || !env.relayUrl) return Promise.resolve(false);
      relayBusy = true;
      var id = pending.handoff;
      return env.fetch(relayBase() + '/v1/handoff/' + id, { method: 'GET', cache: 'no-store' }).then(function (res) {
        return res.status === 200 ? res.json() : null;
      }).then(function (json) {
        relayBusy = false;
        return json && json.params && typeof json.params === 'object' ? takeRelayed(id, json.params) : false;
      }, function () { relayBusy = false; return false; });
    }

    // An answer fetched from the mailbox: exactly the checks of an answer in the address bar.
    function takeRelayed(id, raw) {
      var pending = read(env.localStorage, PENDING_KEY), p = {};
      if (!pending || pending.handoff !== id) return false; // settled meanwhile (another tab)
      CALLBACK_PARAMS.forEach(function (name) { if (typeof raw[name] === 'string' && raw[name]) p[name] = raw[name]; });
      var result = settle(p, pending, null);
      if (!result) return false;
      if (result.type === 'connected') {
        if (env.channel) { try { env.channel.postMessage({ type: 'connected', walletKey: read(env.sessionStorage, SESSION_KEY).wallet, address: result.address }); } catch (e) {} }
        // The game runs here, so it hears about the connection now (as a tab waiting in the browser does), sign-in or not.
        var signStep = result.signStep;
        delete result.signStep;
        emit(result);
        if (signStep) beginSignStep(signStep);
        else closeOverlay();
        return true;
      }
      closeOverlay();
      if (result.type === 'signed') {
        var known = read(env.sessionStorage, SESSION_KEY);
        if (!known || known.address !== result.address) {
          write(env.sessionStorage, SESSION_KEY, { wallet: result.walletKey, address: result.address });
          emit({ type: 'connected', wallet: result.wallet, address: result.address, via: 'app', restored: false });
        }
        return verify(result.backendUrl, result.challengeId, result.address, result.wallet, result.walletKey, result.signature);
      }
      emit(result);
      return true;
    }

    // This page received an answer to a request made elsewhere: post it to the mailbox and send the player back. The
    // game is not loaded here unless the player asks for it.
    function forwardAnswer(r) {
      var doc = env.document;
      var playHere = function (o) {
        o.card.appendChild(plainButton(doc, 'shinkai-wallet-playhere', 'PLAY IN THIS BROWSER INSTEAD', function () { closeOverlay(); release(); }));
      };
      var state = function (name) { if (ui) ui.root.setAttribute('data-state', name); };
      var send = function () {
        if (!overlay('ALMOST THERE', 'Passing your wallet\'s answer to the game…')) { release(); return Promise.resolve(); }
        state('sending');
        return env.fetch(relayBase() + '/v1/handoff/' + r.handoff, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: JSON.stringify({ params: r.params }) })
          .then(function (res) { return res.status; }, function () { return 0; })
          .then(function (status) {
            var o;
            if (status === 204 || status === 409) {
              o = overlay(r.params.errorCode ? 'WALLET ANSWER SENT' : 'APPROVED ✓',
                'Now go back to Battle of Shinkai: the app on your Home Screen (or the browser where you started). It continues there by itself. You can close this tab.');
              state('sent');
            } else if (status === 400) {
              o = overlay('SOMETHING WENT WRONG', 'This wallet answer could not be used. Go back to the game and connect again.');
              state('refused');
            } else {
              o = overlay('COULD NOT REACH THE GAME', 'Check your internet connection, then try again.');
              state('failed');
              o.buttons.appendChild(plainButton(doc, 'shinkai-wallet-resend', 'TRY AGAIN', send));
            }
            if (o) playHere(o);
          });
      };
      return send();
    }

    function start() {
      var result = handleReturn();
      var appConnection = null;
      if (env.channel) env.channel.onmessage = function (e) { onChannelMessage(e && e.data); };
      if (result && result.type === 'forward') { hold(); forwardAnswer(result); return; }
      if (waitingHandoff()) watchRelay(); // e.g. the Home Screen app was reloaded while the wallet was open
      if (result && result.type === 'signed') {
        write(env.sessionStorage, SESSION_KEY, { wallet: result.walletKey, address: result.address });
        emit({ type: 'connected', wallet: result.wallet, address: result.address, via: 'app', restored: false });
        verify(result.backendUrl, result.challengeId, result.address, result.wallet, result.walletKey, result.signature);
      } else if (result && result.type === 'connected') {
        if (env.channel) { try { env.channel.postMessage({ type: 'connected', walletKey: read(env.sessionStorage, SESSION_KEY).wallet, address: result.address }); } catch (e) {} }
        if (result.signStep) { hold(); beginSignStep(result.signStep); }
        else emit(result);
      } else {
        if (result) emit(result);
        appConnection = restoreAppConnection();
        if (appConnection) emit(appConnection);
        var auth = loadAuth();
        if (auth) {
          if (!appConnection) emit({ type: 'connected', wallet: auth.wallet, address: auth.address, via: 'session', restored: true });
          emit({ type: 'session', token: auth.token, expiresAt: auth.expiresAt, address: auth.address, wallet: auth.wallet, restored: true });
        }
      }
    }

    // ---------------------------------------------------------------- game loading hold (the tab between the two wallet
    // trips never needs the game: on iPhone that saves loading it twice)
    function hold() { held = true; }
    function release() {
      if (!held) return;
      held = false;
      var waiters = heldWaiters; heldWaiters = [];
      waiters.forEach(function (fn) { try { fn(); } catch (e) {} });
    }

    // ---------------------------------------------------------------- overlays (real <a> links: a tap on a link is what
    // reliably opens the wallet app through its universal / app link)
    function closeOverlay() {
      if (ui && ui.root && ui.root.parentNode) ui.root.parentNode.removeChild(ui.root);
      ui = null;
    }

    function overlay(titleText, bodyText) {
      var doc = env.document;
      if (!doc) return null;
      closeOverlay();
      injectStyle(doc);
      var root = doc.createElement('div');
      root.id = 'shinkai-wallet';
      root.setAttribute('role', 'dialog');
      var card = el(doc, 'div', 'sw-card', '');
      root.appendChild(card);
      var title = el(doc, 'div', 'sw-title', titleText), text = el(doc, 'div', 'sw-text', bodyText), buttons = el(doc, 'div', 'sw-buttons', '');
      card.appendChild(title); card.appendChild(text); card.appendChild(buttons);
      doc.body.appendChild(root);
      ui = { root: root, card: card, title: title, text: text, buttons: buttons, waiting: false };
      return ui;
    }

    function showMessage(titleText, bodyText) {
      if (!ui) overlay(titleText, bodyText);
      else { ui.title.textContent = titleText; ui.text.textContent = bodyText; ui.buttons.textContent = ''; }
    }

    function linkButton(doc, id, label, href, onTap) {
      var a = el(doc, 'a', 'sw-button', label);
      a.id = id;
      a.href = href;
      a.addEventListener('click', onTap);
      return a;
    }

    function plainButton(doc, id, label, onTap) {
      var b = el(doc, 'button', 'sw-cancel', label);
      b.type = 'button';
      b.id = id;
      b.addEventListener('click', onTap);
      return b;
    }

    function getLinks(doc) {
      var get = el(doc, 'div', 'sw-note', 'No wallet app? ');
      ['phantom', 'solflare'].forEach(function (key, i) {
        var a = el(doc, 'a', 'sw-get', 'Get ' + WALLETS[key].name);
        a.href = WALLETS[key].downloadUrl;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        if (i) get.appendChild(doc.createTextNode(' · '));
        get.appendChild(a);
      });
      return get;
    }

    // Step 1: PHANTOM / SOLFLARE (connect). With backendUrl, step 2 (sign in) follows when the wallet sends the player back.
    // Home Screen app (iPhone): the wallet answers in Safari, and the player switches back here themselves.
    function comeBackText() {
      return env.homeScreenApp && env.relayUrl ? ' Safari then opens for a moment: switch back to this app and it continues by itself.'
        : '; you will come back here automatically.';
    }

    function showChooser(backendUrl) {
      var doc = env.document, homeApp = env.homeScreenApp && env.relayUrl;
      var o = overlay(backendUrl ? 'SIGN IN WITH YOUR WALLET' : 'CONNECT WALLET',
        backendUrl ? 'Choose your wallet app. It opens twice: first to connect, then to sign in.' + (homeApp ? '' : ' You come back here automatically each time.')
          : 'Choose your wallet app. It opens and asks you to approve' + (homeApp ? '.' : ', then brings you back here to keep playing.'));
      if (!o) return false;
      ['phantom', 'solflare'].forEach(function (key) {
        var request = prepare(key, backendUrl);
        o.buttons.appendChild(linkButton(doc, 'shinkai-wallet-' + key, request.wallet.name.toUpperCase(), request.url, function () {
          remember(request);
          if (backendUrl) signInStarted = true;
          if (ui) {
            ui.waiting = true;
            ui.text.textContent = 'Opening ' + request.wallet.name + '… Approve the connection there' + (homeApp ? '.' : '') + comeBackText() + ' '
              + request.wallet.name + ' did not open? Install it, then tap ' + request.wallet.name.toUpperCase() + ' again.';
          }
        }));
      });
      // iPhone keeps Home Screen web apps apart from Safari and opens the wallet's answer in Safari, where the one-time
      // key made here does not exist. With the hand-off mailbox Safari passes the answer on; without it, say so up front.
      if (env.homeScreenApp) {
        var warn = el(doc, 'div', 'sw-note sw-warn', homeApp
          ? 'Playing from the Home Screen: after each approval your wallet opens Safari. Just switch back to this app; it picks up the answer by itself.'
          : 'On iPhone, the wallet answers in Safari, not in a game opened from the Home Screen. To use your wallet, open the game in Safari. Guest play works here.');
        warn.id = 'shinkai-wallet-homescreen';
        o.card.appendChild(warn);
      }
      o.card.appendChild(el(doc, 'div', 'sw-note', backendUrl
        ? 'Signing in proves the wallet is yours so your progress and points are saved. It is not a transaction and costs nothing. Never share your seed phrase.'
        : 'Read-only: the game only reads your public address. No transactions, never your seed phrase.'));
      o.card.appendChild(getLinks(doc));
      o.card.appendChild(plainButton(doc, 'shinkai-wallet-cancel', 'CANCEL', function () {
        signInStarted = false;
        remove(env.localStorage, PENDING_KEY);
        closeOverlay();
        emit(fail('cancelled'));
      }));
      return true;
    }

    // Step 2 (phone): fetch the server's sign-in message, then one tap opens the wallet app to sign it.
    function beginSignStep(step) {
      var doc = env.document, wallet = WALLETS[step.wallet];
      var o = overlay('STEP 2 OF 2 · SIGN IN', 'Connected to ' + wallet.name + '. Getting your sign-in message…');
      if (!o) { release(); return; }
      var guest = function () {
        closeOverlay();
        authError('cancelled', wallet.name);
        release();
      };
      api(step.backendUrl, '/v1/auth/challenge', { address: step.address }).then(function (c) {
        if (c.status !== 200 || typeof c.json.message !== 'string') throw new Error('server');
        var nonce = env.random(24), handoff = newHandoff();
        var payload = boxAfter(utf8Encode(JSON.stringify({ message: base58Encode(utf8Encode(c.json.message)), session: step.session, display: 'utf8' })), nonce, base58Decode(step.shared));
        var url = wallet.signUrl + '?' + query([['dapp_encryption_public_key', step.dappPublic], ['nonce', base58Encode(nonce)], ['redirect_link', pageUrl(handoff)], ['payload', base58Encode(payload)]]);
        if (!ui) return;
        ui.text.textContent = wallet.name + ' will ask you to sign a message. It only proves this wallet is yours: it is not a transaction and costs nothing.';
        ui.buttons.appendChild(linkButton(doc, 'shinkai-wallet-sign', 'SIGN IN WITH ' + wallet.name.toUpperCase(), url, function () {
          var pending = { v: 2, kind: 'sign', wallet: wallet.key, shared: step.shared, address: step.address, challengeId: c.json.challengeId, backendUrl: step.backendUrl, created: env.now() };
          if (handoff) pending.handoff = handoff;
          write(env.localStorage, PENDING_KEY, pending);
          watchRelay();
          if (ui) { ui.waiting = true; ui.text.textContent = 'Opening ' + wallet.name + '… Sign the message there' + (env.homeScreenApp && env.relayUrl ? '.' : '') + comeBackText(); }
        }));
        ui.card.appendChild(plainButton(doc, 'shinkai-wallet-guest', 'PLAY AS GUEST', guest));
      }).catch(function () {
        if (!ui) return;
        ui.text.textContent = 'Could not reach the game server. Check your connection and try again.';
        ui.buttons.appendChild(plainButton(doc, 'shinkai-wallet-retry', 'TRY AGAIN', function () { beginSignStep(step); }));
        ui.card.appendChild(plainButton(doc, 'shinkai-wallet-guest', 'PLAY AS GUEST', guest));
      });
    }

    function forget() {
      remove(env.sessionStorage, SESSION_KEY);
      remove(env.localStorage, PENDING_KEY);
      closeOverlay();
    }

    return {
      start: start,
      subscribe: function (fn) {
        listeners.push(fn);
        var pending = queue; queue = [];
        pending.forEach(function (evt) { try { fn(evt); } catch (e) {} });
      },
      showChooser: showChooser,
      closeChooser: closeOverlay,
      signIn: signIn,
      signOut: signOut,
      forget: forget,
      isChooserOpen: function () { return !!ui; },
      isGameHeld: function () { return held; },
      whenGameAllowed: function (fn) { if (held) heldWaiters.push(fn); else fn(); },
      // for tests
      _prepare: prepare,
      _remember: remember,
      _handleReturn: handleReturn,
      _restore: restoreAppConnection,
      _loadAuth: loadAuth,
      _pollRelay: pollRelay,
      _waitingHandoff: waitingHandoff
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
      '#shinkai-wallet .sw-warn{color:#ffcf5a;font-size:13px}',
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
    now: function () { return Date.now(); },
    fetch: function (url, init) { return global.fetch(url, init); },
    homeScreenApp: !!(global.navigator && global.navigator.standalone === true), // iOS only
    relayUrl: typeof global.SHINKAI_HANDOFF_URL === 'string' ? global.SHINKAI_HANDOFF_URL : DEFAULT_RELAY,
    timer: function (fn, ms) { return global.setTimeout(fn, ms); },
    isHidden: function () { return !!(global.document && global.document.hidden); },
    onVisible: function (fn) {
      try {
        global.document.addEventListener('visibilitychange', function () { if (!global.document.hidden) fn(); });
        global.addEventListener('focus', fn);
        global.addEventListener('pageshow', fn);
      } catch (e) {}
    }
  });
  link.WALLETS = WALLETS;
  global.ShinkaiWalletLink = link;
  link.start();
})(typeof window !== 'undefined' ? window : this);
