// Battle of Shinkai — browser helpers for the game page (Phase 7, 2026-10-09), used by ShinkaiBrowser.jslib:
//  - BACK button: while the game has somewhere to go back to (a sub-screen of the menus, or a battle) it keeps ONE extra
//    history entry on top. Pressing BACK pops it; the game is told (takeBack) and steps back itself (closes the screen,
//    pauses the battle…); the entry is put back while there is still somewhere to go back to. At the main menu there is no
//    extra entry, so BACK leaves the page as on any website. The page address never changes.
//  - copy(text) / copyResult(): the room code to the clipboard (Clipboard API, or a hidden text field + execCommand as a
//    fallback) and the browser's real answer (copied / refused) — the game only says CODE COPIED when it was.
//    iPhone Safari allows the clipboard only DURING the tap, and the game reacts a frame later: so while the room code is
//    on screen the game tells this script where it is (setCopyTarget, in the canvas's own pixels) and the copy is made in
//    the tap's own touchend / pointerup. A target the game stops refreshing (keepCopyTarget) is ignored after 1 s.
//  - prefersReducedMotion(): the system / browser "reduce motion" setting (the game's own setting overrides it).
// Nothing here stores anything.
(function (global) {
  'use strict';

  // env: { history, addEventListener(type, fn, capture), matchMedia(query), navigator, document, isSecureContext,
  //        canvas() → the game's canvas, now() → ms }
  function createNav(env) {
    var guard = !!(env.history && env.history.state && env.history.state.shinkaiGuard); // our entry is on top (also after a reload)
    var want = false;       // the game has somewhere to go back to
    var ignorePops = 0;     // pops caused by our own history.back()
    var pending = 0;        // BACK presses the game has not taken yet
    var target = null;      // { text, x0, y0, x1, y1, seen }: the room code on screen (origin bottom-left, canvas pixels)
    var copySeq = 0, copyState = 0, copyText = '', tapCopyAt = -1e9; // copyState: 0 none / waiting, 1 copied, 2 refused
    var now = env.now || function () { return Date.now(); };

    function push() {
      try { env.history.pushState({ shinkaiGuard: true }, ''); guard = true; } catch (e) { guard = false; }
    }

    function onPop() {
      if (ignorePops > 0) { ignorePops--; return; }
      if (!guard) return;   // a pop below our entry: the browser's own navigation, nothing to do
      guard = false;
      pending++;
      if (want) push();     // still somewhere to go back to: be ready for the next press
    }

    function setCanGoBack(value) {
      want = !!value;
      if (want && !guard) push();
      else if (!want && guard) {
        guard = false;
        ignorePops++;
        try { env.history.back(); } catch (e) { ignorePops--; }
      }
    }

    function takeBack() {
      if (pending <= 0) return false;
      pending--;
      return true;
    }

    function fallbackCopy(text) {
      var doc = env.document;
      if (!doc || !doc.body || !doc.createElement) return false;
      var field = doc.createElement('textarea');
      field.value = text;
      field.setAttribute('readonly', '');
      field.style.position = 'fixed';
      field.style.left = '-1000px';
      field.style.top = '0';
      doc.body.appendChild(field);
      var ok = false;
      try { field.select(); if (field.setSelectionRange) field.setSelectionRange(0, text.length); ok = !!doc.execCommand('copy'); } catch (e) { ok = false; }
      doc.body.removeChild(field);
      return ok;
    }

    // Starts a copy; its answer arrives in copyState (the Clipboard API answers later).
    function startCopy(text) {
      var seq = ++copySeq;
      copyState = 0;
      copyText = text;
      function done(ok) { if (seq === copySeq) copyState = ok ? 1 : 2; }
      var clipboard = env.navigator && env.navigator.clipboard;
      if (clipboard && clipboard.writeText && env.isSecureContext) {
        try {
          clipboard.writeText(text).then(function () { done(true); }, function () { done(fallbackCopy(text)); });
          return;
        } catch (e) { /* fall back */ }
      }
      done(fallbackCopy(text));
    }

    // The game's copy (a frame after the tap). When the tap itself already copied this text, its answer is used.
    function copy(text) {
      text = String(text == null ? '' : text);
      if (!text) return false;
      if (text === copyText && now() - tapCopyAt < 1500) return true;
      startCopy(text);
      return true;
    }

    function copyResult() { return copyState; }

    function setCopyTarget(text, x0, y0, x1, y1) {
      text = String(text == null ? '' : text);
      target = text && x1 > x0 && y1 > y0 ? { text: text, x0: x0, y0: y0, x1: x1, y1: y1, seen: now() } : null;
    }

    function keepCopyTarget() { if (target) target.seen = now(); }

    // A tap that ends on the room code copies it right here, inside the tap (the only place iPhone Safari allows it).
    function onTapEnd(e) {
      if (!target || now() - target.seen > 1000) return;
      if (e.type === 'pointerup' && e.pointerType === 'touch') return; // touches: touchend (Safari's tap gesture)
      var canvas = env.canvas && env.canvas();
      if (!canvas || !canvas.getBoundingClientRect) return;
      var r = canvas.getBoundingClientRect();
      if (!r.width || !r.height) return;
      var p = e.changedTouches && e.changedTouches.length ? e.changedTouches[0] : e;
      var x = (p.clientX - r.left) * canvas.width / r.width;
      var y = canvas.height - (p.clientY - r.top) * canvas.height / r.height;
      if (x < target.x0 || x > target.x1 || y < target.y0 || y > target.y1) return;
      tapCopyAt = now();
      startCopy(target.text);
    }

    function prefersReducedMotion() {
      try { return !!(env.matchMedia && env.matchMedia('(prefers-reduced-motion: reduce)').matches); } catch (e) { return false; }
    }

    if (env.addEventListener) {
      env.addEventListener('popstate', onPop);
      env.addEventListener('touchend', onTapEnd, true);  // capture: before the game's own handlers
      env.addEventListener('pointerup', onTapEnd, true);
    }
    return {
      setCanGoBack: setCanGoBack,
      takeBack: takeBack,
      copy: copy,
      copyResult: copyResult,
      setCopyTarget: setCopyTarget,
      keepCopyTarget: keepCopyTarget,
      prefersReducedMotion: prefersReducedMotion,
      _state: function () { return { guard: guard, want: want, pending: pending, ignorePops: ignorePops, target: target, copyState: copyState, tapCopyAt: tapCopyAt }; }
    };
  }

  if (typeof module !== 'undefined' && module.exports) { module.exports = { createNav: createNav }; return; }

  global.ShinkaiNav = createNav({
    history: global.history,
    addEventListener: function (type, fn, capture) { global.addEventListener(type, fn, { capture: !!capture, passive: true }); },
    matchMedia: function (q) { return global.matchMedia ? global.matchMedia(q) : null; },
    navigator: global.navigator,
    document: global.document,
    isSecureContext: !!global.isSecureContext,
    canvas: function () { return global.document ? global.document.getElementById('unity-canvas') : null; },
    now: function () { return Date.now(); }
  });
})(typeof window !== 'undefined' ? window : this);
