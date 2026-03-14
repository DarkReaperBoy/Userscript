// ==UserScript==
// @name         Bale Bridge Encryptor/Decryptor (Ultimate Privacy)
// @namespace    http://tampermonkey.net/
// @version      9.0
// @description  Per-chat keys, Shield button, Material UI, Auto-decrypt, Draft blocker. Desktop & Mobile.
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// ==/UserScript==
(function () {
  "use strict";

  // ─── 0. WebSocket Draft Blocker ───────────────────────────────────────────
  const _origWsSend = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) {
    try {
      const t =
        typeof data === "string" ? data : new TextDecoder().decode(data);
      if (t.includes("EditParameter") && t.includes("drafts_")) return;
    } catch (_) {}
    return _origWsSend.apply(this, arguments);
  };

  // ─── 1. Settings (Per-Chat) ───────────────────────────────────────────────
  const getChatId = () => {
    const p = new URLSearchParams(location.search);
    return (
      p.get("uid") ||
      p.get("groupId") ||
      p.get("channelId") ||
      location.pathname.split("/").pop() ||
      "global"
    );
  };
  const getChatSettings = () => {
    const s = localStorage.getItem("bale_bridge_settings_" + getChatId());
    return s ? JSON.parse(s) : { enabled: true, customKey: "" };
  };
  const saveChatSettings = (s) =>
    localStorage.setItem(
      "bale_bridge_settings_" + getChatId(),
      JSON.stringify(s),
    );

  // ─── 2. Crypto Engine ─────────────────────────────────────────────────────
  const GLOBAL_KEY = "%CC*em@h*%YCFXMkhnm^kTqHTW##uy97"; // <- you must change this. must be 32 characters, i randomly generated with proton pass.
  const keyCache = new Map();

  async function getCryptoKey(k = GLOBAL_KEY) {
    if (keyCache.has(k)) return keyCache.get(k);
    let b = new TextEncoder().encode(k);
    if (b.length !== 32) {
      const p = new Uint8Array(32);
      p.set(b.slice(0, 32));
      b = p;
    }
    const key = await crypto.subtle.importKey(
      "raw",
      b,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    keyCache.set(k, key);
    return key;
  }

  // Base85 (RFC 1924)
  const B85 =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
  const B85D = new Map([...B85].map((c, i) => [c, i]));

  function b85enc(buf) {
    let out = "";
    for (let i = 0; i < buf.length; i += 4) {
      let acc = 0,
        rem = Math.min(4, buf.length - i);
      for (let j = 0; j < 4; j++)
        acc = (acc << 8) | (i + j < buf.length ? buf[i + j] : 0);
      acc >>>= 0;
      let chunk = "";
      for (let j = 0; j < 5; j++) {
        chunk = B85[acc % 85] + chunk;
        acc = Math.floor(acc / 85);
      }
      out += rem < 4 ? chunk.slice(0, rem + 1) : chunk;
    }
    return out;
  }

  function b85dec(str) {
    str = str.replace(/\s/g, "");
    const out = [];
    for (let i = 0; i < str.length; i += 5) {
      let chunk = str.slice(i, i + 5),
        pad = 5 - chunk.length;
      chunk = chunk.padEnd(5, "~");
      let acc = 0;
      for (let j = 0; j < 5; j++) acc = acc * 85 + B85D.get(chunk[j]);
      out.push(
        (acc >>> 24) & 0xff,
        (acc >>> 16) & 0xff,
        (acc >>> 8) & 0xff,
        acc & 0xff,
      );
      if (pad) out.splice(out.length - pad, pad);
    }
    return new Uint8Array(out);
  }

  async function compress(text) {
    const cs = new CompressionStream("deflate");
    const w = cs.writable.getWriter();
    w.write(new TextEncoder().encode(text));
    w.close();
    return new Uint8Array(await new Response(cs.readable).arrayBuffer());
  }
  async function decompress(buf) {
    const ds = new DecompressionStream("deflate");
    const w = ds.writable.getWriter();
    w.write(buf);
    w.close();
    return new TextDecoder().decode(
      await new Response(ds.readable).arrayBuffer(),
    );
  }

  async function encrypt(text) {
    const s = getChatSettings();
    const key = await getCryptoKey(
      s.enabled && s.customKey ? s.customKey : GLOBAL_KEY,
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        await compress(text),
      ),
    );
    const payload = new Uint8Array(12 + ct.length);
    payload.set(iv);
    payload.set(ct, 12);
    return "@@" + b85enc(payload);
  }

  async function decrypt(text) {
    if (!text.startsWith("@@")) return text;
    try {
      const buf = b85dec(text.slice(2));
      const iv = buf.slice(0, 12),
        data = buf.slice(12);
      const s = getChatSettings();
      let plain;
      try {
        const key = await getCryptoKey(
          s.enabled && s.customKey ? s.customKey : GLOBAL_KEY,
        );
        plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
      } catch (_) {
        // Fallback to global key
        plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          await getCryptoKey(GLOBAL_KEY),
          data,
        );
      }
      return await decompress(new Uint8Array(plain));
    } catch (_) {
      return text;
    }
  }

  // ─── 3. DOM Scanner (Auto-decrypt) ────────────────────────────────────────
  function scanTree(root) {
    for (const el of root.getElementsByTagName("*")) {
      if (
        el.id === "secure-input-overlay" ||
        el.id === "editable-message-text" ||
        el.id === "main-message-input"
      )
        continue;
      if (el._isDecrypted || el._isDecrypting) continue;
      const text = el.textContent.trim();
      if (!text.startsWith("@@") || text.length <= 20) continue;
      if ([...el.children].some((c) => c.textContent.trim() === text)) continue;
      el._isDecrypting = true;
      decrypt(text)
        .then((plain) => {
          if (plain !== text) {
            el.innerHTML = "🔓 " + plain.replace(/\n/g, "<br>");
            el.style.color = "inherit";
            el._isDecrypted = true;
          }
        })
        .finally(() => {
          el._isDecrypting = false;
        });
    }
  }

  // ─── 4. Input Helpers ─────────────────────────────────────────────────────
  // Desktop: <div id="editable-message-text" contenteditable>
  // Mobile:  <textarea id="main-message-input">
  const getRealInput = () =>
    document.getElementById("editable-message-text") ||
    document.getElementById("main-message-input");

  const isMobileInput = (el) => el?.tagName === "TEXTAREA";

  // React's synthetic system requires using the native prototype setter to
  // trigger onChange on controlled inputs.
  const _textareaSetter = Object.getOwnPropertyDescriptor(
    HTMLTextAreaElement.prototype,
    "value",
  )?.set;

  function reactSet(el, value) {
    if (isMobileInput(el)) {
      _textareaSetter?.call(el, value);
    } else {
      el.focus();
      document.execCommand("selectAll", false, null);
      document.execCommand("insertText", false, value);
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // ─── 5. Styles ────────────────────────────────────────────────────────────
  document.head.insertAdjacentHTML(
    "beforeend",
    `<style>
        /* Secure input – works for both div[contenteditable] and textarea */
        #secure-input-overlay {
            width: 100%; box-sizing: border-box; min-height: 44px; max-height: 150px;
            overflow-y: auto; background-color: var(--color-neutrals-surface, #fff);
            border: 2px solid var(--color-primary-p-50, #00ab80);
            box-shadow: 0 4px 12px rgba(0,171,128,.15); border-radius: 16px;
            padding: 10px 16px; font-family: inherit; font-size: inherit; outline: none;
            white-space: pre-wrap; word-break: break-word; margin-right: 10px; resize: none;
            color: var(--color-neutrals-n-600, #151515); z-index: 100;
            position: relative; transition: box-shadow .2s ease, border-color .2s ease;
            display: block;
        }
        #secure-input-overlay:focus {
            box-shadow: 0 4px 16px rgba(0,171,128,.3);
            border-color: var(--color-primary-p-60, #00916d);
        }
        /* Placeholder for contenteditable div */
        div#secure-input-overlay:empty::before {
            content: attr(data-placeholder);
            color: var(--color-neutrals-n-300, #888);
            pointer-events: none; display: block;
        }

        #bale-bridge-menu {
            position: fixed; z-index: 999999; background: var(--color-neutrals-surface, #fff);
            border: 1px solid var(--color-neutrals-n-40, #dfe1e6); border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,.15); display: none; flex-direction: column;
            overflow: hidden; font-family: inherit; color: var(--color-neutrals-n-500, #091e42);
            min-width: 180px; animation: bb-pop .2s cubic-bezier(.2,.8,.2,1);
        }
        .bale-menu-item {
            padding: 14px 18px; cursor: pointer; font-size: 14px; font-weight: 500;
            transition: background .15s; display: flex; align-items: center; gap: 12px;
        }
        .bale-menu-item:hover { background: var(--color-neutrals-n-20, #f4f5f7); }

        #bb-modal-overlay {
            position: fixed; inset: 0; background: rgba(0,0,0,.4); backdrop-filter: blur(3px);
            display: flex; align-items: center; justify-content: center; z-index: 9999999;
            animation: bb-fade .2s ease-out;
        }
        #bb-modal-card {
            background: var(--color-neutrals-surface, #fff); padding: 24px; border-radius: 20px;
            width: 340px; max-width: 92vw; box-shadow: 0 10px 40px rgba(0,0,0,.25);
            color: var(--color-neutrals-n-600, #151515); font-family: inherit;
            animation: bb-pop .3s cubic-bezier(.2,.8,.2,1);
        }
        .bb-modal-title { margin: 0 0 10px; font-size: 18px; font-weight: bold; }
        .bb-modal-desc  { margin: 0 0 20px; font-size: 13px; color: var(--color-neutrals-n-300, #888); }
        .bb-input {
            width: 100%; padding: 12px; border-radius: 8px;
            border: 1px solid var(--color-neutrals-n-100, #ccc);
            margin-top: 6px; box-sizing: border-box; background: transparent;
            color: inherit; font-family: inherit; font-size: 14px; transition: border-color .2s;
        }
        .bb-input:focus { outline: none; border-color: var(--color-primary-p-50, #00ab80); }
        .bb-toggle-lbl { display: flex; align-items: center; gap: 8px; font-size: 14px; cursor: pointer; }
        .bb-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 24px; }
        .bb-btn {
            padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer;
            font-weight: 600; font-size: 14px; transition: background .2s, transform .1s;
        }
        .bb-btn:active { transform: scale(.95); }
        .bb-btn-cancel { background: transparent; color: var(--color-neutrals-n-300, #888); }
        .bb-btn-cancel:hover { background: var(--color-neutrals-n-20, #f4f5f7); }
        .bb-btn-save { background: var(--color-primary-p-50, #00ab80); color: #fff; }
        .bb-btn-save:hover { background: var(--color-primary-p-60, #00916d); }

        @keyframes bb-fade { from { opacity: 0 } to { opacity: 1 } }
        @keyframes bb-pop  { from { opacity: 0; transform: scale(.95) } to { opacity: 1; transform: scale(1) } }
    </style>`,
  );

  // ─── 6. Context Menu ──────────────────────────────────────────────────────
  const popupMenu = document.createElement("div");
  popupMenu.id = "bale-bridge-menu";
  popupMenu.innerHTML = `
        <div class="bale-menu-item" id="bale-menu-enc">🔒 Send Encrypted</div>
        <div class="bale-menu-item" id="bale-menu-plain">🌐 Send Plaintext</div>`;
  document.body.appendChild(popupMenu);

  const showMenu = (x, y) => {
    Object.assign(popupMenu.style, {
      display: "flex",
      left: Math.min(x, innerWidth - 190) + "px",
      top: Math.min(y, innerHeight - 110) + "px",
    });
  };
  document.addEventListener("click", (e) => {
    if (!popupMenu.contains(e.target)) popupMenu.style.display = "none";
  });
  document.getElementById("bale-menu-enc").onclick = () => {
    popupMenu.style.display = "none";
    window._bbSend?.(true);
  };
  document.getElementById("bale-menu-plain").onclick = () => {
    popupMenu.style.display = "none";
    window._bbSend?.(false);
  };

  // ─── 7. Settings Modal ────────────────────────────────────────────────────
  function openSettingsModal() {
    const s = getChatSettings();
    document.body.insertAdjacentHTML(
      "beforeend",
      `
            <div id="bb-modal-overlay">
                <div id="bb-modal-card">
                    <h3 class="bb-modal-title">Shield Settings 🛡️</h3>
                    <p class="bb-modal-desc">Configure encryption for this specific chat.</p>
                    <label class="bb-toggle-lbl">
                        <input type="checkbox" id="bb-enable-enc" ${s.enabled ? "checked" : ""}
                            style="width:16px;height:16px;accent-color:var(--color-primary-p-50,#00ab80)">
                        <span>Enable Encryption Here</span>
                    </label>
                    <div style="margin-top:16px;border-top:1px solid var(--color-neutrals-n-20,#f4f5f7);padding-top:16px">
                        <label style="font-size:12px;color:var(--color-neutrals-n-500,#151515);font-weight:600">
                            Custom Encryption Key (Optional)
                        </label>
                        <input type="password" id="bb-custom-key" class="bb-input"
                            placeholder="Leave empty for default key..."
                            value="${s.customKey || ""}">
                        <p style="font-size:11px;color:#d32f2f;margin-top:8px;line-height:1.4;font-weight:500;text-align:right" dir="rtl">
                            ⚠️ کلید باید دقیقاً ۳۲ نویسه (Character) باشد. برای امنیت حداکثری حتماً از برنامه‌های تولید پسورد امن استفاده کنید.
                        </p>
                    </div>
                    <div class="bb-actions">
                        <button class="bb-btn bb-btn-cancel" id="bb-btn-cancel">Cancel</button>
                        <button class="bb-btn bb-btn-save" id="bb-btn-save">Save</button>
                    </div>
                </div>
            </div>`,
    );
    const overlay = document.getElementById("bb-modal-overlay");
    document.getElementById("bb-btn-cancel").onclick = () => overlay.remove();
    document.getElementById("bb-btn-save").onclick = () => {
      saveChatSettings({
        enabled: document.getElementById("bb-enable-enc").checked,
        customKey: document.getElementById("bb-custom-key").value.trim(),
      });
      overlay.remove();
      syncInputVisibility();
    };
  }

  // ─── 8. Secure Input & Shield Button ──────────────────────────────────────
  let isSending = false,
    lastHasText = false,
    isSyncing = false;

  const lockInput = (el) =>
    Object.assign(el.style, {
      position: "absolute",
      opacity: "0",
      pointerEvents: "none",
      height: "0px",
      width: "0px",
      overflow: "hidden",
      zIndex: "-9999",
    });
  const unlockInput = (el) =>
    Object.assign(el.style, {
      position: "",
      opacity: "1",
      pointerEvents: "auto",
      height: "",
      width: "100%",
      overflow: "auto",
      zIndex: "",
    });

  function syncInputVisibility() {
    const real = getRealInput();
    const secure = document.getElementById("secure-input-overlay");
    const btn = document.getElementById("bb-settings-btn");
    if (!real || !secure) return;
    const enabled = getChatSettings().enabled;
    if (enabled) {
      lockInput(real);
      secure.style.display = "";
      if (btn) btn.style.color = "var(--color-primary-p-50, #00ab80)";
    } else {
      unlockInput(real);
      secure.style.display = "none";
      if (btn) btn.style.color = "#5E6C84";
    }
  }

  function ensureSecureInput() {
    const realInput = getRealInput();
    if (!realInput) return;

    const mobile = isMobileInput(realInput);
    const wrapper = realInput.parentElement;

    // ── Shield button (replaces emoji button) ──────────────────────────
    // Desktop: role="button" aria-label="emoji-icon" .MmBErq
    // Mobile:  role="button" aria-label="emoji-icon" .MmBErq  (same structure)
    const emojiBtn =
      document.querySelector('[aria-label="emoji-icon"]') ||
      document.querySelector(".MmBErq");
    if (emojiBtn) emojiBtn.style.display = "none";

    if (emojiBtn && !document.getElementById("bb-settings-btn")) {
      const shieldBtn = document.createElement("div");
      shieldBtn.id = "bb-settings-btn";
      shieldBtn.className = emojiBtn.className;
      shieldBtn.setAttribute("role", "button");
      shieldBtn.style.cssText =
        "display:flex;align-items:center;justify-content:center;cursor:pointer;transition:color .2s";
      shieldBtn.innerHTML = `
                <div style="border-radius:50%;line-height:0;position:relative">
                    <svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10
                                 c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2
                                 s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1
                                 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                    </svg>
                </div>`;
      shieldBtn.onclick = openSettingsModal;
      emojiBtn.parentElement.insertBefore(shieldBtn, emojiBtn);
    }

    // Already set up – just refresh visibility and re-expose send trigger
    if (document.getElementById("secure-input-overlay")) {
      window._bbSend = document.getElementById(
        "secure-input-overlay",
      )._triggerSend;
      syncInputVisibility();
      return;
    }

    // ── Hijack real input (prevent user from typing directly) ──────────
    if (!realInput._hasStrictHijack) {
      realInput._hasStrictHijack = true;
      realInput.addEventListener("focus", () => {
        if (!isSyncing && getChatSettings().enabled) {
          realInput.blur();
          document.getElementById("secure-input-overlay")?.focus();
        }
      });
      ["keydown", "keypress", "keyup", "paste", "drop"].forEach((evt) =>
        realInput.addEventListener(
          evt,
          (e) => {
            if (!isSyncing && getChatSettings().enabled) {
              e.preventDefault();
              e.stopPropagation();
              document.getElementById("secure-input-overlay")?.focus();
            }
          },
          true,
        ),
      );
    }

    // ── Build the secure overlay ───────────────────────────────────────
    // Use <textarea> on mobile so the virtual keyboard opens correctly.
    // Use <div contenteditable> on desktop to match Bale's own element.
    let secureInput;
    if (mobile) {
      secureInput = document.createElement("textarea");
      secureInput.id = "secure-input-overlay";
      secureInput.dir = "auto";
      secureInput.placeholder = "🔒 پیام امن...";
      secureInput.rows = 1;
      // Auto-resize to content
      secureInput.addEventListener("input", () => {
        secureInput.style.height = "auto";
        secureInput.style.height =
          Math.min(secureInput.scrollHeight, 150) + "px";
      });
    } else {
      secureInput = document.createElement("div");
      secureInput.id = "secure-input-overlay";
      secureInput.contentEditable = "true";
      secureInput.dir = "auto";
      secureInput.dataset.placeholder = "🔒 پیام امن...";
      wrapper.style.overflow = "visible";
    }
    secureInput.className = realInput.className;
    wrapper.insertBefore(secureInput, realInput);

    // ── Text accessors (abstract desktop vs mobile) ────────────────────
    const getText = () =>
      mobile ? secureInput.value.trim() : secureInput.innerText.trim();
    const setText = (v) => {
      if (mobile) secureInput.value = v;
      else secureInput.innerText = v;
    };

    // ── Sync "has text" state to real input (shows/hides send button) ──
    const syncHasText = (hasText) => {
      if (hasText === lastHasText) return;
      lastHasText = hasText;
      isSyncing = true;
      if (mobile) {
        // On mobile: use native setter so React detects the change
        _textareaSetter?.call(realInput, hasText ? " " : "");
        realInput.dispatchEvent(new Event("input", { bubbles: true }));
      } else {
        const sel = window.getSelection();
        const range = sel.rangeCount > 0 ? sel.getRangeAt(0) : null;
        realInput.focus();
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, hasText ? " " : "");
        realInput.dispatchEvent(new Event("input", { bubbles: true }));
        realInput.dispatchEvent(new Event("change", { bubbles: true }));
        secureInput.focus();
        if (range) {
          sel.removeAllRanges();
          sel.addRange(range);
        }
      }
      isSyncing = false;
    };
    secureInput.addEventListener("input", () =>
      syncHasText(getText().length > 0),
    );

    // ── Send ──────────────────────────────────────────────────────────
    const triggerSend = async (doEncrypt = true) => {
      if (isSending) return;
      const text = getText();
      if (!text) return;
      isSending = true;
      isSyncing = true;
      setText(doEncrypt ? "🔒 Encrypting..." : "🌐 Sending...");
      try {
        const out = doEncrypt ? await encrypt(text) : text;

        unlockInput(realInput);
        if (mobile) {
          _textareaSetter?.call(realInput, out);
          realInput.dispatchEvent(new Event("input", { bubbles: true }));
        } else {
          realInput.focus();
          document.execCommand("selectAll", false, null);
          document.execCommand("insertText", false, out);
          realInput.dispatchEvent(new Event("input", { bubbles: true }));
        }

        await new Promise((r) => setTimeout(r, 50));

        const sendBtn = document.querySelector('[aria-label="send-button"]');
        if (sendBtn) {
          sendBtn.click();
        } else {
          realInput.dispatchEvent(
            new KeyboardEvent("keydown", {
              bubbles: true,
              cancelable: true,
              key: "Enter",
              keyCode: 13,
            }),
          );
        }

        setText("");
        lastHasText = false;

        await new Promise((r) => setTimeout(r, 50));

        if (mobile) {
          _textareaSetter?.call(realInput, "");
          realInput.dispatchEvent(new Event("input", { bubbles: true }));
        } else {
          realInput.focus();
          document.execCommand("selectAll", false, null);
          document.execCommand("insertText", false, "");
          realInput.dispatchEvent(new Event("input", { bubbles: true }));
        }

        lockInput(realInput);
        secureInput.focus();
      } catch (e) {
        console.error("[Bale Bridge] Send failed:", e);
        setText(text);
        alert("Send failed!");
      } finally {
        isSending = false;
        isSyncing = false;
      }
    };

    secureInput._triggerSend = triggerSend;
    window._bbSend = triggerSend;

    // Enter = send (Shift+Enter = newline)
    secureInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        e.stopPropagation();
        triggerSend(true);
      }
    });

    syncInputVisibility();
  }

  // ─── 9. Send Button Event Interception ───────────────────────────────────
  const getSecureText = () => {
    const si = document.getElementById("secure-input-overlay");
    return si
      ? si.tagName === "TEXTAREA"
        ? si.value.trim()
        : si.innerText.trim()
      : "";
  };
  const isSendBtn = (t) => !!t.closest('[aria-label="send-button"]');

  document.addEventListener(
    "mousedown",
    (e) => {
      if (e.button !== 0 || isSending || !isSendBtn(e.target)) return;
      if (!getChatSettings().enabled || !getSecureText()) return;
      e.preventDefault();
      e.stopPropagation();
      window._bbSend?.(true);
    },
    true,
  );

  document.addEventListener(
    "contextmenu",
    (e) => {
      if (!isSendBtn(e.target) || isSending) return;
      if (!getChatSettings().enabled || !getSecureText()) return;
      e.preventDefault();
      e.stopPropagation();
      showMenu(e.clientX, e.clientY);
    },
    true,
  );

  let touchTimer = null;
  document.addEventListener(
    "touchstart",
    (e) => {
      if (!isSendBtn(e.target) || isSending) return;
      if (!getChatSettings().enabled || !getSecureText()) return;
      touchTimer = setTimeout(() => {
        e.preventDefault();
        showMenu(e.touches[0].clientX, e.touches[0].clientY);
      }, 500);
    },
    { passive: false, capture: true },
  );
  document.addEventListener("touchend", () => clearTimeout(touchTimer), true);
  document.addEventListener("touchmove", () => clearTimeout(touchTimer), true);

  // ─── 10. MutationObserver & SPA URL Tracker ───────────────────────────────
  let scanTO = null,
    lastUrl = location.href;
  new MutationObserver(() => {
    clearTimeout(scanTO);
    scanTO = setTimeout(() => {
      scanTree(document.body);
      ensureSecureInput();
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        syncInputVisibility();
      }
    }, 100);
  }).observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
  });
})();
