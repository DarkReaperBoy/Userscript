// ==UserScript==
// @name         Rubika Bridge Encryptor/Decryptor (Ultimate Privacy)
// @namespace    http://tampermonkey.net/
// @version      3.0
// @description  Per-chat encryption keys, Shield button, Markdown UI, Auto-decrypt, Draft blocker. Desktop + Mobile.
// @author       You
// @match        *://web.rubika.ir/*
// @grant        none
// ==/UserScript==
!function(){"use strict";

const ALGO = "AES-GCM";
const COMPRESS = "deflate";
const SETTINGS_PREFIX = "rubika_bridge_settings_";
const BASE85_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
const KEY_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~";
const HTML_ESC = {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"};
const URL_RE = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;

let cachedChatId = null;
let cachedSettings = null;

// ── Platform detection ──
function isMobile() {
    return document.body.classList.contains("is-mobile");
}

// ── Chat ID ──
function getChatId() {
    let h = location.hash;
    if (h.startsWith("#c=")) return h.slice(3);
    let p = new URLSearchParams(location.search);
    return p.get("uid") || p.get("groupId") || p.get("channelId") || location.pathname.split("/").pop() || "global";
}

// ── Settings ──
function getSettings() {
    let id = getChatId();
    if (id === cachedChatId && cachedSettings !== null) return cachedSettings;
    let raw = localStorage.getItem(SETTINGS_PREFIX + id);
    cachedSettings = raw ? JSON.parse(raw) : { enabled: true, customKey: "" };
    cachedChatId = id;
    return cachedSettings;
}

function saveSettings(s) {
    let id = getChatId();
    cachedSettings = s;
    cachedChatId = id;
    localStorage.setItem(SETTINGS_PREFIX + id, JSON.stringify(s));
}

function getKey() {
    let s = getSettings();
    return s.enabled && s.customKey && s.customKey.length === 32 ? s.customKey : null;
}

function isEnabled() {
    return getSettings().enabled;
}

// ── Crypto helpers ──
const keyCache = new Map();

async function deriveKey(k) {
    if (keyCache.has(k)) return keyCache.get(k);
    let raw = new Uint8Array(32);
    raw.set(new TextEncoder().encode(k).subarray(0, 32));
    let key = await crypto.subtle.importKey("raw", raw, { name: ALGO }, false, ["encrypt", "decrypt"]);
    keyCache.set(k, key);
    return key;
}

async function compress(text) {
    let cs = new CompressionStream(COMPRESS);
    let w = cs.writable.getWriter();
    w.write(new TextEncoder().encode(text));
    w.close();
    return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function decompress(data) {
    let ds = new DecompressionStream(COMPRESS);
    let w = ds.writable.getWriter();
    w.write(data);
    w.close();
    return new TextDecoder().decode(await new Response(ds.readable).arrayBuffer());
}

// ── Base85 ──
const B85_DECODE = new Uint8Array(128);
for (let i = 0; i < BASE85_CHARS.length; i++) B85_DECODE[BASE85_CHARS.charCodeAt(i)] = i;

function base85encode(bytes) {
    let n = bytes.length, rem = n % 4;
    let out = Array(5 * (n >>> 2) + (rem ? rem + 1 : 0));
    let idx = 0;
    for (let i = 0; i < n; i += 4) {
        let cnt = Math.min(4, n - i), val = 0;
        for (let j = 0; j < 4; j++) val = (val << 8) | (i + j < n ? bytes[i + j] : 0);
        val >>>= 0;
        let outCnt = cnt < 4 ? cnt + 1 : 5;
        let tmp = [,,,,, ];
        for (let j = 4; j >= 0; j--) { tmp[j] = BASE85_CHARS[val % 85]; val = Math.floor(val / 85); }
        for (let j = 0; j < outCnt; j++) out[idx++] = tmp[j];
    }
    return out.join("");
}

function base85decode(str) {
    let n = str.length, rem = n % 5;
    let out = new Uint8Array(4 * Math.floor(n / 5) + (rem ? rem - 1 : 0));
    let idx = 0;
    for (let i = 0; i < n; i += 5) {
        let end = Math.min(i + 5, n), skip = 5 - (end - i), val = 0;
        for (let j = 0; j < 5; j++) {
            let ch = i + j < n ? str.charCodeAt(i + j) : 126;
            val = val * 85 + B85_DECODE[ch];
        }
        let cnt = 4 - skip;
        if (cnt >= 1) out[idx++] = (val >>> 24) & 0xFF;
        if (cnt >= 2) out[idx++] = (val >>> 16) & 0xFF;
        if (cnt >= 3) out[idx++] = (val >>> 8) & 0xFF;
        if (cnt >= 4) out[idx++] = val & 0xFF;
    }
    return out.subarray(0, idx);
}

// ── Encrypt / Decrypt ──
async function encrypt(text) {
    let k = getKey();
    if (!k) return null;
    let iv = crypto.getRandomValues(new Uint8Array(12));
    let comp = await compress(text);
    let aesKey = await deriveKey(k);
    let enc = new Uint8Array(await crypto.subtle.encrypt({ name: ALGO, iv }, aesKey, comp));
    let combined = new Uint8Array(12 + enc.length);
    combined.set(iv);
    combined.set(enc, 12);
    return "@@" + base85encode(combined);
}

async function decrypt(text) {
    if (!text.startsWith("@@")) return text;
    let k = getKey();
    if (!k) return text;
    try {
        let data = base85decode(text.slice(2));
        let iv = data.subarray(0, 12);
        let ct = data.subarray(12);
        let aesKey = await deriveKey(k);
        let dec = await crypto.subtle.decrypt({ name: ALGO, iv }, aesKey, ct);
        return await decompress(new Uint8Array(dec));
    } catch { return text; }
}

async function splitEncrypt(text) {
    let result = await encrypt(text);
    if (!result) return null;
    if (result.length <= 4000) return [result];
    let mid = Math.floor(text.length / 2);
    let splitAt = text.lastIndexOf("\n", mid);
    if (splitAt <= 0) splitAt = text.lastIndexOf(" ", mid);
    if (splitAt <= 0) splitAt = mid;
    let a = await splitEncrypt(text.slice(0, splitAt).trim());
    let b = await splitEncrypt(text.slice(splitAt).trim());
    return a && b ? [...a, ...b] : null;
}

// ── Markdown rendering ──
function escapeHtml(s) { return s.replace(/[&<>"]/g, c => HTML_ESC[c]); }

function renderInline(s) {
    return s
        .replace(/``([^`]+)``|`([^`]+)`/g, (_, a, b) =>
            `<code style="background:var(--color-neutrals-n-20,#f4f5f7);border-radius:4px;padding:1px 5px;font-family:monospace;font-size:.92em">${a ?? b}</code>`)
        .replace(/\|\|(.+?)\|\|/g, (_, t) =>
            `<span class="bb-spoiler" style="background:var(--color-neutrals-n-400,#42526e);color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none" title="Click to reveal">${t}</span>`)
        .replace(/\*\*\*(.+?)\*\*\*/g, (_, t) => `<strong><em>${t}</em></strong>`)
        .replace(/\*\*(.+?)\*\*/g, (_, t) => `<strong>${t}</strong>`)
        .replace(/(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g, (_, t) => `<u>${t}</u>`)
        .replace(/\*([^*\n]+)\*/g, (_, t) => `<em>${t}</em>`)
        .replace(/(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g, (_, p, t) => `${p}<em>${t}</em>`)
        .replace(/~~(.+?)~~/g, (_, t) => `<del>${t}</del>`)
        .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_, t, u) =>
            `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer" style="color:#00ab80;text-decoration:underline">${t}</a>`);
}

function renderWithUrls(s) {
    let parts = [], last = 0;
    URL_RE.lastIndex = 0;
    let m;
    while ((m = URL_RE.exec(s)) !== null) {
        parts.push(renderInline(escapeHtml(s.slice(last, m.index))));
        let u = escapeHtml(m[0]);
        parts.push(`<a href="${u}" target="_blank" rel="noopener noreferrer" style="color:#00ab80;text-decoration:underline;word-break:break-all">${u}</a>`);
        last = m.index + m[0].length;
    }
    parts.push(renderInline(escapeHtml(s.slice(last))));
    return parts.join("");
}

function renderMarkdown(text) {
    let lines = text.split("\n"), result = [], i = 0;
    const wrapBlock = html => `<span dir="auto" class="bb-block" style="display:block;unicode-bidi:plaintext;">${html}</span>`;

    while (i < lines.length) {
        let line = lines[i];
        if (line.startsWith("> ") || line === ">") {
            let qLines = [];
            while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">"))
                qLines.push(lines[i++].replace(/^> ?/, ""));
            result.push(`<span dir="auto" class="bb-quote" style="display:block;border-inline-start:3px solid #00ab80;padding:2px 10px;margin:2px 0;font-style:italic;opacity:0.9;unicode-bidi:plaintext;">${qLines.map(renderWithUrls).join("<br>")}</span>`);
            continue;
        }
        if (/^[-*+] /.test(line)) {
            let items = [];
            while (i < lines.length && /^[-*+] /.test(lines[i]))
                items.push(`<li style="margin:2px 0;padding-inline-start:2px">${renderWithUrls(lines[i++].slice(2))}</li>`);
            result.push(`<ul dir="auto" style="margin:4px 0;padding-inline-start:22px;list-style:disc;unicode-bidi:plaintext;">${items.join("")}</ul>`);
            continue;
        }
        if (/^\d+\. /.test(line)) {
            let items = [];
            while (i < lines.length && /^\d+\. /.test(lines[i]))
                items.push(`<li style="margin:2px 0;padding-inline-start:2px">${renderWithUrls(lines[i++].replace(/^\d+\. /, ""))}</li>`);
            result.push(`<ol dir="auto" style="margin:4px 0;padding-inline-start:22px;list-style:decimal;unicode-bidi:plaintext;">${items.join("")}</ol>`);
            continue;
        }
        let hMatch = line.match(/^(#{1,3}) (.+)/);
        if (hMatch) {
            let sizes = ["1.25em", "1.1em", "1em"];
            let lvl = Math.min(hMatch[1].length, 3) - 1;
            result.push(wrapBlock(`<span style="font-weight:700;font-size:${sizes[lvl]}">${renderWithUrls(hMatch[2])}</span>`));
            i++; continue;
        }
        if (/^([-*_])\1{2,}$/.test(line.trim())) {
            result.push('<span style="display:block;border-top:1px solid #ccc;margin:6px 0;"></span>');
            i++; continue;
        }
        if (line.trim() !== "") {
            result.push(wrapBlock(renderWithUrls(line)));
            i++; continue;
        }
        result.push('<span style="display:block;height:0.4em;"></span>');
        i++;
    }
    return result.join("");
}

// ── Context menu ──
let ctxMenu = null;

function showCtxMenu(x, y) {
    Object.assign(ctxMenu.style, {
        display: "flex",
        left: Math.min(x, innerWidth - 210) + "px",
        top: Math.min(y, innerHeight - 120) + "px"
    });
}

function hideCtxMenu() { ctxMenu.style.display = "none"; }

// ── Settings modal ──
function openSettings() {
    document.getElementById("bb-modal-overlay")?.remove();
    let s = getSettings();
    document.body.insertAdjacentHTML("beforeend", `
    <div id="bb-modal-overlay">
        <div id="bb-modal-card">
            <h3 class="bb-modal-title">Shield Settings 🛡️</h3>
            <p class="bb-modal-desc">Configure encryption for this chat. When enabled, a 32-character key is required.</p>
            <label class="bb-toggle-lbl">
                <input type="checkbox" id="bb-enable-enc" ${s.enabled ? "checked" : ""} style="width:16px;height:16px;accent-color:#00ab80">
                <span>Enable Encryption Here</span>
            </label>
            <div id="bb-key-section" style="margin-top:16px;border-top:1px solid #f4f5f7;padding-top:16px">
                <label style="font-size:12px;color:#151515;font-weight:600">Encryption Key <span style="color:#d32f2f">*</span></label>
                <div class="bb-key-row">
                    <input type="password" id="bb-custom-key" class="bb-input" placeholder="Enter exactly 32 characters…" maxlength="32" value="${s.customKey || ""}">
                    <button class="bb-icon-btn" id="bb-toggle-vis" title="Show / hide key">👁</button>
                    <button class="bb-icon-btn" id="bb-copy-key" title="Copy key">📋</button>
                </div>
                <div class="bb-key-tools">
                    <button class="bb-tool-btn" id="bb-gen-key">⚡ Generate Random Key</button>
                </div>
                <div class="bb-key-meta">
                    <span class="bb-key-error" id="bb-key-error"></span>
                    <span class="bb-key-counter" id="bb-key-counter">0 / 32</span>
                </div>
            </div>
            <div class="bb-actions">
                <button class="bb-btn bb-btn-cancel" id="bb-btn-cancel">Cancel</button>
                <button class="bb-btn bb-btn-save" id="bb-btn-save">Save</button>
            </div>
        </div>
    </div>`);

    let overlay = document.getElementById("bb-modal-overlay");
    let keyInput = document.getElementById("bb-custom-key");
    let keySection = document.getElementById("bb-key-section");
    let counter = document.getElementById("bb-key-counter");
    let error = document.getElementById("bb-key-error");
    let saveBtn = document.getElementById("bb-btn-save");
    let enableChk = document.getElementById("bb-enable-enc");
    let copyBtn = document.getElementById("bb-copy-key");
    let genBtn = document.getElementById("bb-gen-key");
    let visBtn = document.getElementById("bb-toggle-vis");

    function validate() {
        let len = keyInput.value.length;
        let on = enableChk.checked;
        counter.textContent = `${len} / 32`;
        counter.className = "bb-key-counter" + (len === 32 ? " exact" : "");
        keySection.style.display = on ? "" : "none";
        if (!on) { error.textContent = ""; saveBtn.disabled = false; return; }
        if (len === 0) { error.textContent = "A key is required when encryption is enabled."; saveBtn.disabled = true; }
        else if (len !== 32) { error.textContent = `Key must be exactly 32 characters (currently ${len}).`; saveBtn.disabled = true; }
        else { error.textContent = ""; saveBtn.disabled = false; }
    }

    keyInput.addEventListener("input", validate);
    enableChk.addEventListener("change", validate);
    validate();

    visBtn.addEventListener("click", () => {
        let show = keyInput.type === "password";
        keyInput.type = show ? "text" : "password";
        visBtn.textContent = show ? "🙈" : "👁";
    });

    copyBtn.addEventListener("click", () => {
        if (keyInput.value) {
            navigator.clipboard.writeText(keyInput.value).then(() => {
                copyBtn.textContent = "✅";
                copyBtn.classList.add("copied");
                setTimeout(() => { copyBtn.textContent = "📋"; copyBtn.classList.remove("copied"); }, 1500);
            });
        }
    });

    genBtn.addEventListener("click", () => {
        let bytes = crypto.getRandomValues(new Uint8Array(32));
        keyInput.value = Array.from(bytes, b => KEY_CHARS[b % KEY_CHARS.length]).join("");
        keyInput.type = "text";
        visBtn.textContent = "🙈";
        validate();
    });

    document.getElementById("bb-btn-cancel").onclick = () => overlay.remove();
    saveBtn.onclick = () => {
        if (saveBtn.disabled) return;
        saveSettings({ enabled: enableChk.checked, customKey: keyInput.value });
        overlay.remove();
        refreshUI();
    };
}

// ── Shield icons ──
const ICONS = {
    active: `<svg width="24" height="24" fill="#00ab80" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>`,
    missingKey: `<svg width="24" height="24" fill="#d32f2f" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h1.39v4.19H10.6v-4.19H12zM12 9.17c-.77 0-1.39-.62-1.39-1.39 0-.77.62-1.39 1.39-1.39.77 0 1.39.62 1.39 1.39 0 .77-.62 1.39-1.39 1.39z"/></svg>`,
    disabled: `<svg width="24" height="24" fill="#888" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 19.93c-3.95-1.17-6.9-5.11-7.7-9.43l7.7-3.42 7.7 3.42c-.8 4.32-3.75 8.26-7.7 9.43z"/></svg>`
};

// ── Find elements (cross-platform) ──
function findTextarea() {
    return document.querySelector(".composer_rich_textarea[contenteditable]");
}

function findInputContainer() {
    return document.querySelector(".input-message-container");
}

function findInputWrapper() {
    // The scrollable wrapper that contains the textarea
    return document.querySelector(".input-message-input.scrollable");
}

function findSendButton() {
    return document.querySelector(".btn-send-container .btn-send") ||
           document.querySelector(".btn-send") ||
           document.querySelector(".btn-send-container");
}

function findEmojiButton() {
    return document.querySelector("button.toggle-emoticons");
}

function findNewMessageWrapper() {
    return document.querySelector(".new-message-wrapper");
}

// ── Send button state ──
function setSendButtonState(hasText) {
    let btn = findSendButton();
    if (!btn) return;

    if (hasText) {
        if (btn.classList.contains("send") && !btn.classList.contains("record")) return;
        btn.classList.remove("record");
        btn.classList.add("send");
        let mic = btn.querySelector(".rbico-microphone");
        if (mic) mic.setAttribute("hidden", "true");
        let send = btn.querySelector(".rbico-send");
        if (send) send.removeAttribute("hidden");
        // Handle ripple visibility for mobile
        let rrRipple = btn.querySelector(".rr.c-ripple");
        let ttRipple = btn.querySelector(".tt.c-ripple");
        if (rrRipple) rrRipple.removeAttribute("hidden");
        if (ttRipple) ttRipple.setAttribute("hidden", "true");
    } else {
        if (btn.classList.contains("record") && !btn.classList.contains("send")) return;
        btn.classList.remove("send");
        btn.classList.add("record");
        let send = btn.querySelector(".rbico-send");
        if (send) send.setAttribute("hidden", "true");
        let mic = btn.querySelector(".rbico-microphone");
        if (mic) mic.removeAttribute("hidden");
        let rrRipple = btn.querySelector(".rr.c-ripple");
        let ttRipple = btn.querySelector(".tt.c-ripple");
        if (rrRipple) rrRipple.setAttribute("hidden", "true");
        if (ttRipple) ttRipple.removeAttribute("hidden");
    }
}

// ── UI refresh ──
function refreshUI() {
    let inputContainer = findInputContainer();
    if (!inputContainer) return;

    let inputWrapper = findInputWrapper();
    let overlay = document.getElementById("secure-input-overlay");
    let notice = document.getElementById("bb-no-key-notice");
    let shieldBtn = document.getElementById("bb-settings-btn");
    let textarea = findTextarea();

    if (!inputWrapper && !textarea) return;

    let on = isEnabled();
    let hasKey = !!getKey();

    if (shieldBtn) {
        if (on && hasKey) { shieldBtn.innerHTML = ICONS.active; shieldBtn.title = "Encryption Active - Click to configure"; }
        else if (on && !hasKey) { shieldBtn.innerHTML = ICONS.missingKey; shieldBtn.title = "Encryption Active (No Key) - Click to configure"; }
        else { shieldBtn.innerHTML = ICONS.disabled; shieldBtn.title = "Encryption Disabled - Click to enable"; }
    }

    // For mobile, the textarea IS the input (no separate scrollable wrapper)
    let hideTarget = inputWrapper || textarea;

    if (on) {
        if (hasKey) {
            if (hideTarget) hideTarget.classList.add("rb-locked-input");
            if (overlay) overlay.style.display = "";
            if (notice) notice.style.display = "none";
        } else {
            if (hideTarget) hideTarget.classList.add("rb-locked-input");
            if (overlay) overlay.style.display = "none";
            if (notice) notice.style.display = "flex";
        }
    } else {
        if (hideTarget) hideTarget.classList.remove("rb-locked-input");
        if (overlay) overlay.style.display = "none";
        if (notice) notice.style.display = "none";
    }
}

// ── State flags ──
let isSending = false;
let hasContent = false;
let isBypass = false;

function overlayHasContent() {
    let el = document.getElementById("secure-input-overlay");
    return !!el && !!el.innerText.trim();
}

function isSendTarget(el) {
    return !!el.closest(".btn-send-container") || !!el.closest(".btn-send") ||
           (el.classList && (el.classList.contains("btn-send") || el.classList.contains("btn-send-container")));
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Draft blocker ──
(function() {
    let origSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function(data) {
        try {
            let str = typeof data === "string" ? data : new TextDecoder().decode(data);
            if (str.includes("EditParameter") && str.includes("drafts_")) return;
        } catch {}
        return origSend.apply(this, arguments);
    };
})();

// ── Styles ──
document.head.insertAdjacentHTML("beforeend", `<style>
/* Hide original emoji button */
button.toggle-emoticons { display: none !important; }

/* Hide original input when encryption is active */
.rb-locked-input {
    position: absolute !important;
    left: -9999px !important;
    top: -9999px !important;
    opacity: 0 !important;
    pointer-events: none !important;
    z-index: -1 !important;
    width: 0 !important;
    height: 0 !important;
    overflow: hidden !important;
}

/* Secure input overlay */
#secure-input-overlay {
    flex: 1; width: 100%; box-sizing: border-box;
    min-height: 40px; max-height: 150px; overflow-y: auto;
    background-color: transparent;
    border: 2px solid #00ab80; border-radius: 16px;
    padding: 10px 16px;
    font-family: inherit; font-size: 14px;
    outline: none; white-space: pre-wrap; word-break: break-word;
    color: inherit; z-index: 100; position: relative;
    transition: box-shadow .2s ease, border-color .2s ease;
    margin: 5px 0; cursor: text;
    -webkit-user-select: text;
    user-select: text;
    -webkit-overflow-scrolling: touch;
}
#secure-input-overlay:focus {
    box-shadow: 0 4px 16px rgba(0,171,128,.3);
    border-color: #00916d;
}
#secure-input-overlay:empty::before {
    content: attr(data-placeholder);
    color: #888; pointer-events: none; display: block;
}

/* Mobile adjustments */
.is-mobile #secure-input-overlay {
    min-height: 36px;
    padding: 8px 12px;
    font-size: 16px; /* prevent iOS zoom */
    border-radius: 20px;
    margin: 3px 0;
}
.is-mobile #bb-settings-btn {
    width: 36px !important;
    height: 36px !important;
}

/* No-key warning notice */
#bb-no-key-notice {
    display: none; align-items: flex-start; gap: 10px; flex: 1;
    width: 100%; box-sizing: border-box; padding: 10px 14px;
    background: rgba(211,47,47,0.1); border: 2px solid #d32f2f;
    border-radius: 16px; font-family: inherit; font-size: 13px;
    color: inherit; line-height: 1.5;
    position: relative; z-index: 101; margin: 5px 0;
}
#bb-no-key-notice .bb-notice-icon { font-size: 20px; flex-shrink: 0; margin-top: 1px; }
#bb-no-key-notice .bb-notice-body { flex: 1; }
#bb-no-key-notice strong { display: block; font-size: 13px; margin-bottom: 3px; color: #d32f2f; }
#bb-no-key-notice .bb-notice-btn {
    display: inline-block; margin-top: 7px; padding: 5px 12px;
    border-radius: 8px; border: none;
    background: #d32f2f; color: #fff;
    font-size: 12px; font-weight: 700; cursor: pointer;
    transition: background .15s;
}
#bb-no-key-notice .bb-notice-btn:hover { background: #b71c1c; }

/* Context menu */
#bale-bridge-menu {
    position: fixed; z-index: 999999; background: #fff;
    border: 1px solid #dfe1e6; border-radius: 12px;
    box-shadow: 0 8px 24px rgba(0,0,0,.15);
    display: none; flex-direction: column; overflow: hidden;
    font-family: inherit; color: #091e42; min-width: 180px;
    animation: bb-pop .2s cubic-bezier(.2,.8,.2,1);
}
.bale-menu-item {
    padding: 14px 18px; cursor: pointer; font-size: 14px;
    font-weight: 500; transition: background .15s;
    display: flex; align-items: center; gap: 12px;
}
.bale-menu-item:hover { background: #f4f5f7; }
.bale-menu-item:active { background: #e8e8e8; }

/* Settings modal */
#bb-modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,.4);
    backdrop-filter: blur(3px);
    display: flex; align-items: center; justify-content: center;
    z-index: 9999999; animation: bb-fade .2s ease-out;
}
#bb-modal-card {
    background: #fff; padding: 24px; border-radius: 20px;
    width: 360px; max-width: 92vw;
    box-shadow: 0 10px 40px rgba(0,0,0,.25);
    color: #151515; font-family: inherit;
    animation: bb-pop .3s cubic-bezier(.2,.8,.2,1);
    max-height: 90vh; overflow-y: auto;
}
.bb-modal-title { margin: 0 0 10px; font-size: 18px; font-weight: bold; }
.bb-modal-desc { margin: 0 0 20px; font-size: 13px; color: #888; }
.bb-input {
    width: 100%; padding: 10px 12px; border-radius: 8px;
    border: 1px solid #ccc; box-sizing: border-box;
    background: transparent; color: inherit;
    font-family: monospace; font-size: 13px;
    transition: border-color .2s; letter-spacing: .04em;
}
.bb-input:focus { outline: none; border-color: #00ab80; }
.bb-key-row { display: flex; gap: 8px; align-items: center; margin-top: 6px; }
.bb-key-row .bb-input { flex: 1; margin-top: 0; }
.bb-icon-btn {
    flex-shrink: 0; padding: 0; width: 36px; height: 36px;
    border-radius: 8px; border: 1px solid #ccc;
    background: transparent; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px; transition: background .15s, border-color .15s;
    color: inherit;
}
.bb-icon-btn:hover { background: #f4f5f7; border-color: #00ab80; }
.bb-icon-btn.copied { background: #e8f5e9; border-color: #43a047; color: #43a047; }
.bb-key-tools { display: flex; gap: 8px; margin-top: 8px; }
.bb-tool-btn {
    flex: 1; padding: 7px 0; border-radius: 8px;
    border: 1px solid #ccc; background: transparent;
    cursor: pointer; font-size: 12px; font-weight: 600;
    display: flex; align-items: center; justify-content: center; gap: 5px;
    transition: background .15s, border-color .15s; color: inherit;
}
.bb-tool-btn:hover { background: #f4f5f7; border-color: #00ab80; }
.bb-toggle-lbl { display: flex; align-items: center; gap: 8px; font-size: 14px; cursor: pointer; }
.bb-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 24px; }
.bb-btn {
    padding: 8px 16px; border-radius: 8px; border: none;
    cursor: pointer; font-weight: 600; font-size: 14px;
    transition: background .2s, transform .1s;
}
.bb-btn:active { transform: scale(.95); }
.bb-btn-cancel { background: transparent; color: #888; }
.bb-btn-cancel:hover { background: #f4f5f7; }
.bb-btn-save { background: #00ab80; color: #fff; }
.bb-btn-save:hover { background: #00916d; }
.bb-btn-save:disabled { background: #ccc; cursor: not-allowed; transform: none; }
.bb-key-meta { display: flex; justify-content: space-between; align-items: center; margin-top: 6px; font-size: 11px; }
.bb-key-counter { color: #888; }
.bb-key-counter.exact { color: #00ab80; font-weight: 600; }
.bb-key-error { color: #d32f2f; font-weight: 500; font-size: 11px; min-height: 16px; }

@keyframes bb-fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes bb-pop { from { opacity: 0; transform: scale(.95); } to { opacity: 1; transform: scale(1); } }
</style>`);

// ── Spoiler click handler ──
document.addEventListener("click", e => {
    let sp = e.target.closest(".bb-spoiler");
    if (sp) { sp.style.color = "inherit"; sp.style.background = "#dfe1e6"; }
}, true);

// ── Context menu setup ──
ctxMenu = document.createElement("div");
ctxMenu.id = "bale-bridge-menu";
ctxMenu.innerHTML = `
    <div class="bale-menu-item" id="bale-menu-enc">🔒 Send Encrypted</div>
    <div class="bale-menu-item" id="bale-menu-plain">⚠️ Send Unencrypted</div>`;
document.body.appendChild(ctxMenu);

document.getElementById("bale-menu-enc").onclick = () => { hideCtxMenu(); window._bbSendMessage?.(true); };
document.getElementById("bale-menu-plain").onclick = () => { hideCtxMenu(); window._bbSendMessage?.(false); };

document.addEventListener("click", e => { if (!ctxMenu.contains(e.target)) hideCtxMenu(); });

// ── Desktop: mouse events for send button ──
document.addEventListener("mousedown", e => {
    if (e.button === 0 && !isSending && isSendTarget(e.target) && isEnabled() && overlayHasContent()) {
        e.preventDefault(); e.stopPropagation();
        window._bbSendMessage?.(true);
    }
}, true);

document.addEventListener("contextmenu", e => {
    if (isSendTarget(e.target) && !isSending && isEnabled() && overlayHasContent()) {
        e.preventDefault(); e.stopPropagation();
        showCtxMenu(e.clientX, e.clientY);
    }
}, true);

// ── Mobile: touch events for send button ──
let longPressTimer = null;
let touchHandled = false;

document.addEventListener("touchstart", e => {
    if (!isSendTarget(e.target) || isSending) return;
    if (!isEnabled() || !overlayHasContent()) return;

    touchHandled = false;

    // Long press for context menu
    longPressTimer = setTimeout(() => {
        touchHandled = true;
        e.preventDefault();
        let touch = e.touches[0];
        showCtxMenu(touch.clientX, touch.clientY);
    }, 500);
}, { passive: false, capture: true });

document.addEventListener("touchend", e => {
    clearTimeout(longPressTimer);
    if (!isSendTarget(e.target) || isSending) return;
    if (!isEnabled() || !overlayHasContent()) return;

    if (touchHandled) {
        touchHandled = false;
        e.preventDefault();
        e.stopPropagation();
        return;
    }

    // Normal tap = encrypted send
    e.preventDefault();
    e.stopPropagation();
    window._bbSendMessage?.(true);
}, { passive: false, capture: true });

document.addEventListener("touchmove", () => {
    clearTimeout(longPressTimer);
    touchHandled = false;
}, true);

// ── Also intercept click on send button (mobile sometimes fires click after touch) ──
document.addEventListener("click", e => {
    if (isSendTarget(e.target) && !isSending && isEnabled() && overlayHasContent()) {
        e.preventDefault();
        e.stopPropagation();
        // Don't double-send; touchend already handles it
    }
}, true);

// ── Auto-decrypt messages ──
function decryptMessages() {
    let nodes = document.body.querySelectorAll("div[rb-copyable]");
    for (let node of nodes) {
        if (node._isDecrypting) continue;
        let text = node.textContent.trim();

        if (node._isDecrypted) {
            if (!text.startsWith("@@") || node.querySelector(".bb-copy-btn")) continue;
            node._isDecrypted = false;
            node.removeAttribute("data-orig-text");
        }

        if (!text.startsWith("@@") || text.length <= 20) continue;

        if (!node.hasAttribute("data-orig-text")) node.setAttribute("data-orig-text", text);
        let raw = node.getAttribute("data-orig-text").replace(/\s/g, "");
        node._isDecrypting = true;

        decrypt(raw).then(dec => {
            if (dec !== raw) {
                node.style.overflow = "hidden";
                node.style.overflowWrap = "anywhere";
                node.style.wordBreak = "break-word";
                node.style.maxWidth = "100%";
                node.style.color = "inherit";
                node.innerHTML = renderMarkdown(dec) + `<span style="display:inline-block;font-size:9px;opacity:0.5;letter-spacing:0.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap">
                    🔒 encrypted
                    <span class="bb-copy-btn" title="Copy decrypted message" style="cursor:pointer;margin-inline-start:4px;font-size:11px;font-style:normal;transition:opacity 0.2s;">📋</span>
                </span>`;
                node._isDecrypted = true;
                let copyBtn = node.querySelector(".bb-copy-btn");
                if (copyBtn) {
                    copyBtn.addEventListener("click", ev => {
                        ev.preventDefault(); ev.stopPropagation();
                        navigator.clipboard.writeText(dec).then(() => {
                            copyBtn.textContent = "✅";
                            setTimeout(() => copyBtn.textContent = "📋", 1500);
                        });
                    });
                }
            } else {
                if (!node._hasLockBadge) {
                    node.innerHTML = `
                        <span style="word-break:break-all; opacity:0.6;">${raw}</span><br>
                        <span style="font-size:11px; color:#d32f2f; font-weight:bold; margin-top:4px; display:inline-block;">
                            🔒 Encrypted (Need Key)
                        </span>`;
                    node._hasLockBadge = true;
                }
            }
        }).finally(() => { node._isDecrypting = false; });
    }
}

// ── Inject secure input UI ──
function injectUI() {
    let inputContainer = findInputContainer();
    if (!inputContainer) return;

    let textarea = findTextarea();
    let inputWrapper = findInputWrapper();
    if (!textarea) return;

    // Create shield button if not exists
    if (!document.getElementById("bb-settings-btn")) {
        let emojiBtn = findEmojiButton();
        let shieldBtn = document.createElement("button");
        shieldBtn.id = "bb-settings-btn";
        shieldBtn.className = "btn-icon rp";
        shieldBtn.style.cssText = "display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s;background:none;border:none;outline:none;width:44px;height:44px;flex-shrink:0;";
        shieldBtn.onclick = openSettings;

        // On mobile, emoji button might be inside new-message-wrapper
        if (emojiBtn?.parentElement) {
            emojiBtn.parentElement.insertBefore(shieldBtn, emojiBtn);
        } else {
            // Fallback: insert into new-message-wrapper or input-message-container
            let wrapper = findNewMessageWrapper() || inputContainer;
            wrapper.insertBefore(shieldBtn, wrapper.firstChild);
        }
    }

    // Create no-key notice if not exists
    if (!document.getElementById("bb-no-key-notice")) {
        let notice = document.createElement("div");
        notice.id = "bb-no-key-notice";
        notice.innerHTML = `
            <div class="bb-notice-icon">⚠️</div>
            <div class="bb-notice-body">
                <strong>Encryption key not set — sending is blocked.</strong>
                Tap the shield icon to set up encryption or disable it.
                <br>
                <button class="bb-notice-btn" id="bb-notice-set-key">🛡 Set Encryption Key</button>
            </div>`;
        // Insert before the input wrapper or textarea
        let insertTarget = inputWrapper || textarea;
        insertTarget.parentElement.insertBefore(notice, insertTarget);
        notice.querySelector("#bb-notice-set-key").onclick = openSettings;
    }

    // Create secure overlay if not exists
    let overlay = document.getElementById("secure-input-overlay");
    if (overlay) {
        window._bbSendMessage = overlay._triggerSend;
        refreshUI();
        return;
    }

    // Prevent textarea from getting focus when encryption is on
    if (!textarea._hasStrictHijack) {
        textarea._hasStrictHijack = true;
        textarea.addEventListener("focus", () => {
            if (!isBypass && isEnabled()) {
                textarea.blur();
                document.getElementById("secure-input-overlay")?.focus();
            }
        });
    }

    // Also block the parent scrollable input wrapper on mobile
    if (inputWrapper && !inputWrapper._hasStrictHijack) {
        inputWrapper._hasStrictHijack = true;
        inputWrapper.addEventListener("focus", e => {
            if (!isBypass && isEnabled()) {
                e.preventDefault();
                document.getElementById("secure-input-overlay")?.focus();
            }
        }, true);
        inputWrapper.addEventListener("click", e => {
            if (!isBypass && isEnabled()) {
                e.preventDefault();
                e.stopPropagation();
                document.getElementById("secure-input-overlay")?.focus();
            }
        }, true);
    }

    let secureInput = document.createElement("div");
    secureInput.id = "secure-input-overlay";
    secureInput.contentEditable = "true";
    secureInput.dir = "auto";
    secureInput.dataset.placeholder = "🔒 پیام امن...";

    // Insert the overlay into the DOM
    // On mobile, insert next to the textarea's container
    let insertParent = inputWrapper?.parentElement || textarea.parentElement;
    let insertBefore = inputWrapper || textarea;
    insertParent.insertBefore(secureInput, insertBefore);

    // Prevent event propagation on the secure input
    ["keydown", "keypress", "keyup", "paste", "drop"].forEach(evt => {
        secureInput.addEventListener(evt, e => { e.stopPropagation(); });
    });

    function getOverlayText() { return secureInput.innerText.trim(); }
    function setOverlayText(t) { secureInput.innerText = t; }

    function syncHasContent(has) {
        if (has !== hasContent) {
            hasContent = has;
            // We need to make the real textarea think there's content for the send button
            textarea.textContent = has ? "." : "";
            textarea.dispatchEvent(new Event("input", { bubbles: true }));
            setSendButtonState(has);
        }
    }

    async function injectAndSend(msgText) {
        isBypass = true;

        // Unhide the real input temporarily
        let hideTarget = inputWrapper || textarea;
        hideTarget.classList.remove("rb-locked-input");
        hideTarget.style.cssText = "position:absolute!important;top:0!important;left:0!important;opacity:0!important;pointer-events:none!important;z-index:-1!important";

        textarea.focus();
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, msgText);
        textarea.dispatchEvent(new Event("input", { bubbles: true }));

        let enterEvt = { bubbles: true, cancelable: true, key: "Enter", keyCode: 13, which: 13 };
        textarea.dispatchEvent(new KeyboardEvent("keydown", enterEvt));
        textarea.dispatchEvent(new KeyboardEvent("keyup", enterEvt));

        // Wait for send button to be ready
        let sendBtn = null;
        for (let attempt = 0; attempt < 20; attempt++) {
            await delay(50);
            let btn = findSendButton();
            if (!btn) continue;
            let isReady = btn.classList.contains("send") || !btn.classList.contains("record") ||
                          !!btn.querySelector(".rbico-send:not([hidden])");
            if (isReady) { sendBtn = btn; break; }
        }

        if (sendBtn) {
            let evtOpts = { bubbles: true, cancelable: true, view: window };
            sendBtn.dispatchEvent(new PointerEvent("pointerdown", evtOpts));
            sendBtn.dispatchEvent(new MouseEvent("mousedown", evtOpts));
            sendBtn.dispatchEvent(new PointerEvent("pointerup", evtOpts));
            sendBtn.dispatchEvent(new MouseEvent("mouseup", evtOpts));
            sendBtn.dispatchEvent(new MouseEvent("click", evtOpts));
            sendBtn.click();

            // On mobile, also try touching the send ripple
            if (isMobile()) {
                let ripple = sendBtn.querySelector(".rr.c-ripple");
                if (ripple) {
                    ripple.dispatchEvent(new PointerEvent("pointerdown", evtOpts));
                    ripple.dispatchEvent(new MouseEvent("mousedown", evtOpts));
                    ripple.dispatchEvent(new PointerEvent("pointerup", evtOpts));
                    ripple.dispatchEvent(new MouseEvent("mouseup", evtOpts));
                    ripple.dispatchEvent(new MouseEvent("click", evtOpts));
                }
            }
        } else {
            // Fallback: fire Enter on textarea
            textarea.focus();
            ["keydown", "keypress", "keyup"].forEach(name => {
                textarea.dispatchEvent(new KeyboardEvent(name, enterEvt));
            });
        }

        await delay(300);

        // Clear textarea
        textarea.focus();
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, "");
        textarea.dispatchEvent(new Event("input", { bubbles: true }));

        // Restore locked state
        hideTarget.style.cssText = "";
        hideTarget.classList.add("rb-locked-input");
        isBypass = false;
    }

    async function triggerSend(encrypted = true) {
        if (isSending) return;
        let text = getOverlayText();
        if (!text) return;

        if (encrypted) {
            if (!getKey()) { openSettings(); return; }
            isSending = true;
            isBypass = true;
            setOverlayText("🔒 Encrypting...");
            try {
                let chunks = await splitEncrypt(text);
                if (!chunks) { setOverlayText(text); openSettings(); return; }
                for (let chunk of chunks) await injectAndSend(chunk);
                setOverlayText("");
                hasContent = false;
                syncHasContent(false);
                secureInput.focus();
            } catch (err) {
                console.error("[Rubika Bridge] Encrypted send failed:", err);
                setOverlayText(text);
                alert("Send failed!");
            } finally {
                isSending = false;
                isBypass = false;
            }
        } else {
            let confirm_ = confirm("⚠️ You are about to send this message WITHOUT encryption.\n\nThis may expose sensitive information. Are you sure?");
            if (!confirm_) return;
            isSending = true;
            isBypass = true;
            setOverlayText("🌐 Sending...");
            try {
                await injectAndSend(text);
                setOverlayText("");
                hasContent = false;
                syncHasContent(false);
                secureInput.focus();
            } catch (err) {
                console.error("[Rubika Bridge] Plain send failed:", err);
                setOverlayText(text);
                alert("Send failed!");
            } finally {
                isSending = false;
                isBypass = false;
            }
        }
    }

    secureInput._triggerSend = triggerSend;
    window._bbSendMessage = triggerSend;

    secureInput.addEventListener("input", () => {
        syncHasContent(getOverlayText().length > 0);
    });

    secureInput.addEventListener("keydown", e => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            e.stopPropagation();
            triggerSend(true);
        }
    });

    refreshUI();
}

// ── Main observer loop ──
(function startObserver() {
    let debounceTimer;
    let lastHref = location.href;

    const observer = new MutationObserver(() => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            decryptMessages();
            injectUI();

            // Keep send button in sync
            if (isEnabled() && !isSending) {
                let ov = document.getElementById("secure-input-overlay");
                if (ov) setSendButtonState(ov.innerText.trim().length > 0);
            }

            // Handle navigation
            if (location.href !== lastHref) {
                lastHref = location.href;
                cachedSettings = null;
                cachedChatId = null;
                refreshUI();
            }
        }, 100);
    });

    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
})();

}();
