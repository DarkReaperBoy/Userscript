// ==UserScript==
// @name         Bale Bridge Encryptor/Decryptor (Ultimate Privacy)
// @namespace    http://tampermonkey.net/
// @version      11.0
// @description  Per-chat keys, Shield button, Material UI, Auto-decrypt, Draft blocker. Desktop & Mobile.
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// ==/UserScript==
(function() {
	"use strict";
	// ─── 0. WebSocket Draft Blocker ───────────────────────────────────────────
	const _origWsSend = WebSocket.prototype.send;
	WebSocket.prototype.send = function(data) {
		try {
			const t = typeof data === "string" ? data : new TextDecoder().decode(data);
			if (t.includes("EditParameter") && t.includes("drafts_")) return;
		} catch (_) {}
		return _origWsSend.apply(this, arguments);
	};
	// ─── 1. Settings (Per-Chat) ───────────────────────────────────────────────
	const getChatId = () => {
		const p = new URLSearchParams(location.search);
		return p.get("uid") || p.get("groupId") || p.get("channelId") || location.pathname.split("/").pop() || "global";
	};
	let _settingsCacheId = null,
		_settingsCache = null;
	const getChatSettings = () => {
		const id = getChatId();
		if (id === _settingsCacheId && _settingsCache !== null) return _settingsCache;
		const s = localStorage.getItem("bale_bridge_settings_" + id);
		_settingsCache = s ? JSON.parse(s) : {
			enabled: true,
			customKey: ""
		};
		_settingsCacheId = id;
		return _settingsCache;
	};
	const saveChatSettings = (s) => {
		const id = getChatId();
		_settingsCache = s;
		_settingsCacheId = id;
		localStorage.setItem("bale_bridge_settings_" + id, JSON.stringify(s));
	};
	// Returns the active 32-char key, or null if encryption is off or key invalid.
	const getActiveKey = () => {
		const s = getChatSettings();
		if (!s.enabled) return null;
		return s.customKey && s.customKey.length === 32 ? s.customKey : null;
	};
	// Is encryption enabled (regardless of whether key is valid)?
	const isEncryptionEnabled = () => getChatSettings().enabled;
	// ─── 2. Crypto Engine ─────────────────────────────────────────────────────
	const keyCache = new Map();
	async function getCryptoKey(k) {
		if (keyCache.has(k)) return keyCache.get(k);
		const raw = new Uint8Array(32);
		raw.set(new TextEncoder().encode(k).subarray(0, 32));
		const key = await crypto.subtle.importKey("raw", raw, {
			name: "AES-GCM"
		}, false, ["encrypt", "decrypt"]);
		keyCache.set(k, key);
		return key;
	}

	function generateKey() {
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~";
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		return Array.from(bytes, b => chars[b % chars.length]).join("");
	}
	// Base85 (RFC 1924)
	const B85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
	const B85D = new Uint8Array(128);
	for (let i = 0; i < B85.length; i++) B85D[B85.charCodeAt(i)] = i;

	function b85enc(buf) {
		const len = buf.length;
		// Pre-calculate output size for single allocation
		const fullChunks = (len >>> 2);
		const remainder = len & 3;
		const outLen = fullChunks * 5 + (remainder ? remainder + 1 : 0);
		const chars = new Array(outLen);
		let pos = 0;
		for (let i = 0; i < len; i += 4) {
			const rem = len - i < 4 ? len - i : 4;
			let acc = 0;
			for (let j = 0; j < 4; j++) acc = (acc << 8) | (i + j < len ? buf[i + j] : 0);
			acc >>>= 0;
			const count = rem < 4 ? rem + 1 : 5;
			// Extract digits in reverse into temp, then copy forward
			const tmp = new Array(5);
			for (let j = 4; j >= 0; j--) {
				tmp[j] = B85[acc % 85];
				acc = Math.floor(acc / 85);
			}
			for (let j = 0; j < count; j++) chars[pos++] = tmp[j];
		}
		return chars.join("");
	}

	function b85dec(str) {
		const slen = str.length;
		// Estimate output size
		const fullChunks = Math.floor(slen / 5);
		const remChars = slen % 5;
		const outEst = fullChunks * 4 + (remChars ? remChars - 1 : 0);
		const out = new Uint8Array(outEst);
		let wpos = 0;
		for (let i = 0; i < slen; i += 5) {
			const end = Math.min(i + 5, slen);
			const chunkLen = end - i;
			const pad = 5 - chunkLen;
			let acc = 0;
			for (let j = 0; j < 5; j++) {
				const ci = i + j < slen ? str.charCodeAt(i + j) : 126; // '~'
				acc = acc * 85 + B85D[ci];
			}
			const bytes = 4 - pad;
			if (bytes >= 1) out[wpos++] = (acc >>> 24) & 0xff;
			if (bytes >= 2) out[wpos++] = (acc >>> 16) & 0xff;
			if (bytes >= 3) out[wpos++] = (acc >>> 8) & 0xff;
			if (bytes >= 4) out[wpos++] = acc & 0xff;
		}
		return out.subarray(0, wpos);
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
		return new TextDecoder().decode(await new Response(ds.readable).arrayBuffer());
	}
	async function encrypt(text) {
		const k = getActiveKey();
		if (!k) return null;
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const ct = new Uint8Array(await crypto.subtle.encrypt({
			name: "AES-GCM",
			iv
		}, await getCryptoKey(k), await compress(text)));
		const payload = new Uint8Array(12 + ct.length);
		payload.set(iv);
		payload.set(ct, 12);
		return "@@" + b85enc(payload);
	}
	async function decrypt(text) {
		if (!text.startsWith("@@")) return text;
		const k = getActiveKey();
		if (!k) return text;
		try {
			const buf = b85dec(text.slice(2));
			const iv = buf.subarray(0, 12),
				data = buf.subarray(12);
			const plain = await crypto.subtle.decrypt({
				name: "AES-GCM",
				iv
			}, await getCryptoKey(k), data);
			return await decompress(new Uint8Array(plain));
		} catch (_) {
			return text;
		}
	}
	// ─── 2b. Chunked Encrypt ──────────────────────────────────────────────────
	const MAX_ENCRYPTED_LEN = 4000;
	async function encryptChunked(text) {
		const result = await encrypt(text);
		if (result === null) return null;
		if (result.length <= MAX_ENCRYPTED_LEN) return [result];
		const mid = Math.floor(text.length / 2);
		let splitAt = text.lastIndexOf("\n", mid);
		if (splitAt <= 0) splitAt = text.lastIndexOf(" ", mid);
		if (splitAt <= 0) splitAt = mid;
		const a = await encryptChunked(text.slice(0, splitAt).trim());
		const b = await encryptChunked(text.slice(splitAt).trim());
		if (!a || !b) return null;
		return [...a, ...b];
	}
	// ─── 2c. Render Decrypted ─────────────────────────────────────────────────
	const _URL_RE = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
	const _ESC_MAP = {
		"&": "&amp;",
		"<": "&lt;",
		">": "&gt;",
		'"': "&quot;"
	};
	const escapeHtml = (s) => s.replace(/[&<>"]/g, c => _ESC_MAP[c]);

	function applyInlineMarkdown(s) {
		return s.replace(/``([^`]+)``|`([^`]+)`/g, (_, a, b) => `<code style="background:var(--color-neutrals-n-20,#f4f5f7);border-radius:4px;padding:1px 5px;font-family:monospace;font-size:.92em">${a ?? b}</code>`).replace(/\|\|(.+?)\|\|/g, (_, t) => `<span class="bb-spoiler" style="background:var(--color-neutrals-n-400,#42526e);color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none" title="Click to reveal">${t}</span>`).replace(/\*\*\*(.+?)\*\*\*/g, (_, t) => `<strong><em>${t}</em></strong>`).replace(/\*\*(.+?)\*\*/g, (_, t) => `<strong>${t}</strong>`).replace(/(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g, (_, t) => `<u>${t}</u>`).replace(/\*([^*\n]+)\*/g, (_, t) => `<em>${t}</em>`).replace(/(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g, (_, p, t) => `${p}<em>${t}</em>`).replace(/~~(.+?)~~/g, (_, t) => `<del>${t}</del>`).replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_, label, url) => `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" style="color:var(--color-primary-p-50,#00ab80);text-decoration:underline">${label}</a>`);
	}

	function processLine(line) {
		const parts = [];
		let last = 0;
		_URL_RE.lastIndex = 0;
		let m;
		while ((m = _URL_RE.exec(line)) !== null) {
			parts.push(applyInlineMarkdown(escapeHtml(line.slice(last, m.index))));
			const safe = escapeHtml(m[0]);
			parts.push(`<a href="${safe}" target="_blank" rel="noopener noreferrer" style="color:var(--color-primary-p-50,#00ab80);text-decoration:underline;word-break:break-all">${safe}</a>`);
			last = m.index + m[0].length;
		}
		parts.push(applyInlineMarkdown(escapeHtml(line.slice(last))));
		return parts.join("");
	}

	function renderDecrypted(plain) {
		const lines = plain.split("\n");
		const out = [];
		let i = 0;
		const bidiBlock = (html) => `<span dir="auto" class="bb-block">${html}</span>`;
		while (i < lines.length) {
			const line = lines[i];
			if (line.startsWith("> ") || line === ">") {
				const qLines = [];
				while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">")) qLines.push(lines[i++].replace(/^> ?/, ""));
				out.push(`<span dir="auto" class="bb-quote">${qLines.map(processLine).join("<br>")}</span>`);
				continue;
			}
			if (/^[-*+] /.test(line)) {
				const items = [];
				while (i < lines.length && /^[-*+] /.test(lines[i])) items.push(`<li class="bb-li">${processLine(lines[i++].slice(2))}</li>`);
				out.push(`<ul dir="auto" class="bb-ul">${items.join("")}</ul>`);
				continue;
			}
			if (/^\d+\. /.test(line)) {
				const items = [];
				while (i < lines.length && /^\d+\. /.test(lines[i])) items.push(`<li class="bb-li">${processLine(lines[i++].replace(/^\d+\. /, ""))}</li>`);
				out.push(`<ol dir="auto" class="bb-ol">${items.join("")}</ol>`);
				continue;
			}
			const hm = line.match(/^(#{1,3}) (.+)/);
			if (hm) {
				const sz = ["1.25em", "1.1em", "1em"][Math.min(hm[1].length, 3) - 1];
				out.push(bidiBlock(`<span style="font-weight:700;font-size:${sz}">${processLine(hm[2])}</span>`));
				i++;
				continue;
			}
			if (/^([-*_])\1{2,}$/.test(line.trim())) {
				out.push(`<span class="bb-hr"></span>`);
				i++;
				continue;
			}
			if (line.trim() === "") {
				out.push(`<span class="bb-spacer"></span>`);
				i++;
				continue;
			}
			out.push(bidiBlock(processLine(line)));
			i++;
		}
		return out.join("");
	}
	// ─── 3. DOM Scanner (Auto-decrypt) ────────────────────────────────────────
	function scanTree(root) {
		const els = root.getElementsByTagName("*");
		for (let idx = 0, len = els.length; idx < len; idx++) {
			const el = els[idx];
			if (el._isDecrypted || el._isDecrypting) continue;
			const id = el.id;
			if (id === "secure-input-overlay" || id === "secure-edit-overlay" || id === "editable-message-text" || id === "main-message-input" || id === "bb-no-key-notice") continue;
			const text = el.textContent;
			if (text.length <= 20 || text.charCodeAt(0) !== 64 || text.charCodeAt(1) !== 64) continue;
			const trimmed = text.trim();
			if (!trimmed.startsWith("@@") || trimmed.length <= 20) continue;
			let skip = false;
			for (const c of el.children) {
				if (c.textContent.trim() === trimmed) {
					skip = true;
					break;
				}
			}
			if (skip) continue;
			el._isDecrypting = true;
			decrypt(trimmed).then((plain) => {
				if (plain !== trimmed) {
					if (!el._bbOverflowSet) {
						el.style.overflow = "hidden";
						el.style.overflowWrap = "anywhere";
						el.style.wordBreak = "break-word";
						el.style.maxWidth = "100%";
						el.classList.add("bb-msg-container");
						el._bbOverflowSet = true;
					}
					// Appended the copy button inline with the badge to prevent adding vertical space
					el.innerHTML = renderDecrypted(plain) + `<span style="display:inline-block;font-size:9px;opacity:0.5;letter-spacing:0.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap">
                            🔒 encrypted
                            <span class="bb-copy-btn" title="Copy decrypted message" style="cursor:pointer;margin-inline-start:4px;font-size:11px;font-style:normal;transition:opacity 0.2s;">📋</span>
                        </span>`;
					el.style.color = "inherit";
					el._isDecrypted = true;
					// Attach the copy functionality directly to the button
					const copyBtn = el.querySelector('.bb-copy-btn');
					if (copyBtn) {
						copyBtn.addEventListener('click', (e) => {
							e.preventDefault();
							e.stopPropagation();
							navigator.clipboard.writeText(plain).then(() => {
								copyBtn.textContent = "✅";
								setTimeout(() => copyBtn.textContent = "📋", 1500);
							});
						});
					}
				}
			}).finally(() => {
				el._isDecrypting = false;
			});
		}
	}
	// ─── 4. Input Helpers ─────────────────────────────────────────────────────
	const getRealInput = () => document.getElementById("editable-message-text") || document.getElementById("main-message-input");
	const isMobileInput = (el) => el?.tagName === "TEXTAREA";
	const _textareaSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
	// ─── 5. Styles ────────────────────────────────────────────────────────────
	document.addEventListener("click", (e) => {
		const sp = e.target.closest(".bb-spoiler");
		if (!sp) return;
		sp.style.color = "inherit";
		sp.style.background = "var(--color-neutrals-n-40,#dfe1e6)";
	}, true);
	document.head.insertAdjacentHTML("beforeend", `<style>
        #secure-input-overlay {
            width:100%;box-sizing:border-box;min-height:44px;max-height:150px;overflow-y:auto;
            background-color:var(--color-neutrals-surface,#fff);border:2px solid var(--color-primary-p-50,#00ab80);
            box-shadow:0 4px 12px rgba(0,171,128,.15);border-radius:16px;padding:10px 16px;
            font-family:inherit;font-size:inherit;outline:none;white-space:pre-wrap;word-break:break-word;
            margin-right:10px;resize:none;color:var(--color-neutrals-n-600,#151515);z-index:100;
            position:relative;transition:box-shadow .2s ease,border-color .2s ease;display:block;
        }
        #secure-input-overlay:focus{box-shadow:0 4px 16px rgba(0,171,128,.3);border-color:var(--color-primary-p-60,#00916d)}
        div#secure-input-overlay:empty::before{content:attr(data-placeholder);color:var(--color-neutrals-n-300,#888);pointer-events:none;display:block}

        #bb-no-key-notice {
            display:none;align-items:flex-start;gap:10px;
            width:100%;box-sizing:border-box;padding:10px 14px;margin-right:10px;
            background:#fff8e1;border:2px solid #f9a825;border-radius:16px;
            font-family:inherit;font-size:13px;color:#4a3400;line-height:1.5;
            position:relative;z-index:101;
        }
        #bb-no-key-notice .bb-notice-icon{font-size:20px;flex-shrink:0;margin-top:1px}
        #bb-no-key-notice .bb-notice-body{flex:1}
        #bb-no-key-notice strong{display:block;font-size:13px;margin-bottom:3px;color:#b45309}
        #bb-no-key-notice .bb-notice-btn{
            display:inline-block;margin-top:7px;padding:5px 12px;border-radius:8px;border:none;
            background:#f9a825;color:#fff;font-size:12px;font-weight:700;cursor:pointer;
            transition:background .15s;
        }
        #bb-no-key-notice .bb-notice-btn:hover{background:#f59e0b}

        #bale-bridge-menu{
            position:fixed;z-index:999999;background:var(--color-neutrals-surface,#fff);
            border:1px solid var(--color-neutrals-n-40,#dfe1e6);border-radius:12px;
            box-shadow:0 8px 24px rgba(0,0,0,.15);display:none;flex-direction:column;overflow:hidden;
            font-family:inherit;color:var(--color-neutrals-n-500,#091e42);min-width:180px;
            animation:bb-pop .2s cubic-bezier(.2,.8,.2,1);
        }
        .bale-menu-item{padding:14px 18px;cursor:pointer;font-size:14px;font-weight:500;transition:background .15s;display:flex;align-items:center;gap:12px}
        .bale-menu-item:hover{background:var(--color-neutrals-n-20,#f4f5f7)}

        #bb-modal-overlay{
            position:fixed;inset:0;background:rgba(0,0,0,.4);backdrop-filter:blur(3px);
            display:flex;align-items:center;justify-content:center;z-index:9999999;
            animation:bb-fade .2s ease-out;
        }
        #bb-modal-card{
            background:var(--color-neutrals-surface,#fff);padding:24px;border-radius:20px;
            width:360px;max-width:92vw;box-shadow:0 10px 40px rgba(0,0,0,.25);
            color:var(--color-neutrals-n-600,#151515);font-family:inherit;
            animation:bb-pop .3s cubic-bezier(.2,.8,.2,1);
        }
        .bb-modal-title{margin:0 0 10px;font-size:18px;font-weight:bold}
        .bb-modal-desc{margin:0 0 20px;font-size:13px;color:var(--color-neutrals-n-300,#888)}
        .bb-input{
            width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--color-neutrals-n-100,#ccc);
            box-sizing:border-box;background:transparent;color:inherit;
            font-family:monospace;font-size:13px;transition:border-color .2s;letter-spacing:.04em;
        }
        .bb-input:focus{outline:none;border-color:var(--color-primary-p-50,#00ab80)}
        .bb-key-row{display:flex;gap:8px;align-items:center;margin-top:6px}
        .bb-key-row .bb-input{flex:1;margin-top:0}
        .bb-icon-btn{
            flex-shrink:0;padding:0;width:36px;height:36px;border-radius:8px;border:1px solid var(--color-neutrals-n-100,#ccc);
            background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;
            font-size:16px;transition:background .15s,border-color .15s;color:inherit;
        }
        .bb-icon-btn:hover{background:var(--color-neutrals-n-20,#f4f5f7);border-color:var(--color-primary-p-50,#00ab80)}
        .bb-icon-btn.copied{background:#e8f5e9;border-color:#43a047;color:#43a047}
        .bb-key-tools{display:flex;gap:8px;margin-top:8px}
        .bb-tool-btn{
            flex:1;padding:7px 0;border-radius:8px;border:1px solid var(--color-neutrals-n-100,#ccc);
            background:transparent;cursor:pointer;font-size:12px;font-weight:600;
            display:flex;align-items:center;justify-content:center;gap:5px;
            transition:background .15s,border-color .15s;color:inherit;
        }
        .bb-tool-btn:hover{background:var(--color-neutrals-n-20,#f4f5f7);border-color:var(--color-primary-p-50,#00ab80)}
        .bb-tool-btn.copied{background:#e8f5e9;border-color:#43a047;color:#43a047}
        .bb-toggle-lbl{display:flex;align-items:center;gap:8px;font-size:14px;cursor:pointer}
        .bb-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}
        .bb-btn{padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-weight:600;font-size:14px;transition:background .2s,transform .1s}
        .bb-btn:active{transform:scale(.95)}
        .bb-btn-cancel{background:transparent;color:var(--color-neutrals-n-300,#888)}
        .bb-btn-cancel:hover{background:var(--color-neutrals-n-20,#f4f5f7)}
        .bb-btn-save{background:var(--color-primary-p-50,#00ab80);color:#fff}
        .bb-btn-save:hover{background:var(--color-primary-p-60,#00916d)}
        .bb-btn-save:disabled{background:var(--color-neutrals-n-100,#ccc);cursor:not-allowed;transform:none}
        .bb-key-meta{display:flex;justify-content:space-between;align-items:center;margin-top:6px;font-size:11px}
        .bb-key-counter{color:var(--color-neutrals-n-300,#888)}
        .bb-key-counter.exact{color:var(--color-primary-p-50,#00ab80);font-weight:600}
.bb-key-error{color:#d32f2f;font-weight:500;font-size:11px;min-height:16px}
        @keyframes bb-fade{from{opacity:0}to{opacity:1}}
        @keyframes bb-pop{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}

        .bb-block { display: block; unicode-bidi: plaintext; }
        .bb-quote { display: block; border-inline-start: 3px solid var(--color-primary-p-50,#00ab80); padding: 2px 10px; margin: 2px 0; font-style: italic; opacity: 0.9; unicode-bidi: plaintext; }
        .bb-ul { margin: 4px 0; padding-inline-start: 22px; list-style: disc; unicode-bidi: plaintext; }
        .bb-ol { margin: 4px 0; padding-inline-start: 22px; list-style: decimal; unicode-bidi: plaintext; }
        .bb-li { margin: 2px 0; padding-inline-start: 2px; }
        .bb-hr { display: block; border-top: 1px solid var(--color-neutrals-n-100,#ccc); margin: 6px 0; }
        .bb-spacer { display: block; height: 0.4em; }

        /* Smart Compact mode for Reply Previews & Sidebar */
        .BAsWs0 .bb-block, .MRlMpm .bb-block, .dialog-item-content .bb-block, .aqFHpt .bb-block,
        .BAsWs0 .bb-quote, .MRlMpm .bb-quote, .dialog-item-content .bb-quote, .aqFHpt .bb-quote,
        .BAsWs0 .bb-ul, .MRlMpm .bb-ul, .dialog-item-content .bb-ul, .aqFHpt .bb-ul,
        .BAsWs0 .bb-ol, .MRlMpm .bb-ol, .dialog-item-content .bb-ol, .aqFHpt .bb-ol,
        .BAsWs0 .bb-li, .MRlMpm .bb-li, .dialog-item-content .bb-li, .aqFHpt .bb-li {
            display: inline !important;
            margin: 0 !important;
            padding: 0 !important;
            border: none !important;
        }
.BAsWs0 .bb-spacer, .MRlMpm .bb-spacer, .dialog-item-content .bb-spacer, .aqFHpt .bb-spacer,
        .BAsWs0 .bb-hr, .MRlMpm .bb-hr, .dialog-item-content .bb-hr, .aqFHpt .bb-hr,
        .BAsWs0 .bb-copy-btn, .MRlMpm .bb-copy-btn, .dialog-item-content .bb-copy-btn, .aqFHpt .bb-copy-btn {
            display: none !important;
        }
        .bb-copy-btn:hover { opacity: 1 !important; }
        .BAsWs0 .bb-li::after, .MRlMpm .bb-li::after, .dialog-item-content .bb-li::after, .aqFHpt .bb-li::after {
            content: " \\00a0•\\00a0 ";
        }
        
        /* Apply 2-line clamp to the whole preview automatically */
        .BAsWs0 .bb-msg-container, .MRlMpm .bb-msg-container, .dialog-item-content .bb-msg-container, .aqFHpt .bb-msg-container {
            display: -webkit-box !important;
            -webkit-line-clamp: 2 !important;
            -webkit-box-orient: vertical !important;
            white-space: normal !important;
        }
    </style>`);
	// ─── 6. Context Menu ──────────────────────────────────────────────────────
	const popupMenu = document.createElement("div");
	popupMenu.id = "bale-bridge-menu";
	popupMenu.innerHTML = `
        <div class="bale-menu-item" id="bale-menu-enc">🔒 Send Encrypted</div>
        <div class="bale-menu-item" id="bale-menu-plain">⚠️ Send Unencrypted</div>`;
	document.body.appendChild(popupMenu);
	const showMenu = (x, y) => Object.assign(popupMenu.style, {
		display: "flex",
		left: Math.min(x, innerWidth - 210) + "px",
		top: Math.min(y, innerHeight - 120) + "px",
	});
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
		// Remove any existing modal first
		document.getElementById("bb-modal-overlay")?.remove();
		const s = getChatSettings();
		document.body.insertAdjacentHTML("beforeend", `
            <div id="bb-modal-overlay">
                <div id="bb-modal-card">
                    <h3 class="bb-modal-title">Shield Settings 🛡️</h3>
                    <p class="bb-modal-desc">Configure encryption for this chat. When enabled, a 32-character key is required.</p>
                    <label class="bb-toggle-lbl">
                        <input type="checkbox" id="bb-enable-enc" ${s.enabled ? "checked" : ""}
                            style="width:16px;height:16px;accent-color:var(--color-primary-p-50,#00ab80)">
                        <span>Enable Encryption Here</span>
                    </label>
                    <div id="bb-key-section" style="margin-top:16px;border-top:1px solid var(--color-neutrals-n-20,#f4f5f7);padding-top:16px">
                        <label style="font-size:12px;color:var(--color-neutrals-n-500,#151515);font-weight:600">
                            Encryption Key <span style="color:#d32f2f">*</span>
                        </label>
                        <div class="bb-key-row">
                            <input type="password" id="bb-custom-key" class="bb-input"
                                placeholder="Enter exactly 32 characters…"
                                maxlength="32"
                                value="${s.customKey || ""}">
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
		const overlay = document.getElementById("bb-modal-overlay");
		const keyInput = document.getElementById("bb-custom-key");
		const keySection = document.getElementById("bb-key-section");
		const counter = document.getElementById("bb-key-counter");
		const errorEl = document.getElementById("bb-key-error");
		const saveBtn = document.getElementById("bb-btn-save");
		const enableCb = document.getElementById("bb-enable-enc");
		const copyBtn = document.getElementById("bb-copy-key");
		const genBtn = document.getElementById("bb-gen-key");
		const visBtn = document.getElementById("bb-toggle-vis");
		const validate = () => {
			const len = keyInput.value.length;
			const enabled = enableCb.checked;
			counter.textContent = `${len} / 32`;
			counter.className = "bb-key-counter" + (len === 32 ? " exact" : "");
			// Show/hide key section based on encryption toggle
			keySection.style.display = enabled ? "" : "none";
			if (!enabled) {
				// Encryption disabled — always valid, can save freely
				errorEl.textContent = "";
				saveBtn.disabled = false;
				return;
			}
			if (len === 0) {
				errorEl.textContent = "A key is required when encryption is enabled.";
				saveBtn.disabled = true;
			} else if (len !== 32) {
				errorEl.textContent = `Key must be exactly 32 characters (currently ${len}).`;
				saveBtn.disabled = true;
			} else {
				errorEl.textContent = "";
				saveBtn.disabled = false;
			}
		};
		keyInput.addEventListener("input", validate);
		enableCb.addEventListener("change", validate);
		validate();
		visBtn.addEventListener("click", () => {
			const hidden = keyInput.type === "password";
			keyInput.type = hidden ? "text" : "password";
			visBtn.textContent = hidden ? "🙈" : "👁";
		});
		copyBtn.addEventListener("click", () => {
			if (!keyInput.value) return;
			navigator.clipboard.writeText(keyInput.value).then(() => {
				copyBtn.textContent = "✅";
				copyBtn.classList.add("copied");
				setTimeout(() => {
					copyBtn.textContent = "📋";
					copyBtn.classList.remove("copied");
				}, 1500);
			});
		});
		genBtn.addEventListener("click", () => {
			keyInput.value = generateKey();
			keyInput.type = "text";
			visBtn.textContent = "🙈";
			validate();
		});
		document.getElementById("bb-btn-cancel").onclick = () => overlay.remove();
		saveBtn.onclick = () => {
			if (saveBtn.disabled) return;
			saveChatSettings({
				enabled: enableCb.checked,
				customKey: keyInput.value
			});
			overlay.remove();
			syncInputVisibility();
		};
	}
	// ─── 8. Secure Input & Shield Button ──────────────────────────────────────
	let isSending = false,
		lastHasText = false,
		isSyncing = false;
	const lockInput = (el) => Object.assign(el.style, {
		position: "absolute",
		opacity: "0",
		pointerEvents: "none",
		height: "0px",
		width: "0px",
		overflow: "hidden",
		zIndex: "-9999",
	});
	const unlockInput = (el) => Object.assign(el.style, {
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
		const notice = document.getElementById("bb-no-key-notice");
		const btn = document.getElementById("bb-settings-btn");
		if (!real) return;
		const encEnabled = isEncryptionEnabled();
		const hasKey = !!getActiveKey();
		if (!encEnabled) {
			// Encryption OFF → show native input, hide everything else
			unlockInput(real);
			if (secure) secure.style.display = "none";
			if (notice) notice.style.display = "none";
			if (btn) btn.style.color = "#5E6C84"; // gray = inactive
		} else if (hasKey) {
			// Encryption ON + valid key → show secure input
			lockInput(real);
			if (secure) secure.style.display = "";
			if (notice) notice.style.display = "none";
			if (btn) btn.style.color = "var(--color-primary-p-50, #00ab80)";
		} else {
			// Encryption ON + no valid key → show notice, block everything
			lockInput(real);
			if (secure) secure.style.display = "none";
			if (notice) notice.style.display = "flex";
			if (btn) btn.style.color = "#f9a825"; // amber = warning
		}
	}

	function ensureSecureInput() {
		const realInput = getRealInput();
		if (!realInput) return;
		const mobile = isMobileInput(realInput);
		const wrapper = realInput.parentElement;
		// ── Shield button ──────────────────────────────────────────────────
		const emojiBtn = document.querySelector('[aria-label="emoji-icon"]') || document.querySelector(".MmBErq");
		if (emojiBtn) emojiBtn.style.display = "none";
		if (emojiBtn && !document.getElementById("bb-settings-btn")) {
			const shieldBtn = document.createElement("div");
			shieldBtn.id = "bb-settings-btn";
			shieldBtn.className = emojiBtn.className;
			shieldBtn.setAttribute("role", "button");
			shieldBtn.style.cssText = "display:flex;align-items:center;justify-content:center;cursor:pointer;transition:color .2s";
			shieldBtn.innerHTML = `<div style="border-radius:50%;line-height:0;position:relative">
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
		// ── No-key notice ──────────────────────────────────────────────────
		if (!document.getElementById("bb-no-key-notice")) {
			const notice = document.createElement("div");
			notice.id = "bb-no-key-notice";
			notice.innerHTML = `
                <div class="bb-notice-icon">⚠️</div>
                <div class="bb-notice-body">
                    <strong>Encryption key not set — sending is blocked.</strong>
                    Tap the 🔒 lock button to generate a key and share it with your contact, paste a key you received, or disable encryption for this chat.
                    <br>
                    <button class="bb-notice-btn" id="bb-notice-set-key">🛡 Set Encryption Key</button>
                </div>`;
			wrapper.insertBefore(notice, realInput);
			notice.querySelector("#bb-notice-set-key").onclick = openSettingsModal;
		}
		// Already built — refresh
		const existingOverlay = document.getElementById("secure-input-overlay");
		if (existingOverlay) {
			window._bbSend = existingOverlay._triggerSend;
			syncInputVisibility();
			return;
		}
		// ── Hijack real input ──────────────────────────────────────────────
		if (!realInput._hasStrictHijack) {
			realInput._hasStrictHijack = true;
			realInput.addEventListener("focus", () => {
				if (!isSyncing && isEncryptionEnabled()) {
					realInput.blur();
					document.getElementById("secure-input-overlay")?.focus();
				}
			});
			["keydown", "keypress", "keyup", "paste", "drop"].forEach((evt) => realInput.addEventListener(evt, (e) => {
				if (!isSyncing && isEncryptionEnabled()) {
					e.preventDefault();
					e.stopPropagation();
				}
			}, true));
		}
		// ── Build secure overlay ───────────────────────────────────────────
		let secureInput;
		if (mobile) {
			secureInput = document.createElement("textarea");
			secureInput.id = "secure-input-overlay";
			secureInput.dir = "auto";
			secureInput.placeholder = "🔒 پیام امن...";
			secureInput.rows = 1;
			secureInput.addEventListener("input", () => {
				secureInput.style.height = "auto";
				secureInput.style.height = Math.min(secureInput.scrollHeight, 150) + "px";
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
		const getText = () => mobile ? secureInput.value.trim() : secureInput.innerText.trim();
		const setText = (v) => {
			if (mobile) secureInput.value = v;
			else secureInput.innerText = v;
		};
		const syncHasText = (hasText) => {
			if (hasText === lastHasText) return;
			lastHasText = hasText;
			isSyncing = true;
			if (mobile) {
				_textareaSetter?.call(realInput, hasText ? " " : "");
				realInput.dispatchEvent(new Event("input", {
					bubbles: true
				}));
			} else {
				const sel = window.getSelection();
				const range = sel.rangeCount > 0 ? sel.getRangeAt(0) : null;
				realInput.focus();
				document.execCommand("selectAll", false, null);
				document.execCommand("insertText", false, hasText ? " " : "");
				realInput.dispatchEvent(new Event("input", {
					bubbles: true
				}));
				realInput.dispatchEvent(new Event("change", {
					bubbles: true
				}));
				secureInput.focus();
				if (range) {
					sel.removeAllRanges();
					sel.addRange(range);
				}
			}
			isSyncing = false;
		};
		secureInput.addEventListener("input", () => syncHasText(getText().length > 0));
		const sendOneChunk = async (out) => {
			unlockInput(realInput);
			if (mobile) {
				_textareaSetter?.call(realInput, out);
				realInput.dispatchEvent(new Event("input", {
					bubbles: true
				}));
			} else {
				realInput.focus();
				document.execCommand("selectAll", false, null);
				document.execCommand("insertText", false, out);
				realInput.dispatchEvent(new Event("input", {
					bubbles: true
				}));
			}
			await new Promise(r => setTimeout(r, 50));
			const sendBtn = document.querySelector('[aria-label="send-button"]');
			if (sendBtn) sendBtn.click();
			else realInput.dispatchEvent(new KeyboardEvent("keydown", {
				bubbles: true,
				cancelable: true,
				key: "Enter",
				keyCode: 13,
			}));
			await new Promise(r => setTimeout(r, 200));
			if (mobile) {
				_textareaSetter?.call(realInput, "");
				realInput.dispatchEvent(new Event("input", {
					bubbles: true
				}));
			} else {
				realInput.focus();
				document.execCommand("selectAll", false, null);
				document.execCommand("insertText", false, "");
				realInput.dispatchEvent(new Event("input", {
					bubbles: true
				}));
			}
			lockInput(realInput);
		};
		const triggerSend = async (doEncrypt = true) => {
			if (isSending) return;
			const text = getText();
			if (!text) return;
			if (doEncrypt) {
				if (!getActiveKey()) {
					openSettingsModal();
					return;
				}
				isSending = true;
				isSyncing = true;
				setText("🔒 Encrypting...");
				try {
					const chunks = await encryptChunked(text);
					if (!chunks) {
						setText(text);
						openSettingsModal();
						return;
					}
					for (const chunk of chunks) await sendOneChunk(chunk);
					setText("");
					lastHasText = false;
					secureInput.focus();
				} catch (e) {
					console.error("[Bale Bridge] Send failed:", e);
					setText(text);
					alert("Send failed!");
				} finally {
					isSending = false;
					isSyncing = false;
				}
				return;
			}
			// Plaintext send — explicit confirmation
			if (!confirm("⚠️ You are about to send this message WITHOUT encryption.\n\nThis may expose sensitive information. Are you sure?")) return;
			isSending = true;
			isSyncing = true;
			setText("🌐 Sending...");
			try {
				await sendOneChunk(text);
				setText("");
				lastHasText = false;
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
		secureInput.addEventListener("keydown", (e) => {
			if (e.key === "Enter" && !e.shiftKey) {
				e.preventDefault();
				e.stopPropagation();
				triggerSend(true);
			}
		});
		syncInputVisibility();
	}
	// ─── 8b. Secure Edit / Caption Input ─────────────────────────────────────
	function ensureEditInput() {
		const real = document.querySelector('textarea[aria-label="File Description"]');
		if (!real || real._bbEditHooked) return;
		real._bbEditHooked = true;
		const secureEdit = document.createElement("textarea");
		secureEdit.id = "secure-edit-overlay";
		secureEdit.className = real.className;
		secureEdit.placeholder = "🔒 " + (real.placeholder || "ویرایش امن...");
		secureEdit.dir = real.dir || "auto";
		secureEdit.style.cssText = real.style.cssText;
		secureEdit.addEventListener("input", () => {
			secureEdit.style.height = "auto";
			secureEdit.style.height = Math.min(secureEdit.scrollHeight, 150) + "px";
		});
		real.parentElement.insertBefore(secureEdit, real);
		lockInput(real);
		secureEdit.focus();
		const existing = real.value.trim();
		_textareaSetter?.call(real, "");
		real.dispatchEvent(new Event("input", {
			bubbles: true
		}));
		if (existing.startsWith("@@")) {
			decrypt(existing).then((plain) => {
				if (plain !== existing) secureEdit.value = plain;
			});
		} else {
			secureEdit.value = existing;
		}
		const encryptAndForward = async (btn) => {
			if (secureEdit._isSending) return;
			const text = secureEdit.value.trim();
			if (!text) return;
			if (!getActiveKey()) {
				openSettingsModal();
				return;
			}
			secureEdit._isSending = true;
			const prev = secureEdit.value;
			secureEdit.value = "🔒 Encrypting...";
			try {
				const out = await encrypt(text);
				if (!out) {
					secureEdit.value = prev;
					openSettingsModal();
					return;
				}
				secureEdit.value = "";
				unlockInput(real);
				_textareaSetter?.call(real, out);
				real.dispatchEvent(new Event("input", {
					bubbles: true
				}));
				real.dispatchEvent(new Event("change", {
					bubbles: true
				}));
				await new Promise(r => setTimeout(r, 80));
				btn.click();
			} catch (e) {
				console.error("[Bale Bridge] Edit encrypt failed:", e);
				secureEdit.value = prev;
				alert("Encryption failed!");
			} finally {
				secureEdit._isSending = false;
			}
		};
		const isConfirmBtn = (t) => t.closest('[data-testid="confirm-button"]') || (t.closest('button[aria-label="Send"]') && !t.closest('#chat_footer'));
		const editClickHandler = (e) => {
			const btn = isConfirmBtn(e.target);
			if (!btn || !secureEdit.value.trim()) return;
			if (secureEdit._isSending) {
				e.preventDefault();
				e.stopPropagation();
				return;
			}
			e.preventDefault();
			e.stopPropagation();
			encryptAndForward(btn);
		};
		document.addEventListener("click", editClickHandler, true);
		document.addEventListener("mousedown", editClickHandler, true);
		const editObserver = new MutationObserver(() => {
			if (!document.contains(secureEdit)) {
				document.removeEventListener("click", editClickHandler, true);
				document.removeEventListener("mousedown", editClickHandler, true);
				editObserver.disconnect();
			}
		});
		editObserver.observe(document.body, {
			childList: true,
			subtree: true
		});
		secureEdit.addEventListener("keydown", (e) => {
			if (e.key === "Enter" && !e.shiftKey) {
				e.preventDefault();
				e.stopPropagation();
				const btn = document.querySelector('[data-testid="confirm-button"]') || document.querySelector('button[aria-label="Send"]:not(#chat_footer button)');
				if (btn) encryptAndForward(btn);
			}
		});
	}
	// ─── 9. Send Button Event Interception ───────────────────────────────────
	const getSecureText = () => {
		const si = document.getElementById("secure-input-overlay");
		return si ? (si.tagName === "TEXTAREA" ? si.value.trim() : si.innerText.trim()) : "";
	};
	const isSendBtn = (t) => !!t.closest('[aria-label="send-button"]');
	document.addEventListener("mousedown", (e) => {
		if (e.button !== 0 || isSending || !isSendBtn(e.target)) return;
		// Only intercept when encryption is enabled
		if (!isEncryptionEnabled()) return;
		if (!getSecureText()) return;
		e.preventDefault();
		e.stopPropagation();
		window._bbSend?.(true);
	}, true);
	document.addEventListener("contextmenu", (e) => {
		if (!isSendBtn(e.target) || isSending) return;
		if (!isEncryptionEnabled() || !getSecureText()) return;
		e.preventDefault();
		e.stopPropagation();
		showMenu(e.clientX, e.clientY);
	}, true);
	let touchTimer;
	document.addEventListener("touchstart", (e) => {
		if (!isSendBtn(e.target) || isSending) return;
		if (!isEncryptionEnabled() || !getSecureText()) return;
		touchTimer = setTimeout(() => {
			e.preventDefault();
			showMenu(e.touches[0].clientX, e.touches[0].clientY);
		}, 500);
	}, {
		passive: false,
		capture: true
	});
	document.addEventListener("touchend", () => clearTimeout(touchTimer), true);
	document.addEventListener("touchmove", () => clearTimeout(touchTimer), true);
	// ─── 10. MutationObserver & SPA URL Tracker ───────────────────────────────
	let scanTO, lastUrl = location.href;
	new MutationObserver(() => {
		clearTimeout(scanTO);
		scanTO = setTimeout(() => {
			scanTree(document.body);
			ensureSecureInput();
			ensureEditInput();
			if (location.href !== lastUrl) {
				lastUrl = location.href;
				_settingsCache = null;
				_settingsCacheId = null;
				syncInputVisibility();
			}
		}, 100);
	}).observe(document.body, {
		childList: true,
		subtree: true,
		characterData: true
	});
})();
