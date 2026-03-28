// ==UserScript==
// @name         Rubika Bridge Encryptor/Decryptor (Ultimate Privacy)
// @namespace    http://tampermonkey.net/
// @version      2.0
// @description  Per-chat encryption keys, Shield button, Markdown UI, Auto-decrypt, Draft blocker.
// @author       You
// @match        *://web.rubika.ir/*
// @grant        none
// ==/UserScript==

(function () {
    "use strict";

    // =========================================================================
    // SECTION 1: Constants & Configuration
    // =========================================================================

    const MAX_MESSAGE_LENGTH = 4000;
    const KEY_LENGTH = 32;
    const AES_IV_LENGTH = 12;
    const ENCRYPTION_ALGORITHM = "AES-GCM";
    const COMPRESSION_FORMAT = "deflate";
    const STORAGE_PREFIX = "rubika_bridge_settings_";
    const ENCRYPTED_MESSAGE_PREFIX = "@@";
    const LONG_PRESS_DELAY_MS = 500;
    const MUTATION_DEBOUNCE_MS = 100;
    const SEND_BUTTON_POLL_INTERVAL_MS = 50;
    const SEND_BUTTON_POLL_MAX_ATTEMPTS = 20;
    const POST_SEND_DELAY_MS = 250;

    /** Base-85 alphabet for compact binary encoding */
    const BASE85_ALPHABET =
        '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';

    /** Characters used for random key generation */
    const KEY_CHARSET =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~";

    /** HTML entity map for sanitization */
    const HTML_ENTITIES = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
    };

    const URL_REGEX = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;

    // =========================================================================
    // SECTION 2: WebSocket Draft Blocker
    // =========================================================================

    /**
     * Intercepts WebSocket.send to block draft-sync messages,
     * preventing Rubika from leaking typed content to the server.
     */
    function installDraftBlocker() {
        const originalSend = WebSocket.prototype.send;

        WebSocket.prototype.send = function (data) {
            try {
                const text =
                    typeof data === "string"
                        ? data
                        : new TextDecoder().decode(data);

                if (text.includes("EditParameter") && text.includes("drafts_")) {
                    return; // Silently block draft sync
                }
            } catch {
                // If decoding fails, let the message through
            }

            return originalSend.apply(this, arguments);
        };
    }

    // =========================================================================
    // SECTION 3: Chat Identification & Per-Chat Settings
    // =========================================================================

    /** Cache for the current chat's settings to avoid repeated localStorage reads */
    let cachedChatId = null;
    let cachedSettings = null;

    /**
     * Extracts the current chat identifier from the URL.
     * Supports hash-based (#c=...), query-param-based, and path-based routing.
     */
    function getCurrentChatId() {
        const hash = location.hash;
        if (hash.startsWith("#c=")) {
            return hash.slice(3);
        }

        const params = new URLSearchParams(location.search);
        return (
            params.get("uid") ||
            params.get("groupId") ||
            params.get("channelId") ||
            location.pathname.split("/").pop() ||
            "global"
        );
    }

    /**
     * Loads encryption settings for the current chat.
     * Returns cached version if the chat hasn't changed.
     */
    function loadChatSettings() {
        const chatId = getCurrentChatId();

        if (chatId === cachedChatId && cachedSettings !== null) {
            return cachedSettings;
        }

        const stored = localStorage.getItem(STORAGE_PREFIX + chatId);
        cachedSettings = stored
            ? JSON.parse(stored)
            : { enabled: true, customKey: "" };
        cachedChatId = chatId;

        return cachedSettings;
    }

    /**
     * Persists encryption settings for the current chat.
     */
    function saveChatSettings(settings) {
        const chatId = getCurrentChatId();
        cachedSettings = settings;
        cachedChatId = chatId;
        localStorage.setItem(STORAGE_PREFIX + chatId, JSON.stringify(settings));
    }

    /**
     * Returns the active encryption key if encryption is enabled
     * and the key is exactly 32 characters. Otherwise returns null.
     */
    function getActiveEncryptionKey() {
        const settings = loadChatSettings();
        if (settings.enabled && settings.customKey && settings.customKey.length === KEY_LENGTH) {
            return settings.customKey;
        }
        return null;
    }

    /**
     * Returns whether encryption is enabled for the current chat.
     */
    function isEncryptionEnabled() {
        return loadChatSettings().enabled;
    }

    // =========================================================================
    // SECTION 4: Cryptographic Utilities
    // =========================================================================

    /** Cache for imported CryptoKey objects keyed by the string password */
    const cryptoKeyCache = new Map();

    /**
     * Imports a 32-char string as an AES-GCM CryptoKey.
     * Results are cached to avoid redundant imports.
     */
    async function importEncryptionKey(keyString) {
        if (cryptoKeyCache.has(keyString)) {
            return cryptoKeyCache.get(keyString);
        }

        const keyBytes = new Uint8Array(KEY_LENGTH);
        keyBytes.set(new TextEncoder().encode(keyString).subarray(0, KEY_LENGTH));

        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: ENCRYPTION_ALGORITHM },
            false,
            ["encrypt", "decrypt"]
        );

        cryptoKeyCache.set(keyString, cryptoKey);
        return cryptoKey;
    }

    /**
     * Compresses a string using the DEFLATE algorithm.
     */
    async function compressText(text) {
        const stream = new CompressionStream(COMPRESSION_FORMAT);
        const writer = stream.writable.getWriter();
        writer.write(new TextEncoder().encode(text));
        writer.close();
        return new Uint8Array(await new Response(stream.readable).arrayBuffer());
    }

    /**
     * Decompresses DEFLATE-compressed bytes back to a string.
     */
    async function decompressBytes(bytes) {
        const stream = new DecompressionStream(COMPRESSION_FORMAT);
        const writer = stream.writable.getWriter();
        writer.write(bytes);
        writer.close();
        return new TextDecoder().decode(
            await new Response(stream.readable).arrayBuffer()
        );
    }

    // =========================================================================
    // SECTION 5: Base-85 Encoding/Decoding
    // =========================================================================

    /** Precomputed reverse lookup table: charCode -> value */
    const base85DecodeTable = new Uint8Array(128);
    for (let i = 0; i < BASE85_ALPHABET.length; i++) {
        base85DecodeTable[BASE85_ALPHABET.charCodeAt(i)] = i;
    }

    /**
     * Encodes a Uint8Array into a base-85 string for compact representation.
     */
    function encodeBase85(bytes) {
        const length = bytes.length;
        const remainder = length % 4;
        const outputLength = 5 * (length >>> 2) + (remainder ? remainder + 1 : 0);
        const output = new Array(outputLength);
        let outputIndex = 0;

        for (let i = 0; i < length; i += 4) {
            const chunkSize = Math.min(4, length - i);

            // Pack up to 4 bytes into a 32-bit integer
            let value = 0;
            for (let j = 0; j < 4; j++) {
                value = (value << 8) | (i + j < length ? bytes[i + j] : 0);
            }
            value >>>= 0; // Ensure unsigned

            const encodedLength = chunkSize < 4 ? chunkSize + 1 : 5;
            const digits = new Array(5);

            // Convert to base-85 digits (least significant first)
            for (let k = 4; k >= 0; k--) {
                digits[k] = BASE85_ALPHABET[value % 85];
                value = Math.floor(value / 85);
            }

            for (let k = 0; k < encodedLength; k++) {
                output[outputIndex++] = digits[k];
            }
        }

        return output.join("");
    }

    /**
     * Decodes a base-85 string back into a Uint8Array.
     */
    function decodeBase85(encoded) {
        const length = encoded.length;
        const remainder = length % 5;
        const output = new Uint8Array(
            4 * Math.floor(length / 5) + (remainder ? remainder - 1 : 0)
        );
        let outputIndex = 0;

        for (let i = 0; i < length; i += 5) {
            const groupEnd = Math.min(i + 5, length);
            const missingChars = 5 - (groupEnd - i);

            // Decode 5 base-85 characters into a 32-bit integer
            let value = 0;
            for (let j = 0; j < 5; j++) {
                const charCode = i + j < length ? encoded.charCodeAt(i + j) : 126; // '~' as padding
                value = 85 * value + base85DecodeTable[charCode];
            }

            const bytesToWrite = 4 - missingChars;
            if (bytesToWrite >= 1) output[outputIndex++] = (value >>> 24) & 0xff;
            if (bytesToWrite >= 2) output[outputIndex++] = (value >>> 16) & 0xff;
            if (bytesToWrite >= 3) output[outputIndex++] = (value >>> 8) & 0xff;
            if (bytesToWrite >= 4) output[outputIndex++] = value & 0xff;
        }

        return output.subarray(0, outputIndex);
    }

    // =========================================================================
    // SECTION 6: Encrypt / Decrypt
    // =========================================================================

    /**
     * Encrypts a plaintext message using AES-GCM with compression.
     * Returns a string prefixed with "@@" or null if no key is available.
     */
    async function encryptMessage(plaintext) {
        const key = getActiveEncryptionKey();
        if (!key) return null;

        const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
        const compressed = await compressText(plaintext);
        const cryptoKey = await importEncryptionKey(key);

        const ciphertext = new Uint8Array(
            await crypto.subtle.encrypt(
                { name: ENCRYPTION_ALGORITHM, iv },
                cryptoKey,
                compressed
            )
        );

        // Prepend IV to ciphertext
        const payload = new Uint8Array(AES_IV_LENGTH + ciphertext.length);
        payload.set(iv);
        payload.set(ciphertext, AES_IV_LENGTH);

        return ENCRYPTED_MESSAGE_PREFIX + encodeBase85(payload);
    }

    /**
     * Decrypts an "@@"-prefixed encrypted message.
     * Returns the original plaintext, or the input unchanged if decryption fails.
     */
    async function decryptMessage(encryptedText) {
        if (!encryptedText.startsWith(ENCRYPTED_MESSAGE_PREFIX)) {
            return encryptedText;
        }

        const key = getActiveEncryptionKey();
        if (!key) return encryptedText;

        try {
            const payload = decodeBase85(encryptedText.slice(2));
            const iv = payload.subarray(0, AES_IV_LENGTH);
            const ciphertext = payload.subarray(AES_IV_LENGTH);
            const cryptoKey = await importEncryptionKey(key);

            const decrypted = await crypto.subtle.decrypt(
                { name: ENCRYPTION_ALGORITHM, iv },
                cryptoKey,
                ciphertext
            );

            return await decompressBytes(new Uint8Array(decrypted));
        } catch {
            return encryptedText; // Wrong key or corrupted data
        }
    }

    /**
     * Splits a message into chunks that each encrypt to <= MAX_MESSAGE_LENGTH chars.
     * Uses recursive binary splitting when a single encrypted message is too long.
     * Returns an array of encrypted strings, or null on failure.
     */
    async function encryptMessageChunked(plaintext) {
        const encrypted = await encryptMessage(plaintext);
        if (!encrypted) return null;

        if (encrypted.length <= MAX_MESSAGE_LENGTH) {
            return [encrypted];
        }

        // Find a good split point (prefer newline, then space, then midpoint)
        const midpoint = Math.floor(plaintext.length / 2);
        let splitIndex = plaintext.lastIndexOf("\n", midpoint);
        if (splitIndex <= 0) splitIndex = plaintext.lastIndexOf(" ", midpoint);
        if (splitIndex <= 0) splitIndex = midpoint;

        const firstHalf = await encryptMessageChunked(plaintext.slice(0, splitIndex).trim());
        const secondHalf = await encryptMessageChunked(plaintext.slice(splitIndex).trim());

        if (firstHalf && secondHalf) {
            return [...firstHalf, ...secondHalf];
        }
        return null;
    }

    // =========================================================================
    // SECTION 7: Markdown Rendering
    // =========================================================================

    /**
     * Escapes HTML special characters to prevent XSS.
     */
    function escapeHtml(text) {
        return text.replace(/[&<>"]/g, (char) => HTML_ENTITIES[char]);
    }

    /**
     * Renders inline Markdown syntax to HTML.
     * Supports: code, spoiler, bold, italic, underline, strikethrough, links.
     */
    function renderInlineMarkdown(text) {
        return text
            // Double backtick code
            .replace(/``([^`]+)``|`([^`]+)`/g, (_, g1, g2) => {
                const code = g1 ?? g2;
                return `<code style="background:var(--color-neutrals-n-20,#f4f5f7);border-radius:4px;padding:1px 5px;font-family:monospace;font-size:.92em">${code}</code>`;
            })
            // Spoiler
            .replace(
                /\|\|(.+?)\|\|/g,
                (_, content) =>
                    `<span class="bb-spoiler" style="background:var(--color-neutrals-n-400,#42526e);color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none" title="Click to reveal">${content}</span>`
            )
            // Bold italic (***text***)
            .replace(
                /\*\*\*(.+?)\*\*\*/g,
                (_, content) => `<strong><em>${content}</em></strong>`
            )
            // Bold (**text**)
            .replace(
                /\*\*(.+?)\*\*/g,
                (_, content) => `<strong>${content}</strong>`
            )
            // Underline (__text__)
            .replace(
                /(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g,
                (_, content) => `<u>${content}</u>`
            )
            // Italic with asterisk (*text*)
            .replace(
                /\*([^*\n]+)\*/g,
                (_, content) => `<em>${content}</em>`
            )
            // Italic with underscore (_text_)
            .replace(
                /(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g,
                (_, prefix, content) => `${prefix}<em>${content}</em>`
            )
            // Strikethrough (~~text~~)
            .replace(
                /~~(.+?)~~/g,
                (_, content) => `<del>${content}</del>`
            )
            // Links [text](url)
            .replace(
                /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
                (_, label, url) =>
                    `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" style="color:#00ab80;text-decoration:underline">${label}</a>`
            );
    }

    /**
     * Processes a text segment: escapes HTML, auto-links URLs, then applies inline Markdown.
     */
    function renderInlineWithAutolinks(text) {
        const parts = [];
        let lastIndex = 0;

        URL_REGEX.lastIndex = 0;
        let match;
        while ((match = URL_REGEX.exec(text)) !== null) {
            // Text before the URL
            parts.push(renderInlineMarkdown(escapeHtml(text.slice(lastIndex, match.index))));

            // The URL itself
            const escapedUrl = escapeHtml(match[0]);
            parts.push(
                `<a href="${escapedUrl}" target="_blank" rel="noopener noreferrer" style="color:#00ab80;text-decoration:underline;word-break:break-all">${escapedUrl}</a>`
            );

            lastIndex = match.index + match[0].length;
        }

        // Remaining text after last URL
        parts.push(renderInlineMarkdown(escapeHtml(text.slice(lastIndex))));

        return parts.join("");
    }

    /**
     * Renders a full Markdown document to HTML.
     * Supports: headings, blockquotes, unordered/ordered lists, horizontal rules, paragraphs.
     */
    function renderMarkdownToHtml(text) {
        const lines = text.split("\n");
        const output = [];
        let lineIndex = 0;

        const wrapBlock = (html) =>
            `<span dir="auto" class="bb-block" style="display:block;unicode-bidi:plaintext;">${html}</span>`;

        while (lineIndex < lines.length) {
            const line = lines[lineIndex];

            // Blockquote (> ...)
            if (line.startsWith("> ") || line === ">") {
                const quoteLines = [];
                while (
                    lineIndex < lines.length &&
                    (lines[lineIndex].startsWith("> ") || lines[lineIndex] === ">")
                ) {
                    quoteLines.push(lines[lineIndex++].replace(/^> ?/, ""));
                }
                output.push(
                    `<span dir="auto" class="bb-quote" style="display:block;border-inline-start:3px solid #00ab80;padding:2px 10px;margin:2px 0;font-style:italic;opacity:0.9;unicode-bidi:plaintext;">${quoteLines.map(renderInlineWithAutolinks).join("<br>")}</span>`
                );
                continue;
            }

            // Unordered list (- item, * item, + item)
            if (/^[-*+] /.test(line)) {
                const items = [];
                while (lineIndex < lines.length && /^[-*+] /.test(lines[lineIndex])) {
                    items.push(
                        `<li style="margin:2px 0;padding-inline-start:2px">${renderInlineWithAutolinks(lines[lineIndex++].slice(2))}</li>`
                    );
                }
                output.push(
                    `<ul dir="auto" style="margin:4px 0;padding-inline-start:22px;list-style:disc;unicode-bidi:plaintext;">${items.join("")}</ul>`
                );
                continue;
            }

            // Ordered list (1. item)
            if (/^\d+\. /.test(line)) {
                const items = [];
                while (lineIndex < lines.length && /^\d+\. /.test(lines[lineIndex])) {
                    items.push(
                        `<li style="margin:2px 0;padding-inline-start:2px">${renderInlineWithAutolinks(lines[lineIndex++].replace(/^\d+\. /, ""))}</li>`
                    );
                }
                output.push(
                    `<ol dir="auto" style="margin:4px 0;padding-inline-start:22px;list-style:decimal;unicode-bidi:plaintext;">${items.join("")}</ol>`
                );
                continue;
            }

            // Headings (# ## ###)
            const headingMatch = line.match(/^(#{1,3}) (.+)/);
            if (headingMatch) {
                const fontSizes = ["1.25em", "1.1em", "1em"];
                const level = Math.min(headingMatch[1].length, 3) - 1;
                output.push(
                    wrapBlock(
                        `<span style="font-weight:700;font-size:${fontSizes[level]}">${renderInlineWithAutolinks(headingMatch[2])}</span>`
                    )
                );
                lineIndex++;
                continue;
            }

            // Horizontal rule (---, ***, ___)
            if (/^([-*_])\1{2,}$/.test(line.trim())) {
                output.push(
                    '<span style="display:block;border-top:1px solid #ccc;margin:6px 0;"></span>'
                );
                lineIndex++;
                continue;
            }

            // Non-empty line = paragraph
            if (line.trim() !== "") {
                output.push(wrapBlock(renderInlineWithAutolinks(line)));
                lineIndex++;
                continue;
            }

            // Empty line = vertical spacer
            output.push('<span style="display:block;height:0.4em;"></span>');
            lineIndex++;
        }

        return output.join("");
    }

    // =========================================================================
    // SECTION 8: Spoiler Click Handler
    // =========================================================================

    function initializeSpoilerHandler() {
        document.addEventListener(
            "click",
            (event) => {
                const spoiler = event.target.closest(".bb-spoiler");
                if (spoiler) {
                    spoiler.style.color = "inherit";
                    spoiler.style.background = "#dfe1e6";
                }
            },
            true
        );
    }

    // =========================================================================
    // SECTION 9: Stylesheet Injection
    // =========================================================================

    function injectStyles() {
        document.head.insertAdjacentHTML(
            "beforeend",
            `<style>
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
    }

    /* Secure input overlay */
    #secure-input-overlay {
        flex: 1; width: 100%; box-sizing: border-box;
        min-height: 44px; max-height: 150px; overflow-y: auto;
        background-color: transparent;
        border: 2px solid #00ab80; border-radius: 16px;
        padding: 10px 16px;
        font-family: inherit; font-size: 14px;
        outline: none; white-space: pre-wrap; word-break: break-word;
        color: inherit; z-index: 100; position: relative;
        transition: box-shadow .2s ease, border-color .2s ease;
        margin: 5px 0; cursor: text;
    }
    #secure-input-overlay:focus {
        box-shadow: 0 4px 16px rgba(0,171,128,.3);
        border-color: #00916d;
    }
    #secure-input-overlay:empty::before {
        content: attr(data-placeholder);
        color: #888; pointer-events: none; display: block;
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
    </style>`
        );
    }

    // =========================================================================
    // SECTION 10: Context Menu (Send Encrypted / Unencrypted)
    // =========================================================================

    let contextMenuElement = null;

    function createContextMenu() {
        contextMenuElement = document.createElement("div");
        contextMenuElement.id = "bale-bridge-menu";
        contextMenuElement.innerHTML = `
            <div class="bale-menu-item" id="bale-menu-enc">🔒 Send Encrypted</div>
            <div class="bale-menu-item" id="bale-menu-plain">⚠️ Send Unencrypted</div>`;
        document.body.appendChild(contextMenuElement);

        document.getElementById("bale-menu-enc").onclick = () => {
            hideContextMenu();
            window._bbSendMessage?.(true);
        };

        document.getElementById("bale-menu-plain").onclick = () => {
            hideContextMenu();
            window._bbSendMessage?.(false);
        };

        // Close menu when clicking outside
        document.addEventListener("click", (event) => {
            if (!contextMenuElement.contains(event.target)) {
                hideContextMenu();
            }
        });
    }

    function showContextMenu(x, y) {
        Object.assign(contextMenuElement.style, {
            display: "flex",
            left: Math.min(x, innerWidth - 210) + "px",
            top: Math.min(y, innerHeight - 120) + "px",
        });
    }

    function hideContextMenu() {
        contextMenuElement.style.display = "none";
    }

    // =========================================================================
    // SECTION 11: Settings Modal
    // =========================================================================

    function openSettingsModal() {
        // Remove any existing modal
        document.getElementById("bb-modal-overlay")?.remove();

        const settings = loadChatSettings();

        document.body.insertAdjacentHTML(
            "beforeend",
            `<div id="bb-modal-overlay">
                <div id="bb-modal-card">
                    <h3 class="bb-modal-title">Shield Settings 🛡️</h3>
                    <p class="bb-modal-desc">Configure encryption for this chat. When enabled, a 32-character key is required.</p>
                    <label class="bb-toggle-lbl">
                        <input type="checkbox" id="bb-enable-enc" ${settings.enabled ? "checked" : ""} style="width:16px;height:16px;accent-color:#00ab80">
                        <span>Enable Encryption Here</span>
                    </label>
                    <div id="bb-key-section" style="margin-top:16px;border-top:1px solid #f4f5f7;padding-top:16px">
                        <label style="font-size:12px;color:#151515;font-weight:600">Encryption Key <span style="color:#d32f2f">*</span></label>
                        <div class="bb-key-row">
                            <input type="password" id="bb-custom-key" class="bb-input" placeholder="Enter exactly 32 characters…" maxlength="32" value="${settings.customKey || ""}">
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
            </div>`
        );

        const overlay = document.getElementById("bb-modal-overlay");
        const keyInput = document.getElementById("bb-custom-key");
        const keySection = document.getElementById("bb-key-section");
        const keyCounter = document.getElementById("bb-key-counter");
        const keyError = document.getElementById("bb-key-error");
        const saveButton = document.getElementById("bb-btn-save");
        const enableCheckbox = document.getElementById("bb-enable-enc");
        const copyButton = document.getElementById("bb-copy-key");
        const generateButton = document.getElementById("bb-gen-key");
        const toggleVisButton = document.getElementById("bb-toggle-vis");

        function validateKeyInput() {
            const length = keyInput.value.length;
            const isEnabled = enableCheckbox.checked;

            keyCounter.textContent = `${length} / 32`;
            keyCounter.className = "bb-key-counter" + (length === KEY_LENGTH ? " exact" : "");
            keySection.style.display = isEnabled ? "" : "none";

            if (!isEnabled) {
                keyError.textContent = "";
                saveButton.disabled = false;
                return;
            }

            if (length === 0) {
                keyError.textContent = "A key is required when encryption is enabled.";
                saveButton.disabled = true;
            } else if (length !== KEY_LENGTH) {
                keyError.textContent = `Key must be exactly 32 characters (currently ${length}).`;
                saveButton.disabled = true;
            } else {
                keyError.textContent = "";
                saveButton.disabled = false;
            }
        }

        keyInput.addEventListener("input", validateKeyInput);
        enableCheckbox.addEventListener("change", validateKeyInput);
        validateKeyInput();

        toggleVisButton.addEventListener("click", () => {
            const isPassword = keyInput.type === "password";
            keyInput.type = isPassword ? "text" : "password";
            toggleVisButton.textContent = isPassword ? "🙈" : "👁";
        });

        copyButton.addEventListener("click", () => {
            if (!keyInput.value) return;
            navigator.clipboard.writeText(keyInput.value).then(() => {
                copyButton.textContent = "✅";
                copyButton.classList.add("copied");
                setTimeout(() => {
                    copyButton.textContent = "📋";
                    copyButton.classList.remove("copied");
                }, 1500);
            });
        });

        generateButton.addEventListener("click", () => {
            const randomBytes = crypto.getRandomValues(new Uint8Array(KEY_LENGTH));
            keyInput.value = Array.from(
                randomBytes,
                (byte) => KEY_CHARSET[byte % KEY_CHARSET.length]
            ).join("");
            keyInput.type = "text";
            toggleVisButton.textContent = "🙈";
            validateKeyInput();
        });

        document.getElementById("bb-btn-cancel").onclick = () => overlay.remove();

        saveButton.onclick = () => {
            if (saveButton.disabled) return;
            saveChatSettings({
                enabled: enableCheckbox.checked,
                customKey: keyInput.value,
            });
            overlay.remove();
            updateInputVisibility();
        };
    }

    // =========================================================================
    // SECTION 12: Shield Icon SVGs
    // =========================================================================

    const SHIELD_SVG = {
        /** Green shield with checkmark - encryption active with valid key */
        active: `<svg width="24" height="24" fill="#00ab80" viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
        </svg>`,

        /** Red shield with info icon - encryption enabled but no key set */
        missingKey: `<svg width="24" height="24" fill="#d32f2f" viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h1.39v4.19H10.6v-4.19H12zM12 9.17c-.77 0-1.39-.62-1.39-1.39 0-.77.62-1.39 1.39-1.39.77 0 1.39.62 1.39 1.39 0 .77-.62 1.39-1.39 1.39z"/>
        </svg>`,

        /** Gray shield - encryption disabled */
        disabled: `<svg width="24" height="24" fill="#888" viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 19.93c-3.95-1.17-6.9-5.11-7.7-9.43l7.7-3.42 7.7 3.42c-.8 4.32-3.75 8.26-7.7 9.43z"/>
        </svg>`,
    };

    // =========================================================================
    // SECTION 13: Send Button State Management
    // =========================================================================

    /**
     * Forces the native send/record button into the correct visual state.
     * @param {boolean} showSend - true = show send icon, false = show microphone icon
     */
    function updateSendButtonAppearance(showSend) {
        const button = document.querySelector(".btn-send");
        if (!button) return;

        if (showSend) {
            if (button.classList.contains("send") && !button.classList.contains("record")) return;
            button.classList.remove("record");
            button.classList.add("send");

            const micIcon = button.querySelector(".rbico-microphone");
            if (micIcon) micIcon.setAttribute("hidden", "true");

            const sendIcon = button.querySelector(".rbico-send");
            if (sendIcon) sendIcon.removeAttribute("hidden");
        } else {
            if (button.classList.contains("record") && !button.classList.contains("send")) return;
            button.classList.remove("send");
            button.classList.add("record");

            const sendIcon = button.querySelector(".rbico-send");
            if (sendIcon) sendIcon.setAttribute("hidden", "true");

            const micIcon = button.querySelector(".rbico-microphone");
            if (micIcon) micIcon.removeAttribute("hidden");
        }
    }

    // =========================================================================
    // SECTION 14: Input Visibility Controller
    // =========================================================================

    /**
     * Updates the visibility of the secure input overlay, no-key notice,
     * and shield icon based on the current encryption state.
     */
    function updateInputVisibility() {
        const container = document.querySelector(".input-message-container");
        if (!container) return;

        const originalInput = container.querySelector(".input-message-input.scrollable");
        const secureInput = document.getElementById("secure-input-overlay");
        const noKeyNotice = document.getElementById("bb-no-key-notice");
        const settingsButton = document.getElementById("bb-settings-btn");

        if (!originalInput) return;

        const encryptionOn = isEncryptionEnabled();
        const hasValidKey = !!getActiveEncryptionKey();

        // Update shield icon appearance
        if (settingsButton) {
            if (encryptionOn && hasValidKey) {
                settingsButton.innerHTML = SHIELD_SVG.active;
                settingsButton.title = "Encryption Active - Click to configure";
            } else if (encryptionOn && !hasValidKey) {
                settingsButton.innerHTML = SHIELD_SVG.missingKey;
                settingsButton.title = "Encryption Active (No Key) - Click to configure";
            } else {
                settingsButton.innerHTML = SHIELD_SVG.disabled;
                settingsButton.title = "Encryption Disabled - Click to enable";
            }
        }

        // Toggle input elements based on state
        if (encryptionOn) {
            if (hasValidKey) {
                originalInput.classList.add("rb-locked-input");
                if (secureInput) secureInput.style.display = "";
                if (noKeyNotice) noKeyNotice.style.display = "none";
            } else {
                originalInput.classList.add("rb-locked-input");
                if (secureInput) secureInput.style.display = "none";
                if (noKeyNotice) noKeyNotice.style.display = "flex";
            }
        } else {
            originalInput.classList.remove("rb-locked-input");
            if (secureInput) secureInput.style.display = "none";
            if (noKeyNotice) noKeyNotice.style.display = "none";
        }
    }

    // =========================================================================
    // SECTION 15: Send Button Interaction Handlers
    // =========================================================================

    /** Flags to coordinate send operations */
    let isSending = false;
    let isSendButtonSynced = false;
    let isInjectionInProgress = false;

    function hasSecureInputContent() {
        const input = document.getElementById("secure-input-overlay");
        return !!input && !!input.innerText.trim();
    }

    function isClickOnSendButton(target) {
        return !!target.closest(".btn-send");
    }

    let longPressTimer;

    function initializeSendButtonHandlers() {
        // Left-click: send encrypted
        document.addEventListener(
            "mousedown",
            (event) => {
                if (
                    event.button === 0 &&
                    !isSending &&
                    isClickOnSendButton(event.target) &&
                    isEncryptionEnabled() &&
                    hasSecureInputContent()
                ) {
                    event.preventDefault();
                    event.stopPropagation();
                    window._bbSendMessage?.(true);
                }
            },
            true
        );

        // Right-click: show context menu
        document.addEventListener(
            "contextmenu",
            (event) => {
                if (
                    isClickOnSendButton(event.target) &&
                    !isSending &&
                    isEncryptionEnabled() &&
                    hasSecureInputContent()
                ) {
                    event.preventDefault();
                    event.stopPropagation();
                    showContextMenu(event.clientX, event.clientY);
                }
            },
            true
        );

        // Touch: long-press for context menu
        document.addEventListener(
            "touchstart",
            (event) => {
                if (
                    isClickOnSendButton(event.target) &&
                    !isSending &&
                    isEncryptionEnabled() &&
                    hasSecureInputContent()
                ) {
                    longPressTimer = setTimeout(() => {
                        event.preventDefault();
                        showContextMenu(
                            event.touches[0].clientX,
                            event.touches[0].clientY
                        );
                    }, LONG_PRESS_DELAY_MS);
                }
            },
            { passive: false, capture: true }
        );

        document.addEventListener("touchend", () => clearTimeout(longPressTimer), true);
        document.addEventListener("touchmove", () => clearTimeout(longPressTimer), true);
    }

    // =========================================================================
    // SECTION 16: Auto-Decrypt Visible Messages
    // =========================================================================

    /**
     * Scans all visible message elements for encrypted content and decrypts them in place.
     */
    function decryptVisibleMessages() {
        const messageElements = document.body.querySelectorAll("div[rb-copyable]");

        for (const element of messageElements) {
            if (element._isDecrypting) continue;

            const rawText = element.textContent.trim();

            // If previously decrypted, check if the content has been replaced by the app
            if (element._isDecrypted) {
                if (!rawText.startsWith(ENCRYPTED_MESSAGE_PREFIX) || element.querySelector(".bb-copy-btn")) {
                    continue;
                }
                // Content was reset by the app - re-decrypt
                element._isDecrypted = false;
                element.removeAttribute("data-orig-text");
            }

            // Only process messages that look encrypted
            if (!rawText.startsWith(ENCRYPTED_MESSAGE_PREFIX) || rawText.length <= 20) {
                continue;
            }

            // Store original text for re-decryption
            if (!element.hasAttribute("data-orig-text")) {
                element.setAttribute("data-orig-text", rawText);
            }

            const originalText = element.getAttribute("data-orig-text").replace(/\s/g, "");
            element._isDecrypting = true;

            decryptMessage(originalText)
                .then((decrypted) => {
                    if (decrypted !== originalText) {
                        // Successfully decrypted - render with Markdown
                        element.style.overflow = "hidden";
                        element.style.overflowWrap = "anywhere";
                        element.style.wordBreak = "break-word";
                        element.style.maxWidth = "100%";
                        element.style.color = "inherit";

                        element.innerHTML =
                            renderMarkdownToHtml(decrypted) +
                            `<span style="display:inline-block;font-size:9px;opacity:0.5;letter-spacing:0.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap">
                                🔒 encrypted
                                <span class="bb-copy-btn" title="Copy decrypted message" style="cursor:pointer;margin-inline-start:4px;font-size:11px;font-style:normal;transition:opacity 0.2s;">📋</span>
                            </span>`;

                        element._isDecrypted = true;

                        // Attach copy handler
                        const copyBtn = element.querySelector(".bb-copy-btn");
                        if (copyBtn) {
                            copyBtn.addEventListener("click", (event) => {
                                event.preventDefault();
                                event.stopPropagation();
                                navigator.clipboard.writeText(decrypted).then(() => {
                                    copyBtn.textContent = "✅";
                                    setTimeout(() => (copyBtn.textContent = "📋"), 1500);
                                });
                            });
                        }
                    } else if (!element._hasLockBadge) {
                        // Decryption returned same text = wrong key
                        element.innerHTML = `
                            <span style="word-break:break-all; opacity:0.6;">${originalText}</span>
                            <br>
                            <span style="font-size:11px; color:#d32f2f; font-weight:bold; margin-top:4px; display:inline-block;">
                                🔒 Encrypted (Need Key)
                            </span>`;
                        element._hasLockBadge = true;
                    }
                })
                .finally(() => {
                    element._isDecrypting = false;
                });
        }
    }

    // =========================================================================
    // SECTION 17: Secure Input Setup
    // =========================================================================

    /**
     * Creates the secure input overlay, shield button, and no-key notice.
     * Wires up all event handlers for the custom input flow.
     */
    function setupSecureInput() {
        const container = document.querySelector(".input-message-container");
        if (!container) return;

        const originalInput = container.querySelector(".input-message-input.scrollable");
        if (!originalInput) return;

        const composerTextarea = originalInput.querySelector(".composer_rich_textarea");
        if (!composerTextarea) return;

        // --- Create Shield Settings Button ---
        if (!document.getElementById("bb-settings-btn")) {
            const emojiButton = document.querySelector(".toggle-emoticons");
            const settingsButton = document.createElement("button");
            settingsButton.id = "bb-settings-btn";
            settingsButton.className = "btn-icon rp";
            settingsButton.style.cssText =
                "display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s;background:none;border:none;outline:none;width:44px;height:44px;flex-shrink:0;";
            settingsButton.onclick = openSettingsModal;

            if (emojiButton?.parentElement) {
                emojiButton.parentElement.insertBefore(settingsButton, emojiButton);
            }
        }

        // --- Create No-Key Warning Notice ---
        if (!document.getElementById("bb-no-key-notice")) {
            const notice = document.createElement("div");
            notice.id = "bb-no-key-notice";
            notice.innerHTML = `
                <div class="bb-notice-icon">⚠️</div>
                <div class="bb-notice-body">
                    <strong>Encryption key not set — sending is blocked.</strong>
                    Tap the shield icon to set up encryption or disable it.
                    <br>
                    <button class="bb-notice-btn" id="bb-notice-set-key">🛡 Set Encryption Key</button>
                </div>`;
            container.insertBefore(notice, originalInput);
            notice.querySelector("#bb-notice-set-key").onclick = openSettingsModal;
        }

        // --- Check if Secure Input Already Exists ---
        const existingOverlay = document.getElementById("secure-input-overlay");
        if (existingOverlay) {
            window._bbSendMessage = existingOverlay._triggerSend;
            updateInputVisibility();
            return;
        }

        // --- Hijack Focus on Original Input ---
        if (!composerTextarea._hasStrictHijack) {
            composerTextarea._hasStrictHijack = true;
            composerTextarea.addEventListener("focus", () => {
                if (!isInjectionInProgress && isEncryptionEnabled()) {
                    composerTextarea.blur();
                    document.getElementById("secure-input-overlay")?.focus();
                }
            });
        }

        // --- Create Secure Input Overlay ---
        const secureInput = document.createElement("div");
        secureInput.id = "secure-input-overlay";
        secureInput.contentEditable = "true";
        secureInput.dir = "auto";
        secureInput.dataset.placeholder = "🔒 پیام امن...";
        container.insertBefore(secureInput, originalInput);

        function getSecureInputText() {
            return secureInput.innerText.trim();
        }

        function setSecureInputText(text) {
            secureInput.innerText = text;
        }

        // Prevent events from propagating to Rubika's input handlers
        ["keydown", "keypress", "keyup", "paste", "drop"].forEach((eventType) => {
            secureInput.addEventListener(eventType, (event) => {
                event.stopPropagation();
            });
        });

        /**
         * Syncs the "has content" state with Rubika's native input
         * so the send/record button toggles correctly.
         */
        function syncInputState(hasContent) {
            if (hasContent === isSendButtonSynced) return;
            isSendButtonSynced = hasContent;

            composerTextarea.textContent = hasContent ? "." : "";
            composerTextarea.dispatchEvent(new Event("input", { bubbles: true }));
            updateSendButtonAppearance(hasContent);
        }

        secureInput.addEventListener("input", () => {
            syncInputState(getSecureInputText().length > 0);
        });

        /**
         * Injects text into Rubika's native input and triggers a send.
         * Temporarily unhides the original input for the operation.
         */
        async function injectAndSendMessage(messageText) {
            isInjectionInProgress = true;
            originalInput.classList.remove("rb-locked-input");
            originalInput.style.cssText =
                "position:absolute!important;top:0!important;left:0!important;opacity:0!important;pointer-events:none!important;z-index:-1!important";

            // Insert text into native input
            composerTextarea.focus();
            document.execCommand("selectAll", false, null);
            document.execCommand("insertText", false, messageText);
            composerTextarea.dispatchEvent(new Event("input", { bubbles: true }));

            // Trigger Enter key
            const enterKeyOptions = {
                bubbles: true,
                cancelable: true,
                key: "Enter",
                keyCode: 13,
                which: 13,
            };
            composerTextarea.dispatchEvent(new KeyboardEvent("keydown", enterKeyOptions));
            composerTextarea.dispatchEvent(new KeyboardEvent("keyup", enterKeyOptions));

            // Wait for send button to appear
            let sendButton = null;
            for (let attempt = 0; attempt < SEND_BUTTON_POLL_MAX_ATTEMPTS; attempt++) {
                await sleep(SEND_BUTTON_POLL_INTERVAL_MS);

                const btn = document.querySelector(".btn-send");
                if (!btn) continue;

                const isSendState =
                    btn.classList.contains("send") ||
                    !btn.classList.contains("record") ||
                    !!btn.querySelector(".rbico-send:not([hidden])");

                if (isSendState) {
                    sendButton = btn;
                    break;
                }
            }

            if (sendButton) {
                // Click the send button
                const mouseEventOptions = {
                    bubbles: true,
                    cancelable: true,
                    view: window,
                };
                sendButton.dispatchEvent(new PointerEvent("pointerdown", mouseEventOptions));
                sendButton.dispatchEvent(new MouseEvent("mousedown", mouseEventOptions));
                sendButton.dispatchEvent(new PointerEvent("pointerup", mouseEventOptions));
                sendButton.dispatchEvent(new MouseEvent("mouseup", mouseEventOptions));
                sendButton.dispatchEvent(new MouseEvent("click", mouseEventOptions));
                sendButton.click();
            } else {
                // Fallback: try Enter key again
                composerTextarea.focus();
                ["keydown", "keypress", "keyup"].forEach((type) => {
                    composerTextarea.dispatchEvent(
                        new KeyboardEvent(type, enterKeyOptions)
                    );
                });
            }

            // Clean up: clear native input and restore locked state
            await sleep(POST_SEND_DELAY_MS);
            composerTextarea.focus();
            document.execCommand("selectAll", false, null);
            document.execCommand("insertText", false, "");
            composerTextarea.dispatchEvent(new Event("input", { bubbles: true }));
            originalInput.style.cssText = "";
            originalInput.classList.add("rb-locked-input");
            isInjectionInProgress = false;
        }

        /**
         * Main send handler. Encrypts (or not) and sends the message.
         * @param {boolean} shouldEncrypt - Whether to encrypt the message
         */
        async function handleSendMessage(shouldEncrypt = true) {
            if (isSending) return;

            const plaintext = getSecureInputText();
            if (!plaintext) return;

            if (shouldEncrypt) {
                if (!getActiveEncryptionKey()) {
                    openSettingsModal();
                    return;
                }

                isSending = true;
                isInjectionInProgress = true;
                setSecureInputText("🔒 Encrypting...");

                try {
                    const encryptedChunks = await encryptMessageChunked(plaintext);
                    if (!encryptedChunks) {
                        setSecureInputText(plaintext);
                        openSettingsModal();
                        return;
                    }

                    for (const chunk of encryptedChunks) {
                        await injectAndSendMessage(chunk);
                    }

                    setSecureInputText("");
                    isSendButtonSynced = false;
                    syncInputState(false);
                    secureInput.focus();
                } catch (error) {
                    console.error("[Rubika Bridge] Encrypted send failed:", error);
                    setSecureInputText(plaintext);
                    alert("Send failed!");
                } finally {
                    isSending = false;
                    isInjectionInProgress = false;
                }
            } else {
                // Send without encryption (with confirmation)
                const confirmed = confirm(
                    "⚠️ You are about to send this message WITHOUT encryption.\n\n" +
                    "This may expose sensitive information. Are you sure?"
                );
                if (!confirmed) return;

                isSending = true;
                isInjectionInProgress = true;
                setSecureInputText("🌐 Sending...");

                try {
                    await injectAndSendMessage(plaintext);
                    setSecureInputText("");
                    isSendButtonSynced = false;
                    syncInputState(false);
                    secureInput.focus();
                } catch (error) {
                    console.error("[Rubika Bridge] Plain send failed:", error);
                    setSecureInputText(plaintext);
                    alert("Send failed!");
                } finally {
                    isSending = false;
                    isInjectionInProgress = false;
                }
            }
        }

        // Expose send handler globally
        secureInput._triggerSend = handleSendMessage;
        window._bbSendMessage = handleSendMessage;

        // Enter key sends encrypted message
        secureInput.addEventListener("keydown", (event) => {
            if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                event.stopPropagation();
                handleSendMessage(true);
            }
        });

        updateInputVisibility();
    }

    // =========================================================================
    // SECTION 18: Utility Helpers
    // =========================================================================

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    // =========================================================================
    // SECTION 19: DOM Mutation Observer (Main Loop)
    // =========================================================================

    function startMutationObserver() {
        let debounceTimer;
        let lastUrl = location.href;

        const observer = new MutationObserver(() => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                // Auto-decrypt any visible encrypted messages
                decryptVisibleMessages();

                // Ensure secure input is set up
                setupSecureInput();

                // Keep send button in sync when encryption is active
                if (isEncryptionEnabled() && !isSending) {
                    const secureInput = document.getElementById("secure-input-overlay");
                    if (secureInput) {
                        updateSendButtonAppearance(secureInput.innerText.trim().length > 0);
                    }
                }

                // Handle navigation (chat switch)
                if (location.href !== lastUrl) {
                    lastUrl = location.href;
                    cachedSettings = null;
                    cachedChatId = null;
                    updateInputVisibility();
                }
            }, MUTATION_DEBOUNCE_MS);
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true,
        });
    }

    // =========================================================================
    // SECTION 20: Initialization
    // =========================================================================

    function initialize() {
        installDraftBlocker();
        injectStyles();
        initializeSpoilerHandler();
        createContextMenu();
        initializeSendButtonHandlers();
        startMutationObserver();
    }

    initialize();
})();
