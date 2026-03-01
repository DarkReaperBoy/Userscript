// ==UserScript==
// @name         GLWiz Premium Web Player
// @namespace    http://tampermonkey.net/
// @version      4.0
// @description  Forces ArtPlayer to render properly, blocks GLWiz from stealing focus (fixes broken settings), adds PiP, Screenshot, Quality Selection.
// @author       You
// @match        *://*.glwiz.com/Pages/Player/*
// @grant        none
// ==/UserScript==

(function() { // vibe coded with gemini 3.1 pro
    'use strict';

    // 1. Force the site's invisible blockers to disappear and ensure proper Z-indexing
    const style = document.createElement('style');
    style.innerHTML = `
        /* Hide UI blockers, overlays, and invisible traps */
        #divBlock, #adContainer, #divSkipContainer, #divPlayerHelp, #BannerBG, #divAlertMessage {
            display: none !important;
            pointer-events: none !important;
        }

        /* Disable the site's native clunky video player */
        #jsPLayer {
            display: none !important;
        }

        /* Empower the container to accept mouse clicks */
        #PlayerContainer {
            pointer-events: auto !important;
            background-color: #000 !important;
            z-index: 99999 !important;
            overflow: visible !important;
        }

        /* Ensure our beautiful ArtPlayer fills the container properly */
        #custom-artplayer {
            width: 100% !important;
            height: 100% !important;
            position: absolute !important;
            top: 0 !important;
            left: 0 !important;
            z-index: 999999 !important;
            background: #000 !important;
        }

        /* Protect ArtPlayer's UI from being disabled by GLWiz */
        .artplayer-app, .artplayer-app * {
            pointer-events: auto !important;
        }
    `;
    document.head.appendChild(style);

    // 2. Inject core logic into the page context to bypass Sandbox restrictions
    const script = document.createElement('script');
    script.textContent = `(${function() {

        // --- CRITICAL FIX: Stop GLWiz from stealing focus back to its invisible TV Remote anchor ---
        // This prevents the ArtPlayer Settings Menu from instantly closing when clicked.
        const originalFocus = HTMLElement.prototype.focus;
        HTMLElement.prototype.focus = function() {
            if (this.id === 'anchor') return; // Block the anchor from stealing focus
            originalFocus.apply(this, arguments);
        };
        // -------------------------------------------------------------------------------------------

        let art = null;

        // Dynamically load HLS.js and ArtPlayer
        function loadDependencies(callback) {
            console.log("[GLWiz Premium] Injecting Player Dependencies...");
            const hlsScript = document.createElement('script');
            hlsScript.src = 'https://cdn.jsdelivr.net/npm/hls.js@1.4.12/dist/hls.min.js';
            hlsScript.onload = () => {
                const artScript = document.createElement('script');
                artScript.src = 'https://cdn.jsdelivr.net/npm/artplayer@5.1.1/dist/artplayer.js';
                artScript.onload = callback;
                document.head.appendChild(artScript);
            };
            document.head.appendChild(hlsScript);
        }

        function playStream(url) {
            const container = document.getElementById('PlayerContainer');

            // Force container visible
            if (container) {
                container.style.setProperty('display', 'block', 'important');
                container.style.opacity = '1';
                container.style.visibility = 'visible';
            }

            if (!document.getElementById('custom-artplayer')) {
                const customDiv = document.createElement('div');
                customDiv.id = 'custom-artplayer';
                container.appendChild(customDiv);
            }

            const channelName = (window.oChannel && window.oChannel.name) ? window.oChannel.name : 'GLWiz Live Stream';

            if (!art) {
                art = new Artplayer({
                    container: '#custom-artplayer',
                    url: url,
                    type: 'm3u8',
                    title: channelName,
                    theme: '#ae0204',
                    volume: 1,
                    autoplay: true,
                    pip: true,
                    setting: true,          // Enables the gear icon
                    playbackRate: true,     // Enables speed control inside settings
                    screenshot: true,       // Camera icon for screenshots
                    fullscreenWeb: true,
                    fullscreen: true,
                    playsInline: true,
                    customType: {
                        m3u8: function (video, url, art) {
                            if (window.Hls && window.Hls.isSupported()) {
                                if (art.hls) art.hls.destroy();
                                const hls = new window.Hls({ debug: false });
                                art.hls = hls;
                                hls.loadSource(url);
                                hls.attachMedia(video);

                                hls.on(window.Hls.Events.MANIFEST_PARSED, function () {
                                    // Generate Quality Selector inside the Settings Menu
                                    const levels = hls.levels.map((l, index) => ({
                                        default: index === hls.currentLevel,
                                        html: (l.height ? l.height + 'p' : 'Level ' + index) + (l.bitrate ? ' (' + Math.round(l.bitrate/1000) + 'k)' : ''),
                                        level: index
                                    }));

                                    if (levels.length > 1) {
                                        levels.unshift({ html: 'Auto', level: -1, default: hls.currentLevel === -1 });
                                        art.setting.remove('quality');
                                        art.setting.add({
                                            name: 'quality',
                                            width: 200,
                                            html: 'Quality',
                                            tooltip: 'Auto',
                                            selector: levels,
                                            onSelect: function (item) {
                                                hls.currentLevel = item.level;
                                                return item.html;
                                            },
                                        });
                                    }
                                    video.play();
                                });

                                hls.on(window.Hls.Events.ERROR, function(event, data) {
                                    if (data.fatal) {
                                        if (data.type === window.Hls.ErrorTypes.NETWORK_ERROR) {
                                            hls.startLoad();
                                        } else if (data.type === window.Hls.ErrorTypes.MEDIA_ERROR) {
                                            hls.recoverMediaError();
                                        } else {
                                            hls.destroy();
                                        }
                                    }
                                });
                            } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
                                video.src = url;
                                video.play();
                            } else {
                                art.notice.show = 'Unsupported video format';
                            }
                        }
                    }
                });

                // Signal back to the site that the video has loaded, releasing the UI
                art.on('video:playing', () => {
                    if (window.Player && typeof window.Player.OnBufferingComplete === 'function') {
                        window.Player.OnBufferingComplete();
                    }
                });

                // Recalculate dimensions in case it shrunk
                art.on('video:canplay', () => {
                    if (art) art.autoSize();
                });

                art.on('destroy', () => {
                    if (art.hls) {
                        art.hls.destroy();
                        art.hls = null;
                    }
                });

            } else {
                art.switchUrl(url);
                art.title = channelName;
            }
        }

        // Hook into the site's stream engine
        function hookSitePlayer() {
            console.log("[GLWiz Premium] Hooking into site player...");
            const origStopLG = window.Player.StopLG;

            // 1. Hijack Play
            window.Player.PlayLG = function(url) {
                console.log("[GLWiz Premium] Intercepted stream URL:", url);
                playStream(url);
                window.Player.isPlay = 1; // Trick site state
            };

            // 2. Hijack Stop
            window.Player.StopLG = function() {
                if (art) art.pause();
                window.Player.isPlay = 0;
                if (origStopLG) origStopLG.call(window.Player);
            };

            // If a stream already started while we were loading, grab it immediately
            if (window.Player.converturl) {
                window.Player.PlayLG(window.Player.converturl);
            }
        }

        // Wait for the site's JS to finish loading, then inject
        let checkInterval = setInterval(() => {
            if (window.Player && typeof window.Player.PlayLG === 'function') {
                clearInterval(checkInterval);
                loadDependencies(hookSitePlayer);
            }
        }, 200);

        // Smart Keyboard Navigation
        window.addEventListener('keydown', function(e) {
            if (!art) return;

            // Ignore if typing in the search box
            if (e.target.tagName.toLowerCase() === 'input') return;

            const key = e.key.toLowerCase();
            const mediaKeys = ['f', 'm', ' ', 'arrowup', 'arrowdown', 'arrowleft', 'arrowright'];

            if (mediaKeys.includes(key) || e.code === 'Space') {
                // If it's an arrow key, ONLY capture it if we are in Fullscreen.
                // Otherwise, let the site's TV Menu script handle channel navigation.
                if (key.includes('arrow') && !art.fullscreenWeb && !art.fullscreen) {
                    return;
                }

                e.stopPropagation(); // Block site's script
                e.preventDefault();  // Stop page scrolling

                if (key === 'f') art.fullscreenWeb = !art.fullscreenWeb; // Theater mode
                if (key === 'm') art.muted = !art.muted;
                if (key === ' ' || e.code === 'Space') art.toggle();
                if (key === 'arrowup') art.volume = Math.min(art.volume + 0.1, 1);
                if (key === 'arrowdown') art.volume = Math.max(art.volume - 0.1, 0);
                if (key === 'arrowright') art.forward = 10;
                if (key === 'arrowleft') art.backward = 10;
            }
        }, true); // "true" ensures our script fires BEFORE the site's TV remote script

    }})();`;
    document.body.appendChild(script);
})();
