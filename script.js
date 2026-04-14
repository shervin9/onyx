/* ─────────────────────────────────────────────────────────────────
   onyx — landing page interactions
───────────────────────────────────────────────────────────────── */

/* ── Terminal animation ───────────────────────────────────────── */
;(function () {
  'use strict';

  var body = document.getElementById('term-body');
  if (!body) return;

  // Lines to animate. Each entry:
  //   text  — string to display (omit or set falsy for a pure pause)
  //   cls   — CSS class for color (tc=cmd, td=dim, ti=info/blue, tw=warn/amber, to=ok/green)
  //   ms    — milliseconds to wait BEFORE this line appears
  //   type  — if true, characters are typed one-by-one instead of appearing instantly
  var LINES = [
    { text: '$ onyx my-server',                          cls: 'tc', type: true,  ms: 0    },
    { text: '[onyx] checking remote...',                 cls: 'td',              ms: 580  },
    { text: '[onyx] source unchanged · server up',      cls: 'td',              ms: 160  },
    { text: '[mode] QUIC  (session 8b3f1d)',             cls: 'ti',              ms: 280  },
    {                                                                             ms: 2000 },
    { text: '⚡  onyx — connection lost · 8s  reconnecting\u2026', cls: 'tw',   ms: 0    },
    { text: '[session] resumed',                         cls: 'to',              ms: 1150 },
    {                                                                             ms: 2600 },
  ];

  var CHAR_MS  = 28;   // base ms per character when typing
  var JITTER   = 12;   // random extra ms per char (natural feel)
  var FADE_MS  = 420;  // opacity transition duration

  function wait(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  async function run() {
    while (true) {
      // Fade out, clear, fade in — invisible during clear
      body.style.opacity = '0';
      await wait(FADE_MS + 60);
      body.innerHTML = '';
      await wait(80);
      body.style.opacity = '1';
      await wait(460); // settle before first line

      for (var i = 0; i < LINES.length; i++) {
        var line = LINES[i];

        // Pure pause line (no text)
        if (!line.text) {
          await wait(line.ms || 0);
          continue;
        }

        await wait(line.ms || 0);

        // Create row element
        var row = document.createElement('div');
        row.className = 'tl';
        body.appendChild(row);

        var span = document.createElement('span');
        if (line.cls) span.className = line.cls;
        row.appendChild(span);

        if (line.type) {
          // Character-by-character typing with blinking cursor
          var cur = document.createElement('span');
          cur.className = 'tk';
          row.appendChild(cur);

          for (var c = 0; c < line.text.length; c++) {
            span.textContent += line.text[c];
            await wait(CHAR_MS + Math.random() * JITTER);
          }

          row.removeChild(cur);
        } else {
          // Instant appearance
          span.textContent = line.text;
        }
      }

      // Final cursor blinks at the prompt while "user is working"
      var finalCur = document.createElement('span');
      finalCur.className = 'tk';
      body.appendChild(finalCur);
      await wait(700);
    }
  }

  run();
})();


/* ── Scroll reveal ────────────────────────────────────────────── */
(function () {
  'use strict';

  if (!('IntersectionObserver' in window)) {
    // Fallback: show everything immediately for older browsers
    document.querySelectorAll('.reveal').forEach(function (el) {
      el.classList.add('in');
    });
    return;
  }

  var obs = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        obs.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08 });

  document.querySelectorAll('.reveal').forEach(function (el) {
    obs.observe(el);
  });
})();


/* ── Copy install command ─────────────────────────────────────── */
function copyCmd() {
  var text = (document.getElementById('install-cmd') || {}).textContent || '';
  var btn  = document.getElementById('copy-btn');
  if (!text || !btn) return;

  var reset = function () { btn.textContent = 'Copy'; };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () {
      btn.textContent = 'Copied!';
      setTimeout(reset, 2000);
    }).catch(fallback);
  } else {
    fallback();
  }

  function fallback() {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;top:-9999px;opacity:0;pointer-events:none';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      btn.textContent = 'Copied!';
      setTimeout(reset, 2000);
    } catch (e) {
      btn.textContent = 'Failed';
      setTimeout(reset, 1500);
    }
  }
}
