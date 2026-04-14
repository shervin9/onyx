/* ── Terminal typing hint ───────────────────────── */
(function () {
  var el = document.getElementById('typed');
  if (!el) return;

  var text = 'onyx my-server';
  var i = 0;

  function type() {
    if (i < text.length) {
      el.textContent += text[i++];
      setTimeout(type, 55 + Math.random() * 35);
    }
  }

  setTimeout(type, 900);
})();

/* ── Copy install command ───────────────────────── */
function copyCmd() {
  var text = (document.getElementById('install-cmd') || {}).textContent || '';
  var btn  = document.getElementById('copy-btn');
  if (!text || !btn) return;

  function done(msg) {
    btn.textContent = msg;
    setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
  }

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { done('Copied'); }).catch(fb);
  } else {
    fb();
  }

  function fb() {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;top:-9999px;opacity:0;pointer-events:none';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      done('Copied');
    } catch (e) {
      done('Failed');
    }
  }
}
