(function () {
  var typed = document.getElementById("typed");
  var meta = document.getElementById("terminal-meta");
  if (!typed || !meta) return;

  var scenes = [
    { command: "onyx user@server", meta: "[mode] QUIC" },
    { command: "onyx user@server", meta: "[session] resumed" },
    { command: "onyx my-server --forward 8888:8888", meta: "[forward] localhost:8888 → remote:8888" },
    { command: "ssh dev-onyx", meta: "[transport] ProxyCommand onyx proxy %h %p" },
    { command: "onyx dev-onyx", meta: "[mode] SSH fallback" },
    { command: "onyx gpu-runner", meta: "[workflow] AI CLI ready" }
  ];

  var sceneIndex = 0;

  function typeText(text, done) {
    typed.textContent = "";
    meta.textContent = "";
    var i = 0;

    function step() {
      if (i < text.length) {
        typed.textContent += text.charAt(i++);
        setTimeout(step, 36 + Math.random() * 22);
      } else {
        setTimeout(done, 180);
      }
    }

    step();
  }

  function showScene() {
    var scene = scenes[sceneIndex];
    typeText(scene.command, function () {
      meta.textContent = scene.meta;
      sceneIndex = (sceneIndex + 1) % scenes.length;
      setTimeout(showScene, 2200);
    });
  }

  setTimeout(showScene, 700);
})();

function copyCmd() {
  var text = (document.getElementById("install-cmd") || {}).textContent || "";
  var btn = document.getElementById("copy-btn");
  if (!text || !btn) return;

  function done(msg) {
    btn.textContent = msg;
    setTimeout(function () {
      btn.textContent = "Copy";
    }, 1800);
  }

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () {
      done("Copied");
    }).catch(fallback);
  } else {
    fallback();
  }

  function fallback() {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.cssText = "position:fixed;top:-9999px;opacity:0;pointer-events:none";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      done("Copied");
    } catch (err) {
      done("Failed");
    }
  }
}
