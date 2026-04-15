(function () {
  var typed = document.getElementById("typed");
  var meta = document.getElementById("terminal-meta");
  var flowNodes = Array.prototype.slice.call(document.querySelectorAll(".flow-node"));
  var flowPanels = Array.prototype.slice.call(document.querySelectorAll(".flow-panel"));
  var flowMeta = document.getElementById("flow-meta");

  var terminalScenes = [
    { command: "onyx user@server", meta: "[mode] QUIC" },
    { command: "onyx user@server", meta: "[session] resumed" },
    { command: "onyx --forward 8888:8888 user@server", meta: "[forward] localhost:8888 -> remote:8888" },
    { command: "ssh dev-onyx", meta: "[transport] ProxyCommand onyx proxy %h %p" },
    { command: "onyx dev-onyx", meta: "[mode] SSH fallback" }
  ];

  var flowScenes = [
    { step: 0, meta: "[mode] SSH bootstrap" },
    { step: 1, meta: "[mode] QUIC" },
    { step: 2, meta: "[mode] SSH fallback" }
  ];

  function typeText(text, done) {
    if (!typed || !meta) return;
    typed.textContent = "";
    meta.textContent = "";
    var i = 0;

    function step() {
      if (i < text.length) {
        typed.textContent += text.charAt(i++);
        setTimeout(step, 34 + Math.random() * 20);
      } else {
        setTimeout(done, 180);
      }
    }

    step();
  }

  function loopTerminal(index) {
    if (!typed || !meta) return;
    var scene = terminalScenes[index];
    typeText(scene.command, function () {
      meta.textContent = scene.meta;
      setTimeout(function () {
        loopTerminal((index + 1) % terminalScenes.length);
      }, 2200);
    });
  }

  function setFlowStep(stepIndex) {
    flowNodes.forEach(function (node, index) {
      node.classList.toggle("active", index === stepIndex);
    });
    flowPanels.forEach(function (panel) {
      panel.classList.toggle("is-active", Number(panel.getAttribute("data-flow-step")) === stepIndex);
    });
  }

  function loopFlow(index) {
    if (!flowNodes.length || !flowPanels.length) return;
    var scene = flowScenes[index];
    setFlowStep(scene.step);
    if (flowMeta) flowMeta.textContent = scene.meta;
    setTimeout(function () {
      loopFlow((index + 1) % flowScenes.length);
    }, 2400);
  }

  setTimeout(function () {
    loopTerminal(0);
    loopFlow(0);
  }, 700);
})();

function copyText(targetId, button) {
  var target = document.getElementById(targetId);
  if (!target || !button) return;
  var text = target.textContent || "";

  function done(label) {
    var reset = button.getAttribute("data-reset-label") || "Copy";
    button.textContent = label;
    setTimeout(function () {
      button.textContent = reset;
    }, 1800);
  }

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () {
      done("Copied");
    }).catch(function () {
      fallbackCopy(text, done);
    });
  } else {
    fallbackCopy(text, done);
  }
}

function fallbackCopy(text, done) {
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

document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-copy-target]");
  if (!button) return;
  copyText(button.getAttribute("data-copy-target"), button);
});
