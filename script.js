(function () {
  var typed = document.getElementById("typed");
  var meta = document.getElementById("terminal-meta");
  var flowTrack = document.querySelector(".flow-track");
  var flowPulse = document.querySelector(".flow-pulse");
  var flowLine = document.querySelector(".flow-line");
  var flowNodes = Array.prototype.slice.call(document.querySelectorAll(".flow-node"));
  var flowDots = Array.prototype.slice.call(document.querySelectorAll(".flow-dot"));
  var flowPanels = Array.prototype.slice.call(document.querySelectorAll(".flow-panel"));
  var flowMeta = document.getElementById("flow-meta");

  var terminalScenes = [
    { command: "onyx user@server", meta: "[mode] QUIC" },
    { command: "onyx user@server", meta: "[session] tmux-backed" },
    { command: "onyx exec gpu-box --detach -- python train.py", meta: "[job] detached" },
    { command: "onyx attach gpu-box job_a1b2c3d4", meta: "[job] reattached" },
    { command: "ssh dev-onyx", meta: "[transport] ProxyCommand onyx proxy %h %p" }
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

  function dotCenter(dot, trackRect) {
    var r = dot.getBoundingClientRect();
    return {
      x: r.left + r.width / 2 - trackRect.left,
      y: r.top + r.height / 2 - trackRect.top
    };
  }

  function measureFlow() {
    if (!flowTrack || !flowDots.length) return;

    var trackRect = flowTrack.getBoundingClientRect();
    var first = dotCenter(flowDots[0], trackRect);
    var last = dotCenter(flowDots[flowDots.length - 1], trackRect);
    var isVertical = window.matchMedia("(max-width: 900px)").matches;

    if (isVertical) {
      flowTrack.style.setProperty("--flow-line-left", first.x + "px");
      flowTrack.style.setProperty("--flow-line-top", first.y + "px");
      flowTrack.style.setProperty("--flow-line-height", Math.max(last.y - first.y, 0) + "px");
      flowTrack.style.setProperty("--flow-line-width", "1px");
    } else {
      flowTrack.style.setProperty("--flow-line-left", first.x + "px");
      flowTrack.style.setProperty("--flow-line-width", Math.max(last.x - first.x, 0) + "px");
      flowTrack.style.setProperty("--flow-line-top", first.y + "px");
      flowTrack.style.setProperty("--flow-line-height", "1px");
    }
  }

  function placePulse(stepIndex, instant) {
    if (!flowTrack || !flowPulse || !flowDots.length) return;
    var dot = flowDots[stepIndex];
    if (!dot) return;
    var trackRect = flowTrack.getBoundingClientRect();
    var center = dotCenter(dot, trackRect);
    var left = center.x;
    var top = center.y;

    if (instant) {
      flowPulse.style.transition = "none";
    } else {
      flowPulse.style.transition =
        "left 0.72s cubic-bezier(0.22, 1, 0.36, 1), top 0.72s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.24s ease";
    }

    flowTrack.style.setProperty("--flow-pulse-left", left + "px");
    flowTrack.style.setProperty("--flow-pulse-top", top + "px");
    flowPulse.style.boxShadow = "0 0 0 0.35rem rgba(110, 140, 255, 0.12)";

    if (instant) {
      flowPulse.getBoundingClientRect();
      flowPulse.style.transition =
        "left 0.72s cubic-bezier(0.22, 1, 0.36, 1), top 0.72s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.24s ease";
    }

    window.clearTimeout(placePulse._pulseReset);
    placePulse._pulseReset = window.setTimeout(function () {
      if (flowPulse) {
        flowPulse.style.boxShadow = "0 0 0 0 rgba(110, 140, 255, 0.3)";
      }
    }, 360);
  }

  function loopFlow(index) {
    if (!flowNodes.length || !flowPanels.length) return;
    var scene = flowScenes[index];
    measureFlow();
    setFlowStep(scene.step);
    placePulse(scene.step, false);
    if (flowMeta) flowMeta.textContent = scene.meta;
    setTimeout(function () {
      loopFlow((index + 1) % flowScenes.length);
    }, 2400);
  }

  function refreshFlowLayout() {
    measureFlow();
    var activeIndex = 0;
    flowNodes.forEach(function (node, index) {
      if (node.classList.contains("active")) activeIndex = index;
    });
    placePulse(activeIndex, true);
  }

  // ── onyx exec animated demo ───────────────────────────────────────────
  //
  // A narrative loop: the user detaches a training job, loses the
  // network briefly, reattaches, and sees the job has kept going. The
  // animation is pre-scripted — no randomness, no perf work per frame —
  // so it stays restrained and deterministic.

  var execStatuses = Array.prototype.slice.call(document.querySelectorAll(".exec-status"));
  var execCommandLine = document.getElementById("exec-command-line");
  var execLine1 = document.getElementById("exec-line-1");
  var execLine2 = document.getElementById("exec-line-2");
  var execLine3 = document.getElementById("exec-line-3");
  var execLine4 = document.getElementById("exec-line-4");
  var execLine5 = document.getElementById("exec-line-5");
  var execStatusLine = document.getElementById("exec-status-line");
  var execReattachLine = document.getElementById("exec-reattach-line");
  var execCompleteLine = document.getElementById("exec-complete-line");
  var execJobidLine = document.getElementById("exec-jobid-line");
  var execScene = document.getElementById("exec-scene");
  var execRevealLines = [
    execCommandLine,
    execJobidLine,
    execLine1,
    execLine2,
    execLine3,
    execStatusLine,
    execReattachLine,
    execLine4,
    execLine5,
    execCompleteLine
  ];
  var execTimeline = [
    { state: "running", show: [execCommandLine], delay: 580 },
    { show: [execJobidLine], delay: 760 },
    { show: [execLine1], delay: 860 },
    { show: [execLine2], delay: 900 },
    { show: [execLine3], delay: 1040 },
    { state: "reconnecting", show: [execStatusLine], delay: 1400 },
    { state: "reattached", hide: [execStatusLine], show: [execReattachLine], delay: 680 },
    { show: [execLine4], delay: 860 },
    { show: [execLine5], delay: 980 },
    { state: "completed", show: [execCompleteLine], delay: 2400 }
  ];

  function setExecStatus(state) {
    execStatuses.forEach(function (status) {
      status.classList.toggle("is-active", status.getAttribute("data-exec-state") === state);
    });
  }

  function toggleExecLine(el, visible) {
    if (!el) return;
    el.classList.toggle("is-visible", !!visible);
  }

  function resetExecScene() {
    execRevealLines.forEach(function (line) {
      toggleExecLine(line, false);
    });
    setExecStatus("running");
  }

  function runExecStep(i) {
    if (!execScene) return;
    if (i >= execTimeline.length) {
      setTimeout(startExecDemo, 1700);
      return;
    }

    var step = execTimeline[i];
    if (step.state) setExecStatus(step.state);
    if (step.hide) {
      step.hide.forEach(function (line) {
        toggleExecLine(line, false);
      });
    }
    if (step.show) {
      step.show.forEach(function (line) {
        toggleExecLine(line, true);
      });
    }
    setTimeout(function () { runExecStep(i + 1); }, step.delay || 750);
  }

  function startExecDemo() {
    if (!execScene || !execStatuses.length) return;
    resetExecScene();
    setTimeout(function () {
      runExecStep(0);
    }, 520);
  }

  setTimeout(function () {
    refreshFlowLayout();
    loopTerminal(0);
    loopFlow(0);
    startExecDemo();
  }, 700);

  window.addEventListener("resize", refreshFlowLayout);
  window.addEventListener("orientationchange", refreshFlowLayout);
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
