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
  var mcpTrack = document.getElementById("mcp-track");
  var mcpLine = document.querySelector(".mcp-line");
  var mcpPulse = document.querySelector(".mcp-pulse");
  var mcpCards = Array.prototype.slice.call(document.querySelectorAll(".mcp-card"));
  var repoMetaStrip = document.getElementById("repo-meta-strip");
  var repoMetaText = document.getElementById("repo-meta-text");

  var repoApiUrl = "https://api.github.com/repos/shervin9/onyx";
  var latestReleaseApiUrl = "https://api.github.com/repos/shervin9/onyx/releases/latest";

  var terminalScenes = [
    { command: "onyx user@host", meta: "[shell] auto-reconnect" },
    { command: "onyx exec prod -- deploy.sh", meta: "[exec] resumable job" },
    { command: "onyx attach gpu-box job_84f31", meta: "[job] resumed" },
    { command: "onyx jobs gpu-box --json", meta: "[json] NDJSON events" },
    { command: "ssh prod-onyx", meta: "[transport] ProxyCommand onyx proxy %h %p" }
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

  function setMcpStep(stepIndex) {
    mcpCards.forEach(function (card, index) {
      card.classList.toggle("is-active", index === stepIndex);
    });
  }

  function measureMcpTrack() {
    if (!mcpTrack || !mcpCards.length || !mcpLine) return;

    var trackRect = mcpTrack.getBoundingClientRect();
    var first = dotCenter(mcpCards[0], trackRect);
    var last = dotCenter(mcpCards[mcpCards.length - 1], trackRect);
    var isVertical = window.matchMedia("(max-width: 900px)").matches;

    if (isVertical) {
      mcpTrack.style.setProperty("--mcp-line-left", first.x + "px");
      mcpTrack.style.setProperty("--mcp-line-top", first.y + "px");
      mcpTrack.style.setProperty("--mcp-line-height", Math.max(last.y - first.y, 0) + "px");
      mcpTrack.style.setProperty("--mcp-line-width", "1px");
    } else {
      mcpTrack.style.setProperty("--mcp-line-left", first.x + "px");
      mcpTrack.style.setProperty("--mcp-line-width", Math.max(last.x - first.x, 0) + "px");
      mcpTrack.style.setProperty("--mcp-line-top", first.y + "px");
      mcpTrack.style.setProperty("--mcp-line-height", "1px");
    }
  }

  function placeMcpPulse(stepIndex, instant) {
    if (!mcpTrack || !mcpPulse || !mcpCards.length) return;
    var card = mcpCards[stepIndex];
    if (!card) return;

    var trackRect = mcpTrack.getBoundingClientRect();
    var center = dotCenter(card, trackRect);

    if (instant) {
      mcpPulse.style.transition = "none";
    } else {
      mcpPulse.style.transition =
        "left 1.12s cubic-bezier(0.22, 1, 0.36, 1), top 1.12s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.2s ease";
    }

    mcpTrack.style.setProperty("--mcp-pulse-left", center.x + "px");
    mcpTrack.style.setProperty("--mcp-pulse-top", center.y + "px");

    if (instant) {
      mcpPulse.getBoundingClientRect();
      mcpPulse.style.transition =
        "left 1.12s cubic-bezier(0.22, 1, 0.36, 1), top 1.12s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.2s ease";
    }
  }

  var mcpSequence = [0, 1, 2, 1];

  function loopMcp(sequenceIndex) {
    if (!mcpCards.length) return;
    var cardIndex = mcpSequence[sequenceIndex];
    measureMcpTrack();
    setMcpStep(cardIndex);
    placeMcpPulse(cardIndex, false);
    setTimeout(function () {
      loopMcp((sequenceIndex + 1) % mcpSequence.length);
    }, 1700);
  }

  function refreshMcpLayout() {
    measureMcpTrack();
    var activeIndex = 0;
    mcpCards.forEach(function (card, index) {
      if (card.classList.contains("is-active")) activeIndex = index;
    });
    placeMcpPulse(activeIndex, true);
  }

  function fetchJson(url) {
    return fetch(url, {
      headers: {
        Accept: "application/vnd.github+json"
      }
    }).then(function (response) {
      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }
      return response.json();
    });
  }

  function formatCount(value) {
    if (typeof value !== "number" || !isFinite(value)) return "";
    return new Intl.NumberFormat("en-US").format(value);
  }

  function loadRepoMeta() {
    if (!repoMetaStrip || !repoMetaText || !window.fetch) return;

    Promise.all([
      fetchJson(repoApiUrl).catch(function () { return null; }),
      fetchJson(latestReleaseApiUrl).catch(function () { return null; })
    ]).then(function (results) {
      var repo = results[0];
      var release = results[1];
      var parts = [];

      if (release && typeof release.tag_name === "string" && release.tag_name.trim()) {
        parts.push("Latest " + release.tag_name.trim());
      }

      if (repo && typeof repo.stargazers_count === "number") {
        parts.push(formatCount(repo.stargazers_count) + " stars");
      }

      if (repo && typeof repo.forks_count === "number") {
        parts.push(formatCount(repo.forks_count) + " forks");
      }

      if (!parts.length) return;

      repoMetaText.textContent = parts.join(" · ");
      repoMetaStrip.hidden = false;
    }).catch(function () {
      repoMetaStrip.hidden = true;
    });
  }

  // ── onyx exec animated demo ───────────────────────────────────────────
  //
  // A narrative loop: the user detaches a training job, loses the
  // network briefly, reattaches, and sees the job has kept going. The
  // animation is pre-scripted — no randomness, no perf work per frame —
  // so it stays restrained and deterministic.

  var execStatusBadge = document.getElementById("exec-status-badge");
  var execStatusMeta = document.getElementById("exec-status-meta");
  var execCommandLine = document.getElementById("exec-command-line");
  var execLine1 = document.getElementById("exec-line-1");
  var execLine2 = document.getElementById("exec-line-2");
  var execLine3 = document.getElementById("exec-line-3");
  var execLine4 = document.getElementById("exec-line-4");
  var execJobLine = document.getElementById("exec-job-line");
  var execDropLine = document.getElementById("exec-drop-line");
  var execResumedLine = document.getElementById("exec-resumed-line");
  var execScene = document.getElementById("exec-scene");
  var execRevealLines = [
    execCommandLine,
    execJobLine,
    execLine1,
    execLine2,
    execDropLine,
    execResumedLine,
    execLine3,
    execLine4
  ];
  var execTimeline = [
    { label: "starting", tone: "neutral", meta: "gpu-box • preparing job", show: [execCommandLine], delay: 960 },
    { label: "running", tone: "running", meta: "gpu-box • job_84f31", show: [execJobLine], delay: 1080 },
    { label: "streaming", tone: "running", meta: "gpu-box • job_84f31", show: [execLine1], delay: 1180 },
    { label: "streaming", tone: "running", meta: "gpu-box • job_84f31", show: [execLine2], delay: 1480 },
    { label: "connection lost", tone: "lost", meta: "gpu-box • reconnecting", show: [execDropLine], delay: 1900 },
    { label: "resumed", tone: "resumed", meta: "gpu-box • job_84f31", hide: [execDropLine], show: [execResumedLine], delay: 1380 },
    { label: "streaming", tone: "running", meta: "gpu-box • job_84f31", show: [execLine3], delay: 1120 },
    { label: "streaming", tone: "running", meta: "gpu-box • job_84f31", show: [execLine4], delay: 2600 }
  ];

  function setExecStatus(label, tone, metaText) {
    if (execStatusBadge) {
      execStatusBadge.textContent = label || "starting";
      execStatusBadge.setAttribute("data-tone", tone || "neutral");
    }
    if (execStatusMeta && metaText) {
      execStatusMeta.textContent = metaText;
    }
  }

  function toggleExecLine(el, visible) {
    if (!el) return;
    el.classList.toggle("is-visible", !!visible);
  }

  function resetExecScene() {
    execRevealLines.forEach(function (line) {
      toggleExecLine(line, false);
    });
    setExecStatus("starting", "neutral", "gpu-box • preparing job");
  }

  function runExecStep(i) {
    if (!execScene) return;
    if (i >= execTimeline.length) {
      setTimeout(startExecDemo, 1700);
      return;
    }

    var step = execTimeline[i];
    setExecStatus(step.label, step.tone, step.meta);
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
    if (!execScene || !execStatusBadge) return;
    resetExecScene();
    setTimeout(function () {
      runExecStep(0);
    }, 720);
  }

  loadRepoMeta();

  setTimeout(function () {
    refreshFlowLayout();
    refreshMcpLayout();
    loopTerminal(0);
    loopFlow(0);
    loopMcp(0);
    startExecDemo();
  }, 700);

  window.addEventListener("resize", refreshFlowLayout);
  window.addEventListener("orientationchange", refreshFlowLayout);
  window.addEventListener("resize", refreshMcpLayout);
  window.addEventListener("orientationchange", refreshMcpLayout);
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
