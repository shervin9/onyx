(function () {
  var typed = document.getElementById("typed");
  var meta = document.getElementById("terminal-meta");
  var agentTrack = document.getElementById("agent-track");
  var agentLine = document.querySelector(".agent-line");
  var agentPulse = document.querySelector(".agent-pulse");
  var agentCards = Array.prototype.slice.call(document.querySelectorAll(".agent-card"));
  var repoMetaStrip = document.getElementById("repo-meta-strip");
  var repoMetaText = document.getElementById("repo-meta-text");

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

  var repoApiUrl = "https://api.github.com/repos/shervin9/onyx";
  var latestReleaseApiUrl = "https://api.github.com/repos/shervin9/onyx/releases/latest";

  var terminalScenes = [
    { command: "onyx user@host", meta: "[shell] auto-reconnect" },
    { command: "onyx dev-onyx", meta: "[session] resume instantly" },
    { command: "onyx user@host:7373", meta: "[host] custom port" },
    { command: "onyx user@host", meta: "[fallback] SSH when needed" }
  ];

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

  function centerOfElement(element, containerRect) {
    var rect = element.getBoundingClientRect();
    return {
      x: rect.left + rect.width / 2 - containerRect.left,
      y: rect.top + rect.height / 2 - containerRect.top
    };
  }

  function typeText(text, done) {
    if (!typed || !meta) return;
    typed.textContent = "";
    meta.textContent = "";
    var i = 0;

    function step() {
      if (i < text.length) {
        typed.textContent += text.charAt(i++);
        window.setTimeout(step, 34 + Math.random() * 20);
      } else {
        window.setTimeout(done, 180);
      }
    }

    step();
  }

  function loopTerminal(index) {
    if (!typed || !meta || !terminalScenes.length) return;
    var scene = terminalScenes[index];
    typeText(scene.command, function () {
      meta.textContent = scene.meta;
      window.setTimeout(function () {
        loopTerminal((index + 1) % terminalScenes.length);
      }, 2200);
    });
  }

  function setAgentStep(stepIndex) {
    agentCards.forEach(function (card, index) {
      card.classList.toggle("is-active", index === stepIndex);
    });
  }

  function measureAgentTrack() {
    if (!agentTrack || !agentLine || !agentCards.length) return;

    var trackRect = agentTrack.getBoundingClientRect();
    var first = centerOfElement(agentCards[0], trackRect);
    var last = centerOfElement(agentCards[agentCards.length - 1], trackRect);
    var isVertical = window.matchMedia("(max-width: 900px)").matches;

    if (isVertical) {
      agentTrack.style.setProperty("--agent-line-left", first.x + "px");
      agentTrack.style.setProperty("--agent-line-top", first.y + "px");
      agentTrack.style.setProperty("--agent-line-height", Math.max(last.y - first.y, 0) + "px");
      agentTrack.style.setProperty("--agent-line-width", "1px");
    } else {
      agentTrack.style.setProperty("--agent-line-left", first.x + "px");
      agentTrack.style.setProperty("--agent-line-top", first.y + "px");
      agentTrack.style.setProperty("--agent-line-width", Math.max(last.x - first.x, 0) + "px");
      agentTrack.style.setProperty("--agent-line-height", "1px");
    }
  }

  function placeAgentPulse(stepIndex, instant) {
    if (!agentTrack || !agentPulse || !agentCards.length) return;
    var card = agentCards[stepIndex];
    if (!card) return;

    var trackRect = agentTrack.getBoundingClientRect();
    var center = centerOfElement(card, trackRect);

    if (instant) {
      agentPulse.style.transition = "none";
    } else {
      agentPulse.style.transition =
        "left 1.08s cubic-bezier(0.22, 1, 0.36, 1), top 1.08s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.2s ease";
    }

    agentTrack.style.setProperty("--agent-pulse-left", center.x + "px");
    agentTrack.style.setProperty("--agent-pulse-top", center.y + "px");

    if (instant) {
      agentPulse.getBoundingClientRect();
      agentPulse.style.transition =
        "left 1.08s cubic-bezier(0.22, 1, 0.36, 1), top 1.08s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.2s ease";
    }
  }

  function refreshAgentLayout() {
    if (!agentCards.length) return;
    measureAgentTrack();
    var activeIndex = 0;
    agentCards.forEach(function (card, index) {
      if (card.classList.contains("is-active")) activeIndex = index;
    });
    placeAgentPulse(activeIndex, true);
  }

  function loopAgent(index) {
    if (!agentCards.length) return;
    measureAgentTrack();
    setAgentStep(index);
    placeAgentPulse(index, false);

    window.setTimeout(function () {
      var next = index + 1;
      if (next >= agentCards.length) {
        setAgentStep(0);
        placeAgentPulse(0, true);
        window.setTimeout(function () {
          loopAgent(0);
        }, 500);
        return;
      }
      loopAgent(next);
    }, 1650);
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

  function renderRepoMeta(releaseTag, stars, forks) {
    if (!repoMetaText || !repoMetaStrip) return;
    var parts = [];

    if (typeof releaseTag === "string" && releaseTag.trim()) {
      parts.push("Latest " + releaseTag.trim());
    }

    if (typeof stars === "number") {
      parts.push(formatCount(stars) + " stars");
    }

    if (typeof forks === "number") {
      parts.push(formatCount(forks) + " forks");
    }

    if (!parts.length) {
      repoMetaText.textContent = "";
      repoMetaStrip.hidden = true;
      return;
    }

    repoMetaText.textContent = parts.join(" · ");
    repoMetaStrip.hidden = false;
  }

  function loadRepoMeta() {
    if (!repoMetaText || !repoMetaStrip || !window.fetch) return;

    Promise.all([
      fetchJson(repoApiUrl).catch(function () { return null; }),
      fetchJson(latestReleaseApiUrl).catch(function () { return null; })
    ]).then(function (results) {
      var repo = results[0];
      var release = results[1];
      var releaseTag;

      if (release && typeof release.tag_name === "string" && release.tag_name.trim()) {
        releaseTag = release.tag_name.trim();
      }

      renderRepoMeta(
        releaseTag,
        repo && typeof repo.stargazers_count === "number" ? repo.stargazers_count : undefined,
        repo && typeof repo.forks_count === "number" ? repo.forks_count : undefined
      );
    }).catch(function () {
      repoMetaStrip.hidden = true;
    });
  }

  function setExecStatus(label, tone, metaText) {
    if (execStatusBadge) {
      execStatusBadge.textContent = label || "starting";
      execStatusBadge.setAttribute("data-tone", tone || "neutral");
    }
    if (execStatusMeta && metaText) {
      execStatusMeta.textContent = metaText;
    }
  }

  function toggleExecLine(element, visible) {
    if (!element) return;
    element.classList.toggle("is-visible", !!visible);
  }

  function resetExecScene() {
    execRevealLines.forEach(function (line) {
      toggleExecLine(line, false);
    });
    setExecStatus("starting", "neutral", "gpu-box • preparing job");
  }

  function runExecStep(index) {
    if (!execScene) return;
    if (index >= execTimeline.length) {
      window.setTimeout(startExecDemo, 1700);
      return;
    }

    var step = execTimeline[index];
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

    window.setTimeout(function () {
      runExecStep(index + 1);
    }, step.delay || 750);
  }

  function startExecDemo() {
    if (!execScene || !execStatusBadge) return;
    resetExecScene();
    window.setTimeout(function () {
      runExecStep(0);
    }, 720);
  }

  loadRepoMeta();

  window.setTimeout(function () {
    refreshAgentLayout();
    loopTerminal(0);
    loopAgent(0);
    startExecDemo();
  }, 700);

  window.addEventListener("resize", refreshAgentLayout);
  window.addEventListener("orientationchange", refreshAgentLayout);
})();

function copyText(targetId, button) {
  var target = document.getElementById(targetId);
  if (!target || !button) return;
  var text = target.textContent || "";

  function done(label) {
    var reset = button.getAttribute("data-reset-label") || "Copy";
    button.textContent = label;
    window.setTimeout(function () {
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
