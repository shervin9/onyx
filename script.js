(function () {
  "use strict";

  var root = document.documentElement;
  root.classList.add("js");

  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var hasIO = "IntersectionObserver" in window;

  // ── Nav background after scrolling ────────────────────────────────
  var nav = document.getElementById("nav");
  function onScroll() {
    if (nav) nav.classList.toggle("is-scrolled", window.scrollY > 8);
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // ── Scroll reveal ─────────────────────────────────────────────────
  var revealEls = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
  if (!hasIO || reduceMotion) {
    revealEls.forEach(function (el) { el.classList.add("is-in"); });
  } else {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-in");
          revealObserver.unobserve(entry.target);
        }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    revealEls.forEach(function (el) { revealObserver.observe(el); });
  }

  // ── Pause decorative CSS loops while off-screen ───────────────────
  if (hasIO) {
    var loopObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        entry.target.classList.toggle("is-paused", !entry.isIntersecting);
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".card-viz"), function (el) {
      loopObserver.observe(el);
    });
  }

  // ── Card spotlight follows the pointer ────────────────────────────
  Array.prototype.forEach.call(document.querySelectorAll(".card"), function (card) {
    card.addEventListener("pointermove", function (e) {
      var r = card.getBoundingClientRect();
      card.style.setProperty("--mx", (e.clientX - r.left) + "px");
      card.style.setProperty("--my", (e.clientY - r.top) + "px");
    });
  });

  // ── Terminal scene engine ─────────────────────────────────────────
  // A scene is a list of steps run in order, then looped. Scenes only
  // advance while their terminal is on screen and the tab is visible, and a
  // restart cancels any pending timer, so there are never overlapping runs.
  function Scene(container, body, steps, options) {
    this.container = container;
    this.body = body;
    this.steps = steps;
    this.options = options || {};
    this.visible = false;
    this.running = false;
    this.timer = null;
    this.waiter = null;
    this.generation = 0;
  }

  Scene.prototype.clear = function () {
    while (this.body.firstChild) this.body.removeChild(this.body.firstChild);
  };

  Scene.prototype.line = function (text, cls) {
    var el = document.createElement("span");
    el.className = "ln" + (cls ? " " + cls : "");
    el.textContent = text;
    this.body.appendChild(el);
    return el;
  };

  Scene.prototype.sleep = function (ms, gen) {
    var self = this;
    return new Promise(function (resolve, reject) {
      function arm() {
        self.timer = window.setTimeout(function () {
          self.timer = null;
          if (gen !== self.generation) return reject("cancelled");
          if (!self.canRun()) {
            // Hold here until the scene is visible again.
            self.waiter = function () { self.waiter = null; arm(); };
            return;
          }
          resolve();
        }, ms);
      }
      arm();
    });
  };

  Scene.prototype.canRun = function () {
    return this.visible && !document.hidden;
  };

  Scene.prototype.type = function (text, cls, gen) {
    var self = this;
    var el = this.line("", (cls || "") + " ln-typing");
    var caret = document.createElement("span");
    caret.className = "caret";
    el.appendChild(caret);
    var i = 0;
    function next() {
      if (i >= text.length) {
        return self.sleep(260, gen).then(function () {
          if (caret.parentNode) caret.parentNode.removeChild(caret);
        });
      }
      caret.insertAdjacentText("beforebegin", text.charAt(i++));
      return self.sleep(28 + Math.random() * 38, gen).then(next);
    }
    return next();
  };

  Scene.prototype.run = function () {
    var self = this;
    if (this.running) return;
    this.running = true;
    var gen = ++this.generation;
    if (this.options.reset) this.options.reset();
    this.clear();
    var chain = Promise.resolve();
    this.steps.forEach(function (step) {
      chain = chain.then(function () { return step(self, gen); });
    });
    chain.then(function () {
      return self.sleep(self.options.loopDelay || 3500, gen);
    }).then(function () {
      self.running = false;
      self.run();
    }, function () {
      self.running = false;
    });
  };

  Scene.prototype.renderStatic = function () {
    if (this.options.reset) this.options.reset();
    this.clear();
    if (this.options.staticRender) this.options.staticRender(this);
  };

  Scene.prototype.setVisible = function (visible) {
    this.visible = visible;
    if (visible) {
      if (!this.running) this.run();
      else if (this.waiter) this.waiter();
    }
  };

  function mountScene(scene) {
    if (!scene.container || !scene.body) return;
    if (reduceMotion) {
      scene.renderStatic();
      return;
    }
    if (!hasIO) {
      scene.setVisible(true);
      return;
    }
    new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) { scene.setVisible(entry.isIntersecting); });
    }, { threshold: 0.2 }).observe(scene.container);
  }

  document.addEventListener("visibilitychange", function () {
    scenes.forEach(function (s) {
      if (!document.hidden && s.visible && s.waiter) s.waiter();
    });
  });

  // Small helpers for step lists.
  function wait(ms) { return function (s, g) { return s.sleep(ms, g); }; }
  function out(text, cls, after) {
    return function (s, g) { s.line(text, cls); return s.sleep(after || 380, g); };
  }
  function typed(text, after) {
    return function (s, g) {
      return s.type(text, "ln-prompt", g).then(function () { return s.sleep(after || 300, g); });
    };
  }
  function act(fn) { return function () { fn(); }; }

  // ── Hero: connect, dev server, drop, replay ───────────────────────
  var heroTerm = document.getElementById("hero-term");
  var heroConn = document.getElementById("hero-conn");
  var heroTitle = document.getElementById("hero-title");
  function setConn(state, label) {
    if (!heroConn) return;
    heroConn.setAttribute("data-state", state);
    var l = heroConn.querySelector(".conn-label");
    if (l) l.textContent = label;
    if (heroTerm) heroTerm.classList.toggle("is-down", state === "down");
    if (heroTitle) heroTitle.textContent = state === "down" ? "● onyx — reconnecting…" : "onyx dev-box";
  }

  var heroScene = new Scene(heroTerm, document.getElementById("hero-body"), [
    typed("onyx dev-box", 200),
    out("[onyx] connecting…", "ln-dim", 650),
    act(function () { setConn("up", "QUIC"); }),
    out("[mode] QUIC  (session 6b07a1c3)", "ln-dim", 700),
    typed("npm run dev", 250),
    out("  ▲ Next.js ready on http://localhost:3000", "", 900),
    out("[onyx] dev-box:3000 → http://localhost:3000", "ln-onyx", 1300),
    typed("./deploy.sh --env staging", 250),
    out("building image… done", "", 700),
    act(function () { setConn("down", "reconnecting"); }),
    wait(2600),
    act(function () { setConn("up", "QUIC"); }),
    out("pushing layers… done", "ln-replay", 260),
    out("running migrations… done", "ln-replay", 260),
    out("rollout complete ✓", "ln-replay ln-ok", 900)
  ], {
    loopDelay: 4200,
    reset: function () { setConn("idle", "connecting"); },
    staticRender: function (s) {
      setConn("up", "QUIC");
      s.line("onyx dev-box", "ln-prompt");
      s.line("[mode] QUIC  (session 6b07a1c3)", "ln-dim");
      s.line("npm run dev", "ln-prompt");
      s.line("[onyx] dev-box:3000 → http://localhost:3000", "ln-onyx");
      s.line("./deploy.sh --env staging", "ln-prompt");
      s.line("building image… done");
      s.line("pushing layers… done", "ln-replay");
      s.line("rollout complete ✓", "ln-replay ln-ok");
    }
  });

  // ── Ports: dev server, browser, sign-in link, stop ────────────────
  var browser = document.getElementById("ports-browser");
  function setBrowser(open) { if (browser) browser.classList.toggle("is-open", open); }

  var portsScene = new Scene(document.getElementById("ports-demo"), document.getElementById("ports-body"), [
    typed("npm run dev", 250),
    out("  ▲ Next.js ready on http://localhost:3000", "", 900),
    out("[onyx] dev-box:3000 → http://localhost:3000", "ln-onyx", 500),
    act(function () { setBrowser(true); }),
    wait(2200),
    out("^C", "ln-dim", 600),
    act(function () { setBrowser(false); }),
    out("[onyx] dev-box:3000 stopped listening; forward closed", "ln-onyx", 1300),
    typed("gh auth login --web", 300),
    out("! One-time code: 4F2A-91C3", "", 700),
    out("[onyx] opened in your browser: github.com/login/device", "ln-onyx", 2000)
  ], {
    loopDelay: 3200,
    reset: function () { setBrowser(false); },
    staticRender: function (s) {
      s.line("npm run dev", "ln-prompt");
      s.line("  ▲ Next.js ready on http://localhost:3000");
      s.line("[onyx] dev-box:3000 → http://localhost:3000", "ln-onyx");
      setBrowser(true);
    }
  });

  // ── Agent Guard: placeholders in, real keys only where allowed ────
  var agentBadge = document.getElementById("agent-badge");
  var guardCount = { ok: 0, blocked: 0 };
  function setGuard(tone) {
    if (!agentBadge) return;
    var label = guardCount.ok + " allowed · " + guardCount.blocked + " blocked";
    agentBadge.textContent = guardCount.ok || guardCount.blocked ? label : "guarded";
    agentBadge.setAttribute("data-tone", tone);
  }
  function allow() { guardCount.ok += 1; setGuard("running"); }
  function block() { guardCount.blocked += 1; setGuard("lost"); }

  var agentScene = new Scene(document.getElementById("agent-term"), document.getElementById("agent-body"), [
    typed("onyx agent run dev-box --secret ANTHROPIC_API_KEY --secret GITHUB_TOKEN -- \"fix the flaky test, open a PR\"", 250),
    out("[onyx guard] on · 2 secrets · egress locked by Landlock", "ln-guard", 700),
    act(allow),
    out("[onyx guard] allowed api.anthropic.com · injecting ANTHROPIC_API_KEY", "ln-guard", 800),
    out("● Reading tests/payments.spec.ts", "", 600),
    out("● Fixed a race in retryWithBackoff()", "", 700),
    act(allow),
    out("[onyx guard] allowed api.github.com · injecting GITHUB_TOKEN", "ln-guard", 700),
    out("● Opened pull request #482", "ln-ok", 800),
    act(block),
    out("[onyx guard] BLOCKED paste.example.net:443", "ln-block", 900),
    act(function () { setGuard("done"); }),
    out("[job] finished  exit=0", "ln-ok", 600)
  ], {
    loopDelay: 3600,
    reset: function () { guardCount.ok = 0; guardCount.blocked = 0; setGuard("neutral"); },
    staticRender: function (s) {
      guardCount.ok = 2; guardCount.blocked = 1; setGuard("done");
      s.line("onyx agent run dev-box --secret ANTHROPIC_API_KEY -- \"fix the flaky test\"", "ln-prompt");
      s.line("[onyx guard] allowed api.anthropic.com · injecting ANTHROPIC_API_KEY", "ln-guard");
      s.line("● Opened pull request #482", "ln-ok");
      s.line("[onyx guard] BLOCKED paste.example.net:443", "ln-block");
    }
  });

  // ── Exec: detach, reattach, drop, resume ──────────────────────────
  var badge = document.getElementById("exec-badge");
  function setBadge(label, tone) {
    if (!badge) return;
    badge.textContent = label;
    badge.setAttribute("data-tone", tone);
  }

  var execScene = new Scene(document.getElementById("exec-term"), document.getElementById("exec-body"), [
    typed("onyx exec gpu --detach -- python train.py", 250),
    act(function () { setBadge("running", "running"); }),
    out("job_84f31", "", 350),
    out("[onyx] detached; reattach with: onyx attach <target> job_84f31", "ln-dim", 1100),
    typed("onyx attach gpu job_84f31", 300),
    out("epoch=01  loss=0.912  samples=4096", "", 650),
    out("epoch=02  loss=0.734  samples=8192", "", 700),
    act(function () { setBadge("connection lost", "lost"); }),
    out("[net] connection lost, reconnecting…", "ln-warn", 1800),
    act(function () { setBadge("resumed", "resumed"); }),
    out("[job] resumed  seq=27", "ln-dim", 500),
    out("epoch=03  loss=0.581  samples=12288", "", 650),
    out("epoch=04  checkpoint=best.pt", "", 650),
    act(function () { setBadge("done", "done"); }),
    out("[job] finished  exit=0", "ln-ok", 600)
  ], {
    loopDelay: 3600,
    reset: function () { setBadge("starting", "neutral"); },
    staticRender: function (s) {
      setBadge("done", "done");
      s.line("onyx exec gpu --detach -- python train.py", "ln-prompt");
      s.line("onyx attach gpu job_84f31", "ln-prompt");
      s.line("epoch=02  loss=0.734  samples=8192");
      s.line("[job] resumed  seq=27", "ln-dim");
      s.line("[job] finished  exit=0", "ln-ok");
    }
  });

  var scenes = [heroScene, portsScene, agentScene, execScene];
  scenes.forEach(mountScene);

  // ── Install tabs (click + arrow keys) ─────────────────────────────
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  function selectTab(tab) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.classList.toggle("is-active", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.setAttribute("tabindex", on ? "0" : "-1");
      var panel = document.getElementById(t.getAttribute("aria-controls"));
      if (panel) panel.hidden = !on;
    });
  }
  tabs.forEach(function (tab, i) {
    tab.addEventListener("click", function () { selectTab(tab); });
    tab.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      e.preventDefault();
      var next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
      selectTab(next);
      next.focus();
    });
  });

  // ── Copy buttons ──────────────────────────────────────────────────
  function flash(button, label, ok) {
    button.textContent = label;
    button.classList.toggle("is-done", !!ok);
    window.setTimeout(function () {
      button.textContent = "Copy";
      button.classList.remove("is-done");
    }, 1600);
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:-9999px;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest && event.target.closest("[data-copy-target]");
    if (!button) return;
    var target = document.getElementById(button.getAttribute("data-copy-target"));
    if (!target) return;
    var text = (target.textContent || "").trim();
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { flash(button, "Copied", true); }, function () {
        flash(button, fallbackCopy(text) ? "Copied" : "Press ⌘C", true);
      });
    } else {
      flash(button, fallbackCopy(text) ? "Copied" : "Press ⌘C", true);
    }
  });

  // ── GitHub stars + latest release (best effort) ───────────────────
  function getJson(url) {
    return fetch(url, { headers: { Accept: "application/vnd.github+json" } }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }
  if (window.fetch) {
    getJson("https://api.github.com/repos/shervin9/onyx").then(function (repo) {
      var el = document.getElementById("nav-stars");
      if (el && typeof repo.stargazers_count === "number" && repo.stargazers_count > 0) {
        el.textContent = "★ " + new Intl.NumberFormat("en-US").format(repo.stargazers_count);
        el.hidden = false;
      }
    }).catch(function () {});
    getJson("https://api.github.com/repos/shervin9/onyx/releases/latest").then(function (rel) {
      var tag = rel && typeof rel.tag_name === "string" ? rel.tag_name.trim() : "";
      if (!tag) return;
      var fv = document.getElementById("footer-version");
      if (fv) { fv.textContent = tag; fv.hidden = false; }
    }).catch(function () {});
  }

  var year = document.getElementById("year");
  if (year) year.textContent = String(new Date().getFullYear());
})();
