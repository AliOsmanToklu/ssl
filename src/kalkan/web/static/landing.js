// Landing page behaviour. Every part degrades to the server-rendered page without it.
// Loaded in <head> without defer so the "js" class is set before the first paint.
document.documentElement.classList.add("js");
document.addEventListener("DOMContentLoaded", function () {
  "use strict";
  var root = document.documentElement;
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // The headline rises once the page has painted.
  window.requestAnimationFrame(function () {
    window.requestAnimationFrame(function () { root.classList.add("is-loaded"); });
  });

  // --- 1. Kalkan reads this very page: the headers of its own response ------------
  var check = document.querySelector("[data-selfcheck]");
  if (check && window.fetch) {
    var rows = Array.prototype.slice.call(check.querySelectorAll("[data-header]"));
    rows.forEach(function (row) { row.classList.add("is-checking"); });
    fetch(window.location.href, { method: "HEAD", cache: "no-store", credentials: "same-origin" })
      .then(function (response) {
        var ok = 0;
        rows.forEach(function (row, index) {
          var name = row.getAttribute("data-header");
          var value = name ? response.headers.get(name) : (window.location.protocol === "https:" ? "https" : null);
          if (value) ok += 1;
          window.setTimeout(function () {
            row.classList.remove("is-checking", "is-ok", "is-missing");
            row.classList.add("is-done", value ? "is-ok" : "is-missing");
            row.querySelector("[data-value]").textContent = value || check.getAttribute("data-missing");
            var state = row.querySelector("[data-state]");
            state.textContent = value ? check.getAttribute("data-ok") : check.getAttribute("data-missing");
            state.classList.toggle("k-pass", !!value);
            state.classList.toggle("k-medium", !value);
          }, reduced ? 0 : 260 * (index + 1));
        });
        var out = check.querySelector("[data-summary-out]");
        window.setTimeout(function () {
          out.textContent = check.getAttribute("data-summary")
            .replace("{ok}", ok).replace("{total}", rows.length);
        }, reduced ? 0 : 260 * (rows.length + 1));
      })
      .catch(function () {
        rows.forEach(function (row) { row.classList.remove("is-checking"); });
      });
  }

  // --- 2. How it works: the stage shows the state of the statement being read -------
  var stage = document.querySelector("[data-stage]");
  var steps = Array.prototype.slice.call(document.querySelectorAll("[data-step]"));
  if (stage && steps.length && "IntersectionObserver" in window) {
    stage.setAttribute("data-stage", "1");
    var stepObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        steps.forEach(function (step) { step.classList.toggle("is-active", step === entry.target); });
        stage.setAttribute("data-stage", entry.target.getAttribute("data-step"));
      });
    }, { rootMargin: "-45% 0px -45% 0px" });
    steps.forEach(function (step) { stepObserver.observe(step); });
  }

  // --- 3. Fix the sample site and re-grade it with Kalkan's scoring rules ----------
  var panel = document.querySelector("[data-regrade]");
  if (panel) {
    var rules = JSON.parse(panel.getAttribute("data-rules"));
    var summaries = {};
    var tpl = panel.querySelector("template[data-summaries]");
    Array.prototype.forEach.call(tpl.content.querySelectorAll("[data-for]"), function (el) {
      summaries[el.getAttribute("data-for")] = el.textContent;
    });
    var box = panel.querySelector("[data-grade-box]");
    var gradeOut = panel.querySelector("[data-grade]");
    var scoreOut = panel.querySelector("[data-score]");
    var summaryOut = panel.querySelector("[data-grade-summary]");
    var boxes = Array.prototype.slice.call(panel.querySelectorAll("[data-fix]"));

    var regrade = function () {
      var score = 100;
      var open = [];
      boxes.forEach(function (input) {
        var item = panel.querySelector('[data-finding="' + input.getAttribute("data-fix") + '"]');
        item.classList.toggle("is-fixed", input.checked);
        if (!input.checked) open.push(input.getAttribute("data-severity"));
      });
      open.forEach(function (severity) { score -= rules.penalties[severity] || 0; });
      Object.keys(rules.caps).forEach(function (severity) {
        if (open.indexOf(severity) !== -1) score = Math.min(score, rules.caps[severity]);
      });
      score = Math.max(0, Math.min(100, score));
      var grade = "F";
      for (var i = 0; i < rules.grades.length; i += 1) {
        if (score >= rules.grades[i][0]) { grade = rules.grades[i][1]; break; }
      }
      if (gradeOut.textContent !== grade && !reduced) {
        box.classList.add("is-bump");
        window.setTimeout(function () { box.classList.remove("is-bump"); }, 400);
      }
      box.className = box.className.replace(/k-grade-[a-f]\b/, "k-grade-" + grade.toLowerCase());
      gradeOut.textContent = grade;
      scoreOut.textContent = score;
      summaryOut.textContent = summaries[grade] || "";
    };
    boxes.forEach(function (input) { input.addEventListener("change", regrade); });
    regrade();
  }

  // --- 4. Entrances: the parts of each section, one after another -------------------
  var parts = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
  if (!reduced && "IntersectionObserver" in window) {
    var revealObserver = new IntersectionObserver(function (entries) {
      var shown = 0;
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.style.setProperty("--d", (shown * 80) + "ms");
        entry.target.classList.add("is-in");
        revealObserver.unobserve(entry.target);
        shown += 1;
      });
    }, { rootMargin: "0px 0px -8% 0px" });
    parts.forEach(function (part) { revealObserver.observe(part); });
    // At the very end of the page nothing may stay waiting for a scroll that cannot come.
    window.addEventListener("scroll", function () {
      if (window.innerHeight + window.scrollY < document.documentElement.scrollHeight - 4) return;
      parts.forEach(function (part) { part.classList.add("is-in"); });
    }, { passive: true });
  } else {
    parts.forEach(function (part) { part.classList.add("is-in"); });
  }
});
