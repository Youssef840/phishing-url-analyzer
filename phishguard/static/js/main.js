(function () {
  "use strict";

  const form = document.getElementById("analyzeForm");
  const input = document.getElementById("url");

  // Loading state on submit
  form?.addEventListener("submit", () => {
    document.getElementById("spinner").classList.remove("d-none");
    document.getElementById("btnText").textContent = " جارِ التحليل...";
    document.getElementById("submitBtn").disabled = true;
  });

  // Example buttons fill the input and submit
  document.querySelectorAll(".example-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      input.value = btn.dataset.url;
      form.requestSubmit();
    });
  });

  // Score ring + scale marker
  const ring = document.querySelector(".score-ring");
  if (ring) {
    ring.style.setProperty("--val", ring.dataset.score);
    ring.style.setProperty("--ring", `var(--bs-${ring.dataset.color})`);
  }
  const marker = document.querySelector(".scale-marker");
  if (marker) {
    const pct = Math.min(100, Math.max(0, Number(marker.dataset.score)));
    marker.style.right = `calc(${pct}% - 2px)`;
  }

  // Report actions
  const dataEl = document.getElementById("reportData");
  if (dataEl) {
    const report = JSON.parse(dataEl.textContent);

    document.getElementById("downloadJson")?.addEventListener("click", () => {
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `phishguard-${report.domain}-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    });

    document.getElementById("copyUrl")?.addEventListener("click", async (e) => {
      try {
        await navigator.clipboard.writeText(report.url);
        e.currentTarget.innerHTML = '<i class="bi bi-check2"></i> تم النسخ';
      } catch (_) { /* clipboard unavailable */ }
    });
  }
})();
