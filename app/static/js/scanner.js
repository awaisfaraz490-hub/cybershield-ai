// Shared logic for the URL/Message/Image scanner pages
const CyberShieldScanner = (function () {
  function riskClass(level) {
    return "risk-" + level.replace(/\s+/g, "").toLowerCase();
  }
  function badgeClass(level) {
    return "badge-" + level.replace(/\s+/g, "").toLowerCase();
  }

  function renderLoading(container) {
    container.innerHTML = `
      <div class="panel loading-box">
        <div class="spinner-lg"></div>
        <p>Analyzing content for phishing and scam indicators...</p>
      </div>`;
  }

  function renderError(container, message) {
    container.innerHTML = `
      <div class="alert alert-error" style="max-width:720px;">${escapeHtml(message)}</div>`;
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function renderResult(container, result) {
    const findingsHtml = (result.findings && result.findings.length)
      ? result.findings.map((f) => `<li>✓ ${escapeHtml(f)}</li>`).join("")
      : "<li>No strong indicators were detected.</li>";

    const actionsHtml = result.recommended_actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("");

    const extractedHtml = result.extracted_text
      ? `<h3>Extracted Text</h3><div class="extracted-text-box">${escapeHtml(result.extracted_text)}</div>`
      : "";

    const urlsHtml = (result.detected_urls && result.detected_urls.length)
      ? `<h3>Detected Links</h3><div class="extracted-text-box">${result.detected_urls.map(escapeHtml).join("<br>")}</div>`
      : "";

    container.innerHTML = `
      <div class="result-card">
        <div class="result-risk-level ${riskClass(result.risk_level)}">
          <span class="risk-label">${escapeHtml(result.risk_level.toUpperCase())}</span>
          <span class="risk-score">${result.risk_score} / 100</span>
        </div>
        <p>${escapeHtml(result.explanation)}</p>
        <h3>Detected Indicators</h3>
        <ul class="findings-list">${findingsHtml}</ul>
        ${extractedHtml}
        ${urlsHtml}
        <h3>Recommended Actions</h3>
        <ol class="actions-list">${actionsHtml}</ol>
        <p class="analysis-note">${escapeHtml(result.analysis_note)}</p>
        <button class="btn btn-primary" id="scanAnotherBtn">Scan Another</button>
      </div>`;

    document.getElementById("scanAnotherBtn").addEventListener("click", () => {
      container.innerHTML = "";
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  function setLoading(btn, loading) {
    btn.disabled = loading;
    btn.querySelector(".btn-text").style.display = loading ? "none" : "inline";
    btn.querySelector(".btn-spinner").style.display = loading ? "inline-block" : "none";
  }

  function init({ endpoint, buildPayload, inputId }) {
    const form = document.getElementById("scanForm");
    const input = document.getElementById(inputId);
    const btn = document.getElementById("scanBtn");
    const container = document.getElementById("resultContainer");

    document.querySelectorAll(".sample-link").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        input.value = el.dataset.value;
      });
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const val = input.value.trim();
      if (!val) return;

      setLoading(btn, true);
      renderLoading(container);

      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(buildPayload(val)),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          let msg = data.detail || "Something went wrong. Please try again.";
          if (Array.isArray(data.errors) && data.errors.length) {
            msg = data.errors.map((e2) => e2.message).join(" ");
          }
          throw new Error(msg);
        }
        renderResult(container, data);
        container.scrollIntoView({ behavior: "smooth" });
      } catch (err) {
        renderError(container, err.message);
      } finally {
        setLoading(btn, false);
      }
    });
  }

  function initImageScanner({ endpoint }) {
    const form = document.getElementById("imageForm");
    const fileInput = document.getElementById("imageInput");
    const preview = document.getElementById("imagePreview");
    const btn = document.getElementById("scanBtn");
    const container = document.getElementById("resultContainer");

    fileInput.addEventListener("change", () => {
      const file = fileInput.files[0];
      if (!file) {
        preview.style.display = "none";
        return;
      }
      const reader = new FileReader();
      reader.onload = (e) => {
        preview.innerHTML = `<img src="${e.target.result}" alt="Preview">`;
        preview.style.display = "block";
      };
      reader.readAsDataURL(file);
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const file = fileInput.files[0];
      if (!file) return;

      const maxBytes = 5 * 1024 * 1024;
      if (file.size > maxBytes) {
        renderError(container, "Image is too large. Maximum size is 5MB.");
        return;
      }

      setLoading(btn, true);
      renderLoading(container);

      const formData = new FormData();
      formData.append("file", file);

      try {
        const res = await fetch(endpoint, {
          method: "POST",
          credentials: "same-origin",
          body: formData,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.detail || "Something went wrong. Please try again.");
        }
        renderResult(container, data);
        container.scrollIntoView({ behavior: "smooth" });
      } catch (err) {
        renderError(container, err.message);
      } finally {
        setLoading(btn, false);
      }
    });
  }

  return { init, initImageScanner };
})();
