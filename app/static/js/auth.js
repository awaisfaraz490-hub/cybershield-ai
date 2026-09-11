// Handles login/register form submission
(function () {
  function showAlert(message) {
    const alertBox = document.getElementById("formAlert");
    if (!alertBox) return;
    alertBox.textContent = message;
    alertBox.style.display = "block";
  }

  function hideAlert() {
    const alertBox = document.getElementById("formAlert");
    if (alertBox) alertBox.style.display = "none";
  }

  function setLoading(btn, loading) {
    if (!btn) return;
    btn.disabled = loading;
    btn.querySelector(".btn-text").style.display = loading ? "none" : "inline";
    btn.querySelector(".btn-spinner").style.display = loading ? "inline-block" : "none";
  }

  async function submitJson(url, payload) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      let msg = data.detail || "Something went wrong. Please try again.";
      if (Array.isArray(data.errors) && data.errors.length) {
        msg = data.errors.map((e) => e.message).join(" ");
      }
      throw new Error(msg);
    }
    return data;
  }

  const registerForm = document.getElementById("registerForm");
  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAlert();
      const btn = document.getElementById("submitBtn");
      const payload = {
        full_name: document.getElementById("full_name").value.trim(),
        email: document.getElementById("email").value.trim(),
        password: document.getElementById("password").value,
        confirm_password: document.getElementById("confirm_password").value,
      };
      if (payload.password !== payload.confirm_password) {
        showAlert("Passwords do not match.");
        return;
      }
      setLoading(btn, true);
      try {
        await submitJson("/api/auth/register", payload);
        window.location.href = "/dashboard";
      } catch (err) {
        showAlert(err.message);
      } finally {
        setLoading(btn, false);
      }
    });
  }

  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAlert();
      const btn = document.getElementById("submitBtn");
      const payload = {
        email: document.getElementById("email").value.trim(),
        password: document.getElementById("password").value,
      };
      setLoading(btn, true);
      try {
        await submitJson("/api/auth/login", payload);
        window.location.href = "/dashboard";
      } catch (err) {
        showAlert(err.message);
      } finally {
        setLoading(btn, false);
      }
    });
  }
})();
