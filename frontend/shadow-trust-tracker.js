/**
 * Shadow Trust Sector Tracker v1.0
 * ===================================
 * Embed this script in any website to start sending security telemetry
 * to your Shadow Trust sector dashboard.
 *
 * Usage:
 *   1. Add your target in the Shadow Trust dashboard → Sectors → [Sector] → Add Target
 *   2. Copy the generated API key into ST_API_KEY below
 *   3. Update ST_INGEST_URL to point to your Shadow Trust backend
 *   4. Paste this <script> tag before </body>
 */

(function () {
  // ── CONFIG — replace these values ──────────────────────────────────────────
  var ST_API_KEY   = "YOUR_TARGET_API_KEY";          // from Shadow Trust dashboard
  var ST_INGEST_URL = "http://localhost:8000/api/v1/sectors/events/ingest";

  // ── Internal helpers ───────────────────────────────────────────────────────
  function send(attack_type, extras) {
    var payload = Object.assign({
      api_key:      ST_API_KEY,
      attack_type:  attack_type,
      user_agent:   navigator.userAgent,
      request_path: window.location.pathname,
    }, extras || {});

    fetch(ST_INGEST_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    }).catch(function () {}); // silent — never break the host page
  }

  // ── Auto-detectors ─────────────────────────────────────────────────────────

  // 1. XSS patterns in URL
  var url = window.location.href;
  if (/<script|javascript:/i.test(url)) {
    send("XSS", { ioc_value: url.slice(0, 300), ioc_type: "url", risk_score: 8 });
  }

  // 2. SQL injection patterns in URL
  if (/union\s+select|select\s+.+\s+from|drop\s+table|insert\s+into|delete\s+from/i.test(url)) {
    send("SQLi", { ioc_value: url.slice(0, 300), ioc_type: "url", risk_score: 9 });
  }

  // 3. Path traversal
  if (/\.\.[\/\\]/.test(url)) {
    send("Scan", { ioc_value: url.slice(0, 300), ioc_type: "url", risk_score: 7 });
  }

  // 4. Unusual form submissions — capture large/suspicious POST bodies
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var inputs = Array.from(form.querySelectorAll("input, textarea")).map(function (el) {
      return el.name + "=" + el.value.slice(0, 80);
    });
    var payload_str = inputs.join("&");
    if (/<script|javascript:|union\s+select/i.test(payload_str)) {
      send("XSS", {
        ioc_value:   payload_str.slice(0, 300),
        ioc_type:    "url",
        risk_score:  8.5,
        commands:    [payload_str.slice(0, 200)],
      });
    }
  }, true);

  // ── Public API — call manually anywhere on the page ───────────────────────
  /**
   * window.ShadowTrust.report(attack_type, extras)
   *
   * Examples:
   *   ShadowTrust.report("BruteForce", { risk_score: 7.5, commands: [username] });
   *   ShadowTrust.report("RCE",        { ioc_value: "cmd.exe", ioc_type: "domain" });
   */
  window.ShadowTrust = { report: send };

})();
