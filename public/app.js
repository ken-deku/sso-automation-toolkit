/* =========================================================
   SSO Automation Toolkit — Frontend Controller
   Author: Dek Mohamud
   Description:
   Client-side logic for parsing SAML metadata, generating
   Auth0-ready configuration, and producing Service Provider
   setup packs for customer SSO configuration.
   
   Security: No data persistence, client-side only processing
   ========================================================= */

"use strict";

// ==================== STATE (RUNTIME ONLY - NO PERSISTENCE) ====================
let lastAuth0Pack = null; // Cleared on page refresh

// ==================== CONSTANTS ====================
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB limit
const ALLOWED_FILE_TYPES = ["text/xml", "application/xml"];
const API_TIMEOUT = 30000; // 30 seconds
const MAX_FILENAME_LENGTH = 200;

// ==================== THEME TOGGLE ====================
const themeToggle = document.getElementById("themeToggle");
const themeIcon = themeToggle?.querySelector(".theme-icon");
const themeText = themeToggle?.querySelector(".theme-text");

// Load saved theme preference or default to light
const savedTheme = localStorage.getItem("theme") || "light";
if (savedTheme === "dark") {
  document.documentElement.setAttribute("data-theme", "dark");
  if (themeIcon) themeIcon.textContent = "☀️";
  if (themeText) themeText.textContent = "Light";
}

// Theme toggle handler
function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme");
  const newTheme = currentTheme === "dark" ? "light" : "dark";

  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("theme", newTheme);

  // Update button text and icon
  if (newTheme === "dark") {
    if (themeIcon) themeIcon.textContent = "☀️";
    if (themeText) themeText.textContent = "Light";
  } else {
    if (themeIcon) themeIcon.textContent = "🌙";
    if (themeText) themeText.textContent = "Dark";
  }
}

// Add event listeners for theme toggle
themeToggle?.addEventListener("click", toggleTheme);
themeToggle?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    toggleTheme();
  }
});

// ==================== SECURITY & VALIDATION ====================

/**
 * Sanitizes user input to prevent XSS attacks
 * @param {string} text - Raw user input
 * @returns {string} Escaped HTML-safe string
 */
function sanitizeText(text = "") {
  const div = document.createElement("div");
  div.textContent = String(text);
  return div.innerHTML;
}

/**
 * Validates HTTP/HTTPS URLs
 * @param {string} value - URL to validate
 * @returns {boolean} True if valid URL
 */
function isValidUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol);
  } catch {
    return false;
  }
}

/**
 * Validates identifier names (alphanumeric, hyphens, underscores only)
 * @param {string} name - Identifier to validate
 * @returns {boolean} True if valid identifier
 */
function isValidIdentifier(name) {
  if (!name || typeof name !== "string") return false;
  if (name.length > MAX_FILENAME_LENGTH) return false;
  return /^[a-zA-Z0-9_-]+$/.test(name);
}

/**
 * Validates file before upload
 * @param {File} file - File object to validate
 * @returns {Object} { valid: boolean, error: string }
 */
function validateFile(file) {
  if (!file) {
    return { valid: false, error: "No file selected" };
  }

  if (file.size > MAX_FILE_SIZE) {
    return {
      valid: false,
      error: `File exceeds ${MAX_FILE_SIZE / 1024 / 1024}MB limit`,
    };
  }

  const validExtension = file.name.toLowerCase().endsWith(".xml");
  const validType = ALLOWED_FILE_TYPES.includes(file.type);

  if (!validExtension && !validType) {
    return { valid: false, error: "File must be XML format" };
  }

  return { valid: true };
}

/**
 * Fetch wrapper with timeout and error handling
 * @param {string} url - API endpoint
 * @param {Object} options - Fetch options
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options = {}, timeout = API_TIMEOUT) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timer);
    return response;
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      throw new Error("Request timed out. Please try again.");
    }
    throw err;
  }
}

/** Respects prefers-reduced-motion for scrollIntoView */
function scrollToEl(el) {
  if (!el) return;
  const reduce =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  el.scrollIntoView({
    behavior: reduce ? "auto" : "smooth",
    block: "nearest",
  });
}

// ==================== TAB NAVIGATION ====================
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    // Remove active state from all tabs and panels
    document
      .querySelectorAll(".tab")
      .forEach((b) => b.classList.remove("active"));
    document
      .querySelectorAll(".panel")
      .forEach((p) => {
        p.classList.remove("active");
        p.classList.remove("panel--enter");
      });

    // Activate clicked tab
    btn.classList.add("active");
    const targetPanel = document.getElementById(`tab-${btn.dataset.tab}`);
    if (targetPanel) {
      void targetPanel.offsetWidth;
      targetPanel.classList.add("active", "panel--enter");
    }
  });
});

// ==================== UI HELPERS ====================

/**
 * Updates status message display
 * @param {string} id - Element ID
 * @param {string} message - Status message
 * @param {string} type - 'ok' or 'bad'
 */
function setStatus(id, message, type = "ok") {
  const el = document.getElementById(id);
  if (!el) return;

  el.textContent = sanitizeText(message);
  el.classList.remove("hidden", "ok", "bad");
  el.classList.add(type === "bad" ? "bad" : "ok");
}

/**
 * Clears and hides status message
 * @param {string} id - Element ID
 */
function clearStatus(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = "";
  el.classList.add("hidden");
}

/**
 * Safely sets text content
 * @param {string} id - Element ID
 * @param {string} value - Text value
 */
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? "";
}

/**
 * Safely sets input/textarea value
 * @param {string} id - Element ID
 * @param {string} value - Input value
 */
function setValue(id, value) {
  const el = document.getElementById(id);
  if (el) el.value = value ?? "";
}

/**
 * Creates and downloads a file
 * @param {string} filename - Desired filename
 * @param {string} content - File content
 * @param {string} mime - MIME type
 */
function downloadFile(filename, content, mime = "text/plain") {
  // Sanitize filename to prevent directory traversal
  const safeName = filename
    .replace(/[^a-z0-9._-]/gi, "_")
    .substring(0, MAX_FILENAME_LENGTH);

  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = safeName;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();

  // Cleanup
  setTimeout(() => {
    URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }, 100);
}

// ==================== COPY TO CLIPBOARD HANDLER ====================
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".copy");
  if (!btn) return;

  const targetId = btn.dataset.copy;
  if (!targetId) return;

  const el = document.getElementById(targetId);
  if (!el) return;

  const text = el.value ?? el.textContent ?? "";
  if (!text.trim()) {
    alert("Nothing to copy.");
    return;
  }

  try {
    await navigator.clipboard.writeText(text);

    const original = btn.textContent;
    btn.textContent = "Copied ✓";
    btn.classList.add("copied");

    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("copied");
    }, 1500);
  } catch (err) {
    console.error("Clipboard error:", err);
    alert("Clipboard access failed. Please copy manually.");
  }
});

// ==================== IdP → AUTH0 (METADATA URL) ====================
document
  .getElementById("btnParseIdpUrl")
  ?.addEventListener("click", async () => {
    const urlInput = document.getElementById("idpMetadataUrl");
    const domainsInput = document.getElementById("idpDomains");

    const url = urlInput.value.trim();
    const domains = domainsInput.value.trim();

    // Validation
    if (!url) {
      alert("Please enter a metadata URL.");
      urlInput.focus();
      return;
    }

    if (!isValidUrl(url)) {
      alert("Please enter a valid HTTPS or HTTP URL.");
      urlInput.focus();
      return;
    }

    clearStatus("auth0Status");
    setStatus("auth0Status", "Parsing metadata and generating configuration…");

    try {
      const resp = await fetchWithTimeout("/api/idp/from-url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ url, domains }),
      });

      if (!resp.ok) {
        const errorData = await resp.json().catch(() => ({}));
        throw new Error(errorData.error || `Server error: ${resp.status}`);
      }

      const data = await resp.json();

      // Validate response
      if (!data || typeof data !== "object") {
        throw new Error("Invalid response from server");
      }

      renderAuth0Pack(data);
      setStatus("auth0Status", "Configuration generated successfully ✓");

      scrollToEl(document.getElementById("auth0Output"));
    } catch (err) {
      console.error("Parse error:", err);
      setStatus(
        "auth0Status",
        err.message || "Failed to parse metadata",
        "bad"
      );
    }
  });

// ==================== IdP → AUTH0 (FILE UPLOAD) ====================
document
  .getElementById("btnParseIdpFile")
  ?.addEventListener("click", async () => {
    const fileInput = document.getElementById("idpMetadataFile");
    const domainsInput = document.getElementById("idpDomains");

    const file = fileInput.files?.[0];
    const domains = domainsInput.value.trim();

    // Validate file
    const validation = validateFile(file);
    if (!validation.valid) {
      alert(validation.error);
      fileInput.value = ""; // Clear invalid file
      return;
    }

    clearStatus("auth0Status");
    setStatus("auth0Status", "Uploading and parsing file…");

    try {
      const formData = new FormData();
      formData.append("file", file);
      if (domains) formData.append("domains", domains);

      const resp = await fetchWithTimeout("/api/idp/from-file", {
        method: "POST",
        body: formData,
      });

      if (!resp.ok) {
        const errorData = await resp.json().catch(() => ({}));
        throw new Error(errorData.error || `Server error: ${resp.status}`);
      }

      const data = await resp.json();

      // Validate response
      if (!data || typeof data !== "object") {
        throw new Error("Invalid response from server");
      }

      renderAuth0Pack(data);
      setStatus("auth0Status", "Configuration generated successfully ✓");

      scrollToEl(document.getElementById("auth0Output"));
    } catch (err) {
      console.error("File parse error:", err);
      setStatus("auth0Status", err.message || "Failed to parse file", "bad");
    }
  });

// ==================== RENDER AUTH0 CONFIGURATION ====================
function renderCertExpiry(certInfo) {
  const valueEl = document.getElementById("certExpiry");
  const wrap = document.getElementById("certExpiryWrap");
  const badge = document.getElementById("certExpiryBadge");
  if (!valueEl) return;

  const urgency = certInfo?.urgency || "unknown";
  const expires = certInfo?.expires;
  const days = certInfo?.daysUntilExpiry;

  if (wrap) {
    wrap.classList.remove("is-ok", "is-soon", "is-expired", "is-unknown");
    wrap.classList.add(`is-${urgency}`);
  }

  if (badge) {
    badge.className = "cert-expiry-badge";
    if (urgency === "expired") {
      badge.textContent = "Expired";
      badge.classList.add("cert-expiry-badge--expired");
      badge.removeAttribute("hidden");
    } else if (urgency === "soon") {
      badge.textContent = "Renew soon";
      badge.classList.add("cert-expiry-badge--soon");
      badge.removeAttribute("hidden");
    } else {
      badge.textContent = "";
      badge.setAttribute("hidden", "");
    }
  }

  let line = "Unknown";
  if (expires) {
    line = String(expires);
    if (typeof days === "number" && Number.isFinite(days)) {
      if (days <= 0) {
        line += " — expired";
      } else {
        line += ` — ${days} day${days === 1 ? "" : "s"} remaining`;
      }
    }
  } else if (urgency === "unknown" && certInfo?.subject) {
    line = "Unknown (certificate present; expiry not parsed)";
  }

  valueEl.textContent = line;

  let aria = "Certificate expiration date.";
  if (urgency === "expired") {
    aria = "Certificate has expired.";
  } else if (urgency === "soon") {
    aria = "Certificate expires within thirty days.";
  } else if (urgency === "ok") {
    aria = "Certificate expiration is more than thirty days away.";
  } else {
    aria = "Certificate expiration unknown.";
  }
  valueEl.setAttribute("aria-label", aria);
}

function renderExtractedAttributes(data) {
  const card = document.getElementById("extractedAttrsCard");
  const hint = document.getElementById("extractedAttrsHint");
  const list = document.getElementById("extractedAttrsList");
  if (!card || !hint || !list) return;

  const attrs = Array.isArray(data.extractedAttributes)
    ? data.extractedAttributes
    : [];

  if (attrs.length === 0) {
    card.classList.add("hidden");
    list.innerHTML = "";
    hint.textContent = "";
    return;
  }

  card.classList.remove("hidden");

  hint.textContent =
    "Declarations found in metadata (deduped by name). Tags show whether the name came from IdP Attribute elements and/or SP RequestedAttribute sections. Compare with the JSON mapping below.";

  list.innerHTML = "";
  attrs.forEach((attr) => {
    const li = document.createElement("li");
    const name = attr?.name != null ? String(attr.name) : "";
    const friendly = attr?.friendlyName != null ? String(attr.friendlyName) : "";
    const bits = [name];
    if (friendly) bits.push(`(${friendly})`);
    if (attr?.isProfile) bits.push("[profile]");
    else if (attr?.source === "requested") bits.push("[RequestedAttribute]");
    else if (attr?.source === "both") bits.push("[Attribute + RequestedAttribute]");
    li.textContent = bits.join(" ");
    list.appendChild(li);
  });
}

// ==================== RENDER AUTH0 CONFIGURATION ====================
function renderAuth0Pack(data) {
  // Store in runtime memory only (no persistence)
  lastAuth0Pack = data;

  const output = document.getElementById("auth0Output");
  if (!output) return;

  output.classList.remove("hidden");

  // Provider detection
  setText("providerGuess", data.provider || "Unknown");

  // Auth0 fields with safe defaults
  setText("signInUrl", data.fields?.signInUrl || "Not found");
  setText("signOutUrl", data.fields?.signOutUrl || "Not found");
  setText("issuerEntityId", data.fields?.issuer || "Not found");

  // Certificate
  setValue("certPem", data.fields?.certificate || "");
  renderCertExpiry(data.certInfo);

  // Attribute mappings
  try {
    const mappings = data.mapping || {};
    setValue("mappingJson", JSON.stringify(mappings, null, 2));
  } catch (err) {
    console.error("Invalid mapping data:", err);
    setValue("mappingJson", "{}");
  }

  renderExtractedAttributes(data);

  // Warnings and notes
  renderList("warnList", data.warnings, "No warnings detected.");
  renderList("notesList", data.notes, "No additional notes.");
}

/**
 * Renders a list of items or empty message
 * @param {string} id - List element ID
 * @param {Array} items - Array of items to display
 * @param {string} emptyMsg - Message when list is empty
 */
function renderList(id, items = [], emptyMsg) {
  const el = document.getElementById(id);
  if (!el) return;

  el.innerHTML = "";

  if (!Array.isArray(items) || items.length === 0) {
    const li = document.createElement("li");
    li.style.color = "var(--muted2)";
    li.textContent = emptyMsg;
    el.appendChild(li);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = sanitizeText(item);
    el.appendChild(li);
  });
}

// ==================== DOWNLOAD HANDLERS ====================

// Download PEM certificate
document.getElementById("downloadPemBtn")?.addEventListener("click", () => {
  if (!lastAuth0Pack?.fields?.certificate) {
    alert("No certificate available. Please generate a configuration first.");
    return;
  }

  const cert = lastAuth0Pack.fields.certificate;
  const provider = (lastAuth0Pack.provider || "idp")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  const date = new Date().toISOString().slice(0, 10);
  downloadFile(
    `sso-cert-${provider}-${date}.pem`,
    cert,
    "application/x-pem-file"
  );
});

// Download mapping JSON
document.getElementById("downloadMappingBtn")?.addEventListener("click", () => {
  const textarea = document.getElementById("mappingJson");
  if (!textarea) return;

  const content = textarea.value || "";
  if (!content.trim()) {
    alert("No mapping data available.");
    return;
  }

  // Validate JSON before download
  try {
    JSON.parse(content);
  } catch (err) {
    alert("Invalid JSON. Please correct the mapping before downloading.");
    console.error("JSON validation error:", err);
    return;
  }

  const date = new Date().toISOString().slice(0, 10);
  downloadFile(`auth0-mappings-${date}.json`, content, "application/json");
});

// ==================== SERVICE PROVIDER → CUSTOMER PACK ====================
document
  .getElementById("btnGenerateSpPack")
  ?.addEventListener("click", async () => {
    const envSelect = document.getElementById("environment");
    const identifierInput = document.getElementById("spIdentifier");

    const env = envSelect.value;
    const identifier = identifierInput.value.trim();

    // Validation
    if (!identifier) {
      alert("Please enter a connection identifier.");
      identifierInput.focus();
      return;
    }

    if (!isValidIdentifier(identifier)) {
      alert(
        "Identifier can only contain letters, numbers, hyphens, and underscores."
      );
      identifierInput.focus();
      return;
    }

    clearStatus("spStatus");
    setStatus("spStatus", "Generating customer setup pack…");

    try {
      // Try real API first
      try {
        const resp = await fetchWithTimeout("/api/sp/generate", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({ env, identifier }),
        });

        if (resp.ok) {
          const data = await resp.json();

          if (data && typeof data === "object") {
            renderServiceProviderPack(data);
            setStatus("spStatus", "Customer setup pack generated ✓");

            document.getElementById("spOutput")?.scrollIntoView({
              behavior: "smooth",
              block: "nearest",
            });
            return;
          }
        }
      } catch (apiError) {
        console.log("API not available, using mock data:", apiError.message);
      }

      // Fallback to mock data for demo purposes
      const environments = env === "both" ? ["prod", "uat"] : [env];
      const results = environments.map((e) => ({
        env: e.toUpperCase(),
        identifier,
        metadataUrl: `https://auth.example.com/saml/metadata?connection=${identifier}`,
        entityId: `urn:auth0:florencehc-${e}:${identifier}`,
        acsUrl: `https://auth.example.com/login/callback?connection=${identifier}`,
        landingPage: `https://app.example.com/login`,
        warnings: e === "uat" ? ["Non-production environment"] : [],
      }));

      renderServiceProviderPack({ results });
      setStatus("spStatus", "Customer setup pack generated ✓ (demo mode)");

      document.getElementById("spOutput")?.scrollIntoView({
        behavior: "smooth",
        block: "nearest",
      });
    } catch (err) {
      console.error("SP generation error:", err);
      setStatus("spStatus", err.message || "Failed to generate pack", "bad");
    }
  });

// ==================== RENDER SERVICE PROVIDER PACK ====================
function renderServiceProviderPack(data) {
  const wrap = document.getElementById("spCards");
  if (!wrap) return;

  wrap.innerHTML = "";

  const results = Array.isArray(data.results) ? data.results : [];

  if (results.length === 0) {
    wrap.innerHTML =
      '<p class="muted" style="padding: 20px; text-align: center;">No results to display</p>';
    return;
  }

  results.forEach((r, idx) => {
    const packText = `Environment: ${sanitizeText(r.env || "Unknown")}
   Connection: ${sanitizeText(r.identifier || "Unknown")}
   
   Metadata URL:
   ${sanitizeText(r.metadataUrl || "Not available")}
   
   Entity ID (Issuer):
   ${sanitizeText(r.entityId || "Not available")}
   
   ACS / Reply URL:
   ${sanitizeText(r.acsUrl || "Not available")}
   
   Sign-in Landing Page:
   ${sanitizeText(r.landingPage || "Not available")}`;

    const textareaId = `sp-msg-${idx}`;
    const downloadBtnId = `sp-dl-${idx}`;

    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `
         <div class="card-top">
           <div>
             <h3 class="card-title">${sanitizeText(
               r.env || "Unknown"
             )} Environment Setup</h3>
             <div class="micro">Copy and send to customer for IdP configuration.</div>
           </div>
           <div class="actions">
             <button class="btn small ghost copy" data-copy="${textareaId}">Copy</button>
             <button class="btn small" id="${downloadBtnId}">Download .txt</button>
           </div>
         </div>
         <textarea id="${textareaId}" rows="9" readonly spellcheck="false"></textarea>
         ${renderWarnings(r.warnings)}
       `;

    wrap.appendChild(card);

    // Set textarea value after DOM insertion
    const textarea = document.getElementById(textareaId);
    if (textarea) textarea.value = packText;

    // Download handler
    const downloadBtn = document.getElementById(downloadBtnId);
    if (downloadBtn) {
      downloadBtn.addEventListener("click", () => {
        const date = new Date().toISOString().slice(0, 10);
        const envName = (r.env || "unknown")
          .toLowerCase()
          .replace(/[^a-z0-9]/g, "-");
        downloadFile(`sso-setup-${envName}-${date}.txt`, packText);
      });
    }
  });

  document.getElementById("spOutput")?.classList.remove("hidden");
}

/**
 * Renders warning messages
 * @param {Array} warnings - Array of warning strings
 * @returns {string} HTML string
 */
function renderWarnings(warnings = []) {
  if (!Array.isArray(warnings) || warnings.length === 0) {
    return '<div class="micro" style="margin-top: 8px;"><span style="color: var(--muted2);">No warnings.</span></div>';
  }

  const warningText = warnings.map((w) => sanitizeText(w)).join(" | ");
  return `<div class="micro" style="margin-top: 8px;">Warnings: ${warningText}</div>`;
}

// ==================== INITIALIZATION ====================
console.log("SSO Automation Toolkit by Dek - Initialized");

// Security note: Theme preference is stored in localStorage
// All other data is stored in runtime memory only
// No other localStorage, sessionStorage, or cookies are used
// All data (except theme) is cleared on page refresh
