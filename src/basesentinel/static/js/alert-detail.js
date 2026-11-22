"use strict";

const TOKEN_KEY = "basesentinel_token";
const THEME_KEY = "basesentinel_theme";
const state = { token: sessionStorage.getItem(TOKEN_KEY) };
const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
    })[character]);
}

function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "full", timeStyle: "medium",
    }).format(date);
}

function severityName(value) {
    const severity = Number(value);
    if (severity >= 9) return "Critical";
    if (severity >= 7) return "High";
    if (severity >= 4) return "Medium";
    return "Low";
}

function severityClass(value) {
    const severity = Number(value);
    if (severity >= 9) return "severity-critical";
    if (severity >= 7) return "severity-high";
    if (severity >= 4) return "severity-medium";
    return "severity-low";
}

function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    try { localStorage.setItem(THEME_KEY, selected); } catch (_) {}
    $("theme-toggle").querySelector(".theme-label").textContent =
        selected === "dark" ? "LIGHT MODE" : "DARK MODE";
    $("theme-toggle").querySelector(".theme-symbol").textContent =
        selected === "dark" ? "◐" : "◑";
}

async function apiRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (state.token) headers.set("Authorization", `Bearer ${state.token}`);

    const response = await fetch(`/api/v1${path}`, {
        ...options, headers, cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));

    if (response.status === 401) {
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem("basesentinel_user");
        window.location.replace("/login");
    }
    if (!response.ok) {
        throw new Error(data?.error?.message || `Request failed (${response.status}).`);
    }
    return data;
}

function showError(message) {
    $("alert-error").textContent = message || "Unable to load alert details.";
    $("alert-error").hidden = false;
}

function renderAlert(alert) {
    const device = alert.device || {};
    const source = alert.source_event;

    document.title = `${alert.title} | BaseSentinel`;
    $("alert-title").textContent = alert.title;
    $("alert-heading").textContent = alert.title;
    $("alert-subtitle").textContent = `${alert.rule_key} · ${device.display_name || device.hostname || "Unknown device"}`;
    $("alert-description").textContent = alert.description || "No detection description was provided.";
    $("alert-level").innerHTML =
        `<span class="severity-label ${severityClass(alert.severity)}">Level ${Number(alert.severity)} · ${severityName(alert.severity)}</span>`;

    $("alert-status").innerHTML = `<span class="status-label status-${escapeHtml(alert.status)}">${escapeHtml(alert.status)}</span>`;
    $("alert-occurrences").textContent = new Intl.NumberFormat().format(Number(alert.occurrence_count) || 0);
    $("alert-rule").textContent = alert.rule_key || "—";
    $("alert-first-seen").textContent = formatDate(alert.first_seen_at);
    $("alert-last-seen").textContent = formatDate(alert.last_seen_at);
    $("alert-id").textContent = alert.id || "—";

    $("alert-device-name").textContent = device.display_name || device.hostname || "Unknown device";
    $("alert-hostname").textContent = device.hostname || "—";
    $("alert-platform").textContent = [device.platform, device.platform_version].filter(Boolean).join(" ") || "—";
    $("alert-agent-version").textContent = device.agent_version || "—";
    $("alert-agent-id").textContent = alert.agent_id || "—";

    if (source) {
        $("alert-source-event").innerHTML = `
            <div class="alert-source-meta">
                <strong>${escapeHtml(source.event_type || "Security event")}</strong>
                <span class="severity-label ${severityClass(source.severity)}">Level ${Number(source.severity)} · ${severityName(source.severity)}</span>
            </div>
            <p class="event-message">${escapeHtml(source.message || "No event message was recorded.")}</p>
            <dl class="event-detail-list alert-source-fields">
                <div><dt>Category</dt><dd>${escapeHtml(source.category || "—")}</dd></div>
                <div><dt>Source</dt><dd>${escapeHtml(source.source || "—")}</dd></div>
                <div><dt>Windows event ID</dt><dd>${escapeHtml(source.event_code || "—")}</dd></div>
                <div><dt>Occurred</dt><dd>${escapeHtml(formatDate(source.occurred_at))}</dd></div>
                <div><dt>Received</dt><dd>${escapeHtml(formatDate(source.received_at))}</dd></div>
                <div><dt>Event ID</dt><dd class="event-mono">${escapeHtml(source.id)}</dd></div>
            </dl>
            <a class="device-record-link alert-source-link" href="/events/${encodeURIComponent(source.id)}">Open original event details ↗</a>
        `;
    } else {
        $("alert-source-event").innerHTML =
            '<p class="muted">The source event is no longer available. The alert itself is preserved.</p>';
    }

    $("alert-detail-content").hidden = false;
}

function renderInvestigation(data) {
    const events = data.related_events || [];
    $("investigation-count").textContent = `${events.length} EVENTS`;
    $("investigation-window").textContent =
        `Window: ${formatDate(data.window?.from)} – ${formatDate(data.window?.to)}`;
    $("investigation-truncated").hidden = !data.truncated;

    if (!events.length) {
        $("investigation-timeline").innerHTML =
            '<p class="muted">No related events were found in this investigation window.</p>';
        return;
    }

    $("investigation-timeline").innerHTML = events.map((event) => {
        const severity = Number(event.severity);
        const link = event.id
            ? `<a class="investigation-link" href="/events/${encodeURIComponent(event.id)}">Open event details ↗</a>`
            : "";
        return `<article class="investigation-item">
            <div class="investigation-time">${escapeHtml(formatDate(event.occurred_at))}</div>
            <div>
                <div class="investigation-event-title">
                    <span>${escapeHtml(event.event_type || "Security event")}</span>
                    <span class="severity-label ${severityClass(severity)}">Level ${severity} · ${severityName(severity)}</span>
                </div>
                <p class="investigation-message">${escapeHtml(event.message || "No event message was recorded.")}</p>
                <span class="event-mono muted">${escapeHtml(event.category || "—")} · ${escapeHtml(event.source || "—")} · ${escapeHtml(event.event_code || "—")}</span>
                ${link}
            </div>
        </article>`;
    }).join("");
}

function renderInvestigationError(message) {
    $("investigation-count").textContent = "UNAVAILABLE";
    $("investigation-timeline").textContent = message || "Investigation timeline could not be loaded.";
}

async function logout() {
    try { await apiRequest("/auth/logout", { method: "POST" }); } catch (_) {}
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem("basesentinel_user");
    window.location.replace("/login");
}

async function initializeAlertDetail() {
    if (!state.token) {
        window.location.replace("/login");
        return;
    }

    applyTheme(document.documentElement.dataset.theme || "dark");
    $("theme-toggle").addEventListener("click", () => {
        applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    $("logout-button").addEventListener("click", logout);

    try {
        const user = await apiRequest("/auth/me");
        $("current-username").textContent = user.username;
        $("current-role").textContent = user.role;

        const alertId = $("alert-detail-root").dataset.alertId;
        if (!alertId) throw new Error("The alert ID is missing from this page.");

        const alert = await apiRequest(`/alerts/${encodeURIComponent(alertId)}`);
        renderAlert(alert);
        try {
            const investigation = await apiRequest(
                `/operations/alerts/${encodeURIComponent(alertId)}/investigation`,
            );
            renderInvestigation(investigation);
        } catch (investigationError) {
            renderInvestigationError(investigationError.message);
        }
    } catch (error) {
        showError(error.message || "Unable to load alert details.");
    }
}

document.addEventListener("DOMContentLoaded", initializeAlertDetail);
