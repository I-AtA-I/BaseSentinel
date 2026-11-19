"use strict";

const TOKEN_KEY = "basesentinel_token";
const THEME_KEY = "basesentinel_theme";
const state = { token: sessionStorage.getItem(TOKEN_KEY) };
const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
    })[character]);
}

function formatDate(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "full",
        timeStyle: "medium",
    }).format(parsed);
}

function eventTitle(eventType) {
    const known = {
        "login.success": "Successful login",
        "login.failed": "Failed login attempt",
        "privilege.special_assignment": "Special privileges assigned",
        "account.created": "User account created",
    };
    if (known[eventType]) return known[eventType];
    return String(eventType || "Security event")
        .replace(/[._-]+/g, " ")
        .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function severityName(value) {
    const severity = Number(value);
    if (severity === 0) return "Informational";
    if (severity >= 9) return "Critical";
    if (severity >= 7) return "High";
    if (severity >= 4) return "Medium";
    return "Low";
}

function severityClass(value) {
    const severity = Number(value);
    if (severity === 0) return "severity-info";
    if (severity >= 9) return "severity-critical";
    if (severity >= 7) return "severity-high";
    if (severity >= 4) return "severity-medium";
    return "severity-low";
}

function fieldLabel(key) {
    const labels = {
        TargetUserName: "Target account",
        SubjectUserName: "Initiating account",
        IpAddress: "Source IP address",
        WorkstationName: "Source workstation",
        LogonType: "Logon type",
        ProcessName: "Process",
        TargetDomainName: "Target domain",
        SubjectDomainName: "Initiating domain",
        Status: "Status code",
        SubStatus: "Sub-status code",
        PrivilegeList: "Assigned privileges",
        record_id: "Windows record ID",
        computer: "Reporting computer",
    };
    return labels[key] || String(key).replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function displayValue(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "object") return JSON.stringify(value, null, 2);
    return String(value);
}

function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    try {
        localStorage.setItem(THEME_KEY, selected);
    } catch (_) {}
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
        ...options,
        headers,
        cache: "no-store",
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

function renderEvent(event) {
    const level = Number(event.severity);
    const device = event.device || {};

    document.title = `${eventTitle(event.event_type)} | BaseSentinel`;
    $("event-title").textContent = eventTitle(event.event_type);
    $("event-type-heading").textContent = eventTitle(event.event_type);
    $("event-subtitle").textContent =
        `${event.category} · ${event.source}`;
    $("event-level").innerHTML =
        `<span class="severity-label ${severityClass(level)}">Level ${level} · ${severityName(level)}</span>`;

    $("event-message").textContent = event.message || "No message was included with this event.";
    $("event-category").textContent = event.category || "—";
    $("event-type").textContent = event.event_type || "—";
    $("event-source").textContent = event.source || "—";
    $("event-code").textContent = event.event_code || "—";
    $("event-occurred").textContent = formatDate(event.occurred_at);
    $("event-received").textContent = formatDate(event.received_at);
    $("event-id").textContent = event.id || "—";
    $("event-uid").textContent = event.event_uid || "—";
    $("event-schema").textContent = event.schema_version ?? "—";

    $("device-name").textContent = device.display_name || device.hostname || "Unknown device";
    $("device-hostname").textContent = device.hostname || "—";
    $("device-platform").textContent = [device.platform, device.platform_version]
        .filter(Boolean).join(" ") || "—";
    $("device-agent-version").textContent = device.agent_version || "—";
    $("device-architecture").textContent = device.architecture || "—";
    $("device-status").textContent = device.status || "—";
    $("device-enrolled").textContent = formatDate(device.enrolled_at);
    $("device-last-checkin").textContent = formatDate(device.last_checkin_at);
    $("device-id").textContent = device.id || event.agent_id || "—";

    const entries = Object.entries(event.event_data || {});
    $("event-data-table").innerHTML = entries.length
        ? entries.map(([key, value]) => `
            <tr>
                <th>${escapeHtml(fieldLabel(key))}</th>
                <td>${escapeHtml(displayValue(value))}</td>
            </tr>`).join("")
        : '<tr><td colspan="2" class="table-empty">No structured event data was collected.</td></tr>';

    $("event-data-raw").textContent = JSON.stringify(event.event_data || {}, null, 2);
    $("event-detail-content").hidden = false;
}

function showError(message) {
    $("event-error").textContent = message || "Unable to load event details.";
    $("event-error").hidden = false;
}

async function logout() {
    try {
        await apiRequest("/auth/logout", { method: "POST" });
    } catch (_) {
        // Clear the local session even when the API is unavailable.
    }
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem("basesentinel_user");
    window.location.replace("/login");
}

async function initializeEventDetail() {
    if (!state.token) {
        window.location.replace("/login");
        return;
    }

    applyTheme(document.documentElement.dataset.theme || "dark");
    $("theme-toggle").addEventListener("click", () => {
        applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    $("logout-button").addEventListener("click", logout);

    const eventId = $("event-detail-root").dataset.eventId;
    if (!eventId) {
        showError("The event ID is missing from this page.");
        return;
    }

    try {
        const user = await apiRequest("/auth/me");
        $("current-username").textContent = user.username;
        $("current-role").textContent = user.role;

        const event = await apiRequest(`/events/${encodeURIComponent(eventId)}`);
        renderEvent(event);
    } catch (error) {
        showError(error.message || "Unable to load event details.");
    }
}

document.addEventListener("DOMContentLoaded", initializeEventDetail);
