"use strict";

const TOKEN_KEY = "basesentinel_token";
const THEME_KEY = "basesentinel_theme";
const state = {
    token: sessionStorage.getItem(TOKEN_KEY),
    offset: 0,
    limit: 25,
    total: 0,
    items: [],
    busy: false,
};

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

function formatDate(value, options = {}) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
        ...options,
    }).format(parsed);
}

function formatNumber(value) {
    return new Intl.NumberFormat().format(Number(value) || 0);
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

function showError(message) {
    $("events-error").textContent = message || "";
    $("events-error").hidden = !message;
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

function renderEvents() {
    const items = state.items;
    $("count-total").textContent = formatNumber(state.total);
    $("count-severe").textContent = formatNumber(
        items.filter((event) => Number(event.severity) >= 7).length,
    );
    $("count-info").textContent = formatNumber(
        items.filter((event) => Number(event.severity) === 0).length,
    );
    $("latest-received").textContent = items.length
        ? formatDate(items[0].received_at, { dateStyle: undefined })
        : "—";

    $("result-summary").textContent =
        `${formatNumber(state.total)} matching events · ${formatNumber(items.length)} shown on this page`;

    if (!items.length) {
        $("events-table").innerHTML =
            '<tr><td colspan="5" class="table-empty">No events match this view. Try the Level 0 filter to inspect informational audit records.</td></tr>';
    } else {
        $("events-table").innerHTML = items.map((event) => {
            const id = escapeHtml(event.id);
            const message = String(event.message || "").replace(/\s+/g, " ").trim();
            const preview = message.length > 150 ? `${message.slice(0, 147)}…` : message;
            const device = event.device_name || `Device ${String(event.agent_id || "").slice(0, 8)}`;
            const category = String(event.category || "unknown")
                .replace(/[_-]+/g, " ")
                .replace(/\b\w/g, (letter) => letter.toUpperCase());

            return `
                <tr>
                    <td>
                        <a class="event-list-link" href="/events/${id}">
                            <strong>${escapeHtml(eventTitle(event.event_type))}</strong>
                            <span>${escapeHtml(preview || "No message provided")}</span>
                            <small>Open event details ↗</small>
                        </a>
                    </td>
                    <td><span class="severity-label ${severityClass(event.severity)}">Level ${Number(event.severity)} · ${severityName(event.severity)}</span></td>
                    <td>${escapeHtml(category)}</td>
                    <td>
                        <strong class="event-device-name">${escapeHtml(device)}</strong>
                        <small class="event-device-id">${escapeHtml(String(event.agent_id || "").slice(0, 8))}…</small>
                    </td>
                    <td>${escapeHtml(formatDate(event.received_at))}</td>
                </tr>`;
        }).join("");
    }

    const first = state.total ? state.offset + 1 : 0;
    const last = Math.min(state.offset + state.limit, state.total);
    $("pagination-label").textContent =
        `${formatNumber(first)}–${formatNumber(last)} of ${formatNumber(state.total)}`;

    $("page-first").disabled = $("page-prev").disabled = state.offset === 0;
    $("page-next").disabled = $("page-last").disabled =
        state.offset + state.limit >= state.total;
}

async function loadEvents() {
    if (state.busy) return;
    state.busy = true;
    showError("");

    const refreshButton = $("refresh-button");
    refreshButton.disabled = true;
    refreshButton.textContent = "Loading...";

    let reloadAtCorrectedOffset = false;

    try {
        const params = new URLSearchParams({
            limit: String(state.limit),
            offset: String(state.offset),
        });

        const category = $("filter-category").value;
        if (category) params.set("category", category);

        const level = $("filter-level").value;
        if (level === "info") {
            params.set("severity_min", "0");
            params.set("severity_max", "0");
        } else {
            params.set("severity_min", "1");
            params.set("severity_max", "10");
        }

        const result = await apiRequest(`/events?${params.toString()}`);
        state.items = result.items || [];
        state.total = result.pagination?.total ?? 0;

        if (state.offset > 0 && state.offset >= state.total) {
            state.offset = state.total === 0
                ? 0
                : Math.floor((state.total - 1) / state.limit) * state.limit;
            reloadAtCorrectedOffset = true;
            return;
        }

        renderEvents();
        $("last-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
        showError(error.message || "Unable to load security events.");
        $("events-table").innerHTML =
            '<tr><td colspan="5" class="table-empty">Event registry unavailable.</td></tr>';
        $("result-summary").textContent = "Event registry unavailable.";
    } finally {
        state.busy = false;
        refreshButton.disabled = false;
        refreshButton.textContent = "↻ Refresh";
        if (reloadAtCorrectedOffset) await loadEvents();
    }
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

async function initializeEvents() {
    if (!state.token) {
        window.location.replace("/login");
        return;
    }

    applyTheme(document.documentElement.dataset.theme || "dark");
    $("theme-toggle").addEventListener("click", () => {
        applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    $("logout-button").addEventListener("click", logout);
    $("refresh-button").addEventListener("click", loadEvents);

    $("apply-filters").addEventListener("click", () => {
        state.offset = 0;
        state.limit = Number($("filter-limit").value);
        loadEvents();
    });

    $("filter-level").addEventListener("change", () => {
        state.offset = 0;
        loadEvents();
    });
    $("filter-category").addEventListener("change", () => {
        state.offset = 0;
        loadEvents();
    });
    $("filter-limit").addEventListener("change", () => {
        state.offset = 0;
        state.limit = Number($("filter-limit").value);
        loadEvents();
    });

    $("clear-filters").addEventListener("click", () => {
        $("filter-category").value = "";
        $("filter-level").value = "security";
        $("filter-limit").value = "25";
        state.offset = 0;
        state.limit = 25;
        loadEvents();
    });

    $("page-first").addEventListener("click", () => {
        state.offset = 0;
        loadEvents();
    });
    $("page-prev").addEventListener("click", () => {
        state.offset = Math.max(0, state.offset - state.limit);
        loadEvents();
    });
    $("page-next").addEventListener("click", () => {
        state.offset += state.limit;
        loadEvents();
    });
    $("page-last").addEventListener("click", () => {
        state.offset = Math.max(0, Math.floor((state.total - 1) / state.limit) * state.limit);
        loadEvents();
    });

    try {
        const user = await apiRequest("/auth/me");
        $("current-username").textContent = user.username;
        $("current-role").textContent = user.role;
    } catch (error) {
        showError(error.message || "Unable to initialize the event registry.");
        return;
    }

    await loadEvents();
}

document.addEventListener("DOMContentLoaded", initializeEvents);
