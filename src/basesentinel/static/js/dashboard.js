"use strict";

const API_BASE = "/api/v1";
const TOKEN_KEY = "basesentinel_token";
const USER_KEY = "basesentinel_user";
const THEME_KEY = "basesentinel_theme";

const state = {
    token: null,
    user: null,
    period: 24,
    overview: null,
    timeline: null,
    alerts: [],
    busy: false,
};

function getToken() {
    return sessionStorage.getItem(TOKEN_KEY);
}

function setSession(token, user) {
    sessionStorage.setItem(TOKEN_KEY, token);
    sessionStorage.setItem(USER_KEY, JSON.stringify(user));
}

function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
}

function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;

    try {
        localStorage.setItem(THEME_KEY, selected);
    } catch (_) {}

    const button = document.getElementById("theme-toggle");
    if (button) {
        const label = button.querySelector(".theme-label");
        const symbol = button.querySelector(".theme-symbol");
        if (label) label.textContent = selected === "dark" ? "LIGHT MODE" : "DARK MODE";
        if (symbol) symbol.textContent = selected === "dark" ? "◐" : "◑";
        button.setAttribute("aria-label", `Switch to ${selected === "dark" ? "light" : "dark"} theme`);
    }
}

function initializeTheme() {
    let theme = document.documentElement.dataset.theme || "dark";

    try {
        const saved = localStorage.getItem(THEME_KEY);
        if (saved === "light" || saved === "dark") theme = saved;
    } catch (_) {}

    applyTheme(theme);

    const button = document.getElementById("theme-toggle");
    if (button) {
        button.addEventListener("click", () => {
            const current = document.documentElement.dataset.theme;
            applyTheme(current === "dark" ? "light" : "dark");
        });
    }
}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
    })[character]);
}

function formatNumber(value) {
    return new Intl.NumberFormat().format(Number(value) || 0);
}

function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "short",
        timeStyle: "short",
    }).format(date);
}

function severityClass(value) {
    const severity = Number(value);
    if (severity >= 9) return "severity-critical";
    if (severity >= 7) return "severity-high";
    if (severity >= 4) return "severity-medium";
    return "severity-low";
}

function severityName(value) {
    const severity = Number(value);
    if (severity >= 9) return "Critical";
    if (severity >= 7) return "High";
    if (severity >= 4) return "Medium";
    return "Low";
}

async function apiRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");

    if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers,
        cache: "no-store",
    });

    let data = null;
    try {
        data = await response.json();
    } catch {
        data = null;
    }

    if (response.status === 401) {
        clearSession();
        if (window.location.pathname !== "/login") window.location.replace("/login");
    }

    if (!response.ok) {
        throw new Error(data?.error?.message || `Request failed (${response.status}).`);
    }

    return data;
}

function showDashboardError(message) {
    const element = document.getElementById("dashboard-error");
    if (!element) return;
    element.textContent = message;
    element.hidden = false;
}

function clearDashboardError() {
    const element = document.getElementById("dashboard-error");
    if (!element) return;
    element.textContent = "";
    element.hidden = true;
}

async function initializeLogin() {
    const form = document.getElementById("login-form");
    const error = document.getElementById("login-error");
    const button = document.getElementById("login-button");

    if (getToken()) {
        window.location.replace("/");
        return;
    }

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        error.textContent = "";
        button.disabled = true;
        button.textContent = "Authenticating...";

        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value;

        try {
            const response = await fetch(`${API_BASE}/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                cache: "no-store",
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data?.error?.message || "Sign-in failed.");

            setSession(data.token, data.user);
            window.location.replace("/");
        } catch (exception) {
            error.textContent = exception.message || "Unable to sign in.";
            button.disabled = false;
            button.innerHTML = 'Authenticate <span aria-hidden="true">→</span>';
        }
    });
}

async function initializeDashboard() {
    state.token = getToken();

    if (!state.token) {
        window.location.replace("/login");
        return;
    }

    const periodSelect = document.getElementById("period-select");
    const refreshButton = document.getElementById("refresh-button");
    const logoutButton = document.getElementById("logout-button");

    periodSelect.addEventListener("change", async () => {
        state.period = Number(periodSelect.value);
        await loadDashboard();
    });

    refreshButton.addEventListener("click", loadDashboard);
    logoutButton.addEventListener("click", logout);

    try {
        const user = await apiRequest("/auth/me");
        state.user = { username: user.username, role: user.role };

        document.getElementById("current-username").textContent = user.username;
        document.getElementById("current-role").textContent = user.role;
        document.getElementById("user-initial").textContent = user.username.charAt(0).toUpperCase();

        if (user.role === "admin") {
            const flushEventsButton = document.getElementById("flush-events-button");
            flushEventsButton.hidden = false;
            flushEventsButton.addEventListener("click", () => flushAllEvents(flushEventsButton));
        }

        await loadDashboard();
    } catch (exception) {
        showDashboardError(exception.message || "Unable to initialize dashboard.");
    }
}

async function flushAllEvents(button) {
    const confirmed = window.confirm("FLUSH ALL EVENTS?\\n\\nThis permanently deletes every security event. Existing alerts will be preserved, but their source-event links will be removed. This cannot be undone.");
    if (!confirmed) return;

    button.disabled = true;
    clearDashboardError();
    try {
        const result = await apiRequest("/events", { method: "DELETE" });
        await loadDashboard();
        document.getElementById("last-updated").textContent =
            `Deleted ${formatNumber(result.deleted_events)} events. Preserved ${formatNumber(result.detached_alerts)} alerts.`;
    } catch (exception) {
        showDashboardError(exception.message || "Unable to flush events.");
    } finally {
        button.disabled = false;
    }
}

async function logout() {
    try {
        await apiRequest("/auth/logout", { method: "POST" });
    } catch {
        // Clear the local session even when the API is unavailable.
    }

    clearSession();
    window.location.replace("/login");
}

async function loadDashboard() {
    if (state.busy) return;

    state.busy = true;
    clearDashboardError();

    const refreshButton = document.getElementById("refresh-button");
    refreshButton.disabled = true;
    refreshButton.textContent = "Loading...";

    try {
        const [overview, timeline, alerts] = await Promise.all([
            apiRequest(`/dashboard/overview?period_hours=${state.period}`),
            apiRequest(`/dashboard/timeline?period_hours=${state.period}`),
            apiRequest("/alerts?limit=8&offset=0"),
        ]);

        state.overview = overview;
        state.timeline = timeline;
        state.alerts = alerts.items || [];

        renderOverview();
        renderTimeline();
        renderSeverity();
        renderCategories();
        renderAlerts();
        renderAgents();

        document.getElementById("last-updated").textContent = `Updated ${formatDate(overview.generated_at)}`;
    } catch (exception) {
        showDashboardError(exception.message || "Unable to load dashboard data.");
    } finally {
        state.busy = false;
        refreshButton.disabled = false;
        refreshButton.textContent = "↻ Refresh";
    }
}

function renderOverview() {
    const data = state.overview;
    const openAlerts = data.alerts.by_status.find((item) => item.status === "open")?.count || 0;

    document.getElementById("metric-events").textContent = formatNumber(data.events.total);
    document.getElementById("metric-alerts").textContent = formatNumber(data.alerts.total);
    document.getElementById("metric-agents").textContent =
        `${formatNumber(data.agents.active)} / ${formatNumber(data.agents.total)}`;
    document.getElementById("metric-agent-description").textContent = "Active / registered agents";
    document.getElementById("metric-open-alerts").textContent = formatNumber(openAlerts);
}

function renderTimeline() {
    const container = document.getElementById("timeline-chart");
    const timeline = state.timeline;
    const buckets = timeline.buckets || [];

    document.getElementById("timeline-granularity").textContent = timeline.granularity.replace("_", " ");

    if (!buckets.length) {
        container.innerHTML = '<div class="chart-placeholder">No timeline data available.</div>';
        return;
    }

    const width = 900, height = 220, left = 38, right = 12, top = 14, bottom = 30;
    const plotWidth = width - left - right;
    const plotHeight = height - top - bottom;
    const maxValue = Math.max(1, ...buckets.map((bucket) => Math.max(bucket.event_count, bucket.alerts_created)));
    const step = plotWidth / buckets.length;
    const barWidth = Math.max(2, Math.min(16, step * 0.55));

    const grid = [0, .25, .5, .75, 1].map((ratio) => {
        const y = top + plotHeight * ratio;
        const value = Math.round(maxValue * (1 - ratio));
        return `
            <line x1="${left}" y1="${y}" x2="${width-right}" y2="${y}" stroke="var(--line)" stroke-width="1"/>
            <text x="${left-9}" y="${y+4}" fill="var(--muted)" font-size="10" text-anchor="end">${value}</text>
        `;
    }).join("");

    const bars = buckets.map((bucket, index) => {
        const x = left + index * step + (step - barWidth) / 2;
        const eventHeight = (bucket.event_count / maxValue) * plotHeight;
        const alertHeight = (bucket.alerts_created / maxValue) * plotHeight;
        const eventY = top + plotHeight - eventHeight;
        const alertY = top + plotHeight - alertHeight;

        return `
            <rect x="${x}" y="${eventY}" width="${barWidth}" height="${Math.max(0,eventHeight)}"
                fill="var(--chart-event)">
                <title>${escapeHtml(formatDate(bucket.start))}: ${bucket.event_count} events</title>
            </rect>
            ${bucket.alerts_created > 0 ? `
                <rect x="${x}" y="${alertY}" width="${barWidth}" height="${Math.max(0,alertHeight)}"
                    fill="var(--chart-alert)">
                    <title>${bucket.alerts_created} alerts created</title>
                </rect>` : ""}
        `;
    }).join("");

    const labels = buckets.map((bucket, index) => {
        if (buckets.length > 24 && index % Math.ceil(buckets.length / 8) !== 0) return "";
        const x = left + index * step + step / 2;
        const date = new Date(bucket.start);
        const label = timeline.granularity === "day"
            ? date.toLocaleDateString(undefined, { day: "2-digit", month: "short" })
            : date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
        return `<text x="${x}" y="${height-7}" fill="var(--muted)" font-size="10" text-anchor="middle">${escapeHtml(label)}</text>`;
    }).join("");

    container.innerHTML = `
        <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Event and alert activity timeline">
            ${grid}${bars}${labels}
        </svg>`;
}

function renderSeverity() {
    const container = document.getElementById("severity-chart");
    const items = state.overview.events.by_severity || [];
    const counts = Array.from({ length: 11 }, (_, severity) => ({
        severity,
        count: items.find((item) => Number(item.severity) === severity)?.count || 0,
    }));
    const max = Math.max(1, ...counts.map((item) => item.count));

    container.innerHTML = counts.map((item) => {
        let level = "low";
        if (item.severity >= 9) level = "high";
        else if (item.severity >= 7) level = "medium";
        const width = (item.count / max) * 100;

        return `
            <a class="severity-row severity-row-link" href="/events?severity_min=${item.severity}&severity_max=${item.severity}" aria-label="View events and alerts with severity level ${item.severity}">
                <span>Level ${item.severity}</span>
                <div class="severity-track"><div class="severity-fill ${level}" style="width:${width}%"></div></div>
                <strong>${formatNumber(item.count)}</strong>
            </a>`;
    }).join("");
}

function renderCategories() {
    const container = document.getElementById("category-chart");
    const items = state.overview.events.by_category || [];

    if (!items.length) {
        container.innerHTML = '<div class="chart-placeholder">No events in this period.</div>';
        return;
    }

    const max = Math.max(1, ...items.map((item) => item.count));
    container.innerHTML = items.map((item) => {
        const width = (item.count / max) * 100;
        const category = String(item.category || "");
        const href = `/events?category=${encodeURIComponent(category)}`;
        return `
            <a class="category-row category-row-link" href="${href}"
                aria-label="View ${formatNumber(item.count)} events in category ${escapeHtml(category)}">
                <span>${escapeHtml(category)}</span>
                <div class="category-track"><div class="category-fill" style="width:${width}%"></div></div>
                <strong>${formatNumber(item.count)}</strong>
            </a>`;
    }).join("");
}

function renderAlerts() {
    const container = document.getElementById("alerts-table");
    const canManage = ["admin", "analyst"].includes(state.user?.role);

    if (!state.alerts.length) {
        container.innerHTML = '<tr><td colspan="6" class="table-empty">No alerts found.</td></tr>';
        return;
    }

    container.innerHTML = state.alerts.map((alert) => {
        const severity = Number(alert.severity);
        const status = escapeHtml(alert.status);
        let actions = "—";

        if (canManage && alert.status === "open") {
            actions = `<button class="action-button" data-action="acknowledge" data-id="${escapeHtml(alert.id)}">Acknowledge</button>`;
        } else if (canManage && alert.status === "acknowledged") {
            actions = `<button class="action-button" data-action="resolve" data-id="${escapeHtml(alert.id)}">Resolve</button>`;
        }

        return `
            <tr>
                <td><span class="alert-title">${escapeHtml(alert.title)}</span></td>
                <td><span class="severity-label ${severityClass(severity)}">${severity} · ${severityName(severity)}</span></td>
                <td><span class="status-label status-${status}">${status}</span></td>
                <td>${formatNumber(alert.occurrence_count)}</td>
                <td>${formatDate(alert.last_seen_at)}</td>
                <td>${actions}</td>
            </tr>`;
    }).join("");

    container.querySelectorAll("[data-action]").forEach((button) => {
        button.addEventListener("click", async () => transitionAlert(button));
    });
}

async function transitionAlert(button) {
    const action = button.dataset.action;
    const alertId = button.dataset.id;
    if (!["acknowledge", "resolve"].includes(action)) return;

    button.disabled = true;
    try {
        await apiRequest(`/alerts/${encodeURIComponent(alertId)}/${action}`, { method: "POST" });
        await loadDashboard();
    } catch (exception) {
        showDashboardError(exception.message || "Unable to update alert.");
        button.disabled = false;
    }
}

function renderAgents() {
    const container = document.getElementById("agents-list");
    const agents = state.overview.agents.top_by_event_count || [];

    if (!agents.length) {
        container.innerHTML = '<div class="chart-placeholder">No agent activity available.</div>';
        return;
    }

    const max = Math.max(1, ...agents.map((agent) => agent.event_count));
    container.innerHTML = agents.map((agent) => {
        const name = agent.display_name || agent.hostname;
        const width = (agent.event_count / max) * 100;
        return `
            <a class="agent-row agent-row-link" href="/agents/${encodeURIComponent(agent.agent_id)}" title="Open device details for ${escapeHtml(name)}">
                <span class="agent-name" title="${escapeHtml(agent.hostname)}">${escapeHtml(name)}</span>
                <div class="agent-track"><div class="agent-fill" style="width:${width}%"></div></div>
                <span class="agent-count">${formatNumber(agent.event_count)}</span>
            </a>`;
    }).join("");
}

document.addEventListener("DOMContentLoaded", () => {
    initializeTheme();

    if (window.BASESENTINEL_PAGE === "login") initializeLogin();
    else if (window.BASESENTINEL_PAGE === "dashboard") initializeDashboard();
});
