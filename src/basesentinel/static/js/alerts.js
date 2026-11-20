"use strict";

const API_BASE = "/api/v1";
const TOKEN_KEY = "basesentinel_token";
const USER_KEY = "basesentinel_user";
const THEME_KEY = "basesentinel_theme";

const state = {
    token: null,
    user: null,
    offset: 0,
    limit: 25,
    total: 0,
    items: [],
    busy: false,
};

function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
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
        dateStyle: "medium",
        timeStyle: "short",
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

    try {
        localStorage.setItem(THEME_KEY, selected);
    } catch (_) {}

    const button = document.getElementById("theme-toggle");
    if (!button) return;

    button.querySelector(".theme-label").textContent =
        selected === "dark" ? "LIGHT MODE" : "DARK MODE";
    button.querySelector(".theme-symbol").textContent =
        selected === "dark" ? "◐" : "◑";
    button.setAttribute(
        "aria-label",
        `Switch to ${selected === "dark" ? "light" : "dark"} theme`,
    );
}

async function apiRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");

    if (state.token) {
        headers.set("Authorization", `Bearer ${state.token}`);
    }

    if (options.body && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
    }

    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers,
        cache: "no-store",
    });

    let data = null;
    try {
        data = await response.json();
    } catch (_) {}

    if (response.status === 401) {
        clearSession();
        window.location.replace("/login");
    }

    if (!response.ok) {
        throw new Error(data?.error?.message || `Request failed (${response.status}).`);
    }

    return data;
}

function showError(message) {
    const element = document.getElementById("alerts-error");
    element.textContent = message || "";
    element.hidden = !message;
}

function readFilters() {
    const params = new URLSearchParams();
    params.set("limit", String(state.limit));
    params.set("offset", String(state.offset));

    const status = document.getElementById("filter-status").value;
    if (status) params.set("status", status);

    const severity = document.getElementById("filter-severity").value;
    if (severity) {
        const [minimum, maximum] = severity.split("-");
        params.set("severity_min", minimum);
        params.set("severity_max", maximum);
    }

    const ruleKey = document.getElementById("filter-rule-key").value.trim();
    if (ruleKey) {
        if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(ruleKey)) {
            throw new Error("Rule key must use lowercase letters, numbers, dots, underscores or hyphens.");
        }
        params.set("rule_key", ruleKey);
    }

    const agentId = document.getElementById("filter-agent-id").value.trim();
    if (agentId) {
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(agentId)) {
            throw new Error("Agent ID must be a valid UUID.");
        }
        params.set("agent_id", agentId);
    }

    return params;
}

function updateCounters() {
    document.getElementById("count-total").textContent = formatNumber(state.total);
    document.getElementById("count-open").textContent = formatNumber(
        state.items.filter((item) => item.status === "open").length,
    );
    document.getElementById("count-severe").textContent = formatNumber(
        state.items.filter((item) => Number(item.severity) >= 7).length,
    );
    document.getElementById("count-resolved").textContent = formatNumber(
        state.items.filter((item) => item.status === "resolved").length,
    );
}

function renderAlerts() {
    const container = document.getElementById("alerts-table");
    const search = document.getElementById("filter-search").value.trim().toLowerCase();
    const visible = state.items.filter((alert) => {
        if (!search) return true;
        return `${alert.title} ${alert.rule_key}`.toLowerCase().includes(search);
    });
    const canManage = ["admin", "analyst"].includes(state.user?.role);

    if (!visible.length) {
        const message = state.items.length
            ? "No records on this page match the text search."
            : "No alerts match the selected API filters.";
        container.innerHTML = `<tr><td colspan="7" class="table-empty">${message}</td></tr>`;
    } else {
        container.innerHTML = visible.map((alert) => {
            const status = escapeHtml(alert.status);
            let actions = '<span class="read-only-label">Read only</span>';

            if (canManage && alert.status === "open") {
                actions = `<button class="action-button" data-action="acknowledge" data-id="${escapeHtml(alert.id)}">Acknowledge</button> <button class="action-button" data-action="resolve" data-id="${escapeHtml(alert.id)}">Resolve</button>`;
            } else if (canManage && alert.status === "acknowledged") {
                actions = `<button class="action-button" data-action="resolve" data-id="${escapeHtml(alert.id)}">Resolve</button>`;
            } else if (canManage && alert.status === "resolved") {
                actions = '<span class="read-only-label">Closed</span>';
            }
            if (state.user?.role === "admin") {
                actions += ` <button class="action-button action-danger" data-delete-alert="${escapeHtml(alert.id)}">Delete</button>`;
            }

            return `
                <tr>
                    <td class="detection-cell">
                        <span class="alert-title">${escapeHtml(alert.title)}</span>
                        <span class="alert-rule-key">${escapeHtml(alert.rule_key)}</span>
                        <span class="alert-id">${escapeHtml(alert.id)}</span>
                    </td>
                    <td><span class="severity-label ${severityClass(alert.severity)}">${Number(alert.severity)} · ${severityName(alert.severity)}</span></td>
                    <td><span class="status-label status-${status}">${status}</span></td>
                    <td>${formatNumber(alert.occurrence_count)}</td>
                    <td>${formatDate(alert.first_seen_at)}</td>
                    <td>${formatDate(alert.last_seen_at)}</td>
                    <td><div class="alert-actions">${actions}</div></td>
                </tr>`;
        }).join("");
    }

    container.querySelectorAll("[data-action]").forEach((button) => {
        button.addEventListener("click", () => transitionAlert(button));
    });
    container.querySelectorAll("[data-delete-alert]").forEach((button) => button.addEventListener("click", () => deleteAlert(button)));

    document.getElementById("result-summary").textContent =
        `${formatNumber(state.total)} matching alert${state.total === 1 ? "" : "s"} · ${formatNumber(visible.length)} visible on this page`;
}

function updatePagination() {
    const first = state.total === 0 ? 0 : state.offset + 1;
    const last = Math.min(state.offset + state.limit, state.total);
    const lastPageOffset = state.total === 0
        ? 0
        : Math.floor((state.total - 1) / state.limit) * state.limit;

    document.getElementById("pagination-label").textContent =
        `${formatNumber(first)}–${formatNumber(last)} of ${formatNumber(state.total)}`;
    document.getElementById("page-first").disabled = state.offset === 0;
    document.getElementById("page-prev").disabled = state.offset === 0;
    document.getElementById("page-next").disabled = state.offset + state.limit >= state.total;
    document.getElementById("page-last").disabled = state.offset >= lastPageOffset;
}

async function loadAlerts() {
    if (state.busy) return;

    let params;
    try {
        params = readFilters();
    } catch (error) {
        showError(error.message);
        return;
    }

    state.busy = true;
    showError("");

    const refreshButton = document.getElementById("refresh-button");
    refreshButton.disabled = true;
    refreshButton.textContent = "Loading...";

    let reloadAtCorrectedOffset = false;

    try {
        const result = await apiRequest(`/alerts?${params.toString()}`);
        state.items = result.items || [];
        state.total = result.pagination?.total ?? 0;

        if (state.offset > 0 && state.offset >= state.total) {
            state.offset = state.total === 0
                ? 0
                : Math.floor((state.total - 1) / state.limit) * state.limit;
            reloadAtCorrectedOffset = true;
            return;
        }

        updateCounters();
        renderAlerts();
        updatePagination();
        document.getElementById("last-updated").textContent =
            `Updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
        showError(error.message || "Unable to load alerts.");
        document.getElementById("alerts-table").innerHTML =
            '<tr><td colspan="7" class="table-empty">Alert data could not be loaded.</td></tr>';
        document.getElementById("result-summary").textContent = "Alert queue unavailable.";
    } finally {
        state.busy = false;
        refreshButton.disabled = false;
        refreshButton.textContent = "↻ Refresh";

        if (reloadAtCorrectedOffset) {
            await loadAlerts();
        }
    }
}

async function transitionAlert(button) {
    const action = button.dataset.action;
    const alertId = button.dataset.id;

    if (!["acknowledge", "resolve"].includes(action)) return;

    button.disabled = true;
    showError("");

    try {
        await apiRequest(`/alerts/${encodeURIComponent(alertId)}/${action}`, {
            method: "POST",
        });
        await loadAlerts();
    } catch (error) {
        showError(error.message || "Unable to update alert.");
        button.disabled = false;
    }
}

async function deleteAlert(button) {
    const alertId = button.dataset.deleteAlert;
    if (!window.confirm("Permanently delete this alert? The source security event will be preserved.")) return;
    button.disabled = true;
    try {
        await apiRequest("/alerts/" + encodeURIComponent(alertId), {method: "DELETE"});
        await loadAlerts();
    } catch (error) {
        showError(error.message || "Unable to delete alert.");
        button.disabled = false;
    }
}

async function flushAllAlerts() {
    const confirmed = window.confirm("FLUSH ALL ALERTS?\n\nThis permanently deletes every alert. Security events and device records remain. This cannot be undone.");
    if (!confirmed) return;
    const button = document.getElementById("flush-alerts-button");
    button.disabled = true;
    try {
        const result = await apiRequest("/alerts", {method: "DELETE"});
        state.offset = 0;
        showError("");
        await loadAlerts();
        document.getElementById("result-summary").textContent =
            "Deleted " + formatNumber(result.deleted) + " alerts. Source events were preserved.";
    } catch (error) {
        showError(error.message || "Unable to flush alerts.");
    } finally { button.disabled = false; }
}
async function logout() {
    try {
        await apiRequest("/auth/logout", { method: "POST" });
    } catch (_) {
        // Clear the local session even when the API is unavailable.
    }

    clearSession();
    window.location.replace("/login");
}

async function initializeAlerts() {
    state.token = sessionStorage.getItem(TOKEN_KEY);

    if (!state.token) {
        window.location.replace("/login");
        return;
    }

    applyTheme(document.documentElement.dataset.theme || "dark");

    document.getElementById("theme-toggle").addEventListener("click", () => {
        const current = document.documentElement.dataset.theme;
        applyTheme(current === "dark" ? "light" : "dark");
    });
    document.getElementById("logout-button").addEventListener("click", logout);
    document.getElementById("refresh-button").addEventListener("click", loadAlerts);

    try {
        const user = await apiRequest("/auth/me");
        state.user = { username: user.username, role: user.role };
        const flushButton = document.getElementById("flush-alerts-button");
        if (user.role === "admin") {
            flushButton.hidden = false;
            flushButton.addEventListener("click", flushAllAlerts);
        }

        document.getElementById("current-username").textContent = user.username;
        document.getElementById("current-role").textContent = user.role;
        document.getElementById("user-initial").textContent =
            user.username.charAt(0).toUpperCase();
    } catch (error) {
        showError(error.message || "Unable to initialize alert management.");
        return;
    }

    ["filter-status", "filter-severity"].forEach((id) => {
        document.getElementById(id).addEventListener("change", () => {
            state.offset = 0;
            loadAlerts();
        });
    });

    document.getElementById("apply-filters").addEventListener("click", () => {
        state.offset = 0;
        state.limit = Number(document.getElementById("filter-limit").value);
        loadAlerts();
    });

    document.getElementById("filter-rule-key").addEventListener("keydown", (event) => {
        if (event.key === "Enter") document.getElementById("apply-filters").click();
    });
    document.getElementById("filter-agent-id").addEventListener("keydown", (event) => {
        if (event.key === "Enter") document.getElementById("apply-filters").click();
    });

    document.getElementById("filter-search").addEventListener("input", renderAlerts);

    document.getElementById("filter-limit").addEventListener("change", () => {
        state.limit = Number(document.getElementById("filter-limit").value);
        state.offset = 0;
        loadAlerts();
    });

    document.getElementById("clear-filters").addEventListener("click", () => {
        document.getElementById("filter-search").value = "";
        document.getElementById("filter-status").value = "";
        document.getElementById("filter-severity").value = "";
        document.getElementById("filter-rule-key").value = "";
        document.getElementById("filter-agent-id").value = "";
        document.getElementById("filter-limit").value = "25";
        state.limit = 25;
        state.offset = 0;
        loadAlerts();
    });

    document.getElementById("page-first").addEventListener("click", () => {
        state.offset = 0;
        loadAlerts();
    });
    document.getElementById("page-prev").addEventListener("click", () => {
        state.offset = Math.max(0, state.offset - state.limit);
        loadAlerts();
    });
    document.getElementById("page-next").addEventListener("click", () => {
        state.offset += state.limit;
        loadAlerts();
    });
    document.getElementById("page-last").addEventListener("click", () => {
        state.offset = Math.max(0, Math.floor((state.total - 1) / state.limit) * state.limit);
        loadAlerts();
    });

    await loadAlerts();
}

document.addEventListener("DOMContentLoaded", initializeAlerts);
