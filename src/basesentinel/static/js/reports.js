"use strict";

const API_BASE = "/api/v1";
const TOKEN_KEY = "basesentinel_token";
const USER_KEY = "basesentinel_user";
const state = { token: null, report: null, busy: false };

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
    })[character]);
}

function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
}

async function apiRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
    const response = await fetch(`${API_BASE}${path}`, { ...options, headers, cache: "no-store" });
    let data = null;
    try { data = await response.json(); } catch (_) {}
    if (response.status === 401) {
        clearSession();
        window.location.replace("/login");
    }
    if (!response.ok) throw new Error(data?.error?.message || `Request failed (${response.status}).`);
    return data;
}

function showError(message) {
    const element = document.getElementById("report-error");
    element.textContent = message || "";
    element.hidden = !message;
}

function formatNumber(value) {
    return new Intl.NumberFormat().format(Number(value) || 0);
}

function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    try { localStorage.setItem("basesentinel_theme", selected); } catch (_) {}
    const button = document.getElementById("theme-toggle");
    if (!button) return;
}

function renderBars(container, entries, labelFor, valueFor) {
    if (!entries.length) {
        container.innerHTML = '<p class="muted">No data for this period.</p>';
        return;
    }
    const maximum = Math.max(1, ...entries.map(valueFor));
    container.innerHTML = entries.map((entry) => {
        const value = valueFor(entry);
        const width = Math.max(0, Math.min(100, value / maximum * 100));
        return `<div class="report-bar-row">
            <span>${escapeHtml(labelFor(entry))}</span>
            <div class="report-bar"><span style="width:${width}%"></span></div>
            <strong>${formatNumber(value)}</strong>
        </div>`;
    }).join("");
}

function renderReport(report) {
    state.report = report;
    const events = report.events || {};
    const alerts = report.alerts || {};
    const statuses = alerts.by_status || {};
    document.getElementById("metric-events").textContent = formatNumber(events.total);
    document.getElementById("metric-alerts").textContent = formatNumber(alerts.total);
    document.getElementById("metric-open").textContent = formatNumber(statuses.open);
    document.getElementById("metric-agents").textContent = formatNumber(report.active_agent_count);
    document.getElementById("report-window").textContent =
        `From ${formatDate(report.period?.from)} to ${formatDate(report.period?.to)}`;

    const trend = events.trend || [];
    renderBars(
        document.getElementById("report-trend"),
        trend,
        (item) => item.bucket,
        (item) => Number(item.count) || 0,
    );

    const severityEntries = Object.entries(events.by_severity || {})
        .map(([severity, count]) => ({ severity, count: Number(count) || 0 }));
    renderBars(
        document.getElementById("report-severity"),
        severityEntries,
        (item) => `Level ${item.severity}`,
        (item) => item.count,
    );

    const categories = Object.entries(events.by_category || {});
    document.getElementById("report-categories").innerHTML = categories.length
        ? categories.map(([name, count]) => `<tr><td>${escapeHtml(name)}</td><td>${formatNumber(count)}</td></tr>`).join("")
        : '<tr><td colspan="2">No events in this period.</td></tr>';

    const agents = report.agent_activity || [];
    document.getElementById("report-agents").innerHTML = agents.length
        ? agents.map((agent) => `<tr><td>${escapeHtml(agent.hostname || "Unknown")}</td><td>${formatNumber(agent.event_count)}</td></tr>`).join("")
        : '<tr><td colspan="2">No endpoint activity.</td></tr>';

    document.getElementById("report-truncation").hidden =
        !events.truncated && !alerts.truncated;
}

async function loadReport() {
    if (state.busy) return;
    state.busy = true;
    const hours = Number(document.getElementById("report-period").value);
    try {
        const report = await apiRequest(`/reports/security/summary?hours=${hours}`);
        renderReport(report);
        document.getElementById("last-updated").textContent =
            `Updated ${new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }).format(new Date())}`;
        showError("");
    } catch (error) {
        showError(error.message);
    } finally {
        state.busy = false;
    }
}

async function downloadReport(format) {
    const hours = Number(document.getElementById("report-period").value);
    const button = document.getElementById(format === "csv" ? "download-csv" : "download-pdf");
    button.disabled = true;
    try {
        const response = await fetch(`${API_BASE}/reports/security.${format}?hours=${hours}`, {
            headers: { Authorization: `Bearer ${state.token}` },
            cache: "no-store",
        });
        if (response.status === 401) {
            clearSession();
            window.location.replace("/login");
            return;
        }
        if (!response.ok) {
            let message = `Report export failed (${response.status}).`;
            try { message = (await response.json())?.error?.message || message; } catch (_) {}
            throw new Error(message);
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = `basesentinel-security-report-${hours}h.${format}`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
        showError("");
    } catch (error) {
        showError(error.message);
    } finally {
        button.disabled = false;
    }
}

async function initialize() {
    state.token = sessionStorage.getItem(TOKEN_KEY);
    if (!state.token) {
        window.location.replace("/login");
        return;
    }
    try {
        const identity = await apiRequest("/auth/me");
        document.getElementById("current-username").textContent = identity.username;
        document.getElementById("current-role").textContent = identity.role;
        document.getElementById("user-initial").textContent = identity.username.slice(0, 1).toUpperCase();
    } catch (error) {
        showError(error.message);
        return;
    }

    document.getElementById("refresh-report").addEventListener("click", loadReport);
    document.getElementById("report-period").addEventListener("change", loadReport);
    document.getElementById("download-csv").addEventListener("click", () => downloadReport("csv"));
    document.getElementById("download-pdf").addEventListener("click", () => downloadReport("pdf"));
    document.getElementById("logout-button").addEventListener("click", async () => {
        try { await apiRequest("/auth/logout", { method: "POST" }); } catch (_) {}
        clearSession();
        window.location.replace("/login");
    });
    await loadReport();
}

document.addEventListener("DOMContentLoaded", initialize);
