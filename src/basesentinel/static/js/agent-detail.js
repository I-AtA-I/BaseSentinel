"use strict";

const API_BASE = "/api/v1";
const TOKEN_KEY = "basesentinel_token";
const THEME_KEY = "basesentinel_theme";
const root = document.getElementById("device-detail-root");
const agentId = root.dataset.agentId;
const token = sessionStorage.getItem(TOKEN_KEY);
const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({
        "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;",
    })[c]);
}
function dateLabel(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}
function severityClass(value) {
    const n = Number(value);
    if (n >= 9) return "severity-critical";
    if (n >= 7) return "severity-high";
    if (n >= 4) return "severity-medium";
    if (n === 0) return "severity-info";
    return "severity-low";
}
function severityName(value) {
    const n = Number(value);
    return n === 0 ? "Informational" : n >= 9 ? "Critical" : n >= 7 ? "High" : n >= 4 ? "Medium" : "Low";
}
function eventTitle(type) {
    return String(type || "Security event").replace(/[._-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
function showError(message) {
    $("device-error").textContent = message || "";
    $("device-error").hidden = !message;
}
function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    try { localStorage.setItem(THEME_KEY, selected); } catch (_) {}
    $("theme-toggle").querySelector(".theme-label").textContent = selected === "dark" ? "LIGHT MODE" : "DARK MODE";
    $("theme-toggle").querySelector(".theme-symbol").textContent = selected === "dark" ? "◐" : "◑";
}
async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (token) headers.set("Authorization", "Bearer " + token);
    if (options.body) headers.set("Content-Type", "application/json");
    const response = await fetch(API_BASE + path, {...options, headers, cache:"no-store"});
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) {
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem("basesentinel_user");
        window.location.replace("/login");
    }
    if (!response.ok) throw new Error(data?.error?.message || "Request failed (" + response.status + ").");
    return data;
}
async function loadDevice() {
    if (!token) { window.location.replace("/login"); return; }
    showError("");
    $("refresh-device").disabled = true;
    try {
        const results = await Promise.all([
            api("/agents/" + encodeURIComponent(agentId)),
            api("/events?agent_id=" + encodeURIComponent(agentId) + "&limit=100&offset=0"),
            api("/alerts?agent_id=" + encodeURIComponent(agentId) + "&limit=100&offset=0"),
        ]);
        const agent = results[0], events = results[1], alerts = results[2];
        const asset = agent.asset || {};
        const name = asset.display_name || asset.hostname || "Unknown device";
        $("device-title").textContent = name;
        $("device-subtitle").textContent = (agent.platform || "Unknown platform") + " · " + agent.status;
        $("device-platform").textContent = [agent.platform, agent.platform_version].filter(Boolean).join(" · ") || "Unknown platform";
        $("device-hostname").textContent = asset.hostname || "—";
        $("device-version").textContent = agent.agent_version || "—";
        $("device-architecture").textContent = agent.architecture || "—";
        $("device-enrolled").textContent = dateLabel(agent.enrolled_at);
        $("device-id").textContent = agent.id;
        $("device-status").textContent = agent.status || "Unknown";
        $("device-checkin").textContent = dateLabel(agent.last_checkin_at);
        $("device-event-count").textContent = Number(events.pagination?.total || 0).toLocaleString();
        $("device-alert-count").textContent = Number(alerts.pagination?.total || 0).toLocaleString();

        const alertRows = alerts.items || [];
        $("device-alerts").innerHTML = alertRows.length ? alertRows.map((alert) => {
            const status = escapeHtml(alert.status);
            return "<tr><td><strong>" + escapeHtml(alert.title) + "</strong><small>" + escapeHtml(alert.rule_key) + "</small></td>" +
                '<td><span class="severity-label ' + severityClass(alert.severity) + '">' + Number(alert.severity) + " · " + severityName(alert.severity) + "</span></td>" +
                '<td><span class="status-label status-' + status + '">' + status + "</span></td><td>" + escapeHtml(dateLabel(alert.last_seen_at)) + "</td></tr>";
        }).join("") : '<tr><td colspan="4" class="table-empty">No alerts for this device.</td></tr>';

        const eventRows = events.items || [];
        $("device-events").innerHTML = eventRows.length ? eventRows.map((event) =>
            '<tr><td><a class="device-record-link" href="/events/' + encodeURIComponent(event.id) + '">' + escapeHtml(eventTitle(event.event_type)) + "</a><small>" + escapeHtml(event.message || "No message") + "</small></td>" +
            '<td><span class="severity-label ' + severityClass(event.severity) + '">Level ' + Number(event.severity) + " · " + severityName(event.severity) + "</span></td>" +
            "<td>" + escapeHtml(event.category || "—") + "</td><td>" + escapeHtml(dateLabel(event.received_at)) + "</td></tr>"
        ).join("") : '<tr><td colspan="4" class="table-empty">No events for this device.</td></tr>';
    } catch (error) {
        showError(error.message || "Unable to load device activity.");
    } finally {
        $("refresh-device").disabled = false;
    }
}
async function logout() {
    try { await api("/auth/logout", {method:"POST"}); } catch (_) {}
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem("basesentinel_user");
    window.location.replace("/login");
}
async function initialize() {
    if (!token) { window.location.replace("/login"); return; }
    applyTheme(document.documentElement.dataset.theme || "dark");
    $("theme-toggle").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
    $("logout-button").addEventListener("click", logout);
    $("refresh-device").addEventListener("click", loadDevice);
    try {
        const user = await api("/auth/me");
        $("current-username").textContent = user.username;
        $("current-role").textContent = user.role;
    } catch (error) { showError(error.message); return; }
    await loadDevice();
}
document.addEventListener("DOMContentLoaded", initialize);
