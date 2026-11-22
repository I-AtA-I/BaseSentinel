"use strict";

const API_BASE = "/api/v1";
const TOKEN_KEY = "basesentinel_token";
const USER_KEY = "basesentinel_user";

const state = { token: null, timer: null, busy: false };

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

function formatDate(value) {
    if (!value) return "Never";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unknown";
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function timeAgo(value) {
    if (!value) return "No data";
    const timestamp = new Date(value).getTime();
    if (Number.isNaN(timestamp)) return "Unknown";
    const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

function showError(message) {
    const element = document.getElementById("health-error");
    element.textContent = message || "";
    element.hidden = !message;
}

function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    try { localStorage.setItem("basesentinel_theme", selected); } catch (_) {}
    const button = document.getElementById("theme-toggle");
    button.querySelector(".theme-label").textContent = selected === "dark" ? "LIGHT MODE" : "DARK MODE";
    button.querySelector(".theme-symbol").textContent = selected === "dark" ? "◐" : "◑";
}

function renderHealth(data) {
    const counts = data.counts || {};
    for (const stateName of ["online", "stale", "disconnected", "inactive"]) {
        document.getElementById(`count-${stateName}`).textContent = Number(counts[stateName] || 0).toLocaleString();
    }

    const banner = document.getElementById("health-banner");
    const disconnected = Number(counts.disconnected || 0);
    const stale = Number(counts.stale || 0);
    if (disconnected > 0) {
        banner.className = "health-banner warning";
        banner.textContent = `${disconnected} endpoint(s) have stopped checking in. Review their connectivity and local agent logs.`;
    } else if (stale > 0) {
        banner.className = "health-banner";
        banner.textContent = `${stale} endpoint(s) have delayed heartbeats. No endpoint is currently classified as disconnected.`;
    } else {
        banner.className = "health-banner success";
        banner.textContent = "All active endpoints are reporting within the expected heartbeat window.";
    }

    const table = document.getElementById("health-table");
    const agents = data.agents || [];
    if (!agents.length) {
        table.innerHTML = '<tr><td colspan="6" class="table-empty">No enrolled endpoints found.</td></tr>';
        return;
    }
    table.innerHTML = agents.map((agent) => {
        const health = ["online", "stale", "disconnected", "inactive"].includes(agent.health) ? agent.health : "inactive";
        const host = agent.display_name || agent.hostname || "Unknown endpoint";
        const event = agent.last_event_at ? formatDate(agent.last_event_at) : "No events received";
        return `<tr>
            <td><a class="health-host" href="/agents/${encodeURIComponent(agent.agent_id)}">${escapeHtml(host)}</a><span class="health-meta">${escapeHtml(agent.hostname || "")} · ${escapeHtml(agent.platform || "Unknown platform")}</span></td>
            <td><span class="health-state ${health}">${health}</span></td>
            <td>${escapeHtml(agent.agent_version || "Unknown")}</td>
            <td>${escapeHtml(timeAgo(agent.last_checkin_at))}<span class="health-meta">${escapeHtml(formatDate(agent.last_checkin_at))}</span></td>
            <td>${escapeHtml(timeAgo(agent.last_event_at))}<span class="health-meta">${escapeHtml(event)}</span></td>
            <td>${escapeHtml(agent.last_event_type || "—")}</td>
        </tr>`;
    }).join("");
}

async function loadHealth() {
    if (state.busy) return;
    state.busy = true;
    try {
        const data = await apiRequest("/operations/agents");
        renderHealth(data);
        document.getElementById("last-updated").textContent = `Updated ${new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }).format(new Date())}`;
        showError("");
    } catch (error) {
        showError(error.message);
    } finally {
        state.busy = false;
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

    document.getElementById("refresh-button").addEventListener("click", loadHealth);
    document.getElementById("theme-toggle").addEventListener("click", () => {
        applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    document.getElementById("logout-button").addEventListener("click", async () => {
        try { await apiRequest("/auth/logout", { method: "POST" }); } catch (_) {}
        clearSession();
        window.location.replace("/login");
    });

    applyTheme(document.documentElement.dataset.theme);
    await loadHealth();
    state.timer = window.setInterval(loadHealth, 15000);
    window.addEventListener("beforeunload", () => {
        if (state.timer !== null) window.clearInterval(state.timer);
    }, { once: true });
}

document.addEventListener("DOMContentLoaded", initialize);
