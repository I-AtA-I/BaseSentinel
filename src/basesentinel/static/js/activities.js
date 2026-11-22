"use strict";

const TOKEN_KEY = "basesentinel_token";
const THEME_KEY = "basesentinel_theme";
const token = sessionStorage.getItem(TOKEN_KEY);
const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
    })[character]);
}

function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium", timeStyle: "medium",
    }).format(date);
}

function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    try { localStorage.setItem(THEME_KEY, selected); } catch (_) {}
    $("theme-toggle").querySelector(".theme-label").textContent = selected === "dark" ? "LIGHT MODE" : "DARK MODE";
    $("theme-toggle").querySelector(".theme-symbol").textContent = selected === "dark" ? "◐" : "◑";
}

async function api(path, options = {}) {
    const response = await fetch(`/api/v1${path}`, {
        ...options,
        headers: { Accept: "application/json", Authorization: `Bearer ${token}`, ...(options.headers || {}) },
        cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) {
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem("basesentinel_user");
        window.location.replace("/login");
    }
    if (!response.ok) throw new Error(data?.error?.message || `Request failed (${response.status}).`);
    return data;
}

function showError(message) {
    $("activity-error").textContent = message;
    $("activity-error").hidden = false;
}

function renderList(items) {
    $("activity-count").textContent = String(items.length);
    $("source-count").textContent = String(items.reduce((sum, item) => sum + item.occurrence_count, 0));
    $("activities-table").innerHTML = items.length ? items.map((item) => `
        <tr>
            <td><button class="text-button activity-open" type="button" data-id="${escapeHtml(item.id)}">${escapeHtml(item.title)}</button><small>${escapeHtml(item.summary)}</small></td>
            <td>${Number(item.occurrence_count)}</td>
            <td>${escapeHtml(item.agent?.display_name || item.agent?.hostname || "Unknown device")}</td>
            <td>${escapeHtml(formatDate(item.first_seen_at))}</td>
            <td>${escapeHtml(formatDate(item.last_seen_at))}</td>
        </tr>`).join("") : '<tr><td colspan="5" class="table-empty">No correlated activities have been recorded yet.</td></tr>';
    $("activities-table").querySelectorAll(".activity-open").forEach((button) => {
        button.addEventListener("click", () => loadDetail(button.dataset.id));
    });
}

async function loadDetail(id) {
    try {
        const item = await api(`/activities/${encodeURIComponent(id)}`);
        $("detail-title").textContent = item.title;
        $("detail-summary").textContent = item.summary;
        const context = item.context || {};
        const entries = [
            ["Device", item.agent?.display_name || item.agent?.hostname],
            ["Account", context.account],
            ["Domain", context.domain],
            ["Logon ID", context.logon_id],
            ["Correlation quality", context.correlation_quality],
            ["Privileges", Array.isArray(context.privileges) ? context.privileges.join(", ") : null],
            ["First seen", formatDate(item.first_seen_at)],
            ["Last seen", formatDate(item.last_seen_at)],
        ];
        $("activity-context").innerHTML = entries.filter(([, value]) => value).map(([label, value]) => `
            <div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("");
        $("activity-source-events").innerHTML = item.source_events.length ? item.source_events.map((event) => `
            <tr>
                <td><a href="/events/${encodeURIComponent(event.id)}">${escapeHtml(event.event_type)}</a></td>
                <td class="event-mono">${escapeHtml(event.event_code || "—")}</td>
                <td>${escapeHtml(formatDate(event.occurred_at))}</td>
                <td>${escapeHtml(formatDate(event.received_at))}</td>
            </tr>`).join("") : '<tr><td colspan="4" class="table-empty">No source events linked.</td></tr>';
        $("activity-detail").hidden = false;
        $("activity-detail").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
        showError(error.message);
    }
}

async function initialize() {
    if (!token) { window.location.replace("/login"); return; }
    applyTheme(document.documentElement.dataset.theme || "dark");
    $("theme-toggle").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
    $("close-detail").addEventListener("click", () => { $("activity-detail").hidden = true; });
    $("refresh-button").addEventListener("click", loadActivities);
    $("logout-button").addEventListener("click", async () => {
        try { await api("/auth/logout", { method: "POST" }); } catch (_) {}
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem("basesentinel_user");
        window.location.replace("/login");
    });
    try {
        const user = await api("/auth/me");
        $("current-username").textContent = user.username;
        $("current-role").textContent = user.role;
        await loadActivities();
    } catch (error) { showError(error.message); }
}

async function loadActivities() {
    try {
        const data = await api("/activities?limit=100&offset=0");
        renderList(data.items || []);
        $("activity-error").hidden = true;
    } catch (error) { showError(error.message); }
}

document.addEventListener("DOMContentLoaded", initialize);
