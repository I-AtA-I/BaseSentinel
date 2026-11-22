"use strict";

const API_BASE = "/api/v1";
const TOKEN_KEY = "basesentinel_token";
const USER_KEY = "basesentinel_user";

const state = { token: null, user: null, rules: [], editingId: null, busy: false };

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
    })[character]);
}

function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
}

function showMessage(message, isError = true) {
    const element = document.getElementById("rules-message");
    element.textContent = message || "";
    element.hidden = !message;
    element.classList.toggle("success-message", !isError);
}

async function apiRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
    if (options.body) headers.set("Content-Type", "application/json");

    const response = await fetch(`${API_BASE}${path}`, {
        ...options, headers, cache: "no-store",
    });
    let data = null;
    try { data = await response.json(); } catch (_) {}
    if (response.status === 401) {
        clearSession();
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
    try { localStorage.setItem("basesentinel_theme", selected); } catch (_) {}
    const button = document.getElementById("theme-toggle");
    button.querySelector(".theme-label").textContent = selected === "dark" ? "LIGHT MODE" : "DARK MODE";
    button.querySelector(".theme-symbol").textContent = selected === "dark" ? "◐" : "◑";
}

function resetForm() {
    state.editingId = null;
    document.getElementById("rule-form").reset();
    document.getElementById("rule-threshold").value = "1";
    document.getElementById("rule-window").value = "300";
    document.getElementById("rule-severity").value = "9";
    document.getElementById("rule-conditions").value = "{}";
    document.getElementById("editor-title").textContent = "Create detection rule";
    document.getElementById("save-rule").textContent = "Create rule";
    document.getElementById("cancel-edit").hidden = true;
}

function setFormEnabled(enabled) {
    document.querySelectorAll("#rule-form input, #rule-form select, #rule-form textarea, #rule-form button")
        .forEach((element) => { element.disabled = !enabled; });
    if (!enabled) {
        document.getElementById("rule-editor-panel").insertAdjacentHTML(
            "beforeend",
            '<p id="admin-only-note" class="rule-help">Only administrators can create or modify detection rules.</p>',
        );
    }
}

function renderRules() {
    const table = document.getElementById("rules-table");
    document.getElementById("rules-count").textContent = `${state.rules.length} RULES`;
    if (!state.rules.length) {
        table.innerHTML = '<tr><td colspan="6" class="table-empty">No custom detection rules have been configured.</td></tr>';
        return;
    }

    const canManage = state.user?.role === "admin";
    table.innerHTML = state.rules.map((rule) => {
        const criteria = [
            rule.category ? `category=${rule.category}` : null,
            rule.event_type ? `type=${rule.event_type}` : null,
            rule.source ? `source=${rule.source}` : null,
            rule.event_code ? `code=${rule.event_code}` : null,
            rule.min_event_severity !== null ? `severity≥${rule.min_event_severity}` : null,
            Object.keys(rule.conditions || {}).length ? `${Object.keys(rule.conditions).length} event-data condition(s)` : null,
        ].filter(Boolean);
        const actions = canManage
            ? `<div class="rule-row-actions">
                <button type="button" data-edit="${escapeHtml(rule.id)}">Edit</button>
                <button type="button" data-toggle="${escapeHtml(rule.id)}">${rule.enabled ? "Disable" : "Enable"}</button>
                <button type="button" class="delete-rule" data-delete="${escapeHtml(rule.id)}">Delete</button>
               </div>`
            : '<span class="rule-meta">Read only</span>';
        return `<tr>
            <td><span class="rule-name">${escapeHtml(rule.name)}</span><span class="rule-meta">${escapeHtml(rule.description)}</span><span class="rule-meta">${escapeHtml(rule.id)}</span></td>
            <td>${escapeHtml(criteria.join(" · ") || "All events")}</td>
            <td>${Number(rule.threshold)} event(s) / ${Number(rule.window_seconds)}s</td>
            <td>${Number(rule.severity)} / 10</td>
            <td><span class="rule-state ${rule.enabled ? "enabled" : "disabled"}">${rule.enabled ? "Enabled" : "Disabled"}</span></td>
            <td>${actions}</td>
        </tr>`;
    }).join("");

    table.querySelectorAll("[data-edit]").forEach((button) => button.addEventListener("click", () => editRule(button.dataset.edit)));
    table.querySelectorAll("[data-toggle]").forEach((button) => button.addEventListener("click", () => toggleRule(button.dataset.toggle)));
    table.querySelectorAll("[data-delete]").forEach((button) => button.addEventListener("click", () => deleteRule(button.dataset.delete)));
}

async function loadRules() {
    if (state.busy) return;
    state.busy = true;
    try {
        const data = await apiRequest("/detection-rules");
        state.rules = data.items || [];
        renderRules();
        document.getElementById("last-updated").textContent = `Updated ${new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }).format(new Date())}`;
        showMessage("");
    } catch (error) {
        showMessage(error.message);
    } finally {
        state.busy = false;
    }
}

function formPayload() {
    let conditions;
    try {
        conditions = JSON.parse(document.getElementById("rule-conditions").value || "{}");
    } catch (_) {
        throw new Error("Event data conditions must be valid JSON.");
    }
    if (!conditions || typeof conditions !== "object" || Array.isArray(conditions)) {
        throw new Error("Event data conditions must be a JSON object.");
    }

    const optionalText = (id) => document.getElementById(id).value.trim() || null;
    const minSeverity = document.getElementById("rule-min-severity").value;
    return {
        name: document.getElementById("rule-name").value.trim(),
        description: document.getElementById("rule-description").value.trim(),
        category: optionalText("rule-category"),
        event_type: optionalText("rule-event-type"),
        source: optionalText("rule-source"),
        event_code: optionalText("rule-event-code"),
        min_event_severity: minSeverity === "" ? null : Number(minSeverity),
        threshold: Number(document.getElementById("rule-threshold").value),
        window_seconds: Number(document.getElementById("rule-window").value),
        severity: Number(document.getElementById("rule-severity").value),
        conditions,
    };
}

async function saveRule(event) {
    event.preventDefault();
    if (state.user?.role !== "admin") return;
    const button = document.getElementById("save-rule");
    button.disabled = true;
    try {
        const payload = formPayload();
        const editing = Boolean(state.editingId);
        await apiRequest(
            editing ? `/detection-rules/${encodeURIComponent(state.editingId)}` : "/detection-rules",
            { method: editing ? "PATCH" : "POST", body: JSON.stringify(payload) },
        );
        resetForm();
        await loadRules();
        showMessage(editing ? "Detection rule updated." : "Detection rule created.", false);
    } catch (error) {
        showMessage(error.message);
    } finally {
        button.disabled = false;
    }
}

function editRule(id) {
    const rule = state.rules.find((item) => item.id === id);
    if (!rule) return;
    state.editingId = id;
    document.getElementById("rule-name").value = rule.name;
    document.getElementById("rule-description").value = rule.description || "";
    document.getElementById("rule-category").value = rule.category || "";
    document.getElementById("rule-event-type").value = rule.event_type || "";
    document.getElementById("rule-source").value = rule.source || "";
    document.getElementById("rule-event-code").value = rule.event_code || "";
    document.getElementById("rule-min-severity").value = rule.min_event_severity ?? "";
    document.getElementById("rule-threshold").value = rule.threshold;
    document.getElementById("rule-window").value = rule.window_seconds;
    document.getElementById("rule-severity").value = rule.severity;
    document.getElementById("rule-conditions").value = JSON.stringify(rule.conditions || {}, null, 2);
    document.getElementById("editor-title").textContent = "Edit detection rule";
    document.getElementById("save-rule").textContent = "Save changes";
    document.getElementById("cancel-edit").hidden = false;
    document.getElementById("rule-editor-panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function toggleRule(id) {
    const rule = state.rules.find((item) => item.id === id);
    if (!rule) return;
    try {
        await apiRequest(`/detection-rules/${encodeURIComponent(id)}`, {
            method: "PATCH", body: JSON.stringify({ enabled: !rule.enabled }),
        });
        await loadRules();
        showMessage(`Rule ${rule.enabled ? "disabled" : "enabled"}.`, false);
    } catch (error) { showMessage(error.message); }
}

async function deleteRule(id) {
    const rule = state.rules.find((item) => item.id === id);
    if (!rule || !window.confirm(`Delete detection rule "${rule.name}"? Existing alerts will remain.`)) return;
    try {
        await apiRequest(`/detection-rules/${encodeURIComponent(id)}`, { method: "DELETE" });
        if (state.editingId === id) resetForm();
        await loadRules();
        showMessage("Detection rule deleted. Existing alerts were preserved.", false);
    } catch (error) { showMessage(error.message); }
}

async function initialize() {
    state.token = sessionStorage.getItem(TOKEN_KEY);
    if (!state.token) {
        window.location.replace("/login");
        return;
    }
    try {
        const identity = await apiRequest("/auth/me");
        state.user = { username: identity.username, role: identity.role };
        document.getElementById("current-username").textContent = identity.username;
        document.getElementById("current-role").textContent = identity.role;
        document.getElementById("user-initial").textContent = identity.username.slice(0, 1).toUpperCase();
        if (identity.role !== "admin") setFormEnabled(false);
    } catch (error) {
        showMessage(error.message);
        return;
    }

    document.getElementById("rule-form").addEventListener("submit", saveRule);
    document.getElementById("cancel-edit").addEventListener("click", resetForm);
    document.getElementById("refresh-button").addEventListener("click", loadRules);
    document.getElementById("theme-toggle").addEventListener("click", () => {
        applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    document.getElementById("logout-button").addEventListener("click", async () => {
        try { await apiRequest("/auth/logout", { method: "POST" }); } catch (_) {}
        clearSession();
        window.location.replace("/login");
    });
    applyTheme(document.documentElement.dataset.theme);
    await loadRules();
}

document.addEventListener("DOMContentLoaded", initialize);
