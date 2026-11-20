"use strict";

const authToken = sessionStorage.getItem("basesentinel_token");
const table = document.getElementById("clients-table");
const message = document.getElementById("clients-message");
let canManage = false;

async function api(path, options = {}) {
    const response = await fetch("/api/v1" + path, {
        ...options,
        headers: {
            "Accept": "application/json",
            ...(options.body ? {"Content-Type": "application/json"} : {}),
            ...(authToken ? {"Authorization": "Bearer " + authToken} : {}),
        },
        cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) window.location.replace("/login");
    if (!response.ok) throw new Error(data?.error?.message || "Request failed.");
    return data;
}

function showMessage(text, error = false) {
    message.textContent = text;
    message.hidden = false;
    message.dataset.state = error ? "error" : "success";
}

function dateLabel(value) {
    if (!value) return "Never";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function statusLabel(status) {
    return status === "active" ? "Active" : status === "revoked" ? "Revoked" : status;
}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[character]);
}

async function removeAgent(button) {
    const agentId = button.dataset.deleteAgent;
    const row = button.closest("tr");
    const device = row?.querySelector("td strong")?.textContent || "this device";
    const confirmed = window.confirm(
        "PERMANENTLY DELETE " + device + "?\n\nThis removes the endpoint, its credentials, all collected events and alerts. This cannot be undone."
    );
    if (!confirmed) return;

    button.disabled = true;
    try {
        const result = await api("/agents/" + encodeURIComponent(agentId), {method: "DELETE"});
        showMessage(
            "Device permanently deleted. Removed " + result.deleted_events +
            " events, " + result.deleted_alerts + " alerts and " +
            result.deleted_credentials + " credentials."
        );
        await loadClients();
    } catch (error) {
        showMessage(error.message || "Unable to delete device.", true);
        button.disabled = false;
    }
}

async function loadClients() {
    table.innerHTML = '<tr><td colspan="7" class="table-empty">Loading clients...</td></tr>';
    try {
        const data = await api("/agents?limit=100&offset=0");
        const items = data.items || [];
        document.getElementById("client-count").textContent =
            items.length + " of " + (data.pagination?.total ?? items.length) + " clients";
        if (!items.length) {
            table.innerHTML = '<tr><td colspan="7" class="table-empty">No agents enrolled yet.</td></tr>';
            return;
        }
        table.innerHTML = items.map((agent) => {
            const active = agent.status === "active";
            const device = agent.asset?.hostname || agent.asset?.display_name || "Unknown device";
            const platform = [agent.platform, agent.platform_version].filter(Boolean).join(" · ");
            return `<tr>
                <td><a class="device-record-link" href="/agents/${encodeURIComponent(agent.id)}">${escapeHtml(device)}</a><div class="muted">${escapeHtml(agent.id)}</div></td>
                <td>${escapeHtml(platform || "Unknown")}</td>
                <td>${escapeHtml(agent.agent_version || "Unknown")}</td>
                <td><span class="status-pill ${active ? "status-success" : "status-muted"}">${escapeHtml(statusLabel(agent.status))}</span></td>
                <td>${escapeHtml(dateLabel(agent.last_checkin_at))}</td>
                <td>${escapeHtml(dateLabel(agent.enrolled_at))}</td>
                <td><div class="alert-actions">
                    ${canManage && active ? `<button class="secondary-button" type="button" data-revoke-agent="${escapeHtml(agent.id)}">Revoke</button>` : ""}
                    ${canManage ? `<button class="action-button" type="button" data-delete-agent="${escapeHtml(agent.id)}">Delete</button>` : ""}
                </div></td>
            </tr>`;
        }).join("");

        table.querySelectorAll("[data-revoke-agent]").forEach((button) => {
            button.addEventListener("click", async () => {
                if (!window.confirm("Revoke this agent? It will no longer be able to authenticate. Historical events will be preserved.")) return;
                button.disabled = true;
                try {
                    await api("/agents/" + encodeURIComponent(button.dataset.revokeAgent) + "/revoke", {method: "POST"});
                    showMessage("Agent access revoked. Historical events were preserved.");
                    await loadClients();
                } catch (error) {
                    showMessage(error.message, true);
                    button.disabled = false;
                }
            });
        });
        table.querySelectorAll("[data-delete-agent]").forEach((button) => {
            button.addEventListener("click", () => removeAgent(button));
        });
    } catch (error) {
        table.innerHTML = '<tr><td colspan="7" class="table-empty">Could not load clients.</td></tr>';
        showMessage(error.message, true);
    }
}

document.getElementById("refresh-clients").addEventListener("click", loadClients);
(async function initializeClients() {
    try {
        const user = await api("/auth/me");
        canManage = user.role === "admin";
    } catch (error) {
        showMessage(error.message || "Unable to initialize client management.", true);
        return;
    }
    await loadClients();
})();
