"use strict";

const token = sessionStorage.getItem("basesentinel_token");
const message = document.getElementById("settings-message");

function showMessage(text, isError = false) {
    message.textContent = text;
    message.hidden = false;
    message.dataset.state = isError ? "error" : "success";
}

async function api(path, options = {}) {
    const response = await fetch("/api/v1" + path, {
        ...options,
        headers: {
            "Accept": "application/json",
            ...(options.body ? {"Content-Type": "application/json"} : {}),
            ...(token ? {"Authorization": "Bearer " + token} : {}),
        },
        cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) window.location.replace("/login");
    if (!response.ok) throw new Error(data?.error?.message || "Request failed.");
    return data;
}

async function load() {
    if (!token) {
        window.location.replace("/login");
        return;
    }
    try {
        const data = await api("/server/enrollment");
        document.getElementById("server-id").textContent = data.server_id;
        document.getElementById("enrollment-mode").value = data.enrollment_mode;
        if (data.initial_server_secret) {
            document.getElementById("server-secret").textContent = data.initial_server_secret;
            document.getElementById("secret-notice").textContent = "Copy and store this code now. It cannot be retrieved later.";
        }
        await loadInvitations();
    } catch (error) {
        showMessage(error.message, true);
    }
}

document.getElementById("rotate-secret").addEventListener("click", async () => {
    if (!window.confirm("Rotating the access code will prevent new devices using the old code from enrolling. Continue?")) return;
    try {
        const data = await api("/server/enrollment/rotate-secret", {method: "POST"});
        document.getElementById("server-id").textContent = data.server_id;
        document.getElementById("server-secret").textContent = data.server_secret;
        document.getElementById("secret-notice").textContent = "New access code. Copy and store it now; it cannot be retrieved later.";
        showMessage("Server access code rotated.");
    } catch (error) {
        showMessage(error.message, true);
    }
});

document.getElementById("save-settings").addEventListener("click", async () => {
    const password = document.getElementById("connection-password").value;
    try {
        const data = await api("/server/enrollment", {
            method: "PUT",
            body: JSON.stringify({
                enrollment_mode: document.getElementById("enrollment-mode").value,
                connection_password: password,
            }),
        });
        document.getElementById("connection-password").value = "";
        showMessage("Enrollment settings saved. Password required: " + (data.connection_password_required ? "yes" : "no") + ".");
    } catch (error) {
        showMessage(error.message, true);
    }
});

load();


function invitationStatusLabel(status) {
    const labels = {
        active: "Active",
        used: "Used",
        expired: "Expired",
        revoked: "Revoked",
    };
    return labels[status] || "Unknown";
}

async function loadInvitations() {
    const container = document.getElementById("invitations-list");
    try {
        const data = await api("/server/enrollment/invitations");
        const items = data.items || [];
        if (!items.length) {
            container.textContent = "No invitations have been created.";
            return;
        }
        container.innerHTML = items.map((item) => {
            const canRevoke = item.status === "active";
            return `
                <div class="invitation-row" style="display:flex;justify-content:space-between;gap:16px;align-items:center;padding:12px 0;border-top:1px solid var(--line)">
                    <div>
                        <strong>${invitationStatusLabel(item.status)}</strong>
                        <div class="muted">Created ${new Date(item.created_at).toLocaleString()} · Expires ${new Date(item.expires_at).toLocaleString()}</div>
                    </div>
                    ${canRevoke ? `<button class="secondary-button" type="button" data-revoke-invitation="${item.id}">Revoke</button>` : ""}
                </div>`;
        }).join("");
        container.querySelectorAll("[data-revoke-invitation]").forEach((button) => {
            button.addEventListener("click", async () => {
                button.disabled = true;
                try {
                    await api("/server/enrollment/invitations/" + encodeURIComponent(button.dataset.revokeInvitation) + "/revoke", {method: "POST"});
                    await loadInvitations();
                    showMessage("Invitation revoked.");
                } catch (error) {
                    showMessage(error.message, true);
                    button.disabled = false;
                }
            });
        });
    } catch (error) {
        container.textContent = error.message;
    }
}

document.getElementById("create-invitation").addEventListener("click", async () => {
    const button = document.getElementById("create-invitation");
    button.disabled = true;
    try {
        const ttl = Number(document.getElementById("invitation-ttl").value);
        const data = await api("/server/enrollment/invitations", {
            method: "POST",
            body: JSON.stringify({ttl_minutes: ttl}),
        });
        const link = window.location.origin + "/agent-invite#invite=" + encodeURIComponent(data.invitation_token);
        document.getElementById("invitation-link").value = link;
        document.getElementById("invitation-code").textContent = data.invitation_code;
        document.getElementById("invitation-result").hidden = false;
        showMessage("Invitation created. Copy the link or code now; neither can be retrieved later.");
        await loadInvitations();
    } catch (error) {
        showMessage(error.message, true);
    } finally {
        button.disabled = false;
    }
});

document.getElementById("copy-invitation").addEventListener("click", async () => {
    const field = document.getElementById("invitation-link");
    try {
        await navigator.clipboard.writeText(field.value);
        showMessage("Invitation link copied.");
    } catch (_) {
        field.focus();
        field.select();
        showMessage("Select and copy the invitation link manually.");
    }
});


document.getElementById("copy-invitation-code").addEventListener("click", async () => {
    const code = document.getElementById("invitation-code").textContent;
    try {
        await navigator.clipboard.writeText(code);
        showMessage("Invitation code copied.");
    } catch (_) {
        showMessage("Select and copy the invitation code manually.");
    }
});
