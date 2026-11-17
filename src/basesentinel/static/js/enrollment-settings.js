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
