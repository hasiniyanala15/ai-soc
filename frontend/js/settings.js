document.addEventListener('DOMContentLoaded', async () => {
    lucide.createIcons();
    
    // Check backend connection
    try {
        await checkBackendStatus();
    } catch (e) {
        console.error("Backend offline");
    }

    // Load initial settings
    await loadSettings();
    await loadIpBlocklist();
});

async function loadIpBlocklist() {
    const tbody = document.getElementById('ip-blocklist-tbody');
    const emptyState = document.getElementById('ip-blocklist-empty');
    try {
        const response = await getBlockedIps();
        const entries = response.blocked_ips || [];
        tbody.replaceChildren();
        emptyState.hidden = entries.length > 0;

        for (const entry of entries) {
            const row = document.createElement('tr');
            for (const value of [
                entry.source_ip,
                entry.reason,
                new Date(entry.created_at).toLocaleString()
            ]) {
                const cell = document.createElement('td');
                cell.textContent = value;
                row.appendChild(cell);
            }

            const actionCell = document.createElement('td');
            const button = document.createElement('button');
            button.className = 'btn btn-secondary';
            button.textContent = 'Unblock';
            button.addEventListener('click', async () => {
                button.disabled = true;
                try {
                    await unblockIp(entry.id);
                    await loadIpBlocklist();
                } catch (error) {
                    button.disabled = false;
                    showToast(error.message || 'Failed to unblock IP', 'error');
                }
            });
            actionCell.appendChild(button);
            row.appendChild(actionCell);
            tbody.appendChild(row);
        }
    } catch (error) {
        emptyState.hidden = true;
        showToast('Error loading IP denylist: ' + error.message, 'error');
    }
}

async function loadSettings() {
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/settings`);
        if (!response.ok) throw new Error('Failed to load settings');
        const data = await response.json();
        
        document.getElementById('llm-api-key').value = data.LLM_API_KEY || '';
        document.getElementById('llm-api-url').value = data.LLM_API_URL || '';
        document.getElementById('llm-model').value = data.LLM_MODEL || '';
        document.getElementById('hindsight-api-key').value = data.HINDSIGHT_API_KEY || '';
        document.getElementById('sniffer-timeout').value = data.SNIFFER_TIMEOUT || '3';
        
    } catch (error) {
        showToast("Error loading settings: " + error.message, "error");
    }
}

document.getElementById('btn-save-settings').addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn');
    const originalHtml = btn.innerHTML;
    btn.innerHTML = `<div class="spinner"></div> Saving...`;
    btn.disabled = true;
    
    const settingsData = {
        LLM_API_KEY: document.getElementById('llm-api-key').value,
        LLM_API_URL: document.getElementById('llm-api-url').value,
        LLM_MODEL: document.getElementById('llm-model').value,
        HINDSIGHT_API_KEY: document.getElementById('hindsight-api-key').value,
        SNIFFER_TIMEOUT: document.getElementById('sniffer-timeout').value
    };
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/settings`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settingsData)
        });
        
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || 'Failed to save');
        }
        
        showToast("Settings saved successfully!");
    } catch (error) {
        showToast("Error saving settings: " + error.message, "error");
    } finally {
        btn.innerHTML = originalHtml;
        btn.disabled = false;
        lucide.createIcons();
    }
});

document.getElementById('btn-train-network-model').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const status = document.getElementById('model-training-status');
    btn.disabled = true;
    status.textContent = 'Training model...';
    try {
        const result = await trainNetworkModel();
        status.textContent = result.message;
    } catch (error) {
        status.textContent = error.message || 'Model training failed.';
    } finally {
        btn.disabled = false;
    }
});
