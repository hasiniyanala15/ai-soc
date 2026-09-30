/**
 * alerts.js - Logic for the Security Alerts Page (alerts.html)
 */

let allAlerts = [];
let currentAlertId = null;

// Initialize icons
lucide.createIcons();

// Toast Notification Helper
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<span>${type === 'success' ? '✅' : '❌'}</span> <span>${message}</span>`;
    
    // Quick inline style for toast in case dashboard.css isn't perfectly carrying it
    toast.style.cssText = `
        background-color: var(--bg-card); border: 1px solid var(--border-color);
        padding: 1rem 1.5rem; border-radius: var(--radius-md); color: var(--text-main);
        display: flex; gap: 10px; align-items: center; margin-top: 10px;
    `;
    
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

async function loadAlerts() {
    try {
        const response = await getAlerts();
        allAlerts = response.alerts || [];
        renderAlerts();
    } catch (e) {
        showToast("Failed to load alerts", "error");
    }
}

function renderAlerts() {
    const search = document.getElementById('search-input').value.toLowerCase();
    const severity = document.getElementById('filter-severity').value;
    const sort = document.getElementById('sort-time').value;
    
    // Filter
    let filtered = allAlerts.filter(a => {
        const matchSearch = String(a.id).includes(search) || 
                            a.source_ip.toLowerCase().includes(search) || 
                            a.alert_type.toLowerCase().includes(search);
        const matchSeverity = severity === 'ALL' || a.severity.toUpperCase() === severity;
        return matchSearch && matchSeverity;
    });
    
    // Sort
    if (sort === 'ASC') {
        filtered.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    } else {
        filtered.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    }
    
    const tbody = document.getElementById('alerts-tbody');
    const emptyState = document.getElementById('alerts-empty-state');
    const table = document.getElementById('alerts-table');
    
    tbody.innerHTML = '';
    
    if (filtered.length === 0) {
        emptyState.style.display = 'block';
        table.style.display = 'none';
        return;
    }
    
    emptyState.style.display = 'none';
    table.style.display = 'table';
    
    filtered.forEach(alert => {
        const tr = document.createElement('tr');
        const badgeClass = alert.severity.toLowerCase() === 'high' ? 'badge-high' : 
                           alert.severity.toLowerCase() === 'medium' ? 'badge-medium' : 'badge-low';
                           
        let desc = "No description";
        let recAction = "N/A";
        let target = "Unknown";
        try {
            const ev = typeof alert.evidence === 'string' ? JSON.parse(alert.evidence) : alert.evidence;
            if (ev && ev.Description) desc = ev.Description;
            if (ev && ev["Recommended Action"]) recAction = ev["Recommended Action"];
            if (ev && ev.Target) target = ev.Target;
        } catch (e) {}

        let routingStr = target !== "Unknown" ? `${alert.source_ip} ➔ ${target}` : alert.source_ip;

        tr.innerHTML = `
            <td>#${alert.id}</td>
            <td style="text-transform: capitalize;">${alert.alert_type.replace('_', ' ')}</td>
            <td style="font-family: monospace; font-size: 0.85em; white-space: nowrap;">${routingStr}</td>
            <td><span class="badge ${badgeClass}">${alert.severity}</span></td>
            <td>${desc}</td>
            <td>${recAction}</td>
            <td class="text-muted">${new Date(alert.created_at).toLocaleString()}</td>
            <td>
                <button class="btn btn-secondary" onclick="openAlertModal(${alert.id})" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">
                    Details
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function openAlertModal(id) {
    const alert = allAlerts.find(a => a.id === id);
    if (!alert) return;
    
    currentAlertId = id;
    
    document.getElementById('modal-title').textContent = `Alert #${id} - ${alert.alert_type.replace('_', ' ').toUpperCase()}`;
    document.getElementById('modal-ip').textContent = alert.source_ip;
    
    // Safely parse evidence if it's a string, otherwise use object
    let evidenceObj = alert.evidence;
    if (typeof evidenceObj === 'string') {
        try { evidenceObj = JSON.parse(evidenceObj); } catch(e) {}
    }
    
    document.getElementById('modal-reason').textContent = evidenceObj.reason || "Suspicious activity detected";
    document.getElementById('modal-evidence').textContent = JSON.stringify(evidenceObj, null, 2);
    
    document.getElementById('alert-modal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('alert-modal').style.display = 'none';
    currentAlertId = null;
}

// -----------------------------------------
// Event Listeners
// -----------------------------------------

document.getElementById('btn-refresh').addEventListener('click', () => {
    loadAlerts();
    showToast("Alerts refreshed");
});

document.getElementById('search-input').addEventListener('input', renderAlerts);
document.getElementById('filter-severity').addEventListener('change', renderAlerts);
document.getElementById('sort-time').addEventListener('change', renderAlerts);

document.getElementById('btn-investigate').addEventListener('click', async (e) => {
    if (!currentAlertId) return;
    
    const btn = e.target.closest('.btn');
    const originalHtml = btn.innerHTML;
    btn.innerHTML = `<div class="spinner"></div> Investigating...`;
    btn.disabled = true;
    
    try {
        // Ping the Flask backend API
        await investigateAlert(currentAlertId);
        
        showToast("Investigation complete! Redirecting...");
        
        // Wait 1 second so they can read the success toast, then redirect to the report page
        setTimeout(() => {
            window.location.href = `investigations.html?id=${currentAlertId}`;
        }, 1200);
        
    } catch (err) {
        showToast("Investigation failed. Is the LLM offline?", "error");
        btn.innerHTML = originalHtml;
        btn.disabled = false;
        lucide.createIcons();
    }
});

document.getElementById('btn-block-ip').addEventListener('click', async (e) => {
    if (!currentAlertId) return;
    const alert = allAlerts.find(item => item.id === currentAlertId);
    if (!alert || !window.confirm(`Add ${alert.source_ip} to the managed denylist?`)) return;

    const btn = e.currentTarget;
    btn.disabled = true;
    try {
        await blockAlertSource(currentAlertId);
        showToast(`${alert.source_ip} added to the managed denylist`);
    } catch (error) {
        showToast(error.message || 'Failed to add IP to denylist', 'error');
    } finally {
        btn.disabled = false;
    }
});

// Init
document.addEventListener('DOMContentLoaded', loadAlerts);
