/**
 * memory.js - Logic for the Incident Memory Page
 */

lucide.createIcons();

async function loadMemoryStatus() {
    try {
        const response = await getMemoryStatus();
        
        const statusEl = document.getElementById('val-memory-status');
        const urlEl = document.getElementById('val-memory-url');
        
        if (response.status === 'Configured') {
            statusEl.textContent = 'Hindsight Memory: Active';
            statusEl.style.color = 'var(--status-low)';
            urlEl.textContent = `Connected to: ${response.hindsight_server_url}`;
        } else {
            statusEl.textContent = 'Hindsight Memory: Offline';
            statusEl.style.color = 'var(--status-medium)';
            urlEl.textContent = response.message || "Memory disabled due to missing configuration.";
        }
    } catch (e) {
        document.getElementById('val-memory-status').textContent = 'Backend Offline';
        document.getElementById('val-memory-status').style.color = 'var(--status-high)';
        document.getElementById('val-memory-url').textContent = 'Could not reach Flask backend API.';
    }
}

async function loadRecentActivity() {
    try {
        const response = await getAlerts();
        const alerts = response.alerts || [];
        
        const tbody = document.getElementById('memory-tbody');
        tbody.innerHTML = '';
        
        // Show top 10 recent alerts as context
        alerts.slice(0, 10).forEach(alert => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>#${alert.id}</td>
                <td style="font-family: monospace;">${alert.source_ip}</td>
                <td style="text-transform: capitalize;">${alert.alert_type.replace('_', ' ')}</td>
                <td class="text-muted">${new Date(alert.created_at).toLocaleString()}</td>
            `;
            tbody.appendChild(tr);
        });
        
        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 2rem;" class="text-muted">No memory records found.</td></tr>`;
        }
        
    } catch (e) {
        console.error("Failed to load alerts for memory view");
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadMemoryStatus();
    loadRecentActivity();
});
