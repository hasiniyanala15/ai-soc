/**
 * dashboard.js - Logic for the Main Dashboard (index.html)
 */

let chartInstance = null;
let networkChartInstance = null;
let networkLabels = [];
let networkData = [];

// Initialize Lucide icons
lucide.createIcons();

// Set current date
document.getElementById('current-date').textContent = new Date().toLocaleDateString('en-US', { 
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' 
});

// Toast Notification Helper
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    
    // Simple icon based on type
    const icon = type === 'success' ? '✅' : '❌';
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    
    container.appendChild(toast);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// -----------------------------------------
// Dashboard Functionality
// -----------------------------------------

async function checkConnection() {
    const dot = document.getElementById('backend-dot');
    const text = document.getElementById('backend-status-text');
    
    try {
        await checkBackendHealth();
        dot.className = 'status-dot online';
        text.textContent = 'Backend Online';
    } catch (e) {
        dot.className = 'status-dot offline';
        text.textContent = 'Backend Offline';
    }
}

async function loadDashboardData() {
    try {
        const response = await getAlerts();
        const alerts = response.alerts || [];
        
        // 1. Update Summary Cards
        document.getElementById('count-total-alerts').textContent = alerts.length;
        
        const highSeverity = alerts.filter(a => a.severity.toUpperCase() === 'HIGH').length;
        document.getElementById('count-high-alerts').textContent = highSeverity;
        
        // Count reports (assuming we can estimate investigations done by looking at how many alerts have reports, though our API doesn't list reports in the alert summary yet. We'll leave it as a placeholder or calculate it if possible. Let's just put a placeholder or wait for a specific endpoint)
        // For now, we display a placeholder number since our API doesn't return a total report count yet.
        document.getElementById('count-investigations').textContent = "0";
        
        // 2. Update Table (Show top 5)
        const tbody = document.getElementById('alerts-tbody');
        const emptyState = document.getElementById('alerts-empty-state');
        const table = document.getElementById('recent-alerts-table');
        
        tbody.innerHTML = '';
        
        if (alerts.length === 0) {
            emptyState.style.display = 'block';
            table.style.display = 'none';
        } else {
            emptyState.style.display = 'none';
            table.style.display = 'table';
            
            alerts.slice(0, 5).forEach(alert => {
                const tr = document.createElement('tr');
                
                // Format Date
                const date = new Date(alert.created_at).toLocaleString();
                
                // Badge Class
                const badgeClass = alert.severity.toLowerCase() === 'high' ? 'badge-high' : 
                                   alert.severity.toLowerCase() === 'medium' ? 'badge-medium' : 'badge-low';
                                   
                // Extract new JSON fields
                let desc = "No description";
                let recAction = "N/A";
                try {
                    const ev = typeof alert.evidence === 'string' ? JSON.parse(alert.evidence) : alert.evidence;
                    if (ev && ev.Description) desc = ev.Description;
                    if (ev && ev["Recommended Action"]) recAction = ev["Recommended Action"];
                } catch (e) {}

                tr.innerHTML = `
                    <td>#${alert.id}</td>
                    <td style="text-transform: capitalize;">${alert.alert_type.replace('_', ' ')}</td>
                    <td style="font-family: monospace;">${alert.source_ip}</td>
                    <td><span class="badge ${badgeClass}">${alert.severity}</span></td>
                    <td>${desc}</td>
                    <td>${recAction}</td>
                    <td class="text-muted">${date}</td>
                    <td>
                        <a href="alerts.html?id=${alert.id}" class="btn btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">View</a>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
        
        // 3. Update Chart
        updateChart(alerts);
        
    } catch (e) {
        showToast("Failed to load dashboard data", "error");
    }
}

function updateChart(alerts) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    
    let high = 0, medium = 0, low = 0;
    alerts.forEach(a => {
        const s = a.severity.toUpperCase();
        if (s === 'HIGH') high++;
        else if (s === 'MEDIUM') medium++;
        else low++;
    });
    
    // If empty data, show placeholder
    if (high === 0 && medium === 0 && low === 0) {
        high = 1; // Fake data just to show a gray ring
    }

    if (chartInstance) {
        chartInstance.destroy();
    }

    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: alerts.length === 0 ? [1] : [high, medium, low],
                backgroundColor: alerts.length === 0 ? ['#374151'] : ['#E11D48', '#F59E0B', '#3B82F6'],
                borderWidth: 0,
                cutout: '75%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#9CA3AF' } }
            }
        }
    });
}

function initNetworkChart() {
    const ctx = document.getElementById('networkChart');
    if (!ctx) return;
    
    networkChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: networkLabels,
            datasets: [{
                label: 'Flow Duration (ms)',
                data: networkData,
                borderColor: '#00F3FF',
                backgroundColor: 'rgba(0, 243, 255, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#00F3FF'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { display: false },
                y: { 
                    display: true, 
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#9CA3AF' }
                }
            }
        }
    });
}

function updateNetworkChart(flowDuration) {
    if (!networkChartInstance) return;
    
    const now = new Date();
    networkLabels.push(now.toLocaleTimeString());
    networkData.push(flowDuration);
    
    if (networkLabels.length > 15) {
        networkLabels.shift();
        networkData.shift();
    }
    
    networkChartInstance.update();
}

// -----------------------------------------
// Event Listeners
// -----------------------------------------

document.getElementById('btn-refresh').addEventListener('click', () => {
    checkConnection();
    loadDashboardData();
    showToast("Dashboard refreshed");
});



document.getElementById('btn-simulate-packet').addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn');
    const originalHtml = btn.innerHTML;
    btn.innerHTML = `<div class="spinner" style="border-top-color: var(--accent-primary);"></div> Sniffing...`;
    btn.disabled = true;
    
    try {
        const res = await sniffLivePacket();
        const packet = res.packet;
        
        // Hide empty state
        document.getElementById('network-empty-state').style.display = 'none';
        
        // Append row to table
        const tbody = document.getElementById('network-tbody');
        const tr = document.createElement('tr');
        tr.className = 'highlight-row';
        
        // Format confidence (e.g. 95.0%)
        const conf = res.confidence_score ? (res.confidence_score * 100).toFixed(1) + '%' : 'N/A';
        const color = res.predicted_class === 'Benign' ? 'var(--status-low)' : 'var(--status-high)';
        
        tr.innerHTML = `
            <td>${Math.round(packet['Flow Duration'])}ms</td>
            <td>${packet['Total Fwd Packets']}</td>
            <td>${packet['Total Backward Packets']}</td>
            <td>${packet['Destination Port']}</td>
            <td>TCP</td>
            <td style="color: ${color}; font-weight: bold;">${res.predicted_class}</td>
            <td>${conf}</td>
        `;
        
        // Prepend to top
        tbody.insertBefore(tr, tbody.firstChild);
        
        // Keep only top 5 rows
        if (tbody.children.length > 5) {
            tbody.removeChild(tbody.lastChild);
        }
        
        // Update Chart
        updateNetworkChart(packet['Flow Duration']);
        
        // Show raw summary in toast for fun
        if(res.raw_summary) {
            showToast(`Sniffed: ${res.raw_summary}`);
        }
        
        // Refresh alerts if a new one was created
        if(res.alert_created) {
            showToast(`New Alert Generated: ${res.predicted_class}!`, "error");
            loadDashboardData();
        }
        
    } catch (err) {
        showToast("Failed to sniff live packet. Ensure Npcap is installed and backend has permissions.", "error");
    } finally {
        btn.innerHTML = originalHtml;
        btn.disabled = false;
        lucide.createIcons();
    }
});

document.getElementById('btn-simulate-attack').addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn');
    const originalHtml = btn.innerHTML;
    btn.innerHTML = `<div class="spinner"></div> Injecting...`;
    btn.disabled = true;
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/ml/simulate`, {
            method: 'POST'
        });
        
        if (!response.ok) throw new Error('Simulation failed');
        
        const res = await response.json();
        const packet = res.packet;
        
        // Hide empty state
        document.getElementById('network-empty-state').style.display = 'none';
        
        // Append row to table
        const tbody = document.getElementById('network-tbody');
        const tr = document.createElement('tr');
        tr.className = 'highlight-row';
        
        const conf = res.confidence_score ? (res.confidence_score * 100).toFixed(1) + '%' : 'N/A';
        const color = 'var(--accent-critical)';
        
        tr.innerHTML = `
            <td>${Math.round(packet['Flow Duration'])}ms</td>
            <td>${packet['Total Fwd Packets']}</td>
            <td>${packet['Total Backward Packets']}</td>
            <td>${packet['Destination Port']}</td>
            <td>TCP</td>
            <td style="color: ${color}; font-weight: bold;">${res.predicted_class}</td>
            <td>${conf}</td>
        `;
        
        // Prepend to top
        tbody.insertBefore(tr, tbody.firstChild);
        
        // Keep only top 5 rows
        if (tbody.children.length > 5) {
            tbody.removeChild(tbody.lastChild);
        }
        
        // Update Chart
        updateNetworkChart(packet['Flow Duration']);
        
        if(res.raw_summary) {
            showToast(`Simulated: ${res.raw_summary}`);
        }
        
        if(res.alert_created) {
            showToast(`New Alert Generated: ${res.predicted_class}!`, "error");
            loadDashboardData();
        }
        
    } catch (err) {
        showToast("Failed to inject attack.", "error");
    } finally {
        btn.innerHTML = originalHtml;
        btn.disabled = false;
        lucide.createIcons();
    }
});

// Init
document.addEventListener('DOMContentLoaded', () => {
    checkConnection();
    loadDashboardData();
    initNetworkChart();
});
