/**
 * dashboard.js - Logic for the Main Dashboard (index.html)
 */

let chartInstance = null;
let networkChartInstance = null;

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

// Initialize with 15 empty points for smooth scrolling
let networkLabels = Array(15).fill('');
let networkData = Array(15).fill(0);
let currentThroughput = 0;

function initNetworkChart() {
    const ctx = document.getElementById('networkChart');
    if (!ctx) return;
    
    networkChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: networkLabels,
            datasets: [{
                label: 'Throughput (Bytes/s)',
                data: networkData,
                borderColor: '#00F3FF',
                backgroundColor: 'rgba(0, 243, 255, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0 // Hide points for a smoother look
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 0 // Disable animation for live scrolling
            },
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { display: false },
                y: { 
                    display: true, 
                    beginAtZero: true,
                    suggestedMax: 1000,
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#9CA3AF' }
                }
            }
        }
    });

    // Auto-scrolling interval
    setInterval(() => {
        const now = new Date();
        networkLabels.push(now.toLocaleTimeString());
        
        networkData.push(currentThroughput);
        
        if (networkLabels.length > 15) {
            networkLabels.shift();
            networkData.shift();
        }
        
        networkChartInstance.update();
    }, 1000);
}

function updateNetworkChart(bytesPerSec) {
    if (!networkChartInstance) return;
    // Set the spike
    currentThroughput = bytesPerSec;
}

// -----------------------------------------
// Event Listeners
// -----------------------------------------

document.getElementById('btn-refresh').addEventListener('click', () => {
    checkConnection();
    loadDashboardData();
    showToast("Dashboard refreshed");
});

// Continuous Background Sniffing Loop
let isSniffing = false;
async function continuousSniffer() {
    if (isSniffing) return;
    isSniffing = true;
    
    try {
        const res = await sniffLivePacket();
        if (res && res.predictions) {
            // Only update table if we actually found packets (not empty)
            if (res.predictions.length > 0) {
                let newAlerts = 0;
                res.predictions.forEach(prediction => {
                    // Only add to table if it's an actual alert (not benign) to avoid spamming the UI
                    if (prediction.alert_created && prediction.predicted_class !== 'Benign') {
                        const packet = prediction.packet;
                        const tbody = document.getElementById('network-tbody');
                        const tr = document.createElement('tr');
                        tr.className = 'highlight-row';
                        
                        const conf = prediction.confidence_score ? (prediction.confidence_score * 100).toFixed(1) + '%' : 'N/A';
                        const color = prediction.predicted_class === 'Benign' ? 'var(--status-low)' : 'var(--status-high)';
                        const protoStr = packet['Protocol'] === 6 ? 'TCP' : (packet['Protocol'] === 17 ? 'UDP' : packet['Protocol']);
                        
                        tr.innerHTML = `
                            <td>${Math.round(packet['Flow Duration'])}µs</td>
                            <td>${packet['Total Fwd Packets']}</td>
                            <td>${packet['Total Backward Packets']}</td>
                            <td>${packet['Destination Port']}</td>
                            <td>${protoStr}</td>
                            <td style="color: ${color}; font-weight: bold;">${prediction.predicted_class}</td>
                            <td>${conf}</td>
                        `;
                        
                        tbody.insertBefore(tr, tbody.firstChild);
                        if (tbody.children.length > 10) tbody.removeChild(tbody.lastChild);
                        newAlerts++;
                    }
                });
                
                if (newAlerts > 0) {
                    showToast(`${newAlerts} New Alert(s) Detected in Background!`, "error");
                    loadDashboardData();
                    document.getElementById('network-empty-state').style.display = 'none';
                }
            }
            
            // Sustain the throughput level for the chart until the next poll
            if (res.total_throughput !== undefined) {
                currentThroughput = res.total_throughput;
            }
        }
    } catch (err) {
        console.error("Background sniff failed", err);
    } finally {
        isSniffing = false;
        // Schedule the next sniff immediately after this one finishes
        setTimeout(continuousSniffer, 1000);
    }
}


document.getElementById('btn-simulate-packet').addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn');
    const originalHtml = btn.innerHTML;
    btn.innerHTML = `<div class="spinner" style="border-top-color: var(--accent-primary);"></div> Sniffing...`;
    btn.disabled = true;
    
    try {
        const res = await sniffLivePacket();
        const predictions = res.predictions || [];
        
        // Hide empty state
        document.getElementById('network-empty-state').style.display = 'none';
        
        let newAlerts = 0;
        
        predictions.forEach(prediction => {
            const packet = prediction.packet;
            
            // Append row to table
            const tbody = document.getElementById('network-tbody');
            const tr = document.createElement('tr');
            tr.className = 'highlight-row';
            
            // Format confidence (e.g. 95.0%)
            const conf = prediction.confidence_score ? (prediction.confidence_score * 100).toFixed(1) + '%' : 'N/A';
            const color = prediction.predicted_class === 'Benign' ? 'var(--status-low)' : 'var(--status-high)';
            
            // Format Protocol
            const protoStr = packet['Protocol'] === 6 ? 'TCP' : (packet['Protocol'] === 17 ? 'UDP' : packet['Protocol']);
            
            tr.innerHTML = `
                <td>${Math.round(packet['Flow Duration'])}µs</td>
                <td>${packet['Total Fwd Packets']}</td>
                <td>${packet['Total Backward Packets']}</td>
                <td>${packet['Destination Port']}</td>
                <td>${protoStr}</td>
                <td style="color: ${color}; font-weight: bold;">${prediction.predicted_class}</td>
                <td>${conf}</td>
            `;
            
            // Prepend to top
            tbody.insertBefore(tr, tbody.firstChild);
            
            // Keep only top 10 rows
            if (tbody.children.length > 10) {
                tbody.removeChild(tbody.lastChild);
            }
            
            if (prediction.alert_created) newAlerts++;
        });
        
        // Update Chart with total throughput of all flows
        if (res.total_throughput !== undefined) {
            updateNetworkChart(res.total_throughput);
        }
        
        // Show raw summary in toast for fun
        if(res.raw_summary) {
            showToast(`Sniffed: ${res.raw_summary}`);
        }
        
        // Refresh alerts if a new one was created
        if(newAlerts > 0) {
            showToast(`${newAlerts} New Alert(s) Generated!`, "error");
            loadDashboardData();
        }
        
    } catch (err) {
        showToast(`Live capture failed: ${err.message}`, "error");
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
        
        const protoStr = packet['Protocol'] === 6 ? 'TCP' : (packet['Protocol'] === 17 ? 'UDP' : packet['Protocol']);
        
        tr.innerHTML = `
            <td>${Math.round(packet['Flow Duration'])}µs</td>
            <td>${packet['Total Fwd Packets']}</td>
            <td>${packet['Total Backward Packets']}</td>
            <td>${packet['Destination Port']}</td>
            <td>${protoStr}</td>
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
        updateNetworkChart(packet['Flow Bytes/s']);
        
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
    
    // Start continuous sniffing
    continuousSniffer();
});
