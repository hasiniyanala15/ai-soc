/**
 * investigations.js - Logic for the AI Investigations Page
 */

let currentAlertId = null;
lucide.createIcons();

function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<span>${type === 'success' ? '✅' : '❌'}</span> <span>${message}</span>`;
    
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

// UI State Management
function showView(viewId) {
    document.getElementById('empty-view').style.display = 'none';
    document.getElementById('loading-view').style.display = 'none';
    document.getElementById('error-view').style.display = 'none';
    document.getElementById('report-container').style.display = 'none';
    
    const target = document.getElementById(viewId);
    if (target) {
        target.style.display = viewId === 'report-container' ? 'block' : 'flex';
    }
}

async function loadReport(alertId) {
    if (!alertId) return;
    currentAlertId = alertId;
    
    document.getElementById('search-id').value = alertId;
    showView('loading-view');
    
    try {
        let response;
        try {
            // Check if a report already exists
            response = await getInvestigationReport(alertId);
        } catch (e) {
            // If report doesn't exist, try to trigger the investigation
            if (e.message.toLowerCase().includes('not found') || e.message.includes('404')) {
                response = await investigateAlert(alertId);
                // backend returns { message: "...", report: {...} }
            } else {
                throw e; 
            }
        }
        
        if (!response || !response.report) {
            throw new Error("Invalid response format from backend.");
        }
        
        populateReportUI(response.report, alertId);
        showView('report-container');
        
    } catch (e) {
        console.error(e);
        document.getElementById('error-message').textContent = e.message || "Failed to load investigation.";
        showView('error-view');
    }
}

function populateReportUI(report, alertId) {
    // Basic Info
    document.getElementById('val-report-id').textContent = alertId;
    document.getElementById('val-alert-summary').textContent = report.alert_summary || report.summary || "No summary available.";
    
    // Confidence Badge
    const confBadge = document.getElementById('badge-confidence');
    const confidence = (report.confidence_level || report.confidence || "Unknown").toLowerCase();
    confBadge.textContent = `Confidence: ${confidence.charAt(0).toUpperCase() + confidence.slice(1)}`;
    
    if (confidence.includes('high')) {
        confBadge.className = 'badge badge-high';
    } else if (confidence.includes('medium')) {
        confBadge.className = 'badge badge-medium';
    } else {
        confBadge.className = 'badge badge-low';
    }
    
    // Technical Data
    document.getElementById('val-attack-type').textContent = report.attack_type || "Unknown";
    document.getElementById('val-explanation').textContent = report.possible_explanation || "No explanation provided.";
    
    // Evidence (might be string or object depending on backend endpoint)
    let evidenceText = report.evidence || "No evidence recorded.";
    if (typeof evidenceText === 'object') evidenceText = JSON.stringify(evidenceText, null, 2);
    document.getElementById('val-evidence').textContent = evidenceText;
    
    document.getElementById('val-memory').textContent = report.related_previous_incidents || "None available.";
    
    // Steps
    const stepsList = document.getElementById('val-steps');
    stepsList.innerHTML = '';
    
    let steps = report.recommended_investigation_steps || report.recommended_action || [];
    if (typeof steps === 'string') {
        try { steps = JSON.parse(steps); } catch(e) { steps = [steps]; }
    }
    
    if (Array.isArray(steps)) {
        steps.forEach(step => {
            const li = document.createElement('li');
            li.textContent = step;
            stepsList.appendChild(li);
        });
    } else if (steps) {
        const li = document.createElement('li');
        li.textContent = steps;
        stepsList.appendChild(li);
    }
    
    document.getElementById('val-response').textContent = report.recommended_response || "Manual review required.";
    
    const limitations = report.limitations_and_missing_information;
    if (limitations) {
        document.getElementById('val-limitations').textContent = limitations;
        document.getElementById('section-limitations').style.display = 'block';
    } else {
        document.getElementById('section-limitations').style.display = 'none';
    }
    
    // Reset feedback UI
    document.getElementById('feedback-controls').style.display = 'flex';
    document.getElementById('feedback-success').style.display = 'none';
}

async function submitAnalystFeedback(notes, wasHelpful) {
    if (!currentAlertId) return;
    
    const controls = document.getElementById('feedback-controls');
    const successMsg = document.getElementById('feedback-success');
    
    controls.style.opacity = '0.5';
    controls.style.pointerEvents = 'none';
    
    try {
        await submitFeedback(currentAlertId, { analyst_notes: notes, was_helpful: wasHelpful });
        
        controls.style.display = 'none';
        successMsg.style.display = 'block';
        lucide.createIcons();
        
    } catch (e) {
        showToast("Failed to submit feedback", "error");
        controls.style.opacity = '1';
        controls.style.pointerEvents = 'auto';
    }
}

// -----------------------------------------
// Event Listeners
// -----------------------------------------

document.getElementById('btn-load-report').addEventListener('click', () => {
    const id = document.getElementById('search-id').value;
    if (id) {
        loadReport(id);
        const newUrl = new URL(window.location);
        newUrl.searchParams.set('id', id);
        window.history.pushState({}, '', newUrl);
    }
});

document.getElementById('btn-retry').addEventListener('click', () => {
    loadReport(currentAlertId);
});

// Init: Check if URL has an ID parameter
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    
    if (id) {
        loadReport(id);
    } else {
        showView('empty-view');
    }
});
