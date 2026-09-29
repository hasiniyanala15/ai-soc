/**
 * api.js - Centralized Fetch Logic
 * Handles all communication with the Flask backend.
 */

async function fetchAPI(endpoint, options = {}) {
    const url = `${CONFIG.API_BASE_URL}${endpoint}`;
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    try {
        const response = await fetch(url, { ...options, headers });
        
        // Parse JSON even on errors, as our backend sends error JSON
        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(data.error || `HTTP error! status: ${response.status}`);
        }
        
        return data;
    } catch (error) {
        console.error(`[API Error] ${endpoint}:`, error.message);
        throw error;
    }
}

// -----------------------------------------
// Helper Functions mapped to Backend Endpoints
// -----------------------------------------

async function checkBackendHealth() {
    return await fetchAPI('/health');
}

async function getAlerts() {
    return await fetchAPI('/alerts');
}

async function getAlertById(alertId) {
    return await fetchAPI(`/alerts/${alertId}`);
}

async function generateLogs() {
    return await fetchAPI('/logs/generate', { method: 'POST' });
}

async function runDetection() {
    return await fetchAPI('/alerts/detect', { method: 'POST' });
}

async function simulateNetworkPacket(packetData) {
    return await fetchAPI('/ml/predict', { 
        method: 'POST',
        body: JSON.stringify(packetData)
    });
}

async function investigateAlert(alertId) {
    return await fetchAPI(`/alerts/${alertId}/investigate`, { method: 'POST' });
}

async function getInvestigationReport(alertId) {
    return await fetchAPI(`/alerts/${alertId}/report`);
}

async function submitFeedback(alertId, feedbackData) {
    return await fetchAPI(`/alerts/${alertId}/feedback`, {
        method: 'POST',
        body: JSON.stringify(feedbackData)
    });
}

async function getMemoryStatus() {
    return await fetchAPI('/memory/status');
}

async function sniffLivePacket() {
    return await fetchAPI('/ml/sniff');
}
