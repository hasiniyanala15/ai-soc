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
});

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
