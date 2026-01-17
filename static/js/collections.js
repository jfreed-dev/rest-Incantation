/**
 * Collections Page JavaScript
 * Handles collection display, request execution, and response modal
 */

let currentResponse = null;

/**
 * Toggle collection expand/collapse
 */
function toggleCollection(collectionId) {
    const content = document.getElementById(collectionId);
    const icon = document.getElementById('icon-' + collectionId);
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
        icon.style.transform = 'rotate(180deg)';
    } else {
        content.style.display = 'none';
        icon.style.transform = 'rotate(0deg)';
    }
}

/**
 * Execute a request from the collection
 */
async function executeRequest(collectionName, requestName) {
    // Show modal with loading state
    const modal = document.getElementById('responseModal');
    const loading = document.getElementById('responseLoading');
    const error = document.getElementById('responseError');
    const success = document.getElementById('responseSuccess');
    
    document.getElementById('modalRequestName').textContent = requestName;
    modal.classList.remove('hidden');
    loading.classList.remove('hidden');
    error.classList.add('hidden');
    success.classList.add('hidden');
    
    try {
        // Send request to backend
        const response = await fetch('/api/execute-request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                collection_name: collectionName,
                request_name: requestName
            })
        });
        
        const result = await response.json();
        currentResponse = result;
        
        // Hide loading
        loading.classList.add('hidden');
        
        if (result.success) {
            // Show success state
            success.classList.remove('hidden');
            
            // Populate status
            const statusCode = document.getElementById('statusCode');
            statusCode.textContent = result.status_code;
            statusCode.className = 'text-2xl font-bold ' + getStatusColor(result.status_code);
            document.getElementById('statusText').textContent = result.status_text;
            
            // Populate metrics
            document.getElementById('responseTime').textContent = result.time_ms + ' ms';
            document.getElementById('responseSize').textContent = formatBytes(result.size_bytes);
            
            // Populate URL
            document.getElementById('resolvedUrl').textContent = result.resolved_url;
            
            // Populate body
            const bodyElement = document.getElementById('responseBody');
            if (typeof result.body === 'object') {
                bodyElement.textContent = JSON.stringify(result.body, null, 2);
            } else {
                bodyElement.textContent = result.body || '(empty)';
            }
            
            // Populate headers
            const headersContainer = document.getElementById('responseHeaders');
            const headers = result.headers || {};
            const headerKeys = Object.keys(headers);
            document.getElementById('headerCount').textContent = headerKeys.length;
            
            headersContainer.innerHTML = '';
            headerKeys.forEach(key => {
                const div = document.createElement('div');
                div.className = 'flex items-start py-2 px-3 bg-gray-50 rounded';
                div.innerHTML = `
                    <span class="font-mono text-sm font-semibold text-gray-700 mr-3">${escapeHtml(key)}:</span>
                    <span class="font-mono text-sm text-gray-600 flex-1 break-all">${escapeHtml(headers[key])}</span>
                `;
                headersContainer.appendChild(div);
            });
            
        } else {
            // Show error state
            error.classList.remove('hidden');
            document.getElementById('errorMessage').textContent = result.error || 'Unknown error';
            document.getElementById('errorType').textContent = result.error_type ? `Type: ${result.error_type}` : '';
        }
        
    } catch (err) {
        loading.classList.add('hidden');
        error.classList.remove('hidden');
        document.getElementById('errorMessage').textContent = 'Failed to execute request: ' + err.message;
        document.getElementById('errorType').textContent = 'Type: network';
    }
}

/**
 * Close the response modal
 */
function closeResponseModal(event) {
    // If clicked outside modal content, close
    if (!event || event.target.id === 'responseModal') {
        document.getElementById('responseModal').classList.add('hidden');
    }
}

/**
 * Switch between Body and Headers tabs
 */
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active', 'border-primary-600', 'text-primary-600');
        btn.classList.add('border-transparent', 'text-gray-500');
    });
    
    const activeTab = document.getElementById('tab-' + tabName);
    activeTab.classList.add('active', 'border-primary-600', 'text-primary-600');
    activeTab.classList.remove('border-transparent', 'text-gray-500');
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });
    document.getElementById('content-' + tabName).classList.remove('hidden');
}

/**
 * Copy response to clipboard
 */
function copyResponse() {
    if (!currentResponse || !currentResponse.body) {
        return;
    }
    
    const text = typeof currentResponse.body === 'object' 
        ? JSON.stringify(currentResponse.body, null, 2)
        : currentResponse.body;
    
    navigator.clipboard.writeText(text).then(() => {
        // Show temporary success message
        const btn = event.target.closest('button');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>Copied!';
        setTimeout(() => {
            btn.innerHTML = originalText;
        }, 2000);
    });
}

/**
 * Get color class based on HTTP status code
 */
function getStatusColor(statusCode) {
    if (statusCode >= 200 && statusCode < 300) return 'text-green-600';
    if (statusCode >= 300 && statusCode < 400) return 'text-blue-600';
    if (statusCode >= 400 && statusCode < 500) return 'text-orange-600';
    if (statusCode >= 500) return 'text-red-600';
    return 'text-gray-600';
}

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeResponseModal();
    }
});
