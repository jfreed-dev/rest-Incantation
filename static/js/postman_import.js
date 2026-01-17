/**
 * Postman Import Page JavaScript
 * Handles collection upload, preview, and import confirmation
 */

document.addEventListener('DOMContentLoaded', () => {
    const uploadZone = document.getElementById('uploadZone');
    const collectionInput = document.getElementById('collectionFile');
    const fileInfo = document.getElementById('fileInfo');
    const previewCard = document.getElementById('previewCard');
    const successAlert = document.getElementById('successAlert');

    // Drag & Drop
    ['dragenter', 'dragover'].forEach(e => {
        uploadZone.addEventListener(e, (event) => {
            event.preventDefault();
            uploadZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(e => {
        uploadZone.addEventListener(e, () => {
            uploadZone.classList.remove('dragover');
        });
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    collectionInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    // Environment file name display
    document.getElementById('environmentFile').addEventListener('change', (e) => {
        const envFileNameSpan = document.getElementById('envFileName');
        if (e.target.files.length) {
            envFileNameSpan.textContent = e.target.files[0].name;
            envFileNameSpan.classList.remove('text-muted');
            envFileNameSpan.classList.add('fw-semibold');
        } else {
            envFileNameSpan.textContent = 'No file chosen';
            envFileNameSpan.classList.add('text-muted');
            envFileNameSpan.classList.remove('fw-semibold');
        }
    });

    // Reset upload form
    window.resetUpload = function() {
        collectionInput.value = '';
        fileInfo.style.display = 'none';
        uploadZone.style.display = 'block';
    };

    // Handle file preview
    function handleFile(file) {
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = formatSize(file.size);
        uploadZone.style.display = 'none';
        fileInfo.style.display = 'block';
    }

    // Format file size
    function formatSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }

    // Upload Collection
    document.getElementById('collectionUploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('uploadBtn');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';

        const formData = new FormData();
        formData.append('collection_file', collectionInput.files[0]);

        try {
            const response = await fetch('/import/postman/upload', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();

            if (result.success) {
                renderPreview(result.summary, result.preview);
                previewCard.style.display = 'block';
                previewCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                alert('Error: ' + (result.error || 'Unknown error'));
            }
        } catch (err) {
            alert('Upload failed: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    });

    // Upload Environment
    document.getElementById('environmentUploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('uploadEnvBtn');
        const input = document.getElementById('environmentFile');
        
        if (!input.files[0]) {
            return;
        }

        btn.disabled = true;
        const formData = new FormData();
        formData.append('environment_file', input.files[0]);

        try {
            const response = await fetch('/import/postman/environment', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            
            if (result.success) {
                document.getElementById('envCount').textContent = result.imported_count;
                document.getElementById('envSuccess').style.display = 'flex';
            }
        } catch (err) {
            console.error('Environment upload error:', err);
        } finally {
            btn.disabled = false;
        }
    });

    // Confirm Import
    document.getElementById('confirmImportBtn').addEventListener('click', async function() {
        this.disabled = true;
        this.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Importing...';

        try {
            const response = await fetch('/import/postman/confirm', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    import_requests: document.getElementById('importRequests').checked,
                    import_variables: document.getElementById('importVariables').checked,
                    import_auth: document.getElementById('importAuth').checked
                })
            });
            const result = await response.json();

            if (result.success) {
                previewCard.style.display = 'none';
                successAlert.style.display = 'block';
                successAlert.scrollIntoView({ behavior: 'smooth' });
            } else {
                alert('Error: ' + (result.error || 'Unknown error'));
                this.disabled = false;
                this.innerHTML = 'Confirm and Import Collection';
            }
        } catch (err) {
            alert('Import error: ' + err.message);
            this.disabled = false;
            this.innerHTML = 'Confirm and Import Collection';
        }
    });

    // Render collection preview
    function renderPreview(summary, preview) {
        document.getElementById('collectionName').textContent = summary.name;
        document.getElementById('collectionDescription').textContent = summary.description || 'No description provided';
        document.getElementById('requestCount').textContent = summary.total_requests;
        document.getElementById('folderCount').textContent = summary.total_folders;
        document.getElementById('variableCount').textContent = summary.total_variables;
        document.getElementById('authTypeCount').textContent = Object.keys(summary.auth_types || {}).length;
    }
});
