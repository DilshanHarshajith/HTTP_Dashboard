document.addEventListener('DOMContentLoaded', function() {
    // Records buttons
    document.getElementById('send-records-btn')?.addEventListener('click', function() {
        sendRecords('records');
    });
    document.getElementById('clear-records-btn')?.addEventListener('click', function() {
        clearRecords('records');
    });
    document.getElementById('download-records-btn')?.addEventListener('click', function() {
        downloadRecords('records');
    });

    // Common buttons
    document.getElementById('send-other-btn')?.addEventListener('click', function() {
        sendRecords('other');
    });
    document.getElementById('clear-other-btn')?.addEventListener('click', function() {
        clearRecords('other');
    });
    document.getElementById('download-other-btn')?.addEventListener('click', function() {
        downloadRecords('other');
    });

    // File delete buttons
    document.querySelectorAll('.delete-file-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            const filename = btn.getAttribute('data-filename');
            deleteFile(filename);
        });
    });
});

// Functions (copied from your inline JS)
function showAlert(message, type) {
    const alertContainer = document.getElementById('alertContainer');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    alert.style.display = 'block';
    alertContainer.appendChild(alert);
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

function sendRecords(dbType) {
    if (confirm(`Send all ${dbType} records to Telegram?`)) {
        fetch(`/admin/api/send-${dbType}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showAlert(data.message, 'success');
            } else {
                showAlert(data.error || `Failed to send ${dbType} records`, 'danger');
            }
        })
        .catch(error => {
            showAlert('Network error: ' + error.message, 'danger');
        });
    }
}

function clearRecords(dbType) {
    if (confirm(`Are you sure you want to clear all ${dbType} records?`)) {
        fetch(`/admin/api/clear-${dbType}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showAlert(data.message, 'success');
                setTimeout(() => {
                    location.reload();
                }, 1500);
            } else {
                showAlert(data.error || `Failed to clear ${dbType} records`, 'danger');
            }
        })
        .catch(error => {
            showAlert('Network error: ' + error.message, 'danger');
        });
    }
}

function downloadRecords(dbType) {
    window.location.href = `/admin/api/download-${dbType}`;
}

function deleteFile(filename) {
    if (confirm('Are you sure you want to delete this file?')) {
        fetch(`/admin/api/delete-file/${filename}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showAlert(data.message, 'success');
                setTimeout(() => {
                    location.reload();
                }, 1500);
            } else {
                showAlert(data.error || 'Failed to delete file', 'danger');
            }
        })
        .catch(error => {
            showAlert('Network error: ' + error.message, 'danger');
        });
    }
}