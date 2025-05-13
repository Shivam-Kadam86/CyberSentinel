/**
 * NebulaGuard IDS - Dashboard Management
 * Controls the dashboard UI, monitoring operations, and data display
 */

// Global variables
let monitoringActive = false;
let alertCount = 0;
let reportGenerated = false;
let dataRefreshInterval = null;
let lastReportPath = null;

// DOM Elements
const startBtn = document.getElementById('start-monitoring-btn');
const stopBtn = document.getElementById('stop-monitoring-btn');
const monitorStatus = document.getElementById('monitor-status-text');
const radarAnimation = document.getElementById('radar-animation');
const systemStatus = document.getElementById('system-status-indicator');
const footerStatus = document.getElementById('footer-status');
const lastScanTime = document.getElementById('last-scan-time');
const noAlertsMessage = document.getElementById('no-alerts-message');
const alertsList = document.getElementById('alerts-list');
const totalPacketsCounter = document.getElementById('total-packets-counter');
const totalIncidentsCounter = document.getElementById('total-incidents-counter');
const generateReportBtn = document.getElementById('generate-report-btn');
const downloadReportBtn = document.getElementById('download-report-btn');
const sendEmailBtn = document.getElementById('send-email-btn');
const emailRecipient = document.getElementById('email-recipient');
const emailSubject = document.getElementById('email-subject');
const operationStatus = document.getElementById('operation-status');
const clearAlertsBtn = document.getElementById('clear-alerts-btn');

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Set up event listeners
    startBtn.addEventListener('click', startMonitoring);
    stopBtn.addEventListener('click', stopMonitoring);
    generateReportBtn.addEventListener('click', generateReport);
    downloadReportBtn.addEventListener('click', downloadReport);
    sendEmailBtn.addEventListener('click', sendEmail);
    clearAlertsBtn.addEventListener('click', clearAlerts);
    
    // Initially fetch data to populate any existing stats
    fetchTrafficStats();
});

/**
 * Start network monitoring process
 */
function startMonitoring() {
    // Send request to start monitoring
    fetch('/api/monitor/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            monitoringActive = true;
            updateMonitoringUI(true);
            showStatusMessage(data.message, 'success');
            
            // Start periodic data refresh
            dataRefreshInterval = setInterval(fetchTrafficStats, 2000);
            
            // Update last scan time
            lastScanTime.textContent = getCurrentTimeString();
        } else {
            showStatusMessage(data.message, 'warning');
        }
    })
    .catch(error => {
        console.error('Error starting monitoring:', error);
        showStatusMessage('Failed to start monitoring: ' + error, 'error');
    });
}

/**
 * Stop network monitoring process
 */
function stopMonitoring() {
    // Send request to stop monitoring
    fetch('/api/monitor/stop', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            monitoringActive = false;
            updateMonitoringUI(false);
            showStatusMessage(data.message, 'success');
            
            // Stop periodic data refresh
            if (dataRefreshInterval) {
                clearInterval(dataRefreshInterval);
                dataRefreshInterval = null;
            }
        } else {
            showStatusMessage(data.message, 'warning');
        }
    })
    .catch(error => {
        console.error('Error stopping monitoring:', error);
        showStatusMessage('Failed to stop monitoring: ' + error, 'error');
    });
}

/**
 * Fetch current traffic statistics from the server
 */
function fetchTrafficStats() {
    fetch('/api/traffic/stats')
        .then(response => response.json())
        .then(data => {
            // Update traffic data charts
            updateTrafficCharts(data.traffic_data);
            
            // Update packet counter
            totalPacketsCounter.textContent = `${data.total_packets} packets`;
            
            // Check for and display new incidents
            if (data.incidents && data.incidents.length > 0) {
                updateIncidentTimeline(data.incidents);
                displayAlerts(data.incidents);
                totalIncidentsCounter.textContent = `${data.incidents.length} incidents`;
            }
            
            // Check if monitoring state has changed on the server
            if (monitoringActive !== data.monitoring) {
                monitoringActive = data.monitoring;
                updateMonitoringUI(monitoringActive);
            }
        })
        .catch(error => {
            console.error('Error fetching traffic stats:', error);
        });
}

/**
 * Display alerts in the alerts panel
 */
function displayAlerts(incidents) {
    if (!incidents || incidents.length === 0) {
        noAlertsMessage.style.display = 'flex';
        alertsList.innerHTML = '';
        return;
    }
    
    noAlertsMessage.style.display = 'none';
    
    // Check if we already displayed these alerts
    if (alertCount === incidents.length) {
        return;
    }
    
    // Display only new alerts since last check
    const newAlerts = incidents.slice(alertCount);
    alertCount = incidents.length;
    
    // Add new alerts to the list
    newAlerts.forEach(incident => {
        const alertItem = document.createElement('div');
        alertItem.className = `alert-item ${incident.severity}`;
        alertItem.setAttribute('data-bs-toggle', 'modal');
        alertItem.setAttribute('data-bs-target', '#alertModal');
        alertItem.setAttribute('data-incident', JSON.stringify(incident));
        
        // Get icon based on protocol
        let icon = 'fa-network-wired';
        switch(incident.protocol) {
            case 'http': icon = 'fa-globe'; break;
            case 'https': icon = 'fa-lock'; break;
            case 'dns': icon = 'fa-server'; break;
            case 'ssh': icon = 'fa-terminal'; break;
            case 'ftp': icon = 'fa-file-export'; break;
            case 'smtp': icon = 'fa-envelope'; break;
        }
        
        alertItem.innerHTML = `
            <div class="alert-icon">
                <i class="fas ${icon}"></i>
            </div>
            <div class="alert-content">
                <div class="alert-header">
                    <h4 class="alert-title">${getSuspiciousTitle(incident.reason)}</h4>
                    <span class="alert-time">${incident.timestamp}</span>
                </div>
                <p class="alert-details">
                    ${incident.source_ip} → ${incident.destination_ip} (${incident.protocol.toUpperCase()})
                </p>
                <span class="alert-severity">${incident.severity}</span>
            </div>
        `;
        
        // Prepend to show newest alerts first
        alertsList.insertBefore(alertItem, alertsList.firstChild);
        
        // Set up click handler to show details in modal
        alertItem.addEventListener('click', function() {
            const incidentData = JSON.parse(this.getAttribute('data-incident'));
            showAlertDetails(incidentData);
        });
    });
    
    // If there are new alerts, play notification sound and update system status
    if (newAlerts.length > 0) {
        playAlertSound(newAlerts[0].severity);
        updateSystemStatus('alert');
    }
}

/**
 * Show alert details in the modal
 */
function showAlertDetails(incident) {
    const modalBody = document.getElementById('alert-modal-body');
    const modalTitle = document.getElementById('alertModalLabel');
    
    modalTitle.textContent = getSuspiciousTitle(incident.reason);
    
    modalBody.innerHTML = `
        <div class="alert-details-container">
            <div class="detail-row">
                <span class="detail-label">Time:</span>
                <span class="detail-value">${incident.timestamp}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Source IP:</span>
                <span class="detail-value">${incident.source_ip}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Destination IP:</span>
                <span class="detail-value">${incident.destination_ip}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Protocol:</span>
                <span class="detail-value">${incident.protocol.toUpperCase()}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Severity:</span>
                <span class="detail-value severity-${incident.severity}">${incident.severity.toUpperCase()}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Description:</span>
                <span class="detail-value">${incident.reason}</span>
            </div>
            <div class="detail-row recommendation">
                <span class="detail-label">Recommendation:</span>
                <span class="detail-value">${getRecommendation(incident.reason, incident.severity)}</span>
            </div>
        </div>
    `;
}

/**
 * Generate a formatted title from the reason
 */
function getSuspiciousTitle(reason) {
    // Extract first sentence or limit to 50 chars
    const title = reason.split('.')[0] || reason;
    return title.length > 50 ? title.substring(0, 47) + '...' : title;
}

/**
 * Generate security recommendations based on the alert
 */
function getRecommendation(reason, severity) {
    if (reason.includes('port scan')) {
        return 'Block the source IP at your firewall. Monitor for continued scanning activity.';
    } else if (reason.includes('brute force')) {
        return 'Implement IP-based rate limiting. Consider changing credentials and enabling multi-factor authentication.';
    } else if (reason.includes('DoS') || reason.includes('DDoS')) {
        return 'Activate DoS protection measures. Contact your ISP for upstream traffic filtering.';
    } else if (reason.includes('malware') || reason.includes('exploit')) {
        return 'Isolate affected systems. Update antivirus and perform complete system scan.';
    } else if (severity === 'high') {
        return 'Investigate immediately. Consider isolating affected systems until issue is resolved.';
    } else if (severity === 'medium') {
        return 'Monitor the situation closely. Review security policies for this type of traffic.';
    } else {
        return 'Monitor for pattern changes. No immediate action required.';
    }
}

/**
 * Play notification sound based on severity
 */
function playAlertSound(severity) {
    // This would implement audio alerts with tone.js
    // Implementation excluded for simplicity
}

/**
 * Generate PDF report
 */
function generateReport() {
    generateReportBtn.disabled = true;
    generateReportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
    
    fetch('/api/report/generate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        generateReportBtn.disabled = false;
        generateReportBtn.innerHTML = '<i class="fas fa-file-pdf"></i> Generate Report';
        
        if (data.status === 'success') {
            reportGenerated = true;
            lastReportPath = data.report_path;
            downloadReportBtn.disabled = false;
            sendEmailBtn.disabled = false;
            showStatusMessage('Report generated successfully', 'success');
        } else {
            showStatusMessage(data.message, 'error');
        }
    })
    .catch(error => {
        generateReportBtn.disabled = false;
        generateReportBtn.innerHTML = '<i class="fas fa-file-pdf"></i> Generate Report';
        showStatusMessage('Failed to generate report: ' + error, 'error');
    });
}

/**
 * Download generated PDF report
 */
function downloadReport() {
    if (!reportGenerated) {
        showStatusMessage('No report available. Generate a report first.', 'error');
        return;
    }
    
    window.location.href = '/api/report/download';
}

/**
 * Send PDF report via email
 */
function sendEmail() {
    if (!reportGenerated) {
        showStatusMessage('No report available. Generate a report first.', 'error');
        return;
    }
    
    const recipient = emailRecipient.value.trim();
    if (!recipient) {
        showStatusMessage('Please enter a recipient email address', 'error');
        return;
    }
    
    sendEmailBtn.disabled = true;
    sendEmailBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
    
    fetch('/api/report/email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            recipient: recipient,
            subject: emailSubject.value,
            message: 'Please find attached the NebulaGuard IDS monitoring report.'
        })
    })
    .then(response => response.json())
    .then(data => {
        sendEmailBtn.disabled = false;
        sendEmailBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Send Report';
        
        if (data.status === 'success') {
            showStatusMessage(data.message, 'success');
        } else {
            showStatusMessage(data.message, 'error');
        }
    })
    .catch(error => {
        sendEmailBtn.disabled = false;
        sendEmailBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Send Report';
        showStatusMessage('Failed to send email: ' + error, 'error');
    });
}

/**
 * Clear alerts display
 */
function clearAlerts() {
    alertsList.innerHTML = '';
    noAlertsMessage.style.display = 'flex';
    alertCount = 0;
    totalIncidentsCounter.textContent = '0 incidents';
}

/**
 * Update monitoring UI based on active state
 */
function updateMonitoringUI(isActive) {
    if (isActive) {
        startBtn.disabled = true;
        stopBtn.disabled = false;
        monitorStatus.textContent = 'Active - Monitoring network traffic';
        radarAnimation.classList.add('active');
        updateSystemStatus('active');
        footerStatus.textContent = 'Monitoring Active';
    } else {
        startBtn.disabled = false;
        stopBtn.disabled = true;
        monitorStatus.textContent = 'Idle - Click Start to begin monitoring';
        radarAnimation.classList.remove('active');
        updateSystemStatus('inactive');
        footerStatus.textContent = 'System Ready';
    }
}

/**
 * Update system status indicator
 */
function updateSystemStatus(status) {
    const statusCircle = systemStatus.querySelector('.status-circle');
    const statusText = systemStatus.querySelector('.status-value');
    
    statusCircle.classList.remove('active', 'inactive', 'warning', 'danger');
    
    switch(status) {
        case 'active':
            statusCircle.classList.add('active');
            statusText.innerHTML = '<span class="status-circle active"></span> Active';
            break;
        case 'inactive':
            statusCircle.classList.add('inactive');
            statusText.innerHTML = '<span class="status-circle inactive"></span> Idle';
            break;
        case 'alert':
            statusCircle.classList.add('danger');
            statusText.innerHTML = '<span class="status-circle danger"></span> Alert';
            break;
        case 'warning':
            statusCircle.classList.add('warning');
            statusText.innerHTML = '<span class="status-circle warning"></span> Warning';
            break;
    }
}

/**
 * Display operation status message
 */
function showStatusMessage(message, type) {
    operationStatus.textContent = message;
    operationStatus.className = 'operation-status';
    operationStatus.classList.add(type === 'error' ? 'error' : 'success');
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        operationStatus.style.display = 'none';
    }, 5000);
}

/**
 * Get current time as formatted string
 */
function getCurrentTimeString() {
    const now = new Date();
    return now.toLocaleTimeString('en-US', { 
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}
