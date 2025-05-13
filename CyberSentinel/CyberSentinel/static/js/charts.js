/**
 * NebulaGuard IDS - Data Visualization
 * Handles chart creation and updates for the dashboard
 */

// Chart objects
let trafficPieChart = null;
let incidentTimelineChart = null;

// Color scheme for charts
const chartColors = {
    http: '#4CC9F0',
    https: '#4361EE',
    dns: '#3A0CA3',
    ssh: '#7209B7',
    ftp: '#F72585',
    smtp: '#B5179E',
    other: '#480CA8'
};

// Initialize charts
document.addEventListener('DOMContentLoaded', function() {
    // Set up Chart.js global defaults with sci-fi theme
    Chart.defaults.color = '#8490a8';
    Chart.defaults.font.family = "'Rajdhani', sans-serif";
    
    // Create initial charts
    createTrafficPieChart();
    createIncidentTimelineChart();
});

/**
 * Create the traffic distribution pie chart
 */
function createTrafficPieChart() {
    const ctx = document.getElementById('traffic-pie-chart').getContext('2d');
    
    trafficPieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0, 0],
                backgroundColor: Object.values(chartColors),
                borderColor: '#111824',
                borderWidth: 2,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 36, 0.9)',
                    titleFont: {
                        size: 14,
                        family: "'Orbitron', sans-serif"
                    },
                    bodyFont: {
                        size: 13
                    },
                    padding: 12,
                    borderColor: 'rgba(0, 240, 255, 0.3)',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.formattedValue;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((context.raw / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
    
    // Create custom legend
    createTrafficLegend();
}

/**
 * Create custom legend for traffic pie chart
 */
function createTrafficLegend() {
    const legendContainer = document.getElementById('traffic-legend');
    const protocols = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'Other'];
    
    protocols.forEach((protocol, index) => {
        const color = Object.values(chartColors)[index];
        const legendItem = document.createElement('div');
        legendItem.className = 'legend-item';
        legendItem.innerHTML = `
            <span class="legend-color" style="background-color: ${color}"></span>
            <span class="legend-text">${protocol}</span>
        `;
        legendContainer.appendChild(legendItem);
    });
}

/**
 * Create the incident timeline chart
 */
function createIncidentTimelineChart() {
    const ctx = document.getElementById('incidents-timeline-chart').getContext('2d');
    
    // Create gradient for line
    const gradient = ctx.createLinearGradient(0, 0, 0, 250);
    gradient.addColorStop(0, 'rgba(255, 48, 79, 0.7)');
    gradient.addColorStop(1, 'rgba(255, 48, 79, 0)');
    
    incidentTimelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: getTimeLabels(12),
            datasets: [{
                label: 'Incidents',
                data: Array(12).fill(0),
                borderColor: '#ff304f',
                backgroundColor: gradient,
                borderWidth: 2,
                tension: 0.4,
                fill: 'start',
                pointBackgroundColor: '#ff304f',
                pointBorderColor: '#0a0e17',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        color: 'rgba(26, 37, 57, 0.6)',
                        borderColor: 'rgba(26, 37, 57, 0.6)',
                        tickColor: 'rgba(26, 37, 57, 0.6)'
                    },
                    ticks: {
                        maxRotation: 0
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(26, 37, 57, 0.6)',
                        borderColor: 'rgba(26, 37, 57, 0.6)',
                        tickColor: 'rgba(26, 37, 57, 0.6)'
                    },
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 36, 0.9)',
                    titleFont: {
                        size: 14,
                        family: "'Orbitron', sans-serif"
                    },
                    bodyFont: {
                        size: 13
                    },
                    padding: 12,
                    borderColor: 'rgba(255, 48, 79, 0.3)',
                    borderWidth: 1
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

/**
 * Generate time labels for the incident timeline chart
 */
function getTimeLabels(count) {
    const now = new Date();
    const labels = [];
    
    for (let i = count - 1; i >= 0; i--) {
        const time = new Date(now.getTime() - (i * 5 * 60 * 1000)); // 5-minute intervals
        labels.push(time.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit',
            hour12: false 
        }));
    }
    
    return labels;
}

/**
 * Update traffic pie chart with new data
 */
function updateTrafficCharts(trafficData) {
    if (!trafficPieChart || !incidentTimelineChart) return;
    
    // Update pie chart data
    trafficPieChart.data.datasets[0].data = [
        trafficData.http || 0,
        trafficData.https || 0,
        trafficData.dns || 0,
        trafficData.ssh || 0,
        trafficData.ftp || 0,
        trafficData.smtp || 0,
        trafficData.other || 0
    ];
    
    trafficPieChart.update();
}

/**
 * Update incident timeline chart
 */
function updateIncidentTimeline(incidents) {
    if (!incidentTimelineChart) return;
    
    // Group incidents by time (last 12 five-minute intervals)
    const now = new Date();
    const timeSegments = Array(12).fill(0);
    
    incidents.forEach(incident => {
        const incidentTime = new Date(incident.timestamp);
        const minutesAgo = Math.floor((now - incidentTime) / (60 * 1000));
        
        if (minutesAgo < 60) { // Only consider last 60 minutes
            const segmentIndex = Math.floor(minutesAgo / 5);
            if (segmentIndex < 12) {
                timeSegments[11 - segmentIndex]++;
            }
        }
    });
    
    // Update chart data
    incidentTimelineChart.data.labels = getTimeLabels(12);
    incidentTimelineChart.data.datasets[0].data = timeSegments;
    incidentTimelineChart.update();
}
