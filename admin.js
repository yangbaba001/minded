// admin.js - Real Data Dashboard (No Mock Data)

let visitorData = [];
let clickData = [];
let countryStats = {};

// Initialize on load
document.addEventListener('DOMContentLoaded', function() {
    loadData();
    startAutoRefresh();
});

// ===== GENERATE LINK =====
async function createLink() {
    const landingPage = document.getElementById("landingPage").value;

    try {
        const res = await fetch("/admin/create-link", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ landingPage })
        });

        const data = await res.json();
        const resultDiv = document.getElementById("result");

        if (data.url) {
            // Store URL in a data attribute to avoid escaping issues
            resultDiv.innerHTML = `
                <strong>✅ Generated Link:</strong><br>
                <a href="${data.url}" target="_blank">${data.url}</a>
                <button id="copyBtn" data-url="${data.url}" style="margin-top: 10px; padding: 0.5rem 1rem; border-radius: 20px; border: none; background: #0078d7; color: white; cursor: pointer;">
                    📋 Copy Link
                </button>
            `;
            resultDiv.classList.add('show');
            
            // Add click event listener
            document.getElementById('copyBtn').addEventListener('click', function() {
                copyToClipboard(this.getAttribute('data-url'));
            });
        } else {
            resultDiv.innerHTML = "❌ Error generating link.";
            resultDiv.classList.add('show');
        }
    } catch (error) {
        console.error('Error creating link:', error);
        document.getElementById("result").innerHTML = "❌ Error generating link.";
        document.getElementById("result").classList.add('show');
    }
}

// ===== COPY TO CLIPBOARD =====
function copyToClipboard(text) {
    // Modern clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showCopySuccess();
        }).catch(err => {
            console.error('Clipboard API failed:', err);
            fallbackCopyToClipboard(text);
        });
    } else {
        // Fallback for older browsers
        fallbackCopyToClipboard(text);
    }
}

// Fallback copy method
function fallbackCopyToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.top = "-9999px";
    textArea.style.left = "-9999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showCopySuccess();
        } else {
            alert('❌ Failed to copy. Please copy manually.');
        }
    } catch (err) {
        console.error('Fallback copy failed:', err);
        alert('❌ Failed to copy. Please copy manually.');
    }
    
    document.body.removeChild(textArea);
}

// Show success message
function showCopySuccess() {
    const btn = document.getElementById('copyBtn');
    if (btn) {
        const originalText = btn.innerHTML;
        btn.innerHTML = '✅ Copied!';
        btn.style.background = '#28a745';
        
        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.style.background = '#0078d7';
        }, 2000);
    } else {
        alert('✅ Link copied to clipboard!');
    }
}

// ===== LOAD REAL DATA FROM SERVER =====
async function loadData() {
    try {
        const response = await fetch('/__get-antibot-data');
        
        if (response.ok) {
            const data = await response.json();
            visitorData = data.visitors || [];
            clickData = data.clicks || [];
            
            console.log(`✅ Loaded ${visitorData.length} visitors and ${clickData.length} clicks`);
            
            updateDashboard();
        } else {
            console.error('Failed to load data from server');
            showNoDataMessage();
        }
    } catch (error) {
        console.error('Error loading data:', error);
        showNoDataMessage();
    }
}

// ===== SHOW NO DATA MESSAGE =====
function showNoDataMessage() {
    document.getElementById('activityLog').innerHTML = '<p class="no-data">Waiting for first visitor...</p>';
    document.getElementById('recordsBody').innerHTML = '<tr><td colspan="9" class="no-data">No visitors yet. Share your generated links!</td></tr>';
    document.getElementById('countryChart').innerHTML = '<p class="no-data">No data available yet</p>';
}

// ===== UPDATE ENTIRE DASHBOARD =====
function updateDashboard() {
    updateStats();
    updateActivityLog();
    updateRecordsTable();
    updateCountryChart();
    updateLastUpdate();
}

// ===== UPDATE STATS CARDS =====
function updateStats() {
    const realUsers = visitorData.filter(v => v.status === 'ALLOWED').length;
    const botsBlocked = visitorData.filter(v => v.isBot && v.status === 'BLOCKED').length;
    
    // FIX: Count BOTH VPNs AND Data Centers as "VPN/Proxies Blocked"
    const vpnBlocked = visitorData.filter(v => 
        v.status === 'BLOCKED' && (v.isVPN || v.isDataCenter)
    ).length;
    
    const totalClicks = visitorData.length;

    document.getElementById('realUsers').textContent = realUsers;
    document.getElementById('botsBlocked').textContent = botsBlocked;
    document.getElementById('vpnBlocked').textContent = vpnBlocked;
    document.getElementById('totalClicks').textContent = totalClicks;
}

// ===== UPDATE ACTIVITY LOG =====
function updateActivityLog(filter = 'all') {
    const activityLog = document.getElementById('activityLog');
    let filteredData = visitorData;

    if (filter === 'allowed') {
        filteredData = visitorData.filter(v => v.status === 'ALLOWED');
    } else if (filter === 'blocked') {
        filteredData = visitorData.filter(v => v.status === 'BLOCKED');
    }

    if (filteredData.length === 0) {
        activityLog.innerHTML = '<p class="no-data">No activity for this filter</p>';
        return;
    }

    const recentActivities = filteredData.slice(0, 10);
    activityLog.innerHTML = recentActivities.map(visitor => {
        const time = new Date(visitor.timestamp).toLocaleString();
        const statusClass = visitor.status === 'ALLOWED' ? 'allowed' : 'blocked';
        
        return `
            <div class="activity-item ${statusClass}">
                <div class="activity-time">${time}</div>
                <span class="activity-status ${statusClass}">${visitor.status}</span>
                <div class="activity-details">
                    <strong>${visitor.country || 'Unknown'}</strong> - ${visitor.city || 'Unknown'} | ${visitor.ipType || 'Unknown'}
                    <br><small>${visitor.reason || 'No reason provided'}</small>
                </div>
            </div>
        `;
    }).join('');
}

// ===== FILTER ACTIVITY =====
function filterActivity(filter) {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.filter === filter) {
            btn.classList.add('active');
        }
    });
    
    updateActivityLog(filter);
}

// ===== UPDATE RECORDS TABLE =====
function updateRecordsTable() {
    const tbody = document.getElementById('recordsBody');
    
    if (visitorData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="no-data">No visitors yet. Share your links!</td></tr>';
        return;
    }

    tbody.innerHTML = visitorData.map(visitor => {
        const time = new Date(visitor.timestamp).toLocaleString();
        const statusClass = visitor.status === 'ALLOWED' ? 'allowed' : 'blocked';
        
        return `
            <tr>
                <td>${time}</td>
                <td><span class="status-badge ${statusClass}">${visitor.status}</span></td>
                <td>${visitor.ip || 'Unknown'}</td>
                <td>${visitor.countryName || visitor.country || 'Unknown'}</td>
                <td>${visitor.city || 'N/A'}</td>
                <td>${visitor.isp || visitor.org || 'Unknown'}</td>
                <td>${visitor.ipType || 'Unknown'}</td>
                <td>${visitor.reason || 'No reason'}</td>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${visitor.userAgent || 'Unknown'}">
                    ${visitor.userAgent || 'Unknown'}
                </td>
            </tr>
        `;
    }).join('');
}

// ===== UPDATE COUNTRY CHART =====
function updateCountryChart() {
    const countryChart = document.getElementById('countryChart');
    
    // Count visitors by country
    countryStats = {};
    visitorData.forEach(visitor => {
        const country = visitor.countryName || visitor.country || 'Unknown';
        countryStats[country] = (countryStats[country] || 0) + 1;
    });

    const sortedCountries = Object.entries(countryStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    if (sortedCountries.length === 0) {
        countryChart.innerHTML = '<p class="no-data">No country data yet</p>';
        return;
    }

    const maxCount = sortedCountries[0][1];

    countryChart.innerHTML = sortedCountries.map(([country, count]) => {
        const percentage = (count / maxCount) * 100;
        return `
            <div class="country-bar">
                <div class="country-name">${country}</div>
                <div class="country-bar-container">
                    <div class="country-bar-fill" style="width: ${percentage}%">
                        ${percentage.toFixed(0)}%
                    </div>
                </div>
                <div class="country-count">${count}</div>
            </div>
        `;
    }).join('');
}

// ===== EXPORT DATA TO CSV =====
function exportData() {
    if (visitorData.length === 0) {
        alert('❌ No data to export');
        return;
    }

    const headers = ['Timestamp', 'Status', 'IP', 'Country', 'City', 'ISP', 'Type', 'Reason', 'User Agent'];
    const csvContent = [
        headers.join(','),
        ...visitorData.map(visitor => [
            visitor.timestamp || '',
            visitor.status || '',
            visitor.ip || '',
            visitor.countryName || visitor.country || '',
            visitor.city || 'N/A',
            visitor.isp || visitor.org || '',
            visitor.ipType || '',
            `"${(visitor.reason || '').replace(/"/g, '""')}"`,
            `"${(visitor.userAgent || '').replace(/"/g, '""')}"`
        ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `antibot-records-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    alert('✅ Data exported successfully!');
}

// ===== REFRESH DATA =====
function refreshData() {
    loadData();
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = '🔄 Refreshing...';
    btn.disabled = true;
    
    setTimeout(() => {
        btn.textContent = originalText;
        btn.disabled = false;
    }, 1000);
}

// ===== AUTO REFRESH (Every 30 seconds) =====
function startAutoRefresh() {
    setInterval(() => {
        loadData();
        console.log('🔄 Auto-refreshed data');
    }, 30000); // 30 seconds
}

// ===== UPDATE LAST UPDATE TIME =====
function updateLastUpdate() {
    const now = new Date().toLocaleString();
    document.getElementById('lastUpdate').textContent = now;
}