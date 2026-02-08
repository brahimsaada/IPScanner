let ipData = {};
let filteredData = {};
let currentTabId = null;

document.addEventListener('DOMContentLoaded', () => {
  loadIPData();
  setupEventListeners();
});

function setupEventListeners() {
  document.getElementById('clearBtn').addEventListener('click', clearAllData);
  document.getElementById('settingsBtn').addEventListener('click', showSettings);
  document.getElementById('closeSettings').addEventListener('click', hideSettings);
  document.getElementById('saveApiKey').addEventListener('click', saveAPIKey);
  document.getElementById('searchInput').addEventListener('input', handleSearch);
  document.getElementById('scanBtn').addEventListener('click', scanAllIPs);
}

function loadIPData() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      currentTabId = tabs[0].id;
      
      chrome.runtime.sendMessage({ type: 'GET_TAB_IPS', tabId: currentTabId }, (response) => {
        ipData = response.ipData;
        filteredData = ipData;
        renderIPList();
        updateStats();
      });
    }
  });
}

async function scanAllIPs() {
  const scanBtn = document.getElementById('scanBtn');
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';

  const ipsToScan = Object.keys(ipData).filter(ip => !ipData[ip].geo || !ipData[ip].abuse);

  for (const ip of ipsToScan) {
    ipData[ip].loading = true;
    renderIPList();

    const enrichedData = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'ENRICH_IP', ip }, resolve);
    });

    ipData[ip] = { ...ipData[ip], ...enrichedData, loading: false };
    
    chrome.storage.local.get({ ipDataByTab: {} }, (result) => {
      const ipDataByTab = result.ipDataByTab;
      ipDataByTab[currentTabId] = ipData;
      chrome.storage.local.set({ ipDataByTab });
    });
    
    renderIPList();
    updateStats();
  }

  scanBtn.disabled = false;
  scanBtn.textContent = '🔍 Scan All';
}

async function scanSingleIP(ip, button) {
  button.disabled = true;
  button.textContent = '...';

  ipData[ip].loading = true;
  
  const searchQuery = document.getElementById('searchInput').value.toLowerCase();
  if (!searchQuery) {
    filteredData = ipData;
  } else {
    filteredData = Object.fromEntries(
      Object.entries(ipData).filter(([ipAddr, data]) =>
        ipAddr.includes(searchQuery) ||
        data.geo?.country?.toLowerCase().includes(searchQuery) ||
        data.geo?.city?.toLowerCase().includes(searchQuery) ||
        data.geo?.isp?.toLowerCase().includes(searchQuery)
      )
    );
  }
  
  renderIPList();

  const enrichedData = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'ENRICH_IP', ip }, resolve);
  });

  ipData[ip] = { ...ipData[ip], ...enrichedData, loading: false };
  
  chrome.storage.local.get({ ipDataByTab: {} }, (result) => {
    const ipDataByTab = result.ipDataByTab;
    ipDataByTab[currentTabId] = ipData;
    chrome.storage.local.set({ ipDataByTab });
  });
  
  if (!searchQuery) {
    filteredData = ipData;
  } else {
    filteredData = Object.fromEntries(
      Object.entries(ipData).filter(([ipAddr, data]) =>
        ipAddr.includes(searchQuery) ||
        data.geo?.country?.toLowerCase().includes(searchQuery) ||
        data.geo?.city?.toLowerCase().includes(searchQuery) ||
        data.geo?.isp?.toLowerCase().includes(searchQuery)
      )
    );
  }
  
  renderIPList();
  updateStats();
}

function renderIPList() {
  const ipList = document.getElementById('ipList');
  const ips = Object.values(filteredData);

  if (ips.length === 0) {
    ipList.innerHTML = '<div class="empty-state"><div>📡</div><p>No IPs detected yet.<br>Browse websites to start scanning.</p></div>';
    return;
  }

  ipList.innerHTML = ips.map(data => createIPCard(data)).join('');

  document.querySelectorAll('.ip-card').forEach(card => {
    card.addEventListener('click', (e) => {
      if (!e.target.closest('.scan-single-btn')) {
        card.classList.toggle('expanded');
      }
    });
  });

  document.querySelectorAll('.scan-single-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const ip = btn.dataset.ip;
      scanSingleIP(ip, btn);
    });
  });
}

function createIPCard(data) {
  const threatLevel = getThreatLevel(data);
  const geoLocation = formatGeoLocation(data.geo);
  const isScanned = data.geo || data.abuse;
  const isLoading = data.loading;

  return `
    <div class="ip-card">
      <div class="ip-header">
        <span class="ip-address">${data.ip}</span>
        <div class="ip-header-right">
          ${!isScanned && !isLoading ? `<button class="scan-single-btn" data-ip="${data.ip}">🔍 Scan</button>` : ''}
          <span class="threat-badge threat-${threatLevel.class}">${threatLevel.label}</span>
        </div>
      </div>
      ${geoLocation ? `<div class="geo-info">🌍 ${geoLocation}</div>` : ''}
      <div class="ip-details">
        ${data.geo ? `
          <div class="detail-row">
            <span class="detail-label">Country:</span>
            <span class="detail-value">${data.geo.country || 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">City:</span>
            <span class="detail-value">${data.geo.city || 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">ISP:</span>
            <span class="detail-value">${data.geo.isp || 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">ASN:</span>
            <span class="detail-value">${data.geo.asn || 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Hostname(s):</span>
            <span class="detail-value">${data.abuse?.hostnames?.join(', ') || 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Domain Name:</span>
            <span class="detail-value">${data.abuse?.domain || data.geo.domain || 'Unknown'}</span>
          </div>
        ` : ''}
        ${data.abuse && !data.abuse.error ? `
          <div class="detail-row">
            <span class="detail-label">Usage Type:</span>
            <span class="detail-value">${data.abuse.usageType || 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Abuse Score:</span>
            <span class="detail-value">${data.abuse.abuseScore}%</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Reports:</span>
            <span class="detail-value">${data.abuse.reports}</span>
          </div>
          ${data.abuse.isTor ? `
          <div class="detail-row">
            <span class="detail-label">Tor Exit:</span>
            <span class="detail-value">Yes</span>
          </div>` : ''}
        ` : data.abuse?.error ? `
          <div class="detail-row">
            <span class="detail-label" style="color: #dc3545;">${data.abuse.error}</span>
          </div>
        ` : ''}
        <div class="abuseipdb-link">
          <a href="https://www.abuseipdb.com/check/${data.ip}" target="_blank" class="check-link">
            🔍 Check on AbuseIPDB
          </a>
        </div>
      </div>
    </div>
  `;
}

function getThreatLevel(data) {
  if (data.loading) {
    return { class: 'loading', label: 'Checking...' };
  }

  if (!data.geo && !data.abuse) {
    return { class: 'loading', label: 'Not Scanned' };
  }

  if (data.abuse && data.abuse.error) {
    return { class: 'loading', label: 'Error' };
  }

  if (!data.abuse || typeof data.abuse.abuseScore === 'undefined') {
    return { class: 'loading', label: 'Not Scanned' };
  }

  const score = data.abuse.abuseScore;

  if (score === 0) return { class: 'safe', label: 'Safe' };
  if (score < 25) return { class: 'low', label: 'Low Risk' };
  if (score < 75) return { class: 'medium', label: 'Medium Risk' };
  return { class: 'high', label: 'High Risk' };
}

function formatGeoLocation(geo) {
  if (!geo) return null;
  
  const parts = [];
  if (geo.city) parts.push(geo.city);
  if (geo.region) parts.push(geo.region);
  if (geo.country) parts.push(geo.country);
  
  return parts.join(', ');
}

function updateStats() {
  const ips = Object.values(ipData);
  const maliciousIPs = ips.filter(data => 
    data.abuse && !data.abuse.error && data.abuse.abuseScore >= 25
  ).length;

  document.getElementById('totalIPs').textContent = ips.length;
  document.getElementById('maliciousIPs').textContent = maliciousIPs;
}

function handleSearch(e) {
  const query = e.target.value.toLowerCase();
  
  if (!query) {
    filteredData = ipData;
  } else {
    filteredData = Object.fromEntries(
      Object.entries(ipData).filter(([ip, data]) =>
        ip.includes(query) ||
        data.geo?.country?.toLowerCase().includes(query) ||
        data.geo?.city?.toLowerCase().includes(query) ||
        data.geo?.isp?.toLowerCase().includes(query)
      )
    );
  }
  
  renderIPList();
}

function clearAllData() {
  if (!confirm('Clear IP data for this tab?')) return;

  chrome.runtime.sendMessage({ type: 'CLEAR_DATA', tabId: currentTabId }, () => {
    ipData = {};
    filteredData = {};
    renderIPList();
    updateStats();
  });
}

function showSettings() {
  document.getElementById('mainPanel').classList.add('hidden');
  document.getElementById('settingsPanel').classList.remove('hidden');

  chrome.storage.local.get({ apiKey: '' }, (result) => {
    document.getElementById('apiKeyInput').value = result.apiKey;
  });
}

function hideSettings() {
  document.getElementById('settingsPanel').classList.add('hidden');
  document.getElementById('mainPanel').classList.remove('hidden');
}

function saveAPIKey() {
  const apiKey = document.getElementById('apiKeyInput').value.trim();

  chrome.runtime.sendMessage({ 
    type: 'SAVE_API_KEY', 
    apiKey 
  }, () => {
    hideSettings();
    loadIPData();
  });
}