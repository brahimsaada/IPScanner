const API_CONFIG = {
  abuseIPDB: 'https://api.abuseipdb.com/api/v2/check',
  geoIP: 'http://ip-api.com/json/'
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'IPS_FOUND') {
    storeIPs(message.ips, message.url, sender.tab.id);
  } else if (message.type === 'ENRICH_IP') {
    enrichIPData(message.ip).then(data => {
      sendResponse(data);
    });
    return true;
  } else if (message.type === 'SAVE_API_KEY') {
    chrome.storage.local.set({ apiKey: message.apiKey }, () => {
      sendResponse({ success: true });
    });
    return true;
  } else if (message.type === 'CLEAR_DATA') {
    chrome.storage.local.get({ ipDataByTab: {} }, (result) => {
      const ipDataByTab = result.ipDataByTab;
      delete ipDataByTab[message.tabId];
      chrome.storage.local.set({ ipDataByTab }, () => {
        sendResponse({ success: true });
      });
    });
    return true;
  } else if (message.type === 'GET_TAB_IPS') {
    chrome.storage.local.get({ ipDataByTab: {} }, (result) => {
      const tabData = result.ipDataByTab[message.tabId] || {};
      sendResponse({ ipData: tabData });
    });
    return true;
  }
});

function storeIPs(ips, sourceUrl, tabId) {
  chrome.storage.local.get({ ipDataByTab: {} }, (result) => {
    const ipDataByTab = result.ipDataByTab;
    
    if (!ipDataByTab[tabId]) {
      ipDataByTab[tabId] = {};
    }
    
    const tabIpData = ipDataByTab[tabId];

    for (const ip of ips) {
      if (!tabIpData[ip]) {
        tabIpData[ip] = {
          ip,
          firstSeen: Date.now(),
          sources: [sourceUrl]
        };
      } else if (!tabIpData[ip].sources.includes(sourceUrl)) {
        tabIpData[ip].sources.push(sourceUrl);
      }
    }

    chrome.storage.local.set({ ipDataByTab });
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.get({ ipDataByTab: {} }, (result) => {
    const ipDataByTab = result.ipDataByTab;
    delete ipDataByTab[tabId];
    chrome.storage.local.set({ ipDataByTab });
  });
});

async function enrichIPData(ip) {
  const [geoData, abuseData] = await Promise.all([
    fetchGeoIP(ip),
    fetchAbuseIPDB(ip)
  ]);

  return {
    geo: geoData,
    abuse: abuseData,
    lastChecked: Date.now()
  };
}

async function fetchGeoIP(ip) {
  try {
    const response = await fetch(`${API_CONFIG.geoIP}${ip}?fields=status,country,city,isp,as,reverse,org`);
    const data = await response.json();
    
    if (data.status === 'success') {
      const asnMatch = data.as ? data.as.match(/AS\d+/) : null;
      
      return {
        country: data.country,
        city: data.city,
        isp: data.isp,
        asn: asnMatch ? asnMatch[0] : data.as,
        domain: data.reverse,
        org: data.org
      };
    }
  } catch (error) {
    console.error('GeoIP lookup failed:', error);
  }
  return null;
}

async function fetchAbuseIPDB(ip) {
  try {
    const apiKey = await getAPIKey();
    if (!apiKey) {
      return { error: 'API key not configured' };
    }

    const response = await fetch(`${API_CONFIG.abuseIPDB}?ipAddress=${ip}&maxAgeInDays=90`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }

    const result = await response.json();
    const data = result.data;

    return {
      abuseScore: data.abuseConfidenceScore,
      reports: data.totalReports,
      lastReported: data.lastReportedAt,
      usageType: data.usageType,
      isTor: data.isTor,
      isWhitelisted: data.isWhitelisted,
      hostnames: data.hostnames || [],
      domain: data.domain
    };
  } catch (error) {
    console.error('AbuseIPDB check failed:', error);
    return { error: error.message };
  }
}

async function getAPIKey() {
  return new Promise((resolve) => {
    chrome.storage.local.get({ apiKey: '' }, (result) => {
      resolve(result.apiKey);
    });
  });
}