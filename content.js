(function() {
  const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  
  const PRIVATE_IP_RANGES = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^0\./,
    /^169\.254\./,
    /^224\./,
    /^240\./
  ];

  function isPublicIP(ip) {
    return !PRIVATE_IP_RANGES.some(range => range.test(ip));
  }

  function getAllTextContent(element) {
    let text = '';
    
    function traverse(node) {
      if (node.nodeType === Node.TEXT_NODE) {
        text += node.textContent + ' ';
      } else if (node.nodeType === Node.ELEMENT_NODE && 
                 node.tagName !== 'SCRIPT' && 
                 node.tagName !== 'STYLE' && 
                 node.tagName !== 'NOSCRIPT') {
        for (let child of node.childNodes) {
          traverse(child);
        }
      }
    }
    
    traverse(element);
    return text;
  }

  function extractIPs() {
    const pageText = getAllTextContent(document.body);
    const matches = pageText.match(IPV4_REGEX);
    
    if (!matches) return [];
    
    const publicIPs = [...new Set(matches)].filter(isPublicIP);
    
    if (publicIPs.length > 0) {
      chrome.runtime.sendMessage({
        type: 'IPS_FOUND',
        ips: publicIPs,
        url: window.location.href
      });
    }
    
    return publicIPs;
  }

  // Initial extraction
  extractIPs();

  // Monitor for dynamic content changes
  const observer = new MutationObserver((mutations) => {
    let shouldReExtract = false;
    
    for (let mutation of mutations) {
      if (mutation.addedNodes.length > 0 || mutation.type === 'characterData') {
        shouldReExtract = true;
        break;
      }
    }
    
    if (shouldReExtract) {
      extractIPs();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
    characterDataOldValue: false
  });
})();
