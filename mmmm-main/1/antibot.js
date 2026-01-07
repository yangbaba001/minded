// antibot.js - Client-Side Security & Tracking

// ===== ENHANCED BOT DETECTION =====
function detectBot() {
    const botPatterns = [
        /bot/i, /crawl/i, /spider/i, /slurp/i, /mediapartners/i,
        /headless/i, /phantom/i, /selenium/i, /webdriver/i, /scraper/i,
        /curl/i, /wget/i, /python/i, /java/i, /perl/i, /ruby/i, /go-http/i,
        /axios/i, /okhttp/i, /httpclient/i, /node-fetch/i
    ];
    
    const userAgent = navigator.userAgent;
    const platform = navigator.platform;
    
    // Direct bot detection
    const isDirectBot = botPatterns.some(pattern => pattern.test(userAgent));
    
    // Check for headless browser
    const isHeadless = (
        navigator.webdriver === true ||
        !window.chrome ||
        navigator.plugins.length === 0 ||
        !navigator.languages ||
        navigator.languages.length === 0
    );
    
    // Check for automation tools
    const hasAutomationTools = !!(
        window.document.documentElement.getAttribute('webdriver') ||
        window.callPhantom ||
        window._phantom ||
        window.phantom
    );
    
    // SMART LINUX DETECTION (catches cloud/server Linux, not desktop Linux)
    const isLinux = /linux/i.test(platform) || /linux/i.test(userAgent);
    const hasSuspiciousLinuxPattern = isLinux && (
        // Missing common browser features (headless indicators)
        navigator.plugins.length === 0 ||
        !navigator.languages ||
        navigator.languages.length === 0 ||
        // No common browser in UA
        !/Chrome|Firefox|Safari/i.test(userAgent) ||
        // Webdriver present
        navigator.webdriver === true ||
        // Suspicious screen size (1x1, 800x600 common in bots)
        screen.width === 1 || screen.height === 1 ||
        (screen.width === 800 && screen.height === 600)
    );
    
    // Cloud/Server Linux detection (no X11 means server, not desktop)
    const isCloudLinux = isLinux && (
        !/X11/.test(userAgent) ||  // Desktop Linux shows X11
        !navigator.hardwareConcurrency ||
        navigator.hardwareConcurrency === 1 ||
        navigator.maxTouchPoints === 0
    );
    
    // Calculate suspicion score
    let suspicionScore = 0;
    let reasons = [];
    
    if (isDirectBot) {
        suspicionScore += 100;
        reasons.push('Bot user-agent');
    }
    if (isHeadless) {
        suspicionScore += 80;
        reasons.push('Headless browser');
    }
    if (hasAutomationTools) {
        suspicionScore += 100;
        reasons.push('Automation tools');
    }
    if (hasSuspiciousLinuxPattern) {
        suspicionScore += 60;
        reasons.push('Suspicious Linux');
    }
    if (isCloudLinux) {
        suspicionScore += 50;
        reasons.push('Cloud Linux');
    }
    
    // Threshold: 50+ is suspicious
    const isSuspicious = suspicionScore >= 50;
    
    return {
        isBot: isSuspicious,
        userAgent: userAgent,
        platform: platform,
        suspicionScore: suspicionScore,
        reason: reasons.length > 0 ? reasons.join(', ') : null
    };
}

// ===== BROWSER FINGERPRINTING =====
function getBrowserFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('fingerprint', 2, 2);
        
        return {
            canvasHash: canvas.toDataURL().slice(-50),
            screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            platform: navigator.platform,
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
            deviceMemory: navigator.deviceMemory || 'unknown',
            pluginsCount: navigator.plugins.length
        };
    } catch (error) {
        return { error: 'Fingerprint failed' };
    }
}

// ===== GEO & IP DATA =====
async function getLocationData() {
    try {
        const response = await fetch("https://ipinfo.io/json?token=6646828ead20c6");
        const data = await response.json();
        
        return {
            ip: data.ip,
            hostname: data.hostname,
            city: data.city,
            region: data.region,
            country: data.country,
            countryName: getCountryName(data.country),
            loc: data.loc,
            org: data.org,
            postal: data.postal,
            timezone: data.timezone,
            asn: extractASN(data.org),
            isp: data.org ? data.org.split(' ').slice(1).join(' ') : 'Unknown'
        };
    } catch (error) {
        console.error("Location fetch error:", error);
        return { 
            ip: "Unknown", 
            country: "Unknown", 
            countryName: "Unknown",
            org: "Unknown" 
        };
    }
}

// Extract ASN from org
function extractASN(org) {
    if (!org) return null;
    const match = org.match(/AS(\d+)/);
    return match ? match[1] : null;
}

// Country code to name
function getCountryName(code) {
    const countries = {
        'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada',
        'AU': 'Australia', 'DE': 'Germany', 'FR': 'France', 'IT': 'Italy',
        'ES': 'Spain', 'NL': 'Netherlands', 'SE': 'Sweden', 'NO': 'Norway',
        'DK': 'Denmark', 'FI': 'Finland', 'PL': 'Poland', 'RU': 'Russia',
        'CN': 'China', 'JP': 'Japan', 'KR': 'South Korea', 'IN': 'India',
        'BR': 'Brazil', 'MX': 'Mexico', 'AR': 'Argentina', 'NG': 'Nigeria',
        'ZA': 'South Africa', 'EG': 'Egypt', 'SA': 'Saudi Arabia'
    };
    return countries[code] || code;
}

// ===== VPN/PROXY DETECTION =====
function checkForNonResidentialIP(locationData) {
    const hostingProviders = [
        // Major Cloud Providers
        'digitalocean', 'aws', 'amazon', 'google cloud', 'microsoft', 'azure',
        'linode', 'vultr', 'ovh', 'scaleway', 'hetzner', 'rackspace',
        'hostgator', 'godaddy', 'cloudflare', 'akamai', 'fastly',
        
        // Additional Cloud/Hosting
        'oracle cloud', 'ibm cloud', 'alibaba cloud', 'tencent cloud',
        'dreamhost', 'bluehost', 'hostinger', 'namecheap', 'hostwinds',
        'a2hosting', 'inmotion', 'siteground', 'greengeeks',
        
        // VPS/Dedicated Providers
        'contabo', 'ionos', 'kamatera', 'interserver', 'liquidweb',
        'serverspace', 'upcloud', 'cherry servers', 'time4vps',
        
        // CDN/Edge Providers
        'bunny', 'stackpath', 'sucuri', 'imperva', 'cloudfront',
        'maxcdn', 'keycdn', 'cdn77', 'g-core labs',
        
        // Data Centers
        'equinix', 'cogent', 'level3', 'gthost', 'serverius',
        'leaseweb', 'wholesaleinternet', 'nocix', 'datacamp',
        'quadranet', 'colocrossing', 'sharktech', 'zenlayer',
        
        // Generic Keywords
        'hosting', 'datacenter', 'data center', 'data centre',
        'dedicated', 'server', 'vps', 'cloud', 'colocation',
        'colo', 'network', 'infrastructure', 'fiber', 'backbone',
        'transit', 'peering', 'ix', 'exchange', 'telecom',
        'broadband business', 'business internet', 'enterprise'
    ];

    const vpnKeywords = [
        // Major VPN Providers
        'vpn', 'proxy', 'nordvpn', 'expressvpn', 'surfshark', 
        'protonvpn', 'cyberghost', 'private internet access', 'pia',
        'ipvanish', 'vyprvpn', 'purevpn', 'hotspot shield',
        'tunnelbear', 'windscribe', 'mullvad', 'hide.me',
        
        // More VPN Services
        'torguard', 'astrill', 'ivacy', 'zenmate', 'buffered',
        'goose vpn', 'trust.zone', 'anonymizer', 'hidemyass',
        'perfect privacy', 'boleh vpn', 'airvpn', 'azirevpn',
        
        // Proxy Services
        'smartproxy', 'bright data', 'luminati', 'oxylabs',
        'geosurf', 'storm proxies', 'proxy-seller', 'instantproxies',
        'blazing proxies', 'yourprivateproxy', 'buyproxies',
        'highproxies', 'proxyrack', 'shifter', 'smartdaili',
        
        // Privacy/Security Keywords
        'hide', 'anonymous', 'privacy', 'secure', 'tunnel',
        'masked', 'shield', 'protect', 'encryption', 'stealth',
        'incognito', 'ghost', 'phantom', 'invisible', 'private relay',
        
        // Residential Proxy Networks
        'residential proxy', 'mobile proxy', 'rotating proxy',
        'datacenter proxy', 'backconnect', 'peer', 'p2p network',
        
        // Tor/Anonymity
        'tor exit', 'tor node', 'onion', 'i2p', 'freenet',
        
        // VPN Protocols/Tech
        'openvpn', 'wireguard', 'ikev2', 'l2tp', 'pptp', 'sstp',
        'shadowsocks', 'v2ray', 'trojan', 'xray'
    ];

    const org = (locationData.org || '').toLowerCase();
    const hostname = (locationData.hostname || '').toLowerCase();
    
    const isHosting = hostingProviders.some(p => org.includes(p) || hostname.includes(p));
    const isVPN = vpnKeywords.some(k => org.includes(k) || hostname.includes(k));

    const suspiciousASNs = [
        // Original ASNs
        '14061', '16509', '8075', '15169', '20940', '13335',
        '14618', '16276', '19531', '24940', '26347', '32780',
        
        // Major Cloud Providers
        '16509',  // Amazon AWS
        '14618',  // Amazon AWS
        '15169',  // Google Cloud
        '8075',   // Microsoft Azure
        '396982', // Google Cloud
        '13335',  // Cloudflare
        '20940',  // Akamai
        
        // DigitalOcean
        '14061', '62567', '393406',
        
        // Linode
        '63949',
        
        // Vultr
        '20473',
        
        // OVH
        '16276', '35540',
        
        // Hetzner
        '24940',
        
        // Scaleway
        '12876',
        
        // Contabo
        '51167',
        
        // Oracle Cloud
        '31898', '20001',
        
        // IBM Cloud
        '36351',
        
        // Alibaba Cloud
        '45102', '37963',
        
        // Tencent Cloud
        '132203', '45090',
        
        // DreamHost
        '26347',
        
        // Bluehost
        '46606',
        
        // GoDaddy
        '26496',
        
        // HostGator
        '7684',
        
        // Rackspace
        '27357', '33070',
        
        // Cogent (Major Transit)
        '174',
        
        // Level 3 / Lumen
        '3356', '3549',
        
        // Hurricane Electric (Common for VPS)
        '6939',
        
        // Choopa (Vultr)
        '20473',
        
        // ColoCrossing (Cheap VPS)
        '36352',
        
        // Sharktech
        '46844',
        
        // Quadranet
        '8100',
        
        // M247 (Common proxy/VPN)
        '9009',
        
        // DataCamp (Common for abuse)
        '60068',
        
        // Private Layer (VPN)
        '24961',
        
        // NordVPN
        '202425',
        
        // Express VPN
        '393406',
        
        // Surfshark
        '202425',
        
        // WireGuard/VPN providers
        '209',
        
        // Tor Exit Nodes (various ASNs)
        '19531', '205100', '396356'
    ];
    
    const isSuspiciousASN = suspiciousASNs.includes(locationData.asn);

    return {
        isNonResidential: isHosting || isVPN || isSuspiciousASN,
        type: isVPN ? 'VPN/Proxy' : isHosting ? 'Data Center' : 
              isSuspiciousASN ? 'Suspicious Network' : 'Residential',
        isVPN: isVPN,
        isDataCenter: isHosting
    };
}

// ===== CLICK TRACKING =====
function setupClickTracking() {
    let clickCount = 0;
    let lastClickTime = Date.now();
    
    document.addEventListener('click', async (e) => {
        clickCount++;
        const currentTime = Date.now();
        const timeSinceLastClick = currentTime - lastClickTime;
        lastClickTime = currentTime;
        
        try {
            await fetch('/__track-click', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clickCount: clickCount,
                    timeSinceLastClick: timeSinceLastClick,
                    element: e.target.tagName,
                    x: e.clientX,
                    y: e.clientY,
                    timestamp: new Date().toISOString()
                })
            });
        } catch (error) {
            console.error('Click tracking error:', error);
        }
    });
}

// ===== REPORT TO SERVER =====
async function reportToServer(status, reason, locationData, botInfo, fingerprint, ipCheck) {
    try {
        const response = await fetch('/__antibot-report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                status: status,
                reason: reason,
                timestamp: new Date().toISOString(),
                
                // Location data
                ip: locationData.ip,
                country: locationData.country,
                countryName: locationData.countryName,
                city: locationData.city,
                region: locationData.region,
                coordinates: locationData.loc,
                timezone: locationData.timezone,
                org: locationData.org,
                isp: locationData.isp,
                asn: locationData.asn,
                hostname: locationData.hostname,
                
                // Bot detection
                isBot: botInfo.isBot,
                botReason: botInfo.reason,
                userAgent: botInfo.userAgent,
                suspicionScore: botInfo.suspicionScore,  // NEW: Send score
                
                // IP type
                ipType: ipCheck.type,
                isVPN: ipCheck.isVPN,
                isDataCenter: ipCheck.isDataCenter,
                
                // Fingerprint
                fingerprint: fingerprint,
                
                // Page info
                pageUrl: window.location.href,
                referrer: document.referrer || 'Direct'
            })
        });
        
        return await response.json();
    } catch (error) {
        console.error('Report error:', error);
    }
}


// ===== SHOW BLOCKED PAGE =====
function showPageNotFound() {
    // Just hardcode it for now, or fetch from server
    window.location.href = "https://en.wikipedia.org/wiki/Flight_deck_cruiser";
}

// ===== MAIN INITIALIZATION =====
window.addEventListener('load', async function() {
    try {
        console.log('🛡️ Antibot security check starting...');
        
        // Gather all detection data
        const botInfo = detectBot();
        const fingerprint = getBrowserFingerprint();
        const locationData = await getLocationData();
        const ipCheck = checkForNonResidentialIP(locationData);
        
        console.log(`🤖 Bot Score: ${botInfo.suspicionScore} | ${botInfo.isBot ? 'SUSPICIOUS' : 'CLEAN'}`);
        
        // Decision logic
        let shouldBlock = false;
        let blockReason = "";
        
        if (botInfo.isBot) {
            shouldBlock = true;
            blockReason = `Bot detected: ${botInfo.reason}`;
        } else if (ipCheck.isNonResidential) {
            shouldBlock = true;
            blockReason = `Non-residential IP: ${ipCheck.type}`;
        }
        
        // Report to server and handle response
        const serverResponse = await reportToServer(
            shouldBlock ? "BLOCKED" : "ALLOWED",
            shouldBlock ? blockReason : "Legitimate visitor",
            locationData,
            botInfo,
            fingerprint,
            ipCheck
        );
        
        if (shouldBlock) {
            console.log('🚫 Access blocked:', blockReason);
            showPageNotFound();
        } else {
            console.log('✅ Access granted');
            setupClickTracking(); // Enable click tracking for allowed users
        }
        
    } catch (error) {
        console.error('Antibot error:', error);
        // On error, allow access but log it
    }
});