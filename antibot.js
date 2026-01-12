// antibot.js - Fixed Client-Side Security & Tracking

// ===== ENHANCED BOT DETECTION =====
function detectBot() {
    // More specific bot patterns
    const botPatterns = [
        /bot/i, /crawl/i, /spider/i, /slurp/i, /mediapartners/i,
        /headless/i, /phantom/i, /selenium/i, /webdriver/i, /scraper/i,
        /curl\/[\d.]+$/i, /wget\/[\d.]+$/i, // Only standalone curl/wget
        /python-requests/i, /python-urllib/i, // Python bots
        /java\/[\d.]+$/i, // Standalone Java
        /go-http-client/i, /ruby\/[\d.]+$/i, // Go and Ruby bots
        /axios\/[\d.]+$/i, /okhttp/i, /httpclient/i, /node-fetch/i
    ];
    
    const userAgent = navigator.userAgent;
    const platform = navigator.platform;
    
    // Direct bot detection
    const isDirectBot = botPatterns.some(pattern => pattern.test(userAgent));
    
    // Check for headless browser
    const isHeadless = (
        navigator.webdriver === true ||
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
    
    // Threshold: 80+ is suspicious (raised from 50)
    const isSuspicious = suspicionScore >= 80;
    
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

// ===== IMPROVED VPN/PROXY DETECTION =====
function checkForNonResidentialIP(locationData) {
    // Legitimate ISP keywords - CHECK FIRST
    const legitISPKeywords = [
        'telecom', 'telecommunications', 'telephone',
        'mobile', 'cellular', 'wireless',
        'broadband', 'internet service',
        'cable', 'fiber', 'fibre',
        'isp', 'internet provider',
        'communications', 'networks limited', 'networks ltd',
        'airtel', 'mtn', 'glo', '9mobile', 'vodafone', 'orange',
        'telstra', 'verizon', 'att', 'sprint', 't-mobile',
        'comcast', 'spectrum', 'cox', 'centurylink', 'frontier'
    ];

    // Specific cloud/hosting providers ONLY
    const cloudProviders = [
        'digitalocean', 'digital ocean',
        'amazon web services', 'aws', 'amazon data services', 'amazon.com',
        'google cloud', 'google llc',
        'microsoft corporation', 'microsoft azure', 'azure',
        'linode', 'akamai technologies',
        'vultr', 'choopa',
        'ovh', 'ovh sas', 'ovh hosting',
        'scaleway',
        'hetzner', 'hetzner online',
        'rackspace',
        'cloudflare', 'cloudflare inc',
        'fastly',
        'contabo',
        'oracle cloud', 'ibm cloud', 'alibaba cloud', 'tencent cloud'
    ];

    // Datacenter-specific keywords ONLY
    const datacenterKeywords = [
        'data center', 'datacenter', 'data centre', 'datacentre',
        'colocation', 'colo facility',
        'server farm',
        'dedicated server hosting', // Must include "hosting"
        'vps hosting', 'virtual private server hosting'
    ];

    // VPN providers and keywords
    const vpnKeywords = [
        'vpn', 'virtual private network',
        'proxy server', 'proxy service',
        'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost',
        'privatevpn', 'purevpn', 'ipvanish', 'tunnelbear',
        'hide my ass', 'hidemyass', 'hma',
        'private internet access', 'pia-vpn',
        'windscribe', 'hotspot shield',
        'torguard', 'astrill', 'ivacy', 'zenmate', 'mullvad',
        'anonymizer', 'privacy network',
        'smartproxy', 'bright data', 'luminati', 'oxylabs'
    ];

    const org = (locationData.org || '').toLowerCase();
    const hostname = (locationData.hostname || '').toLowerCase();
    
    // ✅ CHECK IF LEGITIMATE ISP FIRST
    const isLegitISP = legitISPKeywords.some(k => org.includes(k) || hostname.includes(k));
    
    // Only check for cloud/datacenter if NOT a legit ISP
    const isCloudProvider = !isLegitISP && cloudProviders.some(p => 
        org.includes(p) || hostname.includes(p)
    );
    const isDatacenter = !isLegitISP && datacenterKeywords.some(k => 
        org.includes(k) || hostname.includes(k)
    );
    const isVPN = vpnKeywords.some(k => org.includes(k) || hostname.includes(k));

    // Known bad ASNs (actual datacenter/hosting ASNs)
    const suspiciousASNs = [
        '16509',  // Amazon AWS
        '14618',  // Amazon AWS
        '15169',  // Google Cloud
        '8075',   // Microsoft Azure
        '396982', // Google Cloud
        '13335',  // Cloudflare
        '20940',  // Akamai
        '14061',  // DigitalOcean
        '62567',  // DigitalOcean
        '63949',  // Linode
        '20473',  // Vultr
        '16276',  // OVH
        '35540',  // OVH
        '24940',  // Hetzner
        '12876',  // Scaleway
        '51167',  // Contabo
        '31898',  // Oracle Cloud
        '36351',  // IBM Cloud
        '45102',  // Alibaba Cloud
        '132203', // Tencent Cloud
        '26347',  // DreamHost
        '46606',  // Bluehost
        '26496',  // GoDaddy
        '27357',  // Rackspace
        '174',    // Cogent
        '3356',   // Level 3
        '6939',   // Hurricane Electric
        '36352',  // ColoCrossing
        '46844',  // Sharktech
        '8100',   // Quadranet
        '9009',   // M247
        '60068',  // DataCamp
        '202425'  // NordVPN
    ];
    
    const isSuspiciousASN = suspiciousASNs.includes(locationData.asn);
    
    // Final determination
    const isNonResidential = isCloudProvider || isDatacenter || isVPN || isSuspiciousASN;

    return {
        isNonResidential: isNonResidential,
        type: isVPN ? 'VPN/Proxy' : 
              isCloudProvider ? 'Cloud Provider' :
              isDatacenter ? 'Data Center' : 
              isSuspiciousASN ? 'Suspicious Network' : 
              'Residential/ISP',
        isVPN: isVPN,
        isDataCenter: isCloudProvider || isDatacenter
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
                suspicionScore: botInfo.suspicionScore,
                
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
    window.location.href = "https://www.youtube.com";
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
        console.log(`📡 IP Type: ${ipCheck.type}`);
        console.log(`🏢 Org: ${locationData.org}`);
        
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