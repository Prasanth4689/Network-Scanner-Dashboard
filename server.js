const express = require('express');
const path = require('path');
const http = require('http');
const { exec } = require('child_process');
const dns = require('dns');
const net = require('net');
const ip = require('ip');
const ping = require('ping');
const { WebSocketServer } = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── MAC OUI Vendor Lookup ──────────────────────────────────────────
const MAC_VENDORS = {
  '00:00:0c': 'Cisco',
  '00:01:42': 'Cisco',
  '00:05:cd': 'Asus',
  '00:07:e9': 'Intel',
  '00:09:5b': 'Netgear',
  '00:0c:29': 'VMware',
  '00:10:7a': 'Amstrad',
  '00:11:2f': 'Panasonic',
  '00:11:32': 'Synology',
  '00:14:22': 'Dell',
  '00:14:38': 'Hewlett Packard',
  '00:15:65': 'Huawei',
  '00:16:3e': 'Xen',
  '00:17:88': 'Philips',
  '00:19:e3': 'Apple',
  '00:1a:11': 'Google',
  '00:1c:c0': 'HP',
  '00:1d:60': 'Sony',
  '00:1e:8c': 'Asus',
  '00:21:70': 'Dell',
  '00:23:4d': 'Samsung',
  '00:24:8c': 'Asus',
  '00:25:90': 'Supermicro',
  '00:26:bb': 'Apple',
  '00:28:f8': 'Intel',
  '00:50:56': 'VMware',
  '00:90:a9': 'Western Digital',
  '00:e0:4c': 'Realtek',
  '00:e0:64': 'Samsung',
  '04:18:b6': 'Ubiquiti',
  '04:18:d6': 'Ubiquiti',
  '04:d6:aa': 'Samsung',
  '08:00:27': 'Oracle VirtualBox',
  '10:dd:b1': 'Apple',
  '14:20:5e': 'TP-Link',
  '18:68:cb': 'TP-Link',
  '1c:69:7a': 'Intel',
  '24:a0:74': 'Apple',
  '28:c6:8e': 'Apple',
  '30:5a:3a': 'Intel',
  '34:97:f6': 'Samsung',
  '3c:7c:3f': 'Xiaomi',
  '3c:a6:16': 'Apple',
  '40:b4:cd': 'Amazon',
  '48:2c:6a': 'Apple',
  '50:c7:bf': 'TP-Link',
  '54:af:97': 'Intel',
  '60:03:08': 'Apple',
  '6c:40:08': 'Apple',
  '70:3e:ac': 'Apple',
  '70:85:c2': 'Asus',
  '74:ac:5f': 'Intel',
  '84:c9:b2': 'TP-Link',
  '8c:85:90': 'Apple',
  '90:09:df': 'Xiaomi',
  '98:01:a7': 'Apple',
  '98:10:e8': 'Sony',
  '9c:76:13': 'Intel',
  'a4:77:03': 'Google',
  'a8:20:66': 'Intel',
  'a8:5e:45': 'Apple',
  'ac:84:c6': 'Apple',
  'b0:be:76': 'TP-Link',
  'b4:2e:99': 'Samsung',
  'b8:27:eb': 'Raspberry Pi Foundation',
  'c0:56:27': 'Belkin',
  'c4:4f:33': 'Microsoft',
  'd4:3b:04': 'Samsung',
  'd4:a1:48': 'TP-Link',
  'd8:07:b6': 'Apple',
  'dc:a6:32': 'Raspberry Pi Foundation',
  'e0:3f:49': 'Asus',
  'e4:46:da': 'Dell',
  'e8:ab:fa': 'Apple',
  'f0:18:98': 'Apple',
  'f4:31:c3': 'Xiaomi',
  'f4:f2:6d': 'TP-Link',
  'f8:0d:60': 'Apple',
  'f8:ff:c2': 'Apple'
};

function getVendor(mac) {
  if (!mac) return 'Unknown Device';
  const cleanMac = mac.toLowerCase().replace(/[-]/g, ':');
  const prefix = cleanMac.split(':').slice(0, 3).join(':');
  return MAC_VENDORS[prefix] || 'Generic Brand';
}

// ─── Real-Time State ────────────────────────────────────────────────
let currentDevices = new Map();   // ip -> device object
let eventLog = [];                // last 100 events
let scannerInterval = null;
let isMockMode = true;            // default to simulator
let scanStartTime = null;

let totalScans = 0;
const uniqueIpsSeen = new Set();
let peakDeviceCount = 0;
const eventCounts = { joined: 0, left: 0, statusChange: 0 };
const serverStartTime = Date.now();

const MAX_EVENTS = 100;
const SCAN_INTERVAL_MS = 5000;    // scan every 5 seconds

// ─── Event Logging ──────────────────────────────────────────────────
function addEvent(type, device) {
  if (type === 'joined') eventCounts.joined++;
  else if (type === 'left') eventCounts.left++;
  else if (type === 'status_change') eventCounts.statusChange++;

  const event = {
    id: Date.now() + '-' + Math.random().toString(36).slice(2, 7),
    type,   // 'joined', 'left', 'status_change'
    ip: device.ip,
    mac: device.mac,
    vendor: device.vendor,
    timestamp: new Date().toISOString()
  };
  eventLog.unshift(event);
  if (eventLog.length > MAX_EVENTS) eventLog.pop();
  return event;
}

// ─── WebSocket Broadcast ────────────────────────────────────────────
function broadcast(wss, type, payload) {
  const message = JSON.stringify({ type, payload, timestamp: new Date().toISOString() });
  wss.clients.forEach(client => {
    if (client.readyState === 1) { // WebSocket.OPEN
      client.send(message);
    }
  });
}

// ─── Mock Scanner ───────────────────────────────────────────────────
const MOCK_POOL = [
  { ip: '_.1', mac: '14:20:5E:A4:CC:D1', vendor: 'TP-Link Gateway Router' },
  { ip: '_.23', mac: '70:3E:AC:12:F4:9E', vendor: 'Apple MacBook Pro' },
  { ip: '_.52', mac: 'D4:3B:04:8E:B5:12', vendor: 'Samsung Galaxy S24' },
  { ip: '_.77', mac: 'A4:77:03:FB:D1:D1', vendor: 'Google Home Mini' },
  { ip: '_.120', mac: 'DC:A6:32:0C:4B:92', vendor: 'Raspberry Pi Smart Hub' },
  { ip: '_.144', mac: 'C4:4F:33:9A:8B:7C', vendor: 'Microsoft Xbox Series X' },
  { ip: '_.200', mac: '40:B4:CD:E4:AA:21', vendor: 'Amazon Echo Dot' },
  { ip: '_.88', mac: '3C:7C:3F:11:22:33', vendor: 'Xiaomi Redmi Note 13' },
  { ip: '_.165', mac: '98:10:E8:44:55:66', vendor: 'Sony PlayStation 5' },
  { ip: '_.33', mac: 'B8:27:EB:77:88:99', vendor: 'Raspberry Pi Zero W' },
  { ip: '_.210', mac: 'E0:3F:49:AA:BB:CC', vendor: 'Asus ROG Phone' },
  { ip: '_.99', mac: '00:17:88:DD:EE:FF', vendor: 'Philips Hue Bridge' }
];

function runMockScan() {
  const hostIp = ip.address();
  const subnet = hostIp.replace(/\.\d+$/, '');

  // Host device is always present
  const devices = [{
    ip: hostIp,
    mac: 'N/A (Host Interface)',
    vendor: 'This Device (Host System)',
    status: 'Active',
    latency: 0.1,
    isHost: true,
    firstSeen: new Date().toISOString(),
    signalStrength: Math.floor(Math.random() * 51) - 80
  }];

  // Randomly include 5-9 devices from the pool to simulate joins/leaves
  const count = 5 + Math.floor(Math.random() * 5);
  const shuffled = [...MOCK_POOL].sort(() => Math.random() - 0.5);
  const selected = shuffled.slice(0, count);

  selected.forEach(mock => {
    const deviceIp = mock.ip.replace('_', subnet);
    devices.push({
      ip: deviceIp,
      mac: mock.mac,
      vendor: mock.vendor,
      status: 'Active',
      latency: parseFloat((2 + Math.random() * 45).toFixed(1)),
      isHost: false,
      firstSeen: new Date().toISOString(),
      signalStrength: Math.floor(Math.random() * 51) - 80
    });
  });

  return devices;
}

// ─── Real ARP Scanner ───────────────────────────────────────────────
function runRealScan() {
  return new Promise((resolve) => {
    exec('arp -a', async (error, stdout) => {
      if (error) {
        console.error('ARP scan failed:', error.message);
        return resolve([]);
      }

      const lines = stdout.split('\n');
      const devices = [];
      const hostIp = ip.address();

      // Include host
      devices.push({
        ip: hostIp,
        mac: 'N/A (Host Interface)',
        vendor: 'This Device (Host System)',
        status: 'Active',
        latency: 0.1,
        isHost: true,
        firstSeen: new Date().toISOString(),
        signalStrength: Math.floor(Math.random() * 51) - 80
      });

      const ipMacRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f-]{17})/i;

      for (let line of lines) {
        const match = line.match(ipMacRegex);
        if (match) {
          const targetIp = match[1];
          const mac = match[2].toUpperCase().replace(/-/g, ':');

          if (targetIp.endsWith('.255') || targetIp.startsWith('224.') || targetIp === '255.255.255.255') {
            continue;
          }

          if (targetIp !== hostIp) {
            devices.push({
              ip: targetIp,
              mac: mac,
              vendor: getVendor(mac),
              status: 'Offline',
              latency: null,
              isHost: false,
              firstSeen: new Date().toISOString(),
              signalStrength: Math.floor(Math.random() * 51) - 80
            });
          }
        }
      }

      // Ping all discovered devices concurrently
      const pingPromises = devices.map(async (device) => {
        if (device.isHost) return;
        try {
          const res = await ping.promise.probe(device.ip, { timeout: 1 });
          if (res.alive) {
            device.status = 'Active';
            device.latency = res.time !== 'unknown' ? parseFloat(parseFloat(res.time).toFixed(1)) : 1.0;
          } else {
            device.status = 'Shielded';
            device.latency = 25.0;
          }
        } catch {
          device.status = 'Shielded';
          device.latency = 50.0;
        }
      });

      await Promise.all(pingPromises);

      const activeDevices = devices.filter(d => d.status === 'Active' || d.status === 'Shielded' || d.isHost);
      resolve(activeDevices);
    });
  });
}

// ─── Diff Engine: Detect Joins, Leaves, Changes ─────────────────────
function diffDevices(oldMap, newList, wss) {
  const newMap = new Map();
  const joinedDevices = [];
  const leftDevices = [];

  // Build new map and detect joins
  newList.forEach(device => {
    if (oldMap.has(device.ip)) {
      device.firstSeen = oldMap.get(device.ip).firstSeen;
    }
    newMap.set(device.ip, device);

    if (!oldMap.has(device.ip)) {
      // New device joined
      const event = addEvent('joined', device);
      joinedDevices.push(device);
      broadcast(wss, 'device_joined', { device, event });
    } else {
      // Check for status changes
      const old = oldMap.get(device.ip);
      if (old.status !== device.status) {
        const event = addEvent('status_change', device);
        broadcast(wss, 'device_updated', { device, event, oldStatus: old.status });
      }
    }
  });

  // Detect leaves
  oldMap.forEach((device, ipAddr) => {
    if (!newMap.has(ipAddr)) {
      const event = addEvent('left', device);
      leftDevices.push(device);
      broadcast(wss, 'device_left', { device, event });
    }
  });

  return { newMap, joinedDevices, leftDevices };
}

// ─── Continuous Scanner Loop ────────────────────────────────────────
async function scanLoop(wss) {
  try {
    totalScans++;
    let newDevices;

    if (isMockMode) {
      newDevices = runMockScan();
    } else {
      newDevices = await runRealScan();
    }

    newDevices.forEach(d => uniqueIpsSeen.add(d.ip));
    if (newDevices.length > peakDeviceCount) peakDeviceCount = newDevices.length;

    const { newMap } = diffDevices(currentDevices, newDevices, wss);
    currentDevices = newMap;

    // Send full scan to all clients for chart/table sync
    broadcast(wss, 'full_scan', {
      devices: newDevices,
      count: newDevices.length,
      scanTime: new Date().toISOString()
    });

  } catch (err) {
    console.error('Scan loop error:', err.message);
  }
}

function startScanner(wss) {
  if (scannerInterval) clearInterval(scannerInterval);
  scanStartTime = new Date().toISOString();

  // Run immediately, then on interval
  scanLoop(wss);
  scannerInterval = setInterval(() => scanLoop(wss), SCAN_INTERVAL_MS);
  console.log(`Scanner started in ${isMockMode ? 'SIMULATOR' : 'REAL'} mode (every ${SCAN_INTERVAL_MS / 1000}s)`);
}

// ─── REST API Endpoints (backward compatible) ───────────────────────

// Network info
app.get('/api/network-info', (req, res) => {
  try {
    const localIp = ip.address();
    const mask = ip.subnet(localIp, '255.255.255.0');
    res.json({
      success: true,
      ip: localIp,
      subnet: `${mask.networkAddress}/${mask.subnetMaskLength}`,
      netmask: mask.subnetMask,
      broadcast: mask.broadcastAddress,
      numHosts: mask.numHosts
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// One-shot scan (still works for manual triggers)
app.get('/api/scan', async (req, res) => {
  const mock = req.query.mock === 'true';

  if (mock) {
    const mockDevices = runMockScan();
    return res.json({ success: true, count: mockDevices.length, devices: mockDevices });
  }

  const devices = await runRealScan();
  res.json({ success: true, count: devices.length, devices });
});

// Port Scanner
app.get('/api/scan-ports', async (req, res) => {
  const { targetIp, mock } = req.query;

  if (!targetIp) {
    return res.status(400).json({ success: false, error: 'Target IP is required' });
  }

  const portsToScan = [
    { port: 21, service: 'FTP' },
    { port: 22, service: 'SSH' },
    { port: 23, service: 'Telnet' },
    { port: 80, service: 'HTTP' },
    { port: 135, service: 'MS RPC' },
    { port: 139, service: 'NetBIOS' },
    { port: 443, service: 'HTTPS' },
    { port: 445, service: 'Microsoft-DS' },
    { port: 1433, service: 'MSSQL' },
    { port: 3306, service: 'MySQL' },
    { port: 3389, service: 'RDP' },
    { port: 8080, service: 'HTTP-Alt' }
  ];

  if (mock === 'true') {
    const lastByte = parseInt(targetIp.split('.').pop()) || 0;
    const openPorts = [];

    if (lastByte === 1) {
      openPorts.push({ port: 80, service: 'HTTP', status: 'Open' });
      openPorts.push({ port: 443, service: 'HTTPS', status: 'Open' });
    } else if (lastByte % 3 === 0) {
      openPorts.push({ port: 22, service: 'SSH', status: 'Open' });
      openPorts.push({ port: 8080, service: 'HTTP-Alt', status: 'Open' });
    } else if (lastByte % 4 === 0) {
      openPorts.push({ port: 3389, service: 'RDP', status: 'Open' });
    } else {
      openPorts.push({ port: 80, service: 'HTTP', status: 'Open' });
    }

    const results = portsToScan.map(p => {
      const open = openPorts.find(o => o.port === p.port);
      return open ? open : { ...p, status: 'Closed' };
    });

    return res.json({ success: true, targetIp, results });
  }

  // Real port scan
  const results = [];
  const scanPromises = portsToScan.map(({ port, service }) => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(800);

      socket.on('connect', () => {
        results.push({ port, service, status: 'Open' });
        socket.destroy();
        resolve();
      });

      socket.on('timeout', () => {
        results.push({ port, service, status: 'Closed' });
        socket.destroy();
        resolve();
      });

      socket.on('error', () => {
        results.push({ port, service, status: 'Closed' });
        socket.destroy();
        resolve();
      });

      socket.connect(port, targetIp);
    });
  });

  await Promise.all(scanPromises);
  results.sort((a, b) => a.port - b.port);

  res.json({ success: true, targetIp, results });
});

// Ping Target
app.get('/api/ping-target', async (req, res) => {
  const { targetIp, mock } = req.query;

  if (!targetIp) {
    return res.status(400).json({ success: false, error: 'Target IP is required' });
  }

  if (mock === 'true') {
    const baseLatency = targetIp.startsWith('10.') || targetIp.startsWith('192.168.') ? 5.0 : 40.0;
    const fluctuation = (Math.random() - 0.5) * 10;
    const finalLatency = parseFloat(Math.max(1, baseLatency + fluctuation).toFixed(1));
    return res.json({ success: true, targetIp, alive: true, latency: finalLatency });
  }

  try {
    const probeRes = await ping.promise.probe(targetIp, { timeout: 1.5 });
    if (probeRes.alive) {
      res.json({
        success: true,
        targetIp,
        alive: true,
        latency: probeRes.time !== 'unknown' ? parseFloat(parseFloat(probeRes.time).toFixed(1)) : 10.0
      });
    } else {
      res.json({ success: true, targetIp, alive: false, latency: null });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Event log endpoint
app.get('/api/events', (req, res) => {
  res.json({ success: true, events: eventLog });
});

// Scanner mode switch
app.post('/api/scanner-mode', (req, res) => {
  const { mock } = req.body;
  isMockMode = !!mock;

  // Reset state and restart scanner
  currentDevices = new Map();
  eventLog = [];

  if (global.__wss) {
    startScanner(global.__wss);
    broadcast(global.__wss, 'mode_changed', { mock: isMockMode });
  }

  res.json({ success: true, mode: isMockMode ? 'simulator' : 'real' });
});


// ─── NEW APIs ────────────────────────────────────────────────────────

// Traceroute / Hop Analysis API
app.get('/api/traceroute', (req, res) => {
  const { targetIp, mock } = req.query;
  if (!targetIp) return res.status(400).json({ success: false, error: 'Target IP is required' });

  if (mock === 'true') {
    const hops = [
      { hop: 1, ip: '192.168.1.1', latency: 2.3 },
      { hop: 2, ip: '10.0.0.1', latency: 5.1 },
      { hop: 3, ip: '172.16.2.4', latency: 12.5 },
      { hop: 4, ip: '104.28.14.99', latency: 24.0 },
      { hop: 5, ip: targetIp, latency: 45.2 }
    ];
    return res.json({ success: true, targetIp, hops });
  }

  // Real traceroute (Windows)
  exec(`tracert -d -w 1000 -h 15 ${targetIp}`, (error, stdout) => {
    const hops = [];
    const lines = stdout.split('\n');
    lines.forEach(line => {
      const match = line.match(/^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)/);
      if (match) {
        // basic parsing of tracert line
        const hop = parseInt(match[1]);
        const ip = match[2];
        const msMatch = line.match(/(\d+)\s*ms/);
        const latency = msMatch ? parseInt(msMatch[1]) : 0;
        hops.push({ hop, ip, latency });
      }
    });
    res.json({ success: true, targetIp, hops });
  });
});

// Network Health Score API
app.get('/api/health-score', (req, res) => {
  const devices = Array.from(currentDevices.values());
  if (devices.length === 0) {
    return res.json({ success: true, score: 100, breakdown: { latencyScore: 100, reachabilityScore: 100, densityScore: 100 }, grade: 'A+' });
  }

  let totalLatency = 0;
  let latencyCount = 0;
  let activeCount = 0;

  devices.forEach(d => {
    if (d.latency !== null) {
      totalLatency += d.latency;
      latencyCount++;
    }
    if (d.status === 'Active' || d.isHost) {
      activeCount++;
    }
  });

  const avgLatency = latencyCount > 0 ? totalLatency / latencyCount : 0;
  const latencyScore = Math.max(0, 100 - (avgLatency / 2)); // e.g. 50ms drops score by 25
  const reachabilityScore = (activeCount / devices.length) * 100;
  const densityScore = Math.min(100, devices.length * 5); // 20 devices = 100

  const score = Math.round((latencyScore * 0.5) + (reachabilityScore * 0.3) + (densityScore * 0.2));
  let grade = 'D';
  if (score >= 90) grade = 'A+';
  else if (score >= 80) grade = 'A';
  else if (score >= 70) grade = 'B';
  else if (score >= 60) grade = 'C';

  res.json({
    success: true,
    score,
    breakdown: {
      latencyScore: Math.round(latencyScore),
      reachabilityScore: Math.round(reachabilityScore),
      densityScore: Math.round(densityScore)
    },
    grade
  });
});

// DNS Reverse Lookup API
app.get('/api/dns-lookup', (req, res) => {
  const { targetIp, mock } = req.query;
  if (!targetIp) return res.status(400).json({ success: false, error: 'Target IP is required' });

  if (mock === 'true') {
    const mockNames = {
      '_.1': ['router.local', 'gateway'],
      '_.23': ['bhanus-macbook.local'],
      '_.52': ['galaxy-s24'],
      '_.77': ['google-home-mini'],
      '_.120': ['pi-hub.local'],
      '_.144': ['xbox-series-x'],
      '_.200': ['echo-dot'],
      '_.88': ['redmi-note-13'],
      '_.165': ['ps5'],
      '_.33': ['pi-zero'],
      '_.210': ['rog-phone'],
      '_.99': ['hue-bridge']
    };
    
    // Attempt to match mock names
    const lastByte = targetIp.split('.').pop();
    const hostnames = mockNames[`_.${lastByte}`] || [`unknown-device-${lastByte}.local`];
    
    return res.json({ success: true, targetIp, hostnames, responseTime: parseFloat((Math.random() * 20).toFixed(1)) });
  }

  const start = Date.now();
  dns.reverse(targetIp, (err, hostnames) => {
    const responseTime = Date.now() - start;
    if (err) {
      return res.json({ success: true, targetIp, hostnames: [], responseTime });
    }
    res.json({ success: true, targetIp, hostnames, responseTime });
  });
});

// Statistics Summary API
app.get('/api/stats', (req, res) => {
  let totalLatency = 0;
  let latencyCount = 0;
  
  currentDevices.forEach(d => {
    if (d.latency !== null) {
      totalLatency += d.latency;
      latencyCount++;
    }
  });

  const averageLatency = latencyCount > 0 ? parseFloat((totalLatency / latencyCount).toFixed(1)) : 0;
  const uptimeSeconds = Math.floor((Date.now() - serverStartTime) / 1000);

  res.json({
    success: true,
    totalScans,
    totalDevicesEverSeen: uniqueIpsSeen.size,
    currentDeviceCount: currentDevices.size,
    averageLatency,
    uptimeSeconds,
    peakDeviceCount,
    eventCounts
  });
});

// ─── HTTP + WebSocket Server ────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
global.__wss = wss;

wss.on('connection', (ws) => {
  console.log('WebSocket client connected');

  // Send current state to newly connected client
  const devices = Array.from(currentDevices.values());
  ws.send(JSON.stringify({
    type: 'initial_state',
    payload: {
      devices,
      count: devices.length,
      events: eventLog.slice(0, 20),
      mode: isMockMode ? 'simulator' : 'real',
      scanStartTime
    },
    timestamp: new Date().toISOString()
  }));

  ws.on('close', () => {
    console.log('WebSocket client disconnected');
  });
});

server.listen(PORT, () => {
  console.log(`NetPulse Server running on http://localhost:${PORT}`);
  console.log('Starting real-time network scanner...');
  startScanner(wss);
});
