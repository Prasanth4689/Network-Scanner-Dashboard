const express = require('express');
const path = require('path');
const { exec } = require('child_process');
const dns = require('dns');
const net = require('net');
const ip = require('ip');
const ping = require('ping');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Local MAC OUI prefix lookup
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

// Check network info
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

// Run live network scan
app.get('/api/scan', async (req, res) => {
  const mock = req.query.mock === 'true';

  if (mock) {
    // Generate high quality mock scan data
    const mockDevices = [
      { ip: ip.address(), mac: 'D4:A1:48:88:9F:10', vendor: 'This Device (Intel/Dell Host)', status: 'Active', latency: 1.2, isHost: true },
      { ip: ip.address().replace(/\.\d+$/, '.1'), mac: '14:20:5E:A4:CC:D1', vendor: 'TP-Link Gateway Router', status: 'Active', latency: 3.4 },
      { ip: ip.address().replace(/\.\d+$/, '.23'), mac: '70:3E:AC:12:F4:9E', vendor: 'Apple MacBook Pro', status: 'Active', latency: 45.1 },
      { ip: ip.address().replace(/\.\d+$/, '.52'), mac: 'D4:3B:04:8E:B5:12', vendor: 'Samsung Galaxy S24', status: 'Active', latency: 12.8 },
      { ip: ip.address().replace(/\.\d+$/, '.77'), mac: 'A4:77:03:FB:D1:D1', vendor: 'Google Home Mini', status: 'Active', latency: 22.5 },
      { ip: ip.address().replace(/\.\d+$/, '.120'), mac: 'DC:A6:32:0C:4B:92', vendor: 'Raspberry Pi Smart Hub', status: 'Active', latency: 8.9 },
      { ip: ip.address().replace(/\.\d+$/, '.144'), mac: 'C4:4F:33:9A:8B:7C', vendor: 'Microsoft Xbox Series X', status: 'Active', latency: 15.6 },
      { ip: ip.address().replace(/\.\d+$/, '.200'), mac: '40:B4:CD:E4:AA:21', vendor: 'Amazon Echo Dot', status: 'Active', latency: 31.2 }
    ];
    // Add random variations to latencies
    mockDevices.forEach(d => {
      if (!d.isHost) {
        d.latency = parseFloat((d.latency + (Math.random() - 0.5) * 4).toFixed(1));
        if (d.latency < 0.5) d.latency = 0.5;
      }
    });
    return res.json({ success: true, count: mockDevices.length, devices: mockDevices });
  }

  // Real Scan Mode (queries ARP cache first)
  exec('arp -a', async (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ success: false, error: 'Could not run ARP scan on host system: ' + error.message });
    }

    const lines = stdout.split('\n');
    const devices = [];
    const hostIp = ip.address();

    // Include the host device itself
    devices.push({
      ip: hostIp,
      mac: 'N/A (Host Interface)',
      vendor: 'This Device (Host System)',
      status: 'Active',
      latency: 0.1,
      isHost: true
    });

    // Parse ARP output
    // ARP lines format typically has IP addresses, Physical Address, Type (static/dynamic)
    const ipMacRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f-]{17})/i;

    for (let line of lines) {
      const match = line.match(ipMacRegex);
      if (match) {
        const targetIp = match[1];
        const mac = match[2].toUpperCase().replace(/-/g, ':');
        
        // Skip broadcast/multicast IPs
        if (targetIp.endsWith('.255') || targetIp.startsWith('224.') || targetIp === '255.255.255.255') {
          continue;
        }

        if (targetIp !== hostIp) {
          devices.push({
            ip: targetIp,
            mac: mac,
            vendor: getVendor(mac),
            status: 'Offline', // will update with ping
            latency: null
          });
        }
      }
    }

    // Ping discovered IPs to check latency and confirm status
    const pingPromises = devices.map(async (device) => {
      if (device.isHost) return;
      try {
        const res = await ping.promise.probe(device.ip, { timeout: 1 });
        if (res.alive) {
          device.status = 'Active';
          device.latency = res.time !== 'unknown' ? parseFloat(parseFloat(res.time).toFixed(1)) : 1.0;
        } else {
          // If ping fails but it's in the ARP cache, it might be blocking ICMP. 
          // We mark it as 'Shielded/Active' if it exists in ARP, with a default latency.
          device.status = 'Shielded'; 
          device.latency = 25.0; 
        }
      } catch (err) {
        // Fallback
        device.status = 'Shielded';
        device.latency = 50.0;
      }
    });

    await Promise.all(pingPromises);

    // Filter to only return active or shielded devices
    const activeDevices = devices.filter(d => d.status === 'Active' || d.status === 'Shielded' || d.isHost);

    res.json({
      success: true,
      count: activeDevices.length,
      devices: activeDevices
    });
  });
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
    // Generate realistic mock port scan response based on IP subnet last byte
    const lastByte = parseInt(targetIp.split('.').pop()) || 0;
    const openPorts = [];
    
    // Router .1 usually has 80, 443
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

    // Add closed info for remaining
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
      socket.setTimeout(800); // 800ms timeout

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

  res.json({
    success: true,
    targetIp,
    results
  });
});

// Ping Target Endpoint for Stability Monitor
app.get('/api/ping-target', async (req, res) => {
  const { targetIp, mock } = req.query;

  if (!targetIp) {
    return res.status(400).json({ success: false, error: 'Target IP is required' });
  }

  if (mock === 'true') {
    // Return mock latency with random fluctuation
    const baseLatency = targetIp.startsWith('10.') || targetIp.startsWith('192.168.') ? 5.0 : 40.0;
    const fluctuation = (Math.random() - 0.5) * 10;
    const finalLatency = parseFloat(Math.max(1, baseLatency + fluctuation).toFixed(1));
    return res.json({
      success: true,
      targetIp,
      alive: true,
      latency: finalLatency
    });
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
      res.json({
        success: true,
        targetIp,
        alive: false,
        latency: null
      });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Network Scanner Server running on http://localhost:${PORT}`);
});
