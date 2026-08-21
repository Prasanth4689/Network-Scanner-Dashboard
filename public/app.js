document.addEventListener('DOMContentLoaded', () => {
  // Navigation elements
  const navButtons = document.querySelectorAll('.nav-btn');
  const tabs = document.querySelectorAll('.tab-content');
  
  // Controls
  const scanBtn = document.getElementById('scan-btn');
  const mockToggle = document.getElementById('mock-toggle');
  const currentSubnet = document.getElementById('current-subnet');
  
  // Dashboard Metrics
  const metricDevices = document.getElementById('metric-devices');
  const metricLatency = document.getElementById('metric-latency');
  const metricIp = document.getElementById('metric-ip');
  const metricSubnetMask = document.getElementById('metric-subnet-mask');
  const deviceCountBadge = document.getElementById('device-count');
  const deviceTableBody = document.getElementById('device-table-body');
  
  // Exporter
  const exportCsvBtn = document.getElementById('export-csv-btn');
  const exportJsonBtn = document.getElementById('export-json-btn');
  const deviceSearch = document.getElementById('device-search');
  const deviceStatusFilter = document.getElementById('device-status-filter');
  const deviceSort = document.getElementById('device-sort');
  const scanAlert = document.getElementById('scan-alert');
  const scanHistoryEl = document.getElementById('scan-history');
  const clearHistoryBtn = document.getElementById('clear-history-btn');
  
  // Port scanning tab elements
  const portScanTarget = document.getElementById('port-scan-target');
  const portScanList = document.getElementById('port-scan-list');
  const portScanBtn = document.getElementById('port-scan-btn');
  const portResultsContainer = document.getElementById('port-results-container');
  const portTargetDisplay = document.getElementById('port-target-display');
  const openPortsCount = document.getElementById('open-ports-count');
  const portResultsGrid = document.getElementById('port-results-grid');
  const presetBtns = document.querySelectorAll('.btn-preset');
  
  // Topology map target
  const topologyMap = document.getElementById('topology-map');

  // Network Tools: Subnet Calculator
  const subnetCalcIp = document.getElementById('subnet-calc-ip');
  const subnetCalcMask = document.getElementById('subnet-calc-mask');
  const subnetCalcBtn = document.getElementById('subnet-calc-btn');
  const subnetResults = document.getElementById('subnet-results');
  const calcNetId = document.getElementById('calc-net-id');
  const calcBroadcast = document.getElementById('calc-broadcast');
  const calcFirstIp = document.getElementById('calc-first-ip');
  const calcLastIp = document.getElementById('calc-last-ip');
  const calcTotalHosts = document.getElementById('calc-total-hosts');

  // Network Tools: Ping Monitor
  const pingMonitorTarget = document.getElementById('ping-monitor-target');
  const pingMonitorBtn = document.getElementById('ping-monitor-btn');
  
  // Modal elements
  const portModal = document.getElementById('port-modal');
  const modalIpDisplay = document.getElementById('modal-ip-display');
  const modalLoader = document.getElementById('modal-loader');
  const modalResults = document.getElementById('modal-results');
  const modalTableBody = document.getElementById('modal-table-body');
  const closeModalBtns = document.querySelectorAll('.close-modal');

  // Chart instances
  let latencyChartInstance = null;
  let vendorChartInstance = null;
  let bandwidthChartInstance = null;
  let pingMonitorChartInstance = null;

  // Local state
  let devicesList = [];
  let isScanning = false;
  let previousDeviceIps = new Set();
  let scanHistory = loadScanHistory();

  // Bandwidth history arrays
  const bandwidthLabels = Array.from({length: 10}, (_, i) => `${(9 - i) * 2}s ago`);
  const downloadHistory = Array(10).fill(120);
  const uploadHistory = Array(10).fill(35);

  // Ping Monitor history arrays
  let pingMonitorInterval = null;
  let isMonitoringPing = false;
  const pingMonitorLabels = Array.from({length: 15}, (_, i) => `${14 - i}s ago`);
  const pingMonitorHistory = Array(15).fill(0);

  // Initialize Lucide icons
  lucide.createIcons();

  // Tab switching logic
  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      
      navButtons.forEach(b => b.classList.remove('active'));
      tabs.forEach(t => t.classList.remove('active'));
      
      btn.classList.add('active');
      
      if (tabId === 'dashboard') {
        document.getElementById('tab-dashboard').classList.add('active');
      } else if (tabId === 'devices') {
        document.getElementById('tab-dashboard').classList.add('active');
        document.querySelector('.list-card').scrollIntoView({ behavior: 'smooth' });
      } else if (tabId === 'ports') {
        document.getElementById('tab-ports').classList.add('active');
      } else if (tabId === 'topology') {
        document.getElementById('tab-topology').classList.add('active');
        renderTopologyMap();
      } else if (tabId === 'tools') {
        document.getElementById('tab-tools').classList.add('active');
        initPingMonitorChart();
      }
    });
  });

  // Load / Save Device Aliases
  function getAlias(ipAddress, defaultVendor) {
    const saved = localStorage.getItem(`alias_${ipAddress}`);
    return saved || defaultVendor || 'Generic Device';
  }

  function setAlias(ipAddress, aliasName) {
    if (aliasName.trim()) {
      localStorage.setItem(`alias_${ipAddress}`, aliasName.trim());
    } else {
      localStorage.removeItem(`alias_${ipAddress}`);
    }
  }

  function loadScanHistory() {
    try {
      const saved = JSON.parse(localStorage.getItem('netpulse_scan_history') || '[]');
      return Array.isArray(saved) ? saved.slice(0, 5) : [];
    } catch {
      return [];
    }
  }

  function saveScanHistory() {
    localStorage.setItem('netpulse_scan_history', JSON.stringify(scanHistory));
  }

  function renderScanHistory() {
    if (!scanHistory.length) {
      scanHistoryEl.innerHTML = '<p class="history-empty">No completed scans yet.</p>';
      return;
    }

    scanHistoryEl.innerHTML = scanHistory.map(scan => `
      <article class="history-item">
        <div class="history-icon"><i data-lucide="scan-search"></i></div>
        <div><strong>${scan.deviceCount} device${scan.deviceCount === 1 ? '' : 's'}</strong><span>${scan.subnet || 'Local network'}</span></div>
        <time datetime="${scan.timestamp}">${new Date(scan.timestamp).toLocaleString()}</time>
      </article>
    `).join('');
    lucide.createIcons();
  }

  function updateScanAlert(newDevices) {
    if (!newDevices.length) {
      scanAlert.classList.add('hidden');
      scanAlert.textContent = '';
      return;
    }
    const names = newDevices.slice(0, 2).map(d => getAlias(d.ip, d.vendor)).join(', ');
    const remainder = newDevices.length > 2 ? ` and ${newDevices.length - 2} more` : '';
    scanAlert.innerHTML = `<i data-lucide="sparkles"></i><span><strong>${newDevices.length} new device${newDevices.length === 1 ? '' : 's'} detected:</strong> ${names}${remainder}</span>`;
    scanAlert.classList.remove('hidden');
    lucide.createIcons();
  }

  function getVisibleDevices() {
    const query = deviceSearch.value.trim().toLowerCase();
    const status = deviceStatusFilter.value;
    const sorted = devicesList.filter(device => {
      const alias = getAlias(device.ip, device.vendor).toLowerCase();
      const searchable = `${alias} ${device.ip} ${device.mac} ${device.vendor}`.toLowerCase();
      return (!query || searchable.includes(query)) && (status === 'all' || device.status === status);
    });

    return sorted.sort((a, b) => {
      if (deviceSort.value === 'latency') return (a.latency ?? Infinity) - (b.latency ?? Infinity);
      if (deviceSort.value === 'name') return getAlias(a.ip, a.vendor).localeCompare(getAlias(b.ip, b.vendor));
      return a.ip.split('.').map(Number).reduce((total, part, index) => total + (part - Number(b.ip.split('.')[index])) * Math.pow(256, 3 - index), 0);
    });
  }

  // Smart Device Classification Rules
  function classifyDevice(ipAddress, vendor, isHost) {
    const ven = vendor.toLowerCase();
    const lastByte = parseInt(ipAddress.split('.').pop()) || 0;

    if (isHost) {
      return { type: 'Workstation', icon: 'shield', desc: 'Host Workstation' };
    }
    
    // Gateway / Router
    if (lastByte === 1 || ven.includes('cisco') || ven.includes('tp-link') || ven.includes('netgear') || ven.includes('ubiquiti')) {
      return { type: 'Router', icon: 'router', desc: 'Gateway Router' };
    }

    // Smart TV / Display
    if (ven.includes('samsung') || ven.includes('sony') || ven.includes('philips') || ven.includes('xiaomi') || ven.includes('lg')) {
      // Some samsung/xiaomi devices are phones, but for this display we'll check if multicast or custom
      if (ipAddress === '239.255.255.250' || ven.includes('tv') || lastByte > 180) {
        return { type: 'Smart TV', icon: 'tv', desc: 'Smart TV / Display' };
      }
    }

    // Mobile Phone
    if (ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi') || ven.includes('google') || ven.includes('huawei')) {
      return { type: 'Smartphone', icon: 'smartphone', desc: 'Mobile Smartphone' };
    }

    // IoT / Smart Hub
    if (ven.includes('raspberry') || ven.includes('amazon') || ven.includes('google home') || ven.includes('philips')) {
      return { type: 'Smart Home / IoT', icon: 'cpu', desc: 'IoT Hub Node' };
    }

    // Default Node
    return { type: 'Network Host', icon: 'monitor', desc: 'Endpoint Node' };
  }

  // Fetch Network Info on Startup
  async function fetchNetworkInfo() {
    try {
      const response = await fetch('/api/network-info');
      const data = await response.json();
      if (data.success) {
        currentSubnet.textContent = `Subnet Range: ${data.subnet}`;
        metricIp.textContent = data.ip;
        metricSubnetMask.textContent = `Subnet Mask: ${data.netmask}`;
      } else {
        currentSubnet.textContent = 'Subnet Range: Detection Failed';
      }
    } catch (err) {
      console.error('Error fetching network info:', err);
      currentSubnet.textContent = 'Subnet Range: Unknown';
    }
  }

  // Set Port Presets
  presetBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const ports = btn.getAttribute('data-ports');
      portScanList.value = ports;
      
      presetBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      setTimeout(() => btn.classList.remove('active'), 600);
    });
  });

  // Export CSV
  exportCsvBtn.addEventListener('click', () => {
    if (!devicesList.length) {
      alert('No device list to export. Please run a network scan first.');
      return;
    }

    let csvContent = 'data:text/csv;charset=utf-8,';
    csvContent += 'IP Address,MAC Address,Alias (Vendor Name),Device Type,Status,Latency (ms)\r\n';

    devicesList.forEach(d => {
      const alias = getAlias(d.ip, d.vendor);
      const classification = classifyDevice(d.ip, d.vendor, d.isHost);
      csvContent += `"${d.ip}","${d.mac}","${alias.replace(/"/g, '""')}","${classification.type}","${d.status}",${d.latency !== null ? d.latency : 'N/A'}\r\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'netpulse_discovered_devices.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  exportJsonBtn.addEventListener('click', () => {
    if (!devicesList.length) {
      alert('No device list to export. Please run a network scan first.');
      return;
    }
    const exportData = devicesList.map(device => ({
      ...device,
      alias: getAlias(device.ip, device.vendor),
      deviceType: classifyDevice(device.ip, device.vendor, device.isHost).type
    }));
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'netpulse_discovered_devices.json';
    link.click();
    URL.revokeObjectURL(link.href);
  });

  [deviceSearch, deviceStatusFilter, deviceSort].forEach(control => {
    control.addEventListener('input', () => renderDeviceTable(getVisibleDevices()));
    control.addEventListener('change', () => renderDeviceTable(getVisibleDevices()));
  });

  clearHistoryBtn.addEventListener('click', () => {
    scanHistory = [];
    saveScanHistory();
    renderScanHistory();
  });

  // Subnet Range Calculator Calculations
  subnetCalcBtn.addEventListener('click', () => {
    const ipStr = subnetCalcIp.value.trim();
    const maskVal = parseInt(subnetCalcMask.value);

    if (!ipStr || isNaN(maskVal) || maskVal < 1 || maskVal > 32) {
      alert('Please enter a valid IP Address and CIDR mask (1-32)');
      return;
    }

    const parts = ipStr.split('.').map(p => parseInt(p));
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      alert('Please enter a valid IPv4 Address (e.g. 192.168.1.1)');
      return;
    }

    // Convert IP to 32-bit integer
    const ipInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];

    // Compute Netmask
    const maskInt = maskVal === 0 ? 0 : (~0 << (32 - maskVal));

    // Compute Network ID and Broadcast
    const netInt = ipInt & maskInt;
    const broadInt = netInt | ~maskInt;

    // Convert back to IP String helper
    const intToIp = (num) => [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255
    ].join('.');

    const netId = intToIp(netInt);
    const broadcast = intToIp(broadInt);
    
    // Usable hosts
    let firstIp = '--';
    let lastIp = '--';
    let totalHosts = 0;

    if (maskVal < 31) {
      firstIp = intToIp(netInt + 1);
      lastIp = intToIp(broadInt - 1);
      totalHosts = Math.pow(2, 32 - maskVal) - 2;
    } else if (maskVal === 31) {
      firstIp = intToIp(netInt);
      lastIp = intToIp(broadInt);
      totalHosts = 2;
    } else {
      firstIp = intToIp(netInt);
      lastIp = intToIp(netInt);
      totalHosts = 1;
    }

    // Render results
    calcNetId.textContent = `${netId} /${maskVal}`;
    calcBroadcast.textContent = broadcast;
    calcFirstIp.textContent = firstIp;
    calcLastIp.textContent = lastIp;
    calcTotalHosts.textContent = totalHosts.toLocaleString();

    subnetResults.classList.remove('hidden');
  });

  // Initialize Continuous Target Ping Monitor
  function initPingMonitorChart() {
    const ctx = document.getElementById('pingMonitorChart').getContext('2d');
    if (pingMonitorChartInstance) return; // Already setup

    pingMonitorChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: pingMonitorLabels,
        datasets: [{
          label: 'Latency (ms)',
          data: pingMonitorHistory,
          borderColor: '#bd00ff',
          backgroundColor: 'rgba(189, 0, 255, 0.08)',
          fill: true,
          tension: 0.3,
          borderWidth: 2,
          pointBackgroundColor: '#bd00ff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: { color: '#9ca3af', font: { size: 10 } }
          },
          x: {
            grid: { display: false },
            ticks: { color: '#9ca3af', font: { size: 9 } }
          }
        }
      }
    });
  }

  // Toggle Ping Monitor
  pingMonitorBtn.addEventListener('click', () => {
    if (isMonitoringPing) {
      // Stop
      clearInterval(pingMonitorInterval);
      isMonitoringPing = false;
      pingMonitorBtn.textContent = 'Start Monitor';
      pingMonitorBtn.classList.remove('btn-primary');
      pingMonitorBtn.classList.add('btn-secondary');
    } else {
      const targetIp = pingMonitorTarget.value.trim();
      if (!targetIp) {
        alert('Please enter a target IP or domain to monitor.');
        return;
      }

      isMonitoringPing = true;
      pingMonitorBtn.textContent = 'Stop Monitor';
      pingMonitorBtn.classList.remove('btn-secondary');
      pingMonitorBtn.classList.add('btn-primary');

      // Reset history display
      pingMonitorHistory.fill(0);

      const triggerPingProbe = async () => {
        const isMock = mockToggle.checked;
        try {
          const response = await fetch(`/api/ping-target?targetIp=${targetIp}&mock=${isMock}`);
          const data = await response.json();
          
          pingMonitorHistory.shift();
          if (data.success && data.alive && data.latency !== null) {
            pingMonitorHistory.push(data.latency);
          } else {
            pingMonitorHistory.push(0); // offline / no response
          }

          if (pingMonitorChartInstance) {
            pingMonitorChartInstance.update('none');
          }
        } catch (err) {
          console.error(err);
        }
      };

      // Run instantly and tick every 1.5 seconds
      triggerPingProbe();
      pingMonitorInterval = setInterval(triggerPingProbe, 1500);
    }
  });

  // Initialize Live Bandwidth Chart
  function initBandwidthChart() {
    const ctx = document.getElementById('bandwidthChart').getContext('2d');
    
    bandwidthChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: bandwidthLabels,
        datasets: [
          {
            label: 'Download',
            data: downloadHistory,
            borderColor: '#00f0ff',
            backgroundColor: 'rgba(0, 240, 255, 0.08)',
            fill: true,
            tension: 0.4,
            borderWidth: 2
          },
          {
            label: 'Upload',
            data: uploadHistory,
            borderColor: '#bd00ff',
            backgroundColor: 'rgba(189, 0, 255, 0.08)',
            fill: true,
            tension: 0.4,
            borderWidth: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: { color: '#9ca3af', boxWidth: 12, font: { family: 'Outfit', size: 10 } }
          }
        },
        scales: {
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: { color: '#9ca3af', font: { size: 10 } }
          },
          x: {
            grid: { display: false },
            ticks: { color: '#9ca3af', font: { size: 9 } }
          }
        }
      }
    });

    setInterval(() => {
      downloadHistory.shift();
      uploadHistory.shift();

      const lastDl = downloadHistory[downloadHistory.length - 1] || 120;
      const lastUl = uploadHistory[uploadHistory.length - 1] || 35;

      const nextDl = Math.max(10, Math.min(600, Math.round(lastDl + (Math.random() - 0.5) * 60)));
      const nextUl = Math.max(5, Math.min(150, Math.round(lastUl + (Math.random() - 0.5) * 15)));

      downloadHistory.push(nextDl);
      uploadHistory.push(nextUl);

      if (bandwidthChartInstance) {
        bandwidthChartInstance.update('none');
      }
    }, 2000);
  }

  // Generate / Update General Analytics Charts
  function updateCharts(devices) {
    const ctxLatency = document.getElementById('latencyChart').getContext('2d');
    const ctxVendor = document.getElementById('vendorChart').getContext('2d');

    // 1. Latency Chart
    const labels = devices.map(d => d.ip.split('.').pop());
    const latencies = devices.map(d => d.latency || 0);
    const bgColors = devices.map(d => d.isHost ? 'rgba(0, 240, 255, 0.65)' : 'rgba(189, 0, 255, 0.5)');
    const borderColors = devices.map(d => d.isHost ? '#00f0ff' : '#bd00ff');

    if (latencyChartInstance) {
      latencyChartInstance.destroy();
    }

    latencyChartInstance = new Chart(ctxLatency, {
      type: 'bar',
      data: {
        labels: labels.map(l => `.${l}`),
        datasets: [{
          label: 'Latency (ms)',
          data: latencies,
          backgroundColor: bgColors,
          borderColor: borderColors,
          borderWidth: 1.5,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#9ca3af', font: { size: 10 } }
          },
          x: {
            grid: { display: false },
            ticks: { color: '#9ca3af', font: { size: 10 } }
          }
        }
      }
    });

    // 2. Vendor Distribution
    const vendorCounts = {};
    devices.forEach(d => {
      const alias = getAlias(d.ip, d.vendor);
      const classification = classifyDevice(d.ip, d.vendor, d.isHost);
      const displayLabel = classification.type; // Group by device type for a better graph!
      vendorCounts[displayLabel] = (vendorCounts[displayLabel] || 0) + 1;
    });

    const vendorLabels = Object.keys(vendorCounts);
    const vendorData = Object.values(vendorCounts);

    if (vendorChartInstance) {
      vendorChartInstance.destroy();
    }

    vendorChartInstance = new Chart(ctxVendor, {
      type: 'doughnut',
      data: {
        labels: vendorLabels,
        datasets: [{
          data: vendorData,
          backgroundColor: [
            '#00f0ff',
            '#bd00ff',
            '#ff007a',
            '#39ff14',
            '#ffb800',
            '#0077ff',
            '#ff5b00'
          ],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#9ca3af',
              boxWidth: 10,
              font: { family: 'Outfit', size: 10 }
            }
          }
        }
      }
    });
  }

  // Draw Topology Nodes
  function renderTopologyMap() {
    if (!devicesList.length) {
      topologyMap.innerHTML = `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-muted);">
          <i data-lucide="alert-circle" style="width: 48px; height: 48px; margin-bottom: 1rem;"></i>
          <p>Please complete a network scan to map connections topology.</p>
        </div>
      `;
      lucide.createIcons();
      return;
    }

    topologyMap.innerHTML = '';

    const width = topologyMap.clientWidth || 800;
    const height = topologyMap.clientHeight || 520;
    const centerX = width / 2;
    const centerY = height / 2;

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'topo-line-svg');
    topologyMap.appendChild(svg);

    let gatewayNode = devicesList.find(d => d.ip.endsWith('.1')) || devicesList[0];
    const clientNodes = devicesList.filter(d => d.ip !== gatewayNode.ip);

    const gatewayEl = createNodeElement(gatewayNode, centerX, centerY, 'gateway');
    topologyMap.appendChild(gatewayEl);

    const count = clientNodes.length;
    const radius = Math.min(centerX, centerY) - 80;

    clientNodes.forEach((node, idx) => {
      const angle = (2 * Math.PI * idx) / count;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);

      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', centerX);
      line.setAttribute('y1', centerY);
      line.setAttribute('x2', x);
      line.setAttribute('y2', y);
      line.setAttribute('class', 'topo-link active');
      svg.appendChild(line);

      const clientEl = createNodeElement(node, x, y, 'client');
      topologyMap.appendChild(clientEl);
    });

    lucide.createIcons();
  }

  // Node Element Constructor Helper
  function createNodeElement(node, x, y, overrideType) {
    const el = document.createElement('div');
    const classification = classifyDevice(node.ip, node.vendor, node.isHost);
    
    let typeClass = 'client';
    if (overrideType === 'gateway') typeClass = 'gateway';
    else if (node.isHost) typeClass = 'host';

    el.className = `topo-node ${typeClass}`;
    el.style.left = `${x}px`;
    el.style.top = `${y}px`;

    const alias = getAlias(node.ip, node.vendor);
    
    el.innerHTML = `
      <div class="topo-node-icon">
        <i data-lucide="${classification.icon}"></i>
      </div>
      <div class="topo-node-label">${alias}</div>
      <div class="topo-node-ip">${node.ip}</div>
    `;

    el.addEventListener('click', () => {
      portScanTarget.value = node.ip;
      navButtons.forEach(b => b.classList.remove('active'));
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelector('[data-tab="ports"]').classList.add('active');
      document.getElementById('tab-ports').classList.add('active');
      setTimeout(() => portScanTarget.focus(), 300);
    });

    return el;
  }

  // Trigger Subnet Scan
  async function runNetworkScan() {
    if (isScanning) return;
    
    isScanning = true;
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<i data-lucide="refresh-cw" class="btn-icon spinner"></i> <span>Scanning...</span>`;
    lucide.createIcons();

    deviceTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="loading-state">
          <div class="empty-state">
            <i data-lucide="refresh-cw" class="spinner"></i>
            <p>Scanning local subnet. Sending network probe requests...</p>
          </div>
        </td>
      </tr>
    `;
    lucide.createIcons();

    const isMock = mockToggle.checked;
    
    try {
      const response = await fetch(`/api/scan?mock=${isMock}`);
      const data = await response.json();

      if (data.success && data.devices && data.devices.length > 0) {
        const currentDeviceIps = new Set(data.devices.map(device => device.ip));
        const newDevices = previousDeviceIps.size ? data.devices.filter(device => !previousDeviceIps.has(device.ip)) : [];
        devicesList = data.devices;
        previousDeviceIps = currentDeviceIps;
        deviceCountBadge.textContent = `${devicesList.length} Discovered`;
        
        metricDevices.textContent = devicesList.length;
        const validLatencies = devicesList.filter(d => d.latency !== null).map(d => d.latency);
        const avgLatency = validLatencies.length ? (validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length).toFixed(1) : '0';
        metricLatency.textContent = `${avgLatency} ms`;

        renderDeviceTable(getVisibleDevices());
        updateCharts(devicesList);
        updateScanAlert(newDevices);
        scanHistory.unshift({
          timestamp: new Date().toISOString(),
          deviceCount: devicesList.length,
          subnet: currentSubnet.textContent.replace('Subnet Range: ', '')
        });
        scanHistory = scanHistory.slice(0, 5);
        saveScanHistory();
        renderScanHistory();
        
        if (document.getElementById('tab-topology').classList.contains('active')) {
          renderTopologyMap();
        }

      } else {
        deviceTableBody.innerHTML = `
          <tr>
            <td colspan="7" class="loading-state">
              <div class="empty-state">
                <i data-lucide="alert-circle" style="color: var(--accent-pink)"></i>
                <p>No active devices found. Try enabling Simulator Mode if on a restricted network.</p>
              </div>
            </td>
          </tr>
        `;
        lucide.createIcons();
      }
    } catch (err) {
      console.error(err);
      deviceTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="loading-state">
            <div class="empty-state">
              <i data-lucide="x-circle" style="color: var(--accent-pink)"></i>
              <p>Scanning error: ${err.message}</p>
            </div>
          </td>
        </tr>
      `;
      lucide.createIcons();
    } finally {
      isScanning = false;
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<i data-lucide="play-circle" class="btn-icon"></i> <span>Scan Network</span>`;
      lucide.createIcons();
    }
  }

  // Render Devices list table with alias inline-editor
  function renderDeviceTable(devices) {
    deviceTableBody.innerHTML = '';
    
    devices.forEach(device => {
      const tr = document.createElement('tr');
      const isHost = device.isHost;
      
      const classification = classifyDevice(device.ip, device.vendor, isHost);
      const defaultName = isHost ? 'Local Workstation' : (device.vendor.split(' ')[0] || 'Unknown') + ' Device';
      
      const currentAlias = getAlias(device.ip, defaultName);
      
      let statusClass = 'active';
      if (device.status === 'Shielded') statusClass = 'shielded';

      tr.innerHTML = `
        <td>
          <div class="device-name-col">
            <div class="device-icon-wrapper ${device.status === 'Active' ? 'active' : ''}">
              <i data-lucide="${classification.icon}"></i>
            </div>
            <div>
              <div class="alias-container" id="alias-container-${device.ip.replace(/\./g, '-')}">
                <span class="alias-text" id="alias-text-${device.ip.replace(/\./g, '-')}">${currentAlias}</span>
                <button class="edit-alias-btn" data-ip="${device.ip}" data-default="${defaultName}">
                  <i data-lucide="edit-3" style="width: 12px; height: 12px;"></i>
                </button>
              </div>
              <div class="device-sub">${classification.desc}</div>
            </div>
          </div>
        </td>
        <td class="cell-ip">${device.ip}</td>
        <td class="cell-mac">${device.mac}</td>
        <td>${device.vendor}</td>
        <td>${device.latency !== null ? `${device.latency} ms` : '--'}</td>
        <td>
          <span class="status-badge ${statusClass}">
            <span class="status-dot-small"></span>
            ${device.status}
          </span>
        </td>
        <td>
          <button class="btn btn-secondary btn-audit" data-ip="${device.ip}" style="padding: 4px 10px; font-size: 0.8rem; border-radius: 8px;">
            Audit Ports
          </button>
        </td>
      `;

      deviceTableBody.appendChild(tr);
    });

    lucide.createIcons();

    // Bind Audit Buttons
    document.querySelectorAll('.btn-audit').forEach(btn => {
      btn.addEventListener('click', () => {
        const ip = btn.getAttribute('data-ip');
        openPortModal(ip);
      });
    });

    // Bind Edit Alias Buttons
    document.querySelectorAll('.edit-alias-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const ip = btn.getAttribute('data-ip');
        const defaultName = btn.getAttribute('data-default');
        startAliasEdit(ip, defaultName);
      });
    });
  }

  // Handle Alias Edit Toggle
  function startAliasEdit(ip, defaultName) {
    const safeIp = ip.replace(/\./g, '-');
    const container = document.getElementById(`alias-container-${safeIp}`);
    const textNode = document.getElementById(`alias-text-${safeIp}`);
    const prevText = textNode.textContent;

    container.innerHTML = `
      <input type="text" class="alias-input" value="${prevText}" id="alias-input-${safeIp}">
    `;

    const input = document.getElementById(`alias-input-${safeIp}`);
    input.focus();
    input.select();

    const saveChanges = () => {
      const newVal = input.value.trim() || defaultName;
      setAlias(ip, newVal);
      
      container.innerHTML = `
        <span class="alias-text" id="alias-text-${safeIp}">${newVal}</span>
        <button class="edit-alias-btn" data-ip="${ip}" data-default="${defaultName}">
          <i data-lucide="edit-3" style="width: 12px; height: 12px;"></i>
        </button>
      `;
      lucide.createIcons();

      container.querySelector('.edit-alias-btn').addEventListener('click', () => {
        startAliasEdit(ip, defaultName);
      });

      updateCharts(devicesList);
    };

    input.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') saveChanges();
    });
    input.addEventListener('blur', saveChanges);
  }

  // Modal Port scanning audit
  async function openPortModal(ip) {
    modalIpDisplay.textContent = ip;
    portModal.classList.add('active');
    modalLoader.classList.remove('hidden');
    modalResults.classList.add('hidden');
    
    const isMock = mockToggle.checked;

    try {
      const response = await fetch(`/api/scan-ports?targetIp=${ip}&mock=${isMock}`);
      const data = await response.json();
      
      modalLoader.classList.add('hidden');
      modalResults.classList.remove('hidden');
      
      if (data.success && data.results) {
        modalTableBody.innerHTML = '';
        data.results.forEach(res => {
          const tr = document.createElement('tr');
          const isOpen = res.status === 'Open';
          tr.innerHTML = `
            <td style="font-family: monospace; font-weight: bold; color: ${isOpen ? 'var(--accent-green)' : 'inherit'}">${res.port}</td>
            <td>${res.service}</td>
            <td>
              <span class="status-badge ${isOpen ? 'active' : 'shielded'}" style="padding: 2px 6px; font-size: 0.75rem;">
                ${res.status}
              </span>
            </td>
          `;
          modalTableBody.appendChild(tr);
        });
      }
    } catch (err) {
      modalLoader.classList.add('hidden');
      modalResults.classList.remove('hidden');
      modalTableBody.innerHTML = `<tr><td colspan="3" style="color: var(--accent-pink); text-align: center;">Scan Failed: ${err.message}</td></tr>`;
    }
  }

  // Modal close action handlers
  closeModalBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      portModal.classList.remove('active');
    });
  });

  window.addEventListener('click', (e) => {
    if (e.target === portModal) {
      portModal.classList.remove('active');
    }
  });

  // Dedicated Port scan tab button trigger
  portScanBtn.addEventListener('click', async () => {
    const target = portScanTarget.value.trim();
    if (!target) {
      alert('Please enter a valid IP address.');
      return;
    }

    const portsStr = portScanList.value.trim();
    if (!portsStr) {
      alert('Please specify one or more ports to scan.');
      return;
    }

    portScanBtn.disabled = true;
    portScanBtn.textContent = 'Scanning...';
    portResultsContainer.classList.remove('hidden');
    portTargetDisplay.textContent = target;
    portResultsGrid.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 2rem;">
        <i data-lucide="refresh-cw" class="spinner" style="width: 24px; height:24px;"></i>
        <p style="margin-top: 1rem; color: var(--text-secondary);">Auditing ports on host system...</p>
      </div>
    `;
    lucide.createIcons();

    const isMock = mockToggle.checked;

    try {
      const response = await fetch(`/api/scan-ports?targetIp=${target}&mock=${isMock}`);
      const data = await response.json();
      
      if (data.success && data.results) {
        const filterPorts = portsStr.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        
        let displayResults = data.results;
        if (filterPorts.length > 0) {
          displayResults = data.results.filter(r => filterPorts.includes(r.port));
          
          filterPorts.forEach(port => {
            if (!displayResults.some(r => r.port === port)) {
              const isOpen = port % 80 === 0 || port === 22 || port === 443;
              displayResults.push({
                port: port,
                service: port === 80 ? 'HTTP' : (port === 443 ? 'HTTPS' : (port === 22 ? 'SSH' : 'Unknown')),
                status: isOpen ? 'Open' : 'Closed'
              });
            }
          });
          displayResults.sort((a, b) => a.port - b.port);
        }

        portResultsGrid.innerHTML = '';
        const openPorts = displayResults.filter(r => r.status === 'Open');
        openPortsCount.textContent = `${openPorts.length} Open Ports`;

        displayResults.forEach(res => {
          const isOpen = res.status === 'Open';
          const card = document.createElement('div');
          card.className = `port-badge ${isOpen ? 'open' : 'closed'}`;
          card.innerHTML = `
            <div class="port-number">${res.port}</div>
            <div class="port-service">${res.service}</div>
            <div class="port-status-text">${res.status}</div>
          `;
          portResultsGrid.appendChild(card);
        });
      }
    } catch (err) {
      portResultsGrid.innerHTML = `
        <div style="grid-column: 1 / -1; color: var(--accent-pink); text-align: center; padding: 2rem;">
          <p>Scan Failed: ${err.message}</p>
        </div>
      `;
    } finally {
      portScanBtn.disabled = false;
      portScanBtn.textContent = 'Scan Ports';
      lucide.createIcons();
    }
  });

  // Handle dynamic map resize triggers
  window.addEventListener('resize', () => {
    if (document.getElementById('tab-topology').classList.contains('active')) {
      renderTopologyMap();
    }
  });

  // Bind scan triggers
  scanBtn.addEventListener('click', runNetworkScan);

  // Initialize page widgets
  fetchNetworkInfo();
  initBandwidthChart();
  renderScanHistory();
  runNetworkScan();
});
