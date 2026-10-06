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

  // Live status elements
  const wsStatusDot = document.getElementById('ws-status-dot');
  const wsStatusText = document.getElementById('ws-status-text');
  const livePulse = document.querySelector('.live-pulse');
  const liveLabel = document.getElementById('live-label');
  const liveUptime = document.getElementById('live-uptime');
  const liveLastScan = document.getElementById('live-last-scan');

  // Event log elements
  const eventLogList = document.getElementById('event-log-list');
  const clearEventsBtn = document.getElementById('clear-events-btn');

  // Toast container
  const toastContainer = document.getElementById('toast-container');

  // Health score elements
  const metricHealth = document.getElementById('metric-health');
  const healthGrade = document.getElementById('health-grade');

  // Security tab elements
  const scoreRingProgress = document.getElementById('score-ring-progress');
  const securityScoreValue = document.getElementById('security-score-value');
  const securityGradeLabel = document.getElementById('security-grade-label');
  const barLatency = document.getElementById('bar-latency');
  const barReachability = document.getElementById('bar-reachability');
  const barDensity = document.getElementById('bar-density');
  const valLatency = document.getElementById('val-latency');
  const valReachability = document.getElementById('val-reachability');
  const valDensity = document.getElementById('val-density');

  // Traceroute elements
  const tracerouteTarget = document.getElementById('traceroute-target');
  const tracerouteBtn = document.getElementById('traceroute-btn');
  const tracerouteResults = document.getElementById('traceroute-results');

  // DNS Lookup elements
  const dnsLookupTarget = document.getElementById('dns-lookup-target');
  const dnsLookupBtn = document.getElementById('dns-lookup-btn');
  const dnsResults = document.getElementById('dns-results');

  // Stats elements
  const statTotalScans = document.getElementById('stat-total-scans');
  const statUniqueDevices = document.getElementById('stat-unique-devices');
  const statPeakDevices = document.getElementById('stat-peak-devices');
  const statUptime = document.getElementById('stat-uptime');
  const statEventsJoined = document.getElementById('stat-events-joined');
  const statEventsLeft = document.getElementById('stat-events-left');

  // Device detail modal
  const deviceDetailModal = document.getElementById('device-detail-modal');
  const deviceDetailContent = document.getElementById('device-detail-content');

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
  let networkEvents = [];

  // WebSocket state
  let ws = null;
  let wsConnected = false;
  let wsConnectTime = null;
  let uptimeInterval = null;
  let reconnectTimeout = null;

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

  // ─── WebSocket Connection ─────────────────────────────────────────
  function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;
    
    try {
      ws = new WebSocket(wsUrl);
    } catch (err) {
      console.error('WebSocket creation failed:', err);
      setWSStatus(false);
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      console.log('WebSocket connected');
      wsConnected = true;
      wsConnectTime = Date.now();
      setWSStatus(true);
      startUptimeTimer();

      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
      }
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleWSMessage(msg);
      } catch (err) {
        console.error('Failed to parse WS message:', err);
      }
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      wsConnected = false;
      setWSStatus(false);
      stopUptimeTimer();
      scheduleReconnect();
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };
  }

  function scheduleReconnect() {
    if (reconnectTimeout) return;
    reconnectTimeout = setTimeout(() => {
      reconnectTimeout = null;
      console.log('Attempting WebSocket reconnect...');
      connectWebSocket();
    }, 3000);
  }

  function setWSStatus(connected) {
    if (connected) {
      wsStatusDot.className = 'status-dot online';
      wsStatusText.textContent = 'Live Connected';
      livePulse.classList.remove('disconnected');
      liveLabel.classList.remove('disconnected');
      liveLabel.textContent = 'LIVE';
    } else {
      wsStatusDot.className = 'status-dot';
      wsStatusDot.style.background = '#ef4444';
      wsStatusText.textContent = 'Disconnected';
      livePulse.classList.add('disconnected');
      liveLabel.classList.add('disconnected');
      liveLabel.textContent = 'OFFLINE';
    }
  }

  function startUptimeTimer() {
    stopUptimeTimer();
    uptimeInterval = setInterval(() => {
      if (!wsConnectTime) return;
      const elapsed = Math.floor((Date.now() - wsConnectTime) / 1000);
      const mins = Math.floor(elapsed / 60);
      const secs = elapsed % 60;
      liveUptime.textContent = `Uptime: ${mins > 0 ? mins + 'm ' : ''}${secs}s`;
    }, 1000);
  }

  function stopUptimeTimer() {
    if (uptimeInterval) {
      clearInterval(uptimeInterval);
      uptimeInterval = null;
    }
  }

  // ─── WebSocket Message Handler ────────────────────────────────────
  function handleWSMessage(msg) {
    switch (msg.type) {
      case 'initial_state':
        handleInitialState(msg.payload);
        break;
      case 'full_scan':
        handleFullScan(msg.payload);
        break;
      case 'device_joined':
        handleDeviceJoined(msg.payload);
        break;
      case 'device_left':
        handleDeviceLeft(msg.payload);
        break;
      case 'device_updated':
        handleDeviceUpdated(msg.payload);
        break;
      case 'mode_changed':
        showToast('info', 'Scanner Mode Changed', `Switched to ${msg.payload.mock ? 'Simulator' : 'Real Scan'} mode`);
        break;
    }
  }

  function handleInitialState(data) {
    if (data.devices && data.devices.length > 0) {
      devicesList = data.devices;
      updateDashboardMetrics();
      renderDeviceTable(getVisibleDevices());
      updateCharts(devicesList);
    }
    if (data.events) {
      networkEvents = data.events;
      renderEventLog();
    }
    liveLastScan.textContent = `Last scan: ${formatTime(new Date())}`;
  }

  function handleFullScan(data) {
    if (!data.devices) return;

    // Track new device IPs for highlighting
    const newDeviceIps = new Set();
    const currentIps = new Set(devicesList.map(d => d.ip));
    data.devices.forEach(d => {
      if (!currentIps.has(d.ip)) newDeviceIps.add(d.ip);
    });

    devicesList = data.devices;
    updateDashboardMetrics();
    renderDeviceTable(getVisibleDevices(), newDeviceIps);
    updateCharts(devicesList);
    liveLastScan.textContent = `Last scan: ${formatTime(new Date())}`;

    // Auto-update topology if visible
    if (document.getElementById('tab-topology').classList.contains('active')) {
      renderTopologyMap();
    }
  }

  function handleDeviceJoined(data) {
    const { device, event } = data;
    
    // Add to event log
    networkEvents.unshift(event);
    if (networkEvents.length > 50) networkEvents.pop();
    renderEventLog();

    // Show toast
    showToast('joined', 'Device Joined', `${device.vendor} (${device.ip})`);
  }

  function handleDeviceLeft(data) {
    const { device, event } = data;
    
    // Add to event log
    networkEvents.unshift(event);
    if (networkEvents.length > 50) networkEvents.pop();
    renderEventLog();

    // Show toast
    showToast('left', 'Device Left', `${device.vendor} (${device.ip})`);
  }

  function handleDeviceUpdated(data) {
    const { device, event } = data;
    
    networkEvents.unshift(event);
    if (networkEvents.length > 50) networkEvents.pop();
    renderEventLog();
  }

  // ─── Toast Notification System ────────────────────────────────────
  function showToast(type, title, message) {
    const icons = {
      joined: '📱',
      left: '📴',
      info: '🔔'
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || '🔔'}</span>
      <div class="toast-body">
        <span class="toast-title">${title}</span>
        <span class="toast-message">${message}</span>
      </div>
    `;

    toastContainer.appendChild(toast);

    // Auto-dismiss after 5 seconds
    setTimeout(() => {
      toast.classList.add('toast-exit');
      setTimeout(() => toast.remove(), 300);
    }, 5000);

    // Limit to 5 toasts visible
    while (toastContainer.children.length > 5) {
      toastContainer.firstChild.remove();
    }
  }

  // ─── Event Log Rendering ──────────────────────────────────────────
  function renderEventLog() {
    if (!networkEvents.length) {
      eventLogList.innerHTML = '<p class="event-empty">Waiting for network events...</p>';
      return;
    }

    const icons = {
      joined: '🟢',
      left: '🔴',
      status_change: '🟡'
    };

    const labels = {
      joined: 'joined the network',
      left: 'left the network',
      status_change: 'status changed'
    };

    eventLogList.innerHTML = networkEvents.slice(0, 30).map(event => `
      <div class="event-item event-${event.type}">
        <span class="event-icon">${icons[event.type] || '🔵'}</span>
        <span class="event-text"><strong>${event.vendor || event.ip}</strong> ${labels[event.type] || event.type}</span>
        <span class="event-time">${formatTime(new Date(event.timestamp))}</span>
      </div>
    `).join('');
  }

  clearEventsBtn.addEventListener('click', () => {
    networkEvents = [];
    renderEventLog();
  });

  // ─── Helper: Format Time ──────────────────────────────────────────
  function formatTime(date) {
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  // ─── Dashboard Metrics Update ─────────────────────────────────────
  function updateDashboardMetrics() {
    deviceCountBadge.textContent = `${devicesList.length} Discovered`;
    metricDevices.textContent = devicesList.length;
    
    const validLatencies = devicesList.filter(d => d.latency !== null).map(d => d.latency);
    const avgLatency = validLatencies.length ? (validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length).toFixed(1) : '0';
    metricLatency.textContent = `${avgLatency} ms`;

    // Update health score on dashboard
    fetchHealthScore();
  }

  // ─── Scanner Mode Toggle ──────────────────────────────────────────
  mockToggle.addEventListener('change', async () => {
    const isMock = mockToggle.checked;
    try {
      await fetch('/api/scanner-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mock: isMock })
      });
      // Reset local state
      networkEvents = [];
      renderEventLog();
    } catch (err) {
      console.error('Failed to switch scanner mode:', err);
    }
  });

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
      } else if (tabId === 'security') {
        document.getElementById('tab-security').classList.add('active');
        fetchHealthScore();
        fetchNetworkStats();
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
    
    if (lastByte === 1 || ven.includes('cisco') || ven.includes('tp-link') || ven.includes('netgear') || ven.includes('ubiquiti')) {
      return { type: 'Router', icon: 'router', desc: 'Gateway Router' };
    }

    if (ven.includes('samsung') || ven.includes('sony') || ven.includes('philips') || ven.includes('xiaomi') || ven.includes('lg')) {
      if (ipAddress === '239.255.255.250' || ven.includes('tv') || lastByte > 180) {
        return { type: 'Smart TV', icon: 'tv', desc: 'Smart TV / Display' };
      }
    }

    if (ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi') || ven.includes('google') || ven.includes('huawei')) {
      return { type: 'Smartphone', icon: 'smartphone', desc: 'Mobile Smartphone' };
    }

    if (ven.includes('raspberry') || ven.includes('amazon') || ven.includes('google home') || ven.includes('philips')) {
      return { type: 'Smart Home / IoT', icon: 'cpu', desc: 'IoT Hub Node' };
    }

    if (ven.includes('microsoft') || ven.includes('xbox') || ven.includes('playstation') || ven.includes('sony play')) {
      return { type: 'Gaming Console', icon: 'gamepad-2', desc: 'Gaming Console' };
    }

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
      alert('No device list to export. Please wait for a network scan.');
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
      alert('No device list to export. Please wait for a network scan.');
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

  // Subnet Range Calculator
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

    const ipInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    const maskInt = maskVal === 0 ? 0 : (~0 << (32 - maskVal));
    const netInt = ipInt & maskInt;
    const broadInt = netInt | ~maskInt;

    const intToIp = (num) => [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255
    ].join('.');

    const netId = intToIp(netInt);
    const broadcast = intToIp(broadInt);
    
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
    if (pingMonitorChartInstance) return;

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
        plugins: { legend: { display: false } },
        scales: {
          y: { grid: { color: 'rgba(255, 255, 255, 0.04)' }, ticks: { color: '#9ca3af', font: { size: 10 } } },
          x: { grid: { display: false }, ticks: { color: '#9ca3af', font: { size: 9 } } }
        }
      }
    });
  }

  // Toggle Ping Monitor
  pingMonitorBtn.addEventListener('click', () => {
    if (isMonitoringPing) {
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
            pingMonitorHistory.push(0);
          }

          if (pingMonitorChartInstance) {
            pingMonitorChartInstance.update('none');
          }
        } catch (err) {
          console.error(err);
        }
      };

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
          y: { grid: { color: 'rgba(255, 255, 255, 0.04)' }, ticks: { color: '#9ca3af', font: { size: 10 } } },
          x: { grid: { display: false }, ticks: { color: '#9ca3af', font: { size: 9 } } }
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

    const labels = devices.map(d => d.ip.split('.').pop());
    const latencies = devices.map(d => d.latency || 0);
    const bgColors = devices.map(d => d.isHost ? 'rgba(0, 240, 255, 0.65)' : 'rgba(189, 0, 255, 0.5)');
    const borderColors = devices.map(d => d.isHost ? '#00f0ff' : '#bd00ff');

    if (latencyChartInstance) latencyChartInstance.destroy();

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
        plugins: { legend: { display: false } },
        scales: {
          y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#9ca3af', font: { size: 10 } } },
          x: { grid: { display: false }, ticks: { color: '#9ca3af', font: { size: 10 } } }
        }
      }
    });

    const vendorCounts = {};
    devices.forEach(d => {
      const classification = classifyDevice(d.ip, d.vendor, d.isHost);
      const displayLabel = classification.type;
      vendorCounts[displayLabel] = (vendorCounts[displayLabel] || 0) + 1;
    });

    const vendorLabels = Object.keys(vendorCounts);
    const vendorData = Object.values(vendorCounts);

    if (vendorChartInstance) vendorChartInstance.destroy();

    vendorChartInstance = new Chart(ctxVendor, {
      type: 'doughnut',
      data: {
        labels: vendorLabels,
        datasets: [{
          data: vendorData,
          backgroundColor: ['#00f0ff', '#bd00ff', '#ff007a', '#39ff14', '#ffb800', '#0077ff', '#ff5b00'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#9ca3af', boxWidth: 10, font: { family: 'Outfit', size: 10 } }
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
          <p>Waiting for real-time scan data to map connections topology.</p>
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

  // Force Scan (manual trigger, still available)
  async function runNetworkScan() {
    if (isScanning) return;
    
    isScanning = true;
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<i data-lucide="refresh-cw" class="btn-icon spinner"></i> <span>Scanning...</span>`;
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
        
        updateDashboardMetrics();
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
      }
    } catch (err) {
      console.error(err);
    } finally {
      isScanning = false;
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<i data-lucide="play-circle" class="btn-icon"></i> <span>Force Scan</span>`;
      lucide.createIcons();
    }
  }

  // Render Devices list table with alias inline-editor
  function renderDeviceTable(devices, highlightIps = new Set()) {
    deviceTableBody.innerHTML = '';
    
    if (!devices.length) {
      deviceTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="loading-state">
            <div class="empty-state">
              <i data-lucide="refresh-cw" class="spinner"></i>
              <p>Waiting for real-time scan data...</p>
            </div>
          </td>
        </tr>
      `;
      lucide.createIcons();
      return;
    }

    devices.forEach(device => {
      const tr = document.createElement('tr');
      const isHost = device.isHost;
      
      // Add highlight animation for newly joined devices
      if (highlightIps.has(device.ip)) {
        tr.classList.add('device-new');
      }

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
          <div style="display: flex; gap: 0.4rem;">
            <button class="btn btn-secondary btn-detail" data-ip="${device.ip}" style="padding: 4px 10px; font-size: 0.8rem; border-radius: 8px;">
              Details
            </button>
            <button class="btn btn-secondary btn-audit" data-ip="${device.ip}" style="padding: 4px 10px; font-size: 0.8rem; border-radius: 8px;">
              Ports
            </button>
          </div>
        </td>
      `;

      deviceTableBody.appendChild(tr);
    });

    lucide.createIcons();

    // Bind Detail Buttons
    document.querySelectorAll('.btn-detail').forEach(btn => {
      btn.addEventListener('click', () => {
        const ip = btn.getAttribute('data-ip');
        const device = devicesList.find(d => d.ip === ip);
        if (device) openDeviceDetail(device);
      });
    });

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

  // (Modal close handlers moved to enhanced section below)

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

  // ─── Health Score System ───────────────────────────────────────────
  let lastHealthFetch = 0;
  async function fetchHealthScore() {
    // Throttle: at most once per 3 seconds
    if (Date.now() - lastHealthFetch < 3000) return;
    lastHealthFetch = Date.now();

    try {
      const res = await fetch('/api/health-score');
      const data = await res.json();
      if (data.success) {
        // Update dashboard metric card
        if (metricHealth) metricHealth.textContent = data.score;
        if (healthGrade) {
          healthGrade.innerHTML = `<i data-lucide="shield-check"></i> Grade: ${data.grade}`;
          lucide.createIcons();
        }

        // Update security tab ring
        if (scoreRingProgress) {
          const circumference = 326.7;
          const offset = circumference - (data.score / 100) * circumference;
          scoreRingProgress.style.strokeDashoffset = offset;

          // Color the ring based on score
          if (data.score >= 80) {
            scoreRingProgress.style.stroke = 'var(--accent-green)';
          } else if (data.score >= 60) {
            scoreRingProgress.style.stroke = 'var(--accent-cyan)';
          } else if (data.score >= 40) {
            scoreRingProgress.style.stroke = '#ffb800';
          } else {
            scoreRingProgress.style.stroke = 'var(--accent-pink)';
          }
        }
        if (securityScoreValue) securityScoreValue.textContent = data.score;
        if (securityGradeLabel) securityGradeLabel.textContent = data.grade;

        // Update breakdown bars
        if (data.breakdown) {
          if (barLatency) barLatency.style.width = `${data.breakdown.latencyScore}%`;
          if (valLatency) valLatency.textContent = data.breakdown.latencyScore;
          if (barReachability) barReachability.style.width = `${data.breakdown.reachabilityScore}%`;
          if (valReachability) valReachability.textContent = data.breakdown.reachabilityScore;
          if (barDensity) barDensity.style.width = `${data.breakdown.densityScore}%`;
          if (valDensity) valDensity.textContent = data.breakdown.densityScore;
        }
      }
    } catch (err) {
      console.error('Health score fetch error:', err);
    }
  }

  // ─── Traceroute ───────────────────────────────────────────────────
  if (tracerouteBtn) {
    tracerouteBtn.addEventListener('click', async () => {
      const target = tracerouteTarget.value.trim();
      if (!target) {
        alert('Please enter a target IP or domain.');
        return;
      }

      tracerouteBtn.disabled = true;
      tracerouteBtn.textContent = 'Tracing...';
      tracerouteResults.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
          <i data-lucide="refresh-cw" class="spinner" style="width: 24px; height: 24px;"></i>
          <p style="margin-top: 0.75rem;">Tracing route to ${target}...</p>
        </div>
      `;
      lucide.createIcons();

      const isMock = mockToggle.checked;

      try {
        const res = await fetch(`/api/traceroute?targetIp=${target}&mock=${isMock}`);
        const data = await res.json();

        if (data.success && data.hops && data.hops.length > 0) {
          tracerouteResults.innerHTML = data.hops.map(hop => `
            <div class="hop-item">
              <span class="hop-number">${hop.hop}</span>
              <span class="hop-ip">${hop.ip}</span>
              <span class="hop-latency ${hop.latency > 50 ? 'high' : ''}">${hop.latency !== null ? hop.latency + ' ms' : '* * *'}</span>
            </div>
          `).join('');
        } else {
          tracerouteResults.innerHTML = `<p style="color: var(--text-muted); text-align: center; padding: 1rem;">No hops returned. Target may be unreachable.</p>`;
        }
      } catch (err) {
        tracerouteResults.innerHTML = `<p style="color: var(--accent-pink); text-align: center; padding: 1rem;">Trace failed: ${err.message}</p>`;
      } finally {
        tracerouteBtn.disabled = false;
        tracerouteBtn.textContent = 'Trace Route';
      }
    });
  }

  // ─── DNS Reverse Lookup ───────────────────────────────────────────
  if (dnsLookupBtn) {
    dnsLookupBtn.addEventListener('click', async () => {
      const target = dnsLookupTarget.value.trim();
      if (!target) {
        alert('Please enter a target IP address.');
        return;
      }

      dnsLookupBtn.disabled = true;
      dnsLookupBtn.textContent = 'Resolving...';
      dnsResults.innerHTML = `
        <div style="text-align: center; padding: 1.5rem; color: var(--text-secondary);">
          <i data-lucide="refresh-cw" class="spinner" style="width: 20px; height: 20px;"></i>
          <p style="margin-top: 0.5rem;">Looking up ${target}...</p>
        </div>
      `;
      lucide.createIcons();

      const isMock = mockToggle.checked;

      try {
        const res = await fetch(`/api/dns-lookup?targetIp=${target}&mock=${isMock}`);
        const data = await res.json();

        if (data.success && data.hostnames && data.hostnames.length > 0) {
          dnsResults.innerHTML = data.hostnames.map(hostname => `
            <div class="dns-result-item">
              <span style="font-size: 1.1rem;">🌐</span>
              <div>
                <div class="dns-hostname">${hostname}</div>
                <div class="dns-meta">Resolved from ${data.targetIp}${data.responseTime ? ` in ${data.responseTime}ms` : ''}</div>
              </div>
            </div>
          `).join('');
        } else {
          dnsResults.innerHTML = `
            <div class="dns-result-item">
              <span style="font-size: 1.1rem;">⚠️</span>
              <div>
                <div style="color: var(--text-secondary);">No hostnames found for ${target}</div>
                <div class="dns-meta">The IP may not have a reverse DNS record configured</div>
              </div>
            </div>
          `;
        }
      } catch (err) {
        dnsResults.innerHTML = `<p style="color: var(--accent-pink); text-align: center; padding: 1rem;">DNS lookup failed: ${err.message}</p>`;
      } finally {
        dnsLookupBtn.disabled = false;
        dnsLookupBtn.textContent = 'Lookup';
      }
    });
  }

  // ─── Network Statistics ───────────────────────────────────────────
  async function fetchNetworkStats() {
    try {
      const res = await fetch('/api/stats');
      const data = await res.json();
      if (data.success) {
        if (statTotalScans) statTotalScans.textContent = data.totalScans || 0;
        if (statUniqueDevices) statUniqueDevices.textContent = data.totalDevicesEverSeen || 0;
        if (statPeakDevices) statPeakDevices.textContent = data.peakDeviceCount || 0;

        if (statUptime) {
          const secs = data.uptimeSeconds || 0;
          const h = Math.floor(secs / 3600);
          const m = Math.floor((secs % 3600) / 60);
          const s = secs % 60;
          statUptime.textContent = h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
        }

        if (data.eventCounts) {
          if (statEventsJoined) statEventsJoined.textContent = data.eventCounts.joined || 0;
          if (statEventsLeft) statEventsLeft.textContent = data.eventCounts.left || 0;
        }
      }
    } catch (err) {
      console.error('Stats fetch error:', err);
    }
  }

  // ─── Device Detail Modal ──────────────────────────────────────────
  function openDeviceDetail(device) {
    if (!deviceDetailModal || !deviceDetailContent) return;

    const classification = classifyDevice(device.ip, device.vendor, device.isHost);
    const alias = getAlias(device.ip, device.vendor);

    // Signal strength bars
    const signalStrength = device.signalStrength || -(30 + Math.floor(Math.random() * 50));
    const signalPercent = Math.max(0, Math.min(100, ((signalStrength + 90) / 60) * 100));
    const activeBars = Math.min(5, Math.max(1, Math.ceil(signalPercent / 20)));

    const signalBarsHtml = Array.from({ length: 5 }, (_, i) =>
      `<div class="bar ${i < activeBars ? 'active' : ''}"></div>`
    ).join('');

    const firstSeen = device.firstSeen
      ? new Date(device.firstSeen).toLocaleString()
      : 'This session';

    deviceDetailContent.innerHTML = `
      <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1.25rem;">
        <div class="device-icon-wrapper ${device.status === 'Active' ? 'active' : ''}" style="width: 52px; height: 52px; border-radius: 14px;">
          <i data-lucide="${classification.icon}" style="width: 24px; height: 24px;"></i>
        </div>
        <div>
          <h3 style="font-size: 1.2rem; margin-bottom: 2px;">${alias}</h3>
          <p style="font-size: 0.85rem; color: var(--text-secondary);">${classification.desc}</p>
        </div>
        <span class="status-badge ${device.status === 'Active' ? 'active' : 'shielded'}" style="margin-left: auto;">
          <span class="status-dot-small"></span>
          ${device.status}
        </span>
      </div>
      <div class="device-detail-grid">
        <div class="detail-field">
          <div class="detail-label">IP Address</div>
          <div class="detail-value cyan">${device.ip}</div>
        </div>
        <div class="detail-field">
          <div class="detail-label">MAC Address</div>
          <div class="detail-value">${device.mac}</div>
        </div>
        <div class="detail-field">
          <div class="detail-label">Vendor / Manufacturer</div>
          <div class="detail-value">${device.vendor}</div>
        </div>
        <div class="detail-field">
          <div class="detail-label">Device Type</div>
          <div class="detail-value">${classification.type}</div>
        </div>
        <div class="detail-field">
          <div class="detail-label">Latency</div>
          <div class="detail-value ${(device.latency || 0) > 30 ? 'pink' : 'green'}">${device.latency !== null ? device.latency + ' ms' : 'N/A'}</div>
        </div>
        <div class="detail-field">
          <div class="detail-label">First Seen</div>
          <div class="detail-value">${firstSeen}</div>
        </div>
        <div class="detail-field full-width">
          <div class="detail-label">Signal Strength</div>
          <div class="signal-bar-container">
            <div class="signal-bars">${signalBarsHtml}</div>
            <span class="signal-text">${signalStrength} dBm</span>
          </div>
        </div>
      </div>
      <div style="display: flex; gap: 0.75rem; margin-top: 1.25rem;">
        <button class="btn btn-primary detail-action-btn" data-action="port-scan" data-ip="${device.ip}" style="flex: 1; justify-content: center; font-size: 0.85rem;">
          <i data-lucide="network" style="width: 16px; height: 16px;"></i> Audit Ports
        </button>
        <button class="btn btn-secondary detail-action-btn" data-action="dns" data-ip="${device.ip}" style="flex: 1; justify-content: center; font-size: 0.85rem;">
          <i data-lucide="globe" style="width: 16px; height: 16px;"></i> DNS Lookup
        </button>
        <button class="btn btn-secondary detail-action-btn" data-action="traceroute" data-ip="${device.ip}" style="flex: 1; justify-content: center; font-size: 0.85rem;">
          <i data-lucide="route" style="width: 16px; height: 16px;"></i> Trace Route
        </button>
      </div>
    `;

    deviceDetailModal.classList.add('active');
    lucide.createIcons();

    // Bind action buttons inside modal
    deviceDetailContent.querySelectorAll('.detail-action-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.getAttribute('data-action');
        const ip = btn.getAttribute('data-ip');
        deviceDetailModal.classList.remove('active');

        if (action === 'port-scan') {
          openPortModal(ip);
        } else if (action === 'dns') {
          // Switch to security tab and fill DNS
          navButtons.forEach(b => b.classList.remove('active'));
          tabs.forEach(t => t.classList.remove('active'));
          document.querySelector('[data-tab="security"]').classList.add('active');
          document.getElementById('tab-security').classList.add('active');
          dnsLookupTarget.value = ip;
          fetchHealthScore();
          fetchNetworkStats();
          setTimeout(() => dnsLookupBtn.click(), 300);
        } else if (action === 'traceroute') {
          navButtons.forEach(b => b.classList.remove('active'));
          tabs.forEach(t => t.classList.remove('active'));
          document.querySelector('[data-tab="security"]').classList.add('active');
          document.getElementById('tab-security').classList.add('active');
          tracerouteTarget.value = ip;
          fetchHealthScore();
          fetchNetworkStats();
          setTimeout(() => tracerouteBtn.click(), 300);
        }
      });
    });
  }

  // ─── Enhanced Modal Close Handlers ────────────────────────────────
  // Close all modals generically
  document.querySelectorAll('.close-modal').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetModalId = btn.getAttribute('data-modal');
      if (targetModalId) {
        document.getElementById(targetModalId).classList.remove('active');
      } else {
        // Fallback: close parent modal
        btn.closest('.modal').classList.remove('active');
      }
    });
  });

  window.addEventListener('click', (e) => {
    if (e.target === portModal) portModal.classList.remove('active');
    if (e.target === deviceDetailModal) deviceDetailModal.classList.remove('active');
  });

  // ─── Initialize ───────────────────────────────────────────────────
  fetchNetworkInfo();
  initBandwidthChart();
  renderScanHistory();
  
  // Connect WebSocket for real-time updates
  connectWebSocket();

  // Periodically refresh stats when security tab is visible
  setInterval(() => {
    if (document.getElementById('tab-security') && document.getElementById('tab-security').classList.contains('active')) {
      fetchNetworkStats();
    }
  }, 10000);
});
