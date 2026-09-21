(() => {
  'use strict';

  const PROFILE_NAMES = [
    'ALFA', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot', 'Golf', 'Hotel', 'India', 'Juliet',
    'Kilo', 'Lima', 'Mike', 'November', 'Oscar', 'Papa', 'Romeo', 'Quadec', 'Sierra', 'Tango',
    'Uniform', 'Victor', 'Whisky', 'X-ray', 'Yankee', 'Zulu', 'Sentinel', 'Patrol', 'Response',
    'Guardian', 'Control'
  ];

  const usernameInput = document.querySelector('#usernameInput');
  const hardwareUuidInput = document.querySelector('#hardwareUuidInput');
  const connectButton = document.querySelector('#connectButton');
  const connectionBadge = document.querySelector('#connectionBadge');
  const connectionText = document.querySelector('#connectionText');
  const connectionMessage = document.querySelector('#connectionMessage');
  const identityState = document.querySelector('#identityState');
  const channelInput = document.querySelector('#channelInput');
  const pttButton = document.querySelector('#pttButton');
  const pttLabel = document.querySelector('#pttLabel');
  const pttHint = document.querySelector('#pttHint');
  const transmitReadout = document.querySelector('#transmitReadout');
  const directoryGrid = document.querySelector('#directoryGrid');
  const onlineCount = document.querySelector('#onlineCount');
  const alertsLog = document.querySelector('#alertsLog');

  const profiles = new Map(PROFILE_NAMES.map((username) => [username, {
    username,
    role: username === 'ALFA' ? 'leader' : username === 'Control' ? 'admin' : 'user',
    status: 'offline',
    transmitting: false
  }]));

  let socket = null;
  let connected = false;
  let pressed = false;
  let overrideActive = false;
  let overrideTimer = null;

  PROFILE_NAMES.forEach((username) => {
    const option = document.createElement('option');
    option.value = username;
    option.textContent = username;
    usernameInput.appendChild(option);
  });

  const savedUsername = localStorage.getItem('alpha_ptt_username');
  const savedHardwareUuid = localStorage.getItem('alpha_ptt_hardware_uuid');
  if (PROFILE_NAMES.includes(savedUsername)) usernameInput.value = savedUsername;
  if (savedHardwareUuid) hardwareUuidInput.value = savedHardwareUuid;

  function setConnectionState(isConnected, message) {
    connected = isConnected;
    connectionBadge.classList.toggle('connected', isConnected);
    connectionBadge.classList.toggle('disconnected', !isConnected);
    connectionText.textContent = isConnected ? 'Connected' : 'Disconnected';
    identityState.textContent = isConnected ? 'ONLINE' : 'OFFLINE';
    identityState.style.color = isConnected ? 'var(--green)' : '';
    identityState.style.borderColor = isConnected ? 'var(--green-dim)' : '';
    pttButton.disabled = !isConnected || overrideActive;
    if (!isConnected) {
      pressed = false;
      setPttVisual(false);
    }
    connectionMessage.textContent = message;
  }

  function setPttVisual(active) {
    pttButton.classList.toggle('is-pressed', active);
    pttButton.classList.toggle('override', overrideActive);
    if (overrideActive) {
      pttLabel.textContent = 'ALFA OVERRIDE ACTIVE';
      pttHint.textContent = 'CHANNEL LOCKED';
      transmitReadout.textContent = 'PRIORITY TRANSMISSION';
    } else if (active) {
      pttLabel.textContent = 'TRANSMITTING';
      pttHint.textContent = 'RELEASE TO STOP';
      transmitReadout.textContent = 'OUTBOUND VOICE ACTIVE';
    } else {
      pttLabel.textContent = 'PUSH TO TALK';
      pttHint.textContent = connected ? 'HOLD TO TRANSMIT' : 'CONNECT DEVICE FIRST';
      transmitReadout.textContent = connected ? 'CHANNEL READY' : 'CHANNEL OFFLINE';
    }
  }

  function setOverrideState(active, duration = 0) {
    overrideActive = active;
    clearTimeout(overrideTimer);
    if (active && duration > 0) overrideTimer = setTimeout(() => setOverrideState(false), duration);
    pttButton.disabled = !connected || active;
    setPttVisual(false);
  }

  function renderDirectory() {
    directoryGrid.replaceChildren();
    let online = 0;
    profiles.forEach((profile) => {
      if (profile.status === 'online') online += 1;
      const card = document.createElement('article');
      card.className = `profile-card ${profile.status === 'online' ? 'online' : ''} ${profile.transmitting ? 'transmitting' : ''} ${profile.role === 'leader' ? 'leader' : ''}`;
      card.dataset.username = profile.username;
      const avatar = document.createElement('span');
      avatar.className = 'profile-avatar';
      avatar.textContent = profile.role === 'leader' ? '★' : profile.username.slice(0, 2).toUpperCase();
      const copy = document.createElement('div');
      copy.className = 'profile-copy';
      const name = document.createElement('div');
      name.className = 'profile-name';
      name.textContent = profile.username;
      const role = document.createElement('div');
      role.className = 'profile-role';
      role.textContent = profile.role === 'leader' ? 'TEAM LEADER' : profile.role === 'admin' ? 'OPERATIONS CONTROL' : profile.status.toUpperCase();
      copy.append(name, role);
      const status = document.createElement('span');
      status.className = 'profile-status';
      status.title = profile.transmitting ? 'Transmitting' : profile.status;
      card.append(avatar, copy, status);
      directoryGrid.appendChild(card);
    });
    onlineCount.textContent = `${online} / 31 ONLINE`;
  }

  function applyPresence(list) {
    if (!Array.isArray(list)) return;
    list.forEach((item) => {
      const profile = profiles.get(item.username);
      if (!profile) return;
      profile.role = item.role || profile.role;
      profile.status = item.status === 'online' ? 'online' : 'offline';
      profile.transmitting = Boolean(item.current_channel);
    });
    renderDirectory();
  }

  function markTransmitting(username, active) {
    const profile = profiles.get(username);
    if (profile) {
      profile.transmitting = active;
      if (active) profile.status = 'online';
      renderDirectory();
    }
  }

  function addAlert(alert) {
    const empty = alertsLog.querySelector('.empty-alert');
    if (empty) empty.remove();
    const entry = document.createElement('article');
    entry.className = 'alert-entry';
    const time = document.createElement('div');
    time.className = 'alert-time';
    time.textContent = new Date(alert.issued_at || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const message = document.createElement('div');
    message.className = 'alert-message';
    message.textContent = alert.message || 'Emergency broadcast received.';
    entry.append(time, message);
    alertsLog.prepend(entry);
    while (alertsLog.children.length > 8) alertsLog.lastElementChild.remove();
  }

  function disconnectSocket() {
    if (socket) {
      socket.disconnect();
      socket = null;
    }
    setConnectionState(false, 'Device disconnected. Enter credentials to reconnect.');
  }

  function connectSocket() {
    const username = usernameInput.value;
    const hardwareUuid = hardwareUuidInput.value.trim();
    if (!PROFILE_NAMES.includes(username)) {
      setConnectionState(false, 'Select one of the 31 predefined identities.');
      return;
    }
    if (hardwareUuid.length < 8) {
      setConnectionState(false, 'A valid bound hardware UUID is required.');
      hardwareUuidInput.focus();
      return;
    }
    disconnectSocket();
    localStorage.setItem('alpha_ptt_username', username);
    localStorage.setItem('alpha_ptt_hardware_uuid', hardwareUuid);
    socket = io({
      auth: { username, hardware_uuid: hardwareUuid },
      transports: ['websocket', 'polling'],
      autoConnect: false
    });
    socket.on('connect', () => {
      setConnectionState(true, `Secure link established for ${username}.`);
      connectButton.textContent = 'DISCONNECT DEVICE';
    });
    socket.on('disconnect', (reason) => {
      setConnectionState(false, `Connection closed: ${reason}.`);
      connectButton.textContent = 'CONNECT DEVICE';
    });
    socket.on('connect_error', (error) => {
      setConnectionState(false, error.message || 'Secure link rejected.');
      connectButton.textContent = 'CONNECT DEVICE';
    });
    socket.on('ptt_ready', (data) => {
      if (data?.default_channel_id) channelInput.value = data.default_channel_id;
    });
    socket.on('presence_snapshot', (data) => applyPresence(data?.profiles));
    socket.on('presence_update', (data) => applyPresence(data?.profiles));
    socket.on('ptt_started', (data) => {
      markTransmitting(data.username, true);
      if (data.override) setOverrideState(true);
    });
    socket.on('ptt_stopped', (data) => {
      markTransmitting(data.username, false);
      if (data.username === 'ALFA' || data.reason === 'stopped') setOverrideState(false);
    });
    socket.on('leader_transmitting', (data) => {
      markTransmitting('ALFA', true);
      setOverrideState(true, 30000);
      transmitReadout.textContent = `${data.interrupted_username || 'CHANNEL'} MUTED BY ALFA`;
    });
    socket.on('ptt_muted_by_leader', () => {
      pressed = false;
      setOverrideState(true, 30000);
      connectionMessage.textContent = 'Your transmission was overridden by ALFA priority traffic.';
    });
    socket.on('ptt_denied', (data) => {
      pressed = false;
      setPttVisual(false);
      connectionMessage.textContent = `Channel busy: ${data.active_username || 'another operator'} is transmitting.`;
    });
    socket.on('account_disabled', (data) => {
      pressed = false;
      setConnectionState(false, data?.reason || 'Device access disabled by command.');
      connectButton.textContent = 'CONNECT DEVICE';
    });
    socket.on('emergency_broadcast_alert', addAlert);
    socket.connect();
  }

  function startPtt(event) {
    event.preventDefault();
    if (!connected || overrideActive || pressed || !socket) return;
    pressed = true;
    setPttVisual(true);
    socket.emit('ptt_start', { username: usernameInput.value, channel_id: channelInput.value }, (ack) => {
      if (!ack?.ok) {
        pressed = false;
        setPttVisual(false);
        connectionMessage.textContent = ack?.error || 'Transmission request denied.';
      }
    });
  }

  function stopPtt(event) {
    if (event) event.preventDefault();
    if (!pressed || !socket || !connected) return;
    pressed = false;
    setPttVisual(false);
    socket.emit('ptt_stop', { channel_id: channelInput.value });
  }

  connectButton.addEventListener('click', () => {
    if (connected) disconnectSocket();
    else connectSocket();
  });
  pttButton.addEventListener('pointerdown', startPtt);
  pttButton.addEventListener('pointerup', stopPtt);
  pttButton.addEventListener('pointercancel', stopPtt);
  pttButton.addEventListener('pointerleave', (event) => { if (pressed && event.buttons === 0) stopPtt(event); });
  window.addEventListener('blur', () => stopPtt());
  renderDirectory();
})();
