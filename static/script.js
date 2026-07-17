const STATUS_REFRESH_INTERVAL_MS = 15000;
const STATUS_POLL_INTERVAL_MS = 1000;
const STATUS_CLASSES = ['status-online', 'status-offline', 'status-error', 'status-unknown', 'status-checking'];

let previousStatus = {};

document.addEventListener('DOMContentLoaded', function() {
    const currentYear = document.getElementById('current-year');
    if (currentYear) {
        currentYear.textContent = new Date().getFullYear();
    }

    syncCsrfFields();
    checkStatus().catch(() => {});
    setInterval(() => checkStatus().catch(() => {}), STATUS_REFRESH_INTERVAL_MS);

    const refreshButton = document.getElementById('refresh-status-btn');
    if (refreshButton) {
        refreshButton.addEventListener('click', async function() {
            refreshButton.disabled = true;
            refreshButton.textContent = 'Refreshing…';
            try {
                await checkStatus('*');
            } catch {
                // checkStatus already presents an actionable error in the page.
            } finally {
                refreshButton.disabled = false;
                refreshButton.textContent = 'Refresh';
            }
        });
    }

    document.querySelectorAll('.wake-form').forEach(form => {
        form.addEventListener('submit', handleWakeSubmit);
    });
});

function getDeviceCard(computerName) {
    return Array.from(document.querySelectorAll('.device-card')).find(card => card.dataset.computerName === computerName) || null;
}

function buildStatusUrl(refreshComputer) {
    const url = new URL('/status', window.location.origin);
    url.searchParams.set('details', '1');
    if (refreshComputer) {
        url.searchParams.append('refresh', refreshComputer);
    }
    return url;
}

async function checkStatus(refreshComputer = null) {
    const statusMessage = document.getElementById('status-message');

    try {
        const response = await fetch(buildStatusUrl(refreshComputer), {
            cache: 'no-store',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
            },
        });

        if (response.status === 304) {
            return null;
        }
        if (!response.ok) {
            const errorText = await readErrorResponse(response);
            throw new Error(errorText || `Status request failed with status ${response.status}`);
        }

        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            throw new Error('Status request returned an unexpected response type');
        }

        const data = await response.json();
        for (const [computerName, status] of Object.entries(data)) {
            const statusKey = JSON.stringify(status);
            if (previousStatus[computerName] !== statusKey) {
                updateStatusDisplay(computerName, status);
                previousStatus[computerName] = statusKey;
            }
        }

        if (statusMessage) {
            statusMessage.textContent = '';
            setMessageClass(statusMessage, null);
        }
        return data;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Status check failed.';
        if (statusMessage) {
            statusMessage.textContent = message;
            setMessageClass(statusMessage, 'error');
        }
        if (!refreshComputer) {
            document.querySelectorAll('.device-card').forEach(card => {
                setCardStatus(card, 'ERROR', {error: 'Wake server is unavailable'});
            });
        }
        throw error;
    }
}

function updateStatusDisplay(computerName, status) {
    const card = getDeviceCard(computerName);
    if (!card) {
        return;
    }

    const details = typeof status === 'string' ? {state: status} : status;
    setCardStatus(card, details.state || 'UNKNOWN', details);
}

function setCardStatus(card, state, details = {}) {
    const statusDot = card.querySelector('.status-dot');
    const statusText = card.querySelector('.status-text');
    const statusMeta = card.querySelector('.status-meta');
    const states = {
        UP: {label: 'Online', className: 'status-online'},
        DOWN: {label: 'Offline', className: 'status-offline'},
        ERROR: {label: 'Check failed', className: 'status-error'},
        UNKNOWN: {label: 'Not monitored', className: 'status-unknown'},
    };
    const display = states[state] || {label: 'Checking', className: 'status-checking'};

    for (const element of [statusDot, statusText]) {
        if (!element) {
            continue;
        }
        element.classList.remove(...STATUS_CLASSES);
        element.classList.add(display.className);
    }
    if (statusText) {
        statusText.textContent = display.label;
    }

    if (!statusMeta) {
        return;
    }
    if (state === 'UNKNOWN') {
        statusMeta.textContent = 'Status verification is disabled.';
        return;
    }
    const metadata = [];
    if (details.checked_at) {
        metadata.push(`Checked ${formatTimestamp(details.checked_at)}`);
    }
    if (typeof details.latency_ms === 'number') {
        metadata.push(`${details.latency_ms.toFixed(1)} ms`);
    }
    if (state === 'DOWN' && details.last_online) {
        metadata.push(`last online ${formatTimestamp(details.last_online)}`);
    }
    if (details.error) {
        metadata.push(details.error);
    }
    statusMeta.textContent = metadata.join(' · ') || 'Status verification is disabled.';
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }
    return date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
}

function getCookie(name) {
    const encodedName = `${name}=`;
    const cookies = document.cookie.split(';');

    for (const cookie of cookies) {
        const trimmed = cookie.trim();
        if (trimmed.startsWith(encodedName)) {
            return decodeURIComponent(trimmed.substring(encodedName.length));
        }
    }
    return '';
}

function syncCsrfFields() {
    const csrfToken = getCookie('flasgo-csrf');
    document.querySelectorAll('.csrf-token-field').forEach(field => {
        field.value = csrfToken;
    });
    return csrfToken;
}

function buildWakeRequestBody(form, csrfToken) {
    const formData = new FormData(form);
    formData.set('x-csrf-token', csrfToken);
    return new URLSearchParams(formData);
}

async function handleWakeSubmit(event) {
    event.preventDefault();

    const form = event.currentTarget;
    const card = form.closest('.device-card');
    const message = card ? card.querySelector('.wake-message') : null;
    const submitButton = form.querySelector('button[type="submit"]');
    const buttonLabel = submitButton ? submitButton.querySelector('span') : null;
    const computerName = card ? card.dataset.computerName : '';
    const csrfToken = syncCsrfFields();

    if (!csrfToken) {
        showWakeMessage(message, 'Missing CSRF token. Refresh the page and try again.', 'error');
        return;
    }

    setWakeButtonState(submitButton, buttonLabel, true, 'Sending…');
    showWakeMessage(message, '', null);
    let packetSent = false;

    try {
        const response = await fetch(form.action || '/', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': csrfToken,
            },
            body: buildWakeRequestBody(form, csrfToken),
            credentials: 'same-origin',
        });

        if (!response.ok) {
            const errorText = await readErrorResponse(response);
            throw new Error(errorText || `Wake request failed with status ${response.status}`);
        }

        const result = await response.json();
        packetSent = true;
        if (result.probe === 'none') {
            showWakeMessage(message, 'Wake packet sent. Status verification is disabled.', 'success');
            return;
        }

        const timeoutSeconds = Number(result.verification_timeout_seconds) || 30;
        setWakeButtonState(submitButton, buttonLabel, true, 'Waiting…');
        showWakeMessage(message, 'Wake packet sent. Waiting for the device to come online…', 'warning');
        await waitForDevice(computerName, timeoutSeconds, message);
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Wake request failed.';
        const prefix = packetSent ? 'Wake packet sent, but status verification failed: ' : '';
        showWakeMessage(message, `${prefix}${errorMessage}`, packetSent ? 'warning' : 'error');
    } finally {
        setWakeButtonState(submitButton, buttonLabel, false, 'Wake');
    }
}

async function waitForDevice(computerName, timeoutSeconds, message) {
    const started = Date.now();
    const deadline = started + timeoutSeconds * 1000;

    while (Date.now() < deadline) {
        await delay(STATUS_POLL_INTERVAL_MS);
        const data = await checkStatus(computerName);
        const status = data && data[computerName];
        const details = typeof status === 'string' ? {state: status} : status;

        if (details && details.state === 'UP') {
            const elapsedSeconds = Math.max(1, Math.round((Date.now() - started) / 1000));
            showWakeMessage(message, `Device came online after ${elapsedSeconds} seconds.`, 'success');
            return;
        }
        if (details && details.state === 'ERROR') {
            showWakeMessage(message, `Wake packet sent, but verification failed: ${details.error || 'status probe error'}.`, 'warning');
            return;
        }
    }

    showWakeMessage(message, `Wake packet sent, but the device did not come online within ${timeoutSeconds} seconds.`, 'warning');
}

function delay(milliseconds) {
    return new Promise(resolve => window.setTimeout(resolve, milliseconds));
}

async function readErrorResponse(response) {
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        const payload = await response.json();
        return payload.error || '';
    }
    return response.text();
}

function setWakeButtonState(button, label, disabled, text) {
    if (button) {
        button.disabled = disabled;
    }
    if (label) {
        label.textContent = text;
    }
}

function showWakeMessage(element, text, type) {
    if (!element) {
        return;
    }
    element.textContent = text;
    setMessageClass(element, type);
}

function setMessageClass(element, type) {
    element.classList.remove('message-success', 'message-error', 'message-warning');
    if (type) {
        element.classList.add(`message-${type}`);
    }
}
