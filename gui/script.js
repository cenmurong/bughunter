function startIndexings() {
    console.log("Starting indexing...");
    eel.start_indexing();
    updateStatus("Running indexing...");
}
let tempUrl = '';
function startFullScan() {
    const url = document.getElementById('url').value;
    console.log("Starting full scan with URL:", url);
    if (!url) {
        eel.gui_log("error", "URL cannot be empty");
        return;
    }
    tempUrl = url;
    document.getElementById('ssrfModal').style.display = 'flex';
}
function executeFullScan(includeSSRF) {
    console.log("Executing full scan, includeSSRF:", includeSSRF, "with URL:", tempUrl);
    document.getElementById('ssrfModal').style.display = 'none';
    if (!tempUrl) {
        console.error("No URL stored for full scan");
        eel.gui_log("error", "No URL stored for full scan");
        return;
    }
    try {
        console.log("Calling eel.start_scan with:", { full_scan: true, url: tempUrl, module: null, includeSSRF });
        eel.execute_scan_thread(true, tempUrl, null, includeSSRF, function(result) {
            console.log("Scan result callback:", result);
            if (result) {
                updateStatus("Full scan completed successfully");
            } else {
                updateStatus("Full scan failed or stopped");
            }
        });
    } catch (err) {
        console.error("Error in executeFullScan:", err);
        eel.gui_log("error", `Failed to start scan: ${err.message}`);
    }
    tempUrl = '';
}
function startSpecificScan() {
    const url = document.getElementById('url').value;
    const module = document.getElementById('module').value;
    if (!url) {
        eel.gui_log("error", "URL cannot be empty");
        return;
    }
    console.log("Starting specific scan with URL:", url, "Additional Modules:", module || "none (defaults will be used)");
    eel.start_scan(false, url, module || null, true, function(result) {
        console.log("Specific scan result:", result);
        if (result) {
            updateStatus(`Specific scan completed`);
        } else {
            updateStatus(`Specific scan failed or was stopped`);
        }
    });
    updateStatus(`Running specific scan...`);
}
function startProxyDownloader() {
    const count = document.getElementById('proxyCount').value;
    console.log("Starting proxy downloader with count:", count);
    eel.start_proxy_downloader(count, function(result) {
        console.log("Proxy download result:", result);
        if (result) {
            updateStatus("Proxy download completed");
        } else {
            updateStatus("Proxy download failed");
        }
    });
    updateStatus("Downloading proxies...");
}
function stopProcess() {
    console.log("Stopping process...");
    eel.stop_process();
}
function clearLog() {
    const logDiv = document.getElementById('log');
    logDiv.innerHTML = '';
    eel.gui_log('info', 'Log cleared.');
}
function resetGuiState() {
    document.getElementById('url').value = '';
    document.getElementById('module').value = '';
    document.getElementById('proxyCount').value = '0';
    return null;
}
function addLog(message, color) {
    const logDiv = document.getElementById('log');
    const p = document.createElement('p');
    p.style.color = color;
    p.textContent = message;
    logDiv.appendChild(p);
    logDiv.scrollTop = logDiv.scrollHeight;
    return null;
}
function updateStatus(status) {
    document.getElementById('status').textContent = status + ` [${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}]`;
    return null;
}
function updateStopButtonState(enabled) {
    document.getElementById('stopButton').disabled = !enabled;
    return null;
}
function showDialog(message, type, callback) {
    if (type === "input") {
        const userInput = prompt(message);
        if (userInput !== null) {
            callback(userInput);
        }
    }
}
function showDialogOptions(title, options, callback, is_multiple_choice = false) {
    let prompt_message = title;
    if (options && options.length > 0) {
        prompt_message += `\n${options.map((opt, idx) => `${idx + 1}. ${opt}`).join('\n')}`;
        if (is_multiple_choice) {
            prompt_message += `\n\nEnter numbers separated by comma (e.g., 1,2):`;
        } else {
            prompt_message += `\n\nEnter number (1-${options.length}):`;
        }
    } else {
    }
    const userInput = prompt(prompt_message);
    if (userInput === null || userInput.trim() === '') {
        callback(null);
        return;
    }
    const indices = userInput.split(',').map(n => parseInt(n.trim()) - 1);
    const selectedOptions = indices
        .filter(idx => !isNaN(idx) && idx >= 0 && idx < options.length)
        .map(idx => options[idx]);
    if (selectedOptions.length > 0) {
        callback(selectedOptions);
    } else {
        callback(null);
    }
}
if (eel && eel._websocket) {
    const originalOnMessage = eel._websocket.onmessage;
    eel._websocket.onmessage = function (e) {
        let message = JSON.parse(e.data);
        console.log("Received message from Python:", message);
        if (message.hasOwnProperty('call')) {
            if (message.name in eel._exposed_functions) {
                try {
                    let return_val = eel._exposed_functions[message.name](...message.args);
                    eel._websocket.send(eel._toJSON({
                        'return': message.call,
                        'status': 'ok',
                        'value': return_val !== undefined ? return_val : null
                    }));
                } catch (err) {
                    console.error('JavaScript Error:', err);
                    eel._websocket.send(eel._toJSON({
                        'return': message.call,
                        'status': 'error',
                        'value': null,
                        'error': err.message,
                        'stack': err.stack
                    }));
                }
            }
        } else {
            originalOnMessage.apply(this, arguments);
        }
    };
}
eel.expose(addLog);
eel.expose(updateStatus);
eel.expose(resetGuiState);
eel.expose(updateStopButtonState);
eel.expose(showDialog);
eel.expose(showDialogOptions);
eel.expose(startProgress);
eel.expose(updateProgress);
eel.expose(completeTask);

function showSsrfsModal() {
    console.log("Showing SSRF modal from Python call.");
    document.getElementById('ssrfModal').style.display = 'flex';
}

eel.expose(showSsrfsModal);