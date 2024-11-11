function showPage(pageId) {
    var pages = document.getElementsByClassName('content-page');
    for (var i = 0; i < pages.length; i++) {
        pages[i].classList.remove('active');
    }
    document.getElementById(pageId).classList.add('active');

    var links = document.getElementsByClassName('sidebar-link');
    for (var j = 0; j < links.length; j++) {
        links[j].classList.remove('active');
    }
    document.querySelector('#sidebar a[data-page="' + pageId + '"]').classList.add('active');
}

// 加入事件監聽器，讓 Introduce 頁面在首次載入時顯示
document.addEventListener('DOMContentLoaded', function() {
    showPage('introduce');
});


// Fetch network interfaces and populate dropdowns
document.addEventListener('DOMContentLoaded', function () {
    fetch('/get_interfaces')
        .then(response => response.json())
        .then(data => {
            const interfaceSelect = document.getElementById('interfaceSelect');
            const wiresharkInterfaceSelect = document.getElementById('wiresharkInterfaceSelect');
            data.interfaces.forEach(iface => {
                const option1 = document.createElement('option');
                option1.value = iface;
                option1.textContent = iface;
                interfaceSelect.appendChild(option1);

                const option2 = document.createElement('option');
                option2.value = iface;
                option2.textContent = iface;
                wiresharkInterfaceSelect.appendChild(option2);
            });
        });

    // Load initial Suricata results
    fetchSuricataResults();
});

// Start monitoring network traffic
let monitoringInterval;
function startMonitoring() {
    const selectedInterface = document.getElementById('interfaceSelect').value;
    if (!selectedInterface) {
        alert('Please select a network interface.');
        return;
    }

    clearInterval(monitoringInterval);

    monitoringInterval = setInterval(() => {
        fetch('/get_network_traffic', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: selectedInterface })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const rateSent = data.traffic_data.rate_sent;
                const rateRecv = data.traffic_data.rate_recv;
                const currentTime = new Date().toLocaleTimeString();

                const totalRate = rateSent + rateRecv; // Mbps

                // 更新 Chart.js 圖表
                trafficChart.data.labels.push(currentTime);
                trafficChart.data.datasets[0].data.push(totalRate);

                if (trafficChart.data.labels.length > 10) {
                    trafficChart.data.labels.shift();
                    trafficChart.data.datasets[0].data.shift();
                }

                trafficChart.update();
            } else {
                console.error('Failed to retrieve network traffic:', data.message);
            }
        })
        .catch(error => console.error('Error fetching network traffic:', error));
    }, 5000);  // Update every 5 seconds
}

// Initialize Chart.js for traffic monitoring
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: [],
        datasets: [{
            label: 'Network Traffic (Mbps)',
            data: [],
            backgroundColor: 'rgba(75, 192, 192, 0.5)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: { title: { display: true, text: 'Time' } },
            y: { title: { display: true, text: 'Mbps' } }
        }
    }
});


//suricata_scan
let scanInterval;

function startScan() {
    fetch('/start_suricata', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            console.log(data.message);
            // Clear any previous interval to avoid duplicate requests
            if (scanInterval) {
                clearInterval(scanInterval);
            }
            // Start fetching results every 5 seconds
            fetchSuricataResults();  // Fetch data immediately
            scanInterval = setInterval(fetchSuricataResults, 5000);
        } else {
            console.error(data.message);
            alert(data.message);
        }
    })
    .catch(error => console.error('Error starting Suricata:', error));
}

function fetchSuricataResults() {
    fetch('/get_scan_results')
        .then(response => response.json())
        .then(data => {
            const resultsTable = document.getElementById('suricataResults').getElementsByTagName('tbody')[0];
            resultsTable.innerHTML = '';  // Clear previous table contents

            data.results.forEach(result => {
                const row = resultsTable.insertRow();
                row.innerHTML = `<td>${result.time}</td>
                                 <td>${result.msg}</td>
                                 <td>${result.source_ip}</td>
                                 <td>${result.destination_ip}</td>`;
            });
        })
        .catch(error => console.error('Error fetching Suricata results:', error));
}


// Start Wireshark monitoring
let wiresharkInterval;
let packetData = [];

function startWireshark() {
    const selectedInterface = document.getElementById('wiresharkInterfaceSelect').value;
    if (!selectedInterface) {
        alert('Please select a network interface.');
        return;
    }

    clearInterval(wiresharkInterval);

    wiresharkInterval = setInterval(() => {
        fetch(`/get_wireshark_data?interface=${selectedInterface}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    const resultsTable = document.getElementById('wiresharkResults').getElementsByTagName('tbody')[0];

                    data.data.forEach(result => {
                        packetData.unshift(result);

                        if (packetData.length > 15) {
                            packetData.pop();
                        }
                    });

                    resultsTable.innerHTML = '';
                    packetData.forEach((packet, index) => {
                        const row = resultsTable.insertRow();
                        row.innerHTML = `<td>${index + 1}</td><td>${packet.source}</td><td>${packet.destination}</td><td>${packet.protocol}</td><td>${packet.length}</td><td>${packet.info}</td>`;
                    });
                } else {
                    console.error('Failed to fetch Wireshark data:', data.message);
                }
            })
            .catch(error => console.error('Error fetching Wireshark data:', error));
    }, 1000);  // Fetch new packet data every second
}

// Start Error Packet monitoring
let errorPacketInterval;
let errorPacketData = [];

function startErrorPacket() {
    clearInterval(errorPacketInterval);

    errorPacketInterval = setInterval(() => {
        fetch(`/get_error_packet_data`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    const resultsTable = document.getElementById('errorPacketResults').getElementsByTagName('tbody')[0];

                    data.data.forEach(result => {
                        errorPacketData.unshift(result);

                        if (errorPacketData.length > 15) {
                            errorPacketData.pop();
                        }
                    });

                    resultsTable.innerHTML = '';
                    errorPacketData.forEach((packet, index) => {
                        const row = resultsTable.insertRow();
                        row.innerHTML = `<td>${index + 1}</td><td>${packet.time}</td><td>${packet.source}</td><td>${packet.destination}</td><td>${packet.protocol}</td><td>${packet.length}</td><td>${packet.info}</td>`;
                    });
                } else {
                    console.error('Failed to fetch Error Packet data:', data.message);
                }
            })
            .catch(error => console.error('Error fetching Error Packet data:', error));
    }, 1000);  // Fetch new error packet data every second
}

// Function to add a new rule to a.rules
function addRule() {
    const ruleInput = document.getElementById('ruleInput').value;
    const outputResult = document.getElementById('outputResult');

    fetch('/add_rule', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ rule: ruleInput })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            outputResult.value = "Success: The rule was added successfully.";
        } else {
            outputResult.value = "Error: " + data.message;
        }
    })
    .catch(error => {
        outputResult.value = "Error: Failed to add rule. " + error;
    });
}


