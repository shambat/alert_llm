from flask import Flask, render_template_string, jsonify
import threading
import time
import requests
import os
import re
from datetime import datetime

# === CONFIGURATION ===
SNORT_LOG_FILE = "alert.log"  # Should be in the same directory
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY = "PLACE_GROK_API"  # Replace with your Groq API key
MODEL = "llama3-70b-8192"

headers = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

app = Flask(__name__)
alerts = []
alert_counter = 0  # Global alert counter

# === HTML Template with Tailwind CSS ===
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Groq Security Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom scrollbar for better aesthetics */
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #1e293b;
        }
        ::-webkit-scrollbar-thumb {
            background: #38bdf8;
            border-radius: 4px;
        }
        /* Hide alerts container when empty */
        #alerts:empty::before {
            content: "No alerts available.";
            color: #94a3b8;
            text-align: center;
            padding: 2rem;
            display: block;
        }
    </style>
</head>
<body class="bg-gray-900 text-gray-100 font-sans">
    <header class="bg-gray-800 shadow-md py-4">
        <div class="container mx-auto px-4">
            <h1 class="text-3xl font-bold text-sky-400 text-center">Groq Security Dashboard</h1>
            <p class="text-gray-400 text-center mt-1">Real-time Snort Alert Monitoring</p>
        </div>
    </header>

    <div class="container mx-auto px-4 py-6">
        <!-- Controls -->
        <div class="flex flex-col sm:flex-row justify-between items-center mb-6 gap-4">
            <div class="flex items-center gap-4">
                <input id="search" type="text" placeholder="Search by IP or Alert..." class="bg-gray-800 text-gray-100 border border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-sky-400 w-full sm:w-64">
                <select id="sort" class="bg-gray-800 text-gray-100 border border-gray-700 rounded-lg px-4 py-2 focus:outline-none">
                    <option value="timestamp-desc">Newest First</option>
                    <option value="timestamp-asc">Oldest First</option>
                    <option value="src_ip">Source IP</option>
                    <option value="dst_ip">Destination IP</option>
                </select>
            </div>
            <div class="flex items-center gap-4">
                <label class="flex items-center gap-2">
                    <input id="autoRefresh" type="checkbox" checked class="h-4 w-4 text-sky-400 focus:ring-sky-400 bg-gray-800 border-gray-700 rounded">
                    <span>Auto-refresh</span>
                </label>
                <button id="clearAlerts" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition">Clear Alerts</button>
            </div>
        </div>

        <!-- Alerts Container -->
        <div id="alerts" class="space-y-4"></div>
        <div id="loading" class="hidden text-center text-gray-400 py-4">Loading alerts...</div>

        <!-- Pagination -->
        <div id="pagination" class="flex justify-center items-center gap-4 mt-6">
            <button id="prevPage" class="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg disabled:opacity-50" disabled>Previous</button>
            <span id="pageInfo" class="text-gray-300"></span>
            <button id="nextPage" class="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg disabled:opacity-50" disabled>Next</button>
        </div>
    </div>

    <footer class="bg-gray-800 py-4 text-center text-gray-400">
        SHAM Cyber Defense | Powered by Groq + Flask
    </footer>

    <script>
        // Configuration
        const ITEMS_PER_PAGE = 10;
        let alerts = [];
        let currentPage = 1;
        let filteredAlerts = [];

        // DOM Elements
        const alertsContainer = document.getElementById('alerts');
        const loading = document.getElementById('loading');
        const searchInput = document.getElementById('search');
        const sortSelect = document.getElementById('sort');
        const autoRefreshCheckbox = document.getElementById('autoRefresh');
        const clearAlertsButton = document.getElementById('clearAlerts');
        const prevPageButton = document.getElementById('prevPage');
        const nextPageButton = document.getElementById('nextPage');
        const pageInfo = document.getElementById('pageInfo');

        // Sanitize HTML to prevent XSS
        function sanitizeHTML(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        // Render Alerts
        function renderAlerts() {
            alertsContainer.innerHTML = '';
            const start = (currentPage - 1) * ITEMS_PER_PAGE;
            const end = start + ITEMS_PER_PAGE;
            const paginatedAlerts = filteredAlerts.slice(start, end);

            if (paginatedAlerts.length === 0) {
                alertsContainer.innerHTML = '';
                return;
            }

            paginatedAlerts.forEach(alert => {
                const alertElement = document.createElement('div');
                alertElement.className = 'bg-gray-800 p-4 rounded-lg shadow-lg';
                alertElement.innerHTML = `
                    <h2 class="text-xl font-semibold text-yellow-400">Alert #${sanitizeHTML(alert.number)}</h2>
                    <p class="text-gray-400 text-sm">Detected: ${sanitizeHTML(alert.timestamp)}</p>
                    <div class="mt-2 text-gray-300">
                        <span class="inline-block w-32 font-medium text-sky-400">Source:</span> ${sanitizeHTML(alert.src_ip)}:${sanitizeHTML(alert.src_port)}<br>
                        <span class="inline-block w-32 font-medium text-sky-400">Destination:</span> ${sanitizeHTML(alert.dst_ip)}:${sanitizeHTML(alert.dst_port)}
                    </div>
                    <div class="mt-2 bg-gray-700 p-2 rounded text-gray-200">
                        <span class="font-medium text-sky-400">Snort Alert:</span> ${sanitizeHTML(alert.snort_alert)}
                    </div>
                    <div class="mt-2 text-gray-200">${sanitizeHTML(alert.ai_summary).replace(/\\n/g, '<br>')}</div>
                `;
                alertsContainer.appendChild(alertElement);
            });

            // Update Pagination
            const totalPages = Math.ceil(filteredAlerts.length / ITEMS_PER_PAGE);
            pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
            prevPageButton.disabled = currentPage === 1;
            nextPageButton.disabled = currentPage === totalPages;
        }

        // Filter and Sort Alerts
        function filterAndSortAlerts() {
            const searchTerm = searchInput.value.toLowerCase();
            filteredAlerts = alerts.filter(alert =>
                alert.src_ip.toLowerCase().includes(searchTerm) ||
                alert.dst_ip.toLowerCase().includes(searchTerm) ||
                alert.snort_alert.toLowerCase().includes(searchTerm) ||
                alert.ai_summary.toLowerCase().includes(searchTerm)
            );

            const [sortKey, sortOrder] = sortSelect.value.split('-');
            filteredAlerts.sort((a, b) => {
                const key = sortKey === 'timestamp' ? 'timestamp' : sortKey;
                const aValue = key === 'timestamp' ? new Date(a[key]) : a[key];
                const bValue = key === 'timestamp' ? new Date(b[key]) : b[key];
                if (sortOrder === 'asc') {
                    return aValue > bValue ? 1 : -1;
                } else {
                    return aValue < bValue ? 1 : -1;
                }
            });

            currentPage = 1; // Reset to first page on filter/sort
            renderAlerts();
        }

        // Fetch Alerts
        async function fetchAlerts() {
            try {
                loading.classList.remove('hidden');
                const response = await fetch('/alerts');
                if (!response.ok) throw new Error('Network response was not ok');
                alerts = await response.json();
                filterAndSortAlerts();
            } catch (error) {
                alertsContainer.innerHTML = `<p class="text-red-400 text-center">Error fetching alerts: ${sanitizeHTML(error.message)}</p>`;
            } finally {
                loading.classList.add('hidden');
            }
        }

        // Event Listeners
        searchInput.addEventListener('input', filterAndSortAlerts);
        sortSelect.addEventListener('change', filterAndSortAlerts);
        prevPageButton.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                renderAlerts();
            }
        });
        nextPageButton.addEventListener('click', () => {
            if (currentPage < Math.ceil(filteredAlerts.length / ITEMS_PER_PAGE)) {
                currentPage++;
                renderAlerts();
            }
        });
        clearAlertsButton.addEventListener('click', () => {
            alerts = [];
            filteredAlerts = [];
            currentPage = 1;
            renderAlerts();
        });

        // Auto-refresh
        let refreshInterval;
        function startAutoRefresh() {
            if (autoRefreshCheckbox.checked) {
                refreshInterval = setInterval(fetchAlerts, 3000);
            }
        }
        autoRefreshCheckbox.addEventListener('change', () => {
            if (autoRefreshCheckbox.checked) {
                startAutoRefresh();
            } else {
                clearInterval(refreshInterval);
            }
        });

        // Initial Fetch and Auto-refresh
        fetchAlerts();
        startAutoRefresh();
    </script>
</body>
</html>
"""

# === Extract Details from Snort Log ===
def extract_log_details(log_entry):
    """
    Extract src/dst IPs and ports from Snort log entry.
    """
    ips_ports_match = re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", log_entry)
    src_ip, src_port, dst_ip, dst_port = ("Unknown", "Unknown", "Unknown", "Unknown")
    if len(ips_ports_match) >= 2:
        (src_ip, src_port), (dst_ip, dst_port) = ips_ports_match[:2]
    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port
    }

# === AI Summary Function ===
def get_ai_summary(log_entry, details):
    context = (
        f"Snort Alert Details:\n"
        f"- Source IP: {details['src_ip']} Port: {details['src_port']}\n"
        f"- Destination IP: {details['dst_ip']} Port: {details['dst_port']}\n\n"
        f"Raw Alert: {log_entry}\n\n"
        "Analyze the above details and provide:\n"
        "- A brief summary of the attacker activity.\n"
        "- If possible, map it to MITRE ATT&CK (include Technique name and ID).\n"
        "- Keep it concise, SOC-ready. No recommendations."
    )
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a SOC analyst AI. Provide precise summaries for alerts."},
            {"role": "user", "content": context}
        ],
        "temperature": 0.1
    }
    try:
        r = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        return r.json()['choices'][0]['message']['content'].strip()
    except requests.exceptions.RequestException as e:
        return f"[ERROR] Groq API failed: {e}"

# === Monitor Snort Log in Background ===
def monitor_snort_log():
    global alert_counter
    print("Groq-powered Security Monitor started...")
    try:
        with open(SNORT_LOG_FILE, "r") as logfile:
            logfile.seek(0, os.SEEK_END)
            while True:
                line = logfile.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                line = line.strip()
                if line:
                    alert_counter += 1
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    details = extract_log_details(line)
                    summary = get_ai_summary(line, details)
                    alert = {
                        "number": alert_counter,
                        "timestamp": timestamp,
                        "src_ip": details["src_ip"],
                        "src_port": details["src_port"],
                        "dst_ip": details["dst_ip"],
                        "dst_port": details["dst_port"],
                        "snort_alert": line,
                        "ai_summary": summary
                    }
                    alerts.append(alert)
    except FileNotFoundError:
        print(f"[ERROR] Could not find {SNORT_LOG_FILE}")
    except KeyboardInterrupt:
        print("\n[INFO] Stopped.")

# === Flask Routes ===
@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/alerts")
def get_alerts():
    return jsonify(alerts[::-1])  # Reverse for latest on top

# === Start Background Monitor Thread ===
threading.Thread(target=monitor_snort_log, daemon=True).start()

# === Run Flask App ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
