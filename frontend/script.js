const API_URL = "http://127.0.0.1:5000";


// =====================================
// SMS FRAUD SCANNER
// =====================================

async function scanMessage() {

    const message = document.getElementById("messageInput").value.trim();

    if (!message) {
        alert("Please enter a message!");
        return;
    }

    try {

        const response = await fetch(`${API_URL}/analyze`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ message })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "SMS scan failed");
        }

        document.getElementById("result").style.display = "block";

        document.getElementById("riskScore").innerText =
            data.risk_score + "/100";

        document.getElementById("riskStatus").innerText =
            data.status;

        document.getElementById("explanation").innerText =
            data.detected_words.length > 0
                ? "Warning indicators: " + data.detected_words.join(", ")
                : "No suspicious indicators detected.";

        loadHistory();
        loadDashboard();

    } catch (error) {

        alert("Backend connection error: " + error.message);

    }
}


// =====================================
// WEBSITE SAFETY CHECKER
// =====================================

async function scanWebsite() {

    const url = document.getElementById("websiteInput").value.trim();

    if (!url) {
        alert("Please enter a website URL!");
        return;
    }

    try {

        const response = await fetch(`${API_URL}/analyze-website`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Website scan failed");
        }

        document.getElementById("websiteResult").style.display = "block";

        document.getElementById("websiteName").innerText =
            data.website;

        document.getElementById("websiteScore").innerText =
            data.risk_score + "/100";

        document.getElementById("websiteStatus").innerText =
            data.status;

        document.getElementById("websiteWarnings").innerText =
            data.warnings.join(", ");

        loadHistory();
        loadDashboard();

    } catch (error) {

        alert("Backend connection error: " + error.message);

    }
}


// =====================================
// PROFESSIONAL DASHBOARD
// =====================================

async function loadDashboard() {

    try {

        const response = await fetch(`${API_URL}/history`);

        if (!response.ok) {
            throw new Error("Unable to fetch dashboard data");
        }

        const scans = await response.json();

        let total = scans.length;
        let safe = 0;
        let suspicious = 0;
        let highRisk = 0;

        scans.forEach(scan => {

            if (scan.status === "LOW RISK") {
                safe++;
            }

            else if (scan.status === "SUSPICIOUS") {
                suspicious++;
            }

            else if (scan.status === "HIGH RISK") {
                highRisk++;
            }

        });

        document.getElementById("totalScans").innerText = total;

        document.getElementById("safeScans").innerText = safe;

        document.getElementById("suspiciousScans").innerText =
            suspicious;

        document.getElementById("highRiskScans").innerText =
            highRisk;

        // Risk analysis chart

        const chart = document.getElementById("riskChart");

        if (chart) {

            chart.innerHTML = "";

            const categories = [
                {
                    name: "Safe",
                    count: safe
                },
                {
                    name: "Suspicious",
                    count: suspicious
                },
                {
                    name: "High Risk",
                    count: highRisk
                }
            ];

            categories.forEach(category => {

                const percentage = total > 0
                    ? (category.count / total) * 100
                    : 0;

                const row = document.createElement("div");

                row.style.margin = "15px 0";

                const label = document.createElement("p");

                label.textContent =
                    `${category.name}: ${category.count}`;

                const barBackground = document.createElement("div");

                barBackground.style.width = "100%";
                barBackground.style.height = "14px";
                barBackground.style.background = "#e5e7eb";
                barBackground.style.borderRadius = "10px";
                barBackground.style.overflow = "hidden";

                const bar = document.createElement("div");

                bar.style.width = percentage + "%";
                bar.style.height = "100%";
                bar.style.background =
                    category.name === "Safe" ? "#16a34a" :
                    category.name === "Suspicious" ? "#eab308" :
                    "#dc2626";

                bar.style.borderRadius = "10px";
                bar.style.transition = "width 0.5s";

                barBackground.appendChild(bar);

                row.appendChild(label);
                row.appendChild(barBackground);

                chart.appendChild(row);

            });

        }

    } catch (error) {

        console.log("Dashboard error:", error.message);

    }
}


// =====================================
// COMBINED SCAN HISTORY
// =====================================

async function loadHistory() {

    const historyList = document.getElementById("historyList");

    if (!historyList) return;

    try {

        const response = await fetch(`${API_URL}/history`);

        if (!response.ok) {
            throw new Error("History loading failed");
        }

        const scans = await response.json();

        historyList.innerHTML = "";

        if (scans.length === 0) {

            historyList.innerHTML =
                "<p>No scan history available.</p>";

            return;
        }

        scans.forEach(scan => {

            const card = document.createElement("div");

            card.className = "history-card";

            const scanType = scan.scan_type || "SMS";

            card.innerHTML = `
                <h3>${scanType} SCAN #${scan.id}</h3>

                <p><strong>Input:</strong></p>
                <p class="history-message"></p>

                <p><strong>Risk Score:</strong> ${scan.risk_score}/100</p>

                <p><strong>Status:</strong> ${scan.status}</p>

                <p><strong>Warnings:</strong></p>
                <p class="history-warnings"></p>

                <p><strong>Date:</strong> ${scan.scan_time}</p>

                <hr>
            `;

            card.querySelector(".history-message").textContent =
                scan.message;

            card.querySelector(".history-warnings").textContent =
                Array.isArray(scan.detected_words)
                    ? scan.detected_words.join(", ")
                    : scan.detected_words;

            historyList.appendChild(card);

        });

    } catch (error) {

        historyList.innerHTML =
            "<p>Unable to load history. Check backend connection.</p>";

    }
}


// =====================================
// PAGE INITIALIZATION
// =====================================

document.addEventListener("DOMContentLoaded", function () {

    loadHistory();

    loadDashboard();

});