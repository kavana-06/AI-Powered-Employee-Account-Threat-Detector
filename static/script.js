
// ======================================
// SENTINEL AI - DASHBOARD FUNCTIONALITY
// DATABASE + THREAT INVESTIGATION
// ======================================

let totalActivities = 0;
let totalThreats = 0;
let totalNormal = 0;

let selectedActivityId = null;

const form = document.getElementById("threatForm");
const analyzeButton = document.getElementById("analyzeButton");

const resultPanel = document.getElementById("resultPanel");
const resultTitle = document.getElementById("resultTitle");
const resultMessage = document.getElementById("resultMessage");
const resultProbability = document.getElementById("resultProbability");
const resultIcon = document.getElementById("resultIcon");

const investigationTable =
    document.getElementById("investigationTable");

const investigationPanel =
    document.getElementById("investigationPanel");

const investigationForm =
    document.getElementById("investigationForm");

const investigationStatus =
    document.getElementById("investigationStatus");

const investigationNotes =
    document.getElementById("investigationNotes");

const investigationMessage =
    document.getElementById("investigationMessage");


// ======================================
// HELPER FUNCTIONS
// ======================================

function getValue(id) {
    return document.getElementById(id).value;
}


function setText(id, value) {

    const element = document.getElementById(id);

    if (element) {
        element.textContent = value ?? "--";
    }
}


function collectActivity() {

    return {
        department: getValue("department"),
        usual_location: getValue("usual_location").trim(),
        location: getValue("location").trim(),

        usual_login_hour: Number(getValue("usual_login_hour")),
        login_hour: Number(getValue("login_hour")),
        login_hour_deviation: Number(getValue("login_hour_deviation")),

        files_downloaded: Number(getValue("files_downloaded")),
        failed_login_attempts: Number(getValue("failed_login_attempts")),

        device_trusted: Number(getValue("device_trusted")),
        sensitive_files_accessed: Number(getValue("sensitive_files_accessed")),
        usb_connected: Number(getValue("usb_connected")),
        location_unusual: Number(getValue("location_unusual")),
        after_hours: Number(getValue("after_hours"))
    };
}


function formatProbability(value) {

    const probability = Number(value);

    return Number.isFinite(probability)
        ? probability.toFixed(2) + "%"
        : "--";
}


function formatTime(dateValue) {

    if (!dateValue) {
        return "--";
    }

    const date = new Date(dateValue);

    if (Number.isNaN(date.getTime())) {
        return String(dateValue);
    }

    return date.toLocaleTimeString();
}


function createCell(value) {

    const cell = document.createElement("td");

    cell.textContent = value ?? "--";

    return cell;
}


function getStatusClass(status) {

    switch (status) {

        case "NEW":
            return "investigation-new";

        case "UNDER INVESTIGATION":
            return "investigation-pending";

        case "RESOLVED":
            return "investigation-resolved";

        case "FALSE ALARM":
            return "investigation-false-alarm";

        default:
            return "";
    }
}


// ======================================
// DISPLAY AI RESULT
// ======================================

function displayResult(prediction, probability) {

    resultPanel.classList.remove(
        "hidden",
        "threat",
        "normal"
    );

    resultProbability.textContent =
        formatProbability(probability);

    if (prediction === "POTENTIAL THREAT") {

        resultPanel.classList.add("threat");

        resultIcon.textContent = "⚠";

        resultTitle.textContent =
            "Potential Threat Detected";

        resultMessage.textContent =
            "The machine-learning model flagged this activity. " +
            "Please review it before taking any action.";

    } else {

        resultPanel.classList.add("normal");

        resultIcon.textContent = "✓";

        resultTitle.textContent =
            "Activity Classified as Normal";

        resultMessage.textContent =
            "The model did not flag this activity as a potential threat.";
    }
}


// ======================================
// UPDATE STATISTICS
// ======================================

function updateStatistics() {

    setText("activityCount", totalActivities);

    setText("threatCount", totalThreats);

    setText("normalCount", totalNormal);

    setText("summaryTotal", totalActivities);

    setText("summaryNormal", totalNormal);

    setText("summaryThreat", totalThreats);

    updateChart();
}


// ======================================
// UPDATE DONUT CHART
// ======================================

function updateChart() {

    const chart = document.querySelector(".donut-chart");

    if (!chart) {
        return;
    }

    if (totalActivities === 0) {

        chart.style.background =
            "conic-gradient(#21d69a 0% 50%, #ff5570 50% 100%)";

        return;
    }

    const normalPercentage =
        (totalNormal / totalActivities) * 100;

    chart.style.background = `
        conic-gradient(
            var(--green) 0% ${normalPercentage}%,
            var(--red) ${normalPercentage}% 100%
        )
    `;
}


// ======================================
// CREATE HISTORY TABLE ROW
// ======================================

function createHistoryRow(activity) {

    const row = document.createElement("tr");

    row.appendChild(
        createCell(formatTime(activity.created_at))
    );

    row.appendChild(
        createCell(activity.department)
    );

    row.appendChild(
        createCell(activity.location)
    );

    const resultCell = document.createElement("td");

    const badge = document.createElement("span");

    const prediction = activity.prediction || "NORMAL";

    badge.className =
        prediction === "POTENTIAL THREAT"
            ? "result-badge threat-badge"
            : "result-badge normal-badge";

    badge.textContent = prediction;

    resultCell.appendChild(badge);

    row.appendChild(resultCell);

    row.appendChild(
        createCell(
            formatProbability(activity.threat_probability)
        )
    );

    return row;
}


// ======================================
// RENDER ACTIVITY HISTORY
// ======================================

function renderHistory(activities) {

    const table = document.getElementById("historyTable");

    table.innerHTML = "";

    if (!activities || activities.length === 0) {

        const row = document.createElement("tr");

        const cell = createCell("No activity analyzed yet.");

        cell.colSpan = 5;
        cell.className = "table-empty";

        row.appendChild(cell);

        table.appendChild(row);

        return;
    }

    activities.forEach(activity => {

        table.appendChild(
            createHistoryRow(activity)
        );

    });
}


// ======================================
// CREATE THREAT ALERT
// ======================================

function createThreatAlert(activity) {

    const alert = document.createElement("div");

    alert.style.cssText = `
        padding: 18px;
        margin-bottom: 12px;
        background: rgba(255, 85, 112, 0.06);
        border: 1px solid rgba(255, 85, 112, 0.25);
        border-radius: 10px;
    `;

    const heading = document.createElement("h3");

    heading.textContent = "⚠ Potential Threat Flagged";

    heading.style.cssText = `
        color: #ff5570;
        font-size: 13px;
        margin-bottom: 9px;
    `;

    const details = document.createElement("p");

    details.textContent =
        "Activity ID: " + activity.id +
        " | Department: " + activity.department +
        " | Location: " + activity.location +
        " | Threat probability: " +
        formatProbability(activity.threat_probability);

    details.style.cssText = `
        color: #aab9c9;
        font-size: 11px;
        line-height: 1.8;
    `;

    const status = document.createElement("p");

    status.textContent =
        "Investigation status: " +
        (activity.investigation_status || "NEW");

    status.style.cssText = `
        color: #ff9aaa;
        font-size: 11px;
        margin-top: 8px;
    `;

    const button = document.createElement("button");

    button.type = "button";
    button.textContent = "Investigate Threat";

    button.className = "analyze-button";
    button.dataset.activityId = activity.id;

    button.style.marginTop = "12px";

    button.addEventListener("click", function() {

        openInvestigation(activity.id);

    });

    alert.appendChild(heading);
    alert.appendChild(details);
    alert.appendChild(status);
    alert.appendChild(button);

    return alert;
}


// ======================================
// RENDER THREAT ALERTS
// ======================================

function renderThreatAlerts(activities) {

    const alertsList = document.getElementById("alertsList");

    alertsList.innerHTML = "";

    const threats = activities.filter(
        activity => activity.prediction === "POTENTIAL THREAT"
    );

    if (threats.length === 0) {

        alertsList.className = "empty-state";

        const heading = document.createElement("h3");

        heading.textContent = "✓ No alerts yet";

        const message = document.createElement("p");

        message.textContent =
            "Analyzed activities flagged as potential threats will appear here.";

        alertsList.appendChild(heading);
        alertsList.appendChild(message);

        return;
    }

    alertsList.className = "alerts-list";

    threats.forEach(activity => {

        alertsList.appendChild(
            createThreatAlert(activity)
        );

    });
}


// ======================================
// RENDER INVESTIGATION TABLE
// ======================================

function renderInvestigationTable(activities) {

    investigationTable.innerHTML = "";

    const threats = activities.filter(
        activity => activity.prediction === "POTENTIAL THREAT"
    );

    if (threats.length === 0) {

        const row = document.createElement("tr");

        const cell = createCell("No detected threats available.");

        cell.colSpan = 6;
        cell.className = "table-empty";

        row.appendChild(cell);

        investigationTable.appendChild(row);

        return;
    }

    threats.forEach(activity => {

        const row = document.createElement("tr");

        row.appendChild(
            createCell("#" + activity.id)
        );

        row.appendChild(
            createCell(activity.department)
        );

        row.appendChild(
            createCell(activity.location)
        );

        row.appendChild(
            createCell(
                formatProbability(activity.threat_probability)
            )
        );

        // Investigation status badge
        const statusCell = document.createElement("td");

        const statusBadge = document.createElement("span");

        const status =
            activity.investigation_status || "NEW";

        statusBadge.className =
            "result-badge " + getStatusClass(status);

        statusBadge.textContent = status;

        statusCell.appendChild(statusBadge);

        row.appendChild(statusCell);

        // Investigate button
        const actionCell = document.createElement("td");

        const button = document.createElement("button");

        button.type = "button";

        button.textContent = "View / Investigate";

        button.className = "analyze-button";

        button.dataset.activityId = activity.id;

        button.addEventListener("click", function() {

            openInvestigation(activity.id);

        });

        actionCell.appendChild(button);

        row.appendChild(actionCell);

        investigationTable.appendChild(row);

    });
}


// ======================================
// LOAD DASHBOARD FROM DATABASE
// ======================================

async function loadDashboardData() {

    try {

        const [activitiesResponse, statsResponse] =
            await Promise.all([

                fetch("/api/activities?limit=100"),

                fetch("/api/stats")

            ]);

        if (!activitiesResponse.ok) {

            throw new Error(
                "Unable to load activity history."
            );
        }

        const activitiesData =
            await activitiesResponse.json();

        const statsData = statsResponse.ok
            ? await statsResponse.json()
            : {};

        if (activitiesData.status !== "success") {

            throw new Error(
                "Activity API returned an error."
            );
        }

        const activities =
            activitiesData.activities || [];

        // Calculate fallback statistics
        const calculatedTotal = Number(
            activitiesData.total_returned ?? activities.length
        );

        const calculatedThreats = activities.filter(
            activity =>
                activity.prediction === "POTENTIAL THREAT"
        ).length;

        const calculatedNormal = activities.filter(
            activity =>
                activity.prediction === "NORMAL"
        ).length;

        function findStat(names, fallback) {

            for (const name of names) {

                if (
                    statsData[name] !== undefined &&
                    Number.isFinite(Number(statsData[name]))
                ) {
                    return Number(statsData[name]);
                }
            }

            return fallback;
        }

        totalActivities = findStat(
            ["total_activities", "total", "activity_count"],
            calculatedTotal
        );

        totalThreats = findStat(
            [
                "potential_threats",
                "threat_activities",
                "threats",
                "threat_count"
            ],
            calculatedThreats
        );

        totalNormal = findStat(
            [
                "normal_activities",
                "normal",
                "normal_count"
            ],
            calculatedNormal
        );

        // Refresh all dashboard sections
        updateStatistics();

        renderHistory(activities);

        renderThreatAlerts(activities);

        renderInvestigationTable(activities);

        console.log(
            "Dashboard and investigation data loaded."
        );

    } catch (error) {

        console.error(
            "Dashboard loading error:",
            error
        );

        investigationTable.innerHTML = "";

        const row = document.createElement("tr");

        const cell = createCell(
            "Unable to load threats. Check the Flask server."
        );

        cell.colSpan = 6;

        row.appendChild(cell);

        investigationTable.appendChild(row);

    }
}


// ======================================
// OPEN INVESTIGATION DETAILS
// ======================================

async function openInvestigation(activityId) {

    try {

        investigationMessage.textContent =
            "Loading investigation details...";

        investigationPanel.hidden = false;

        investigationPanel.scrollIntoView({

            behavior: "smooth",

            block: "start"

        });

        const response = await fetch(
            `/api/activities/${activityId}`
        );

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.error || "Unable to load activity."
            );
        }

        const activity = data.activity;

        if (activity.prediction !== "POTENTIAL THREAT") {

            throw new Error(
                "Only potential threats can be investigated."
            );
        }

        selectedActivityId = activity.id;

        const input = activity.input_data || {};

        // Display activity information
        setText(
            "investigationActivityId",
            "ACTIVITY #" + activity.id
        );

        setText(
            "investigationDepartment",
            activity.department
        );

        setText(
            "investigationLocation",
            activity.location
        );

        setText(
            "investigationUsualLocation",
            activity.usual_location
        );

        setText(
            "investigationProbability",
            formatProbability(activity.threat_probability)
        );

        setText(
            "investigationFailedLogins",
            input.failed_login_attempts ?? "--"
        );

        setText(
            "investigationFilesDownloaded",
            input.files_downloaded ?? "--"
        );

        setText(
            "investigationUSB",
            Number(input.usb_connected) === 1 ? "Yes" : "No"
        );

        setText(
            "investigationDevice",
            Number(input.device_trusted) === 1 ? "Yes" : "No"
        );

        // Load saved investigation data
        investigationStatus.value =
            activity.investigation_status || "NEW";

        investigationNotes.value =
            activity.investigation_notes || "";

        investigationMessage.textContent =
            "Activity details loaded successfully.";

    } catch (error) {

        investigationMessage.textContent =
            error.message;

        console.error(
            "Investigation loading error:",
            error
        );

    }
}


// ======================================
// SAVE INVESTIGATION STATUS AND NOTES
// ======================================

investigationForm.addEventListener(
    "submit",
    async function(event) {

        event.preventDefault();

        if (selectedActivityId === null) {

            investigationMessage.textContent =
                "Please select a threat first.";

            return;
        }

        const status = investigationStatus.value;

        const notes = investigationNotes.value.trim();

        const allowedStatuses = [
            "NEW",
            "UNDER INVESTIGATION",
            "RESOLVED",
            "FALSE ALARM"
        ];

        if (!allowedStatuses.includes(status)) {

            investigationMessage.textContent =
                "Please select a valid investigation status.";

            return;
        }

        const saveButton =
            document.getElementById("saveInvestigationButton");

        saveButton.disabled = true;

        saveButton.textContent = "Saving...";

        investigationMessage.textContent =
            "Saving investigation...";

        try {

            const response = await fetch(
                `/api/activities/${selectedActivityId}/investigation`,
                {

                    method: "PATCH",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({

                        investigation_status: status,

                        investigation_notes: notes

                    })

                }
            );

            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error || "Unable to save investigation."
                );
            }

            investigationMessage.textContent =
                "✓ Investigation saved successfully!";

            // Reload dashboard and investigation table
            await loadDashboardData();

            // Reload the selected activity
            await openInvestigation(selectedActivityId);

            investigationMessage.textContent =
                "✓ Investigation saved successfully!";

        } catch (error) {

            investigationMessage.textContent =
                "Error: " + error.message;

            console.error(
                "Investigation save error:",
                error
            );

        } finally {

            saveButton.disabled = false;

            saveButton.textContent = "Save Investigation";

        }

    }
);


// ======================================
// REFRESH INVESTIGATIONS
// ======================================

document.getElementById(
    "refreshInvestigationsButton"
).addEventListener("click", async function() {

    this.disabled = true;

    this.textContent = "Refreshing...";

    await loadDashboardData();

    this.disabled = false;

    this.textContent = "↻ Refresh";

});


// ======================================
// CLOSE INVESTIGATION DETAILS
// ======================================

document.getElementById(
    "closeInvestigationButton"
).addEventListener("click", function() {

    investigationPanel.hidden = true;

    selectedActivityId = null;

    investigationMessage.textContent = "";

});


// ======================================
// HANDLE FORM SUBMISSION
// ======================================

form.addEventListener("submit", async function(event) {

    event.preventDefault();

    if (!form.reportValidity()) {
        return;
    }

    const activity = collectActivity();

    analyzeButton.disabled = true;

    analyzeButton.textContent = "Analyzing Activity...";

    resultPanel.classList.add("hidden");

    try {

        const response = await fetch("/predict", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(activity)

        });

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.error || "Unable to analyze activity."
            );
        }

        if (
            data.status !== "success" ||
            !["NORMAL", "POTENTIAL THREAT"].includes(data.prediction) ||
            !Number.isFinite(Number(data.threat_probability))
        ) {

            throw new Error(
                "The server returned an unexpected response."
            );
        }

        displayResult(
            data.prediction,
            data.threat_probability
        );

        // Refresh data from SQLite
        await loadDashboardData();

        resultPanel.scrollIntoView({

            behavior: "smooth",

            block: "center"

        });

    } catch (error) {

        resultPanel.classList.remove(
            "hidden",
            "threat",
            "normal"
        );

        resultIcon.textContent = "✕";

        resultTitle.textContent = "Analysis Failed";

        resultMessage.textContent =
            error.message +
            " Check that the Flask server is running and try again.";

        resultProbability.textContent = "--";

    } finally {

        analyzeButton.disabled = false;

        analyzeButton.textContent = "✦ Analyze Activity";

    }

});


// ======================================
// SIDEBAR NAVIGATION
// ======================================

document.querySelectorAll(".nav-link").forEach(link => {

    link.addEventListener("click", function() {

        document.querySelectorAll(".nav-link").forEach(item => {

            item.classList.remove("active");

        });

        this.classList.add("active");

    });

});


// ======================================
// INITIALIZE DASHBOARD
// ======================================

loadDashboardData();

console.log(
    "SENTINEL AI dashboard and threat investigation loaded successfully."
);
