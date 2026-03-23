const configuredApiBaseUrl = (window.LOG_ANALYZER_CONFIG?.apiBaseUrl || "").trim().replace(/\/$/, "");

const form = document.getElementById("analyze-form");
const fileInput = document.getElementById("log-file");
const analyzeButton = document.getElementById("analyze-button");
const feedback = document.getElementById("feedback");
const resultsSection = document.getElementById("results");
const totalFailedLogins = document.getElementById("total-failed-logins");
const topIpHighlight = document.getElementById("top-ip-highlight");
const alertsContainer = document.getElementById("alerts");
const topIpsContainer = document.getElementById("top-ips");
const eventsBody = document.getElementById("events-body");
const targetedUsernamesContainer = document.getElementById("targeted-usernames");

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const selectedFile = fileInput.files[0];

  if (!selectedFile) {
    showFeedback("Please select an auth.log file before starting the analysis.", true);
    return;
  }

  if (!configuredApiBaseUrl) {
    showFeedback("Frontend is not configured. Set the deployed backend URL in config.js.", true);
    return;
  }

  const formData = new FormData();
  formData.append("file", selectedFile);

  analyzeButton.disabled = true;
  showFeedback("Analyzing log file. This usually takes a few seconds.");

  try {
    const response = await fetch(`${configuredApiBaseUrl}/analyze`, {
      method: "POST",
      body: formData,
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "The backend could not analyze this file.");
    }

    renderResults(data);
    showFeedback("Analysis completed successfully.");
  } catch (error) {
    resultsSection.classList.add("hidden");
    showFeedback(error.message || "Unexpected error while contacting the API.", true);
  } finally {
    analyzeButton.disabled = false;
  }
});

function renderResults(data) {
  resultsSection.classList.remove("hidden");
  totalFailedLogins.textContent = String(data.total_failed_logins);
  topIpHighlight.textContent = data.top_ips.length ? data.top_ips[0].ip_address : "No IPs found";
  renderAlerts(data.alerts || []);
  renderTopIps(data.top_ips);
  renderEvents(data.events);
  renderTargetedUsernames(data.statistics?.most_targeted_usernames || []);
}

function renderAlerts(alerts) {
  alertsContainer.innerHTML = "";

  if (!alerts.length) {
    alertsContainer.textContent = "No alerts were generated for this file.";
    return;
  }

  const list = document.createElement("ul");
  list.className = "alerts-list";

  alerts.forEach((alert) => {
    const item = document.createElement("li");
    item.className = `alert-card severity-${alert.severity || "info"}`;

    const severity = document.createElement("span");
    severity.className = "alert-severity";
    severity.textContent = (alert.severity || "info").toUpperCase();

    const message = document.createElement("p");
    message.textContent = alert.message;

    item.append(severity, message);
    list.appendChild(item);
  });

  alertsContainer.appendChild(list);
}

function renderTopIps(topIps) {
  topIpsContainer.innerHTML = "";

  if (!topIps.length) {
    topIpsContainer.textContent = "No failed SSH attempts were found in this log file.";
    return;
  }

  const list = document.createElement("ul");
  list.className = "ip-list";

  topIps.forEach((entry) => {
    const item = document.createElement("li");
    item.className = entry.is_suspicious ? "suspicious-ip" : "";
    const ipLabel = document.createElement("span");
    const attemptsBadge = document.createElement("span");

    ipLabel.textContent = entry.is_suspicious ? `${entry.ip_address} - Suspicious` : entry.ip_address;
    attemptsBadge.className = "attempt-badge";
    attemptsBadge.textContent = `${entry.attempts} attempts`;

    item.append(ipLabel, attemptsBadge);
    list.appendChild(item);
  });

  topIpsContainer.appendChild(list);
}

function renderEvents(events) {
  eventsBody.innerHTML = "";

  if (!events.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "empty-cell";
    cell.textContent = "No failed SSH events were detected in this file.";
    row.appendChild(cell);
    eventsBody.appendChild(row);
    return;
  }

  events.forEach((event) => {
    const row = document.createElement("tr");
    const values = [
      event.timestamp || "-",
      event.ip_address,
      event.username || "-",
      event.method || "-",
      String(event.line_number),
    ];

    values.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    });

    eventsBody.appendChild(row);
  });
}

function renderTargetedUsernames(usernames) {
  targetedUsernamesContainer.innerHTML = "";

  if (!usernames.length) {
    targetedUsernamesContainer.textContent = "No targeted usernames were found.";
    return;
  }

  const list = document.createElement("ul");
  list.className = "ip-list";

  usernames.forEach((entry) => {
    const item = document.createElement("li");
    const username = document.createElement("span");
    const attemptsBadge = document.createElement("span");

    username.textContent = entry.username;
    attemptsBadge.className = "attempt-badge";
    attemptsBadge.textContent = `${entry.attempts} attempts`;

    item.append(username, attemptsBadge);
    list.appendChild(item);
  });

  targetedUsernamesContainer.appendChild(list);
}

function showFeedback(message, isError = false) {
  feedback.textContent = message;
  feedback.style.color = isError ? "var(--warning)" : "var(--muted)";
}
