import {createAdminApi} from "./admin-api.js";

const params = new URLSearchParams(window.location.search);
const tokenFromUrl = params.get("token");
const storedToken = sessionStorage.getItem("adminToken");

if (tokenFromUrl) {
  sessionStorage.setItem("adminToken", tokenFromUrl);
}

const adminToken = tokenFromUrl || storedToken || "";
const adminApi = createAdminApi(adminToken);

if (tokenFromUrl) {
  history.replaceState(null, "", window.location.pathname);
}

const statusBox = document.getElementById("status");
const dashboard = document.getElementById("dashboard");
const editor = document.getElementById("editor");
const users = document.getElementById("users");
const pageList = document.getElementById("page-list");
const newPageButton = document.getElementById("new-page");
const backButton = document.getElementById("back");
const saveButton = document.getElementById("save");
const deleteButton = document.getElementById("delete");
const previewLink = document.getElementById("preview");
const editorUsersButton = document.getElementById("editor-users");
const editorUsersBottomButton =
  document.getElementById("editor-users-bottom");
const saveBottomButton = document.getElementById("save-bottom");
const refreshButton = document.getElementById("refresh");

const titleInput = document.getElementById("title");
const pageIdInput = document.getElementById("page-id");
const descriptionInput = document.getElementById("description");
const proximityEnabledInput = document.getElementById("proximity-enabled");
const proximityRadiusInput = document.getElementById("proximity-radius");
const proximityRadiusField = document.getElementById("proximity-radius-field");
const selectedCount = document.getElementById("selected-count");
const openPickerButton = document.getElementById("open-picker");
const pickerDialog = document.getElementById("entity-picker");
const closePickerButton = document.getElementById("close-picker");
const pickerDoneButton = document.getElementById("picker-done");
const pickerSearchInput = document.getElementById("picker-search");
const pickerTypes = document.getElementById("picker-types");
const pickerResults = document.getElementById("picker-results");
const pickerPolicy = document.getElementById("picker-policy");
const pickerTargetTab = document.getElementById("picker-target-tab");
const pickerTypeTab = document.getElementById("picker-type-tab");
const usersBackButton = document.getElementById("users-back");
const usersEditButton = document.getElementById("users-edit");
const usersPreviewButton = document.getElementById("users-preview");
const usersTitle = document.getElementById("users-title");
const addUserButton = document.getElementById("add-user");
const userDialog = document.getElementById("user-dialog");
const closeUserDialogButton = document.getElementById("close-user-dialog");
const access_linkLabelInput = document.getElementById("access_link-label");
const nhpVerificationInput = document.getElementById("nhp-verification");
const verificationStatus = document.getElementById("nhp-verification-status");
const refreshVerificationStatus = document.getElementById("refresh-verification-status");
let verificationMethods = {none: true, google: false, email: false};
let verificationStatusRequest = 0;
function applyVerificationMethods() {
 for (const option of nhpVerificationInput.options) {
  option.disabled = verificationMethods[option.value] !== true;
 }
}
async function loadVerificationStatus() {
 const request = ++verificationStatusRequest;
 verificationMethods = {none: true, google: false, email: false};
 applyVerificationMethods();
 refreshVerificationStatus.disabled = true;
 verificationStatus.textContent = "Checking hosted verification options…";
 try {
  const response = await adminApi.fetch("api/admin/verification-status", {cache: "no-store"});
  const data = await responseJson(response, "Could not check verification options");
  if (request !== verificationStatusRequest) return;
  if (!response.ok || data.version !== 1 || !data.methods ||
      !["none", "google", "email"].every(key => typeof data.methods[key] === "boolean") || data.methods.none !== true) {
   throw new Error("Verification options could not be checked. Refresh to retry.");
  }
  verificationMethods = data.methods;
  const configured = [data.methods.google ? "Google" : "", data.methods.email ? "email codes" : ""].filter(Boolean);
  verificationStatus.textContent = configured.length
   ? "Configured in OpenNHP Service: " + configured.join(" and ") + "."
   : "Google and email verification are not configured in OpenNHP Service.";
 } catch {
  if (request !== verificationStatusRequest) return;
  verificationStatus.textContent = "Verification options could not be checked. Refresh to retry. Your selected requirement is preserved.";
 } finally {
  if (request === verificationStatusRequest) {
   applyVerificationMethods();
   refreshVerificationStatus.disabled = false;
  }
 }
}
refreshVerificationStatus.addEventListener("click", loadVerificationStatus);
applyVerificationMethods();
function updateNhpVerification() {
 const method = nhpVerificationInput.value;
 verificationEmailField.classList.toggle("hidden", method === "none");
 document.getElementById("nhp-verification-help").textContent = method === "none"
  ? "Anyone with a valid invitation can open this page."
  : method === "google_or_email" ? "The guest can use Google sign-in or a code sent to the invited email before the page opens."
  : "The guest must verify " + (method === "google" ? "the invited Google account" : "a code sent to the invited email") + " before the page opens.";
}
nhpVerificationInput.addEventListener("change", () => {
 updateNhpVerification();
 if (nhpVerificationInput.value !== "none") verificationEmailInput.focus();
});
const oneTimeUseInput = document.getElementById("one-time-use");
const sendInvitationEmailInput = document.getElementById("send-invitation-email");
const invitationEmailInput = document.getElementById("invitation-email");
const invitationEmailField = document.getElementById("invitation-email-field");
function updateInvitationDelivery() {
  sendInvitationEmailInput.disabled = !emailConfigured;
  if (!emailConfigured) sendInvitationEmailInput.checked = false;
  invitationEmailField.classList.toggle("hidden", !sendInvitationEmailInput.checked);
  document.getElementById("invitation-email-help").textContent = emailConfigured
    ? "Send this invitation through your configured SMTP provider. Verification still happens in OpenNHP Service."
    : "Configure local SMTP to send invitations directly from the app.";
}
sendInvitationEmailInput.addEventListener("change", () => {
  if (sendInvitationEmailInput.checked && !invitationEmailInput.value) invitationEmailInput.value = verificationEmailInput.value;
  updateInvitationDelivery();
  if (sendInvitationEmailInput.checked) invitationEmailInput.focus();
});
const activityNotificationsInput = document.getElementById("activity-notifications");
const activityNotificationOptions = document.getElementById("activity-notification-options");
const notificationTargets = document.getElementById("notification-targets");
const configureNotificationsButton = document.getElementById("configure-notifications");
const verificationEmailField = document.getElementById("verification-email-field");
const verificationEmailInput = document.getElementById("verification-email");
const customLifetime = document.getElementById("custom-lifetime");
const customLifetimeValue = document.getElementById(
  "custom-lifetime-value",
);
const customLifetimeUnit = document.getElementById(
  "custom-lifetime-unit",
);
const lifetimeLimit = document.getElementById("lifetime-limit");
const generateAccessLinkButton = document.getElementById("generate-access_link");
const revokeAccessLinksButton = document.getElementById("revoke-access_links");
const access_linkResult = document.getElementById("access_link-result");
const grantList = document.getElementById("grant-list");
const grantCount = document.getElementById("grant-count");
const revokedList = document.getElementById("revoked-list");
const revokedCount = document.getElementById("revoked-count");
const securityEventList = document.getElementById("security-event-list");
const securityEventCount = document.getElementById("security-event-count");
const activityDialog = document.getElementById("activity-dialog");
const closeActivityDialogButton =
  document.getElementById("close-activity-dialog");
const activityTitle = document.getElementById("activity-title");
const activitySummary = document.getElementById("activity-summary");
const activityList = document.getElementById("activity-list");
const deleteActivityButton = document.getElementById("delete-activity");
const catalog = document.getElementById("catalog");
const openResetDialogButton = document.getElementById("open-reset-dialog");
const resetDialog = document.getElementById("reset-dialog");
const closeResetDialogButton = document.getElementById("close-reset-dialog");
const cancelResetButton = document.getElementById("cancel-reset");
const confirmResetButton = document.getElementById("confirm-reset");
const resetConfirmationInput =
  document.getElementById("reset-confirmation");
const resetStatus = document.getElementById("reset-status");
const gatewayVersion = document.getElementById("gateway-version");
const gatewayHealth = document.getElementById("gateway-health");
const gatewayService = document.getElementById("gateway-access_service");
const gatewayPages = document.getElementById("gateway-pages");
const gatewayConnectors = document.getElementById("gateway-connectors");
const gatewayGuests = document.getElementById("gateway-guests");
const gatewayEmail = document.getElementById("gateway-email");
const gatewayNotifications = document.getElementById("gateway-notifications");
const configureEmailButton = document.getElementById("configure-email");
const emailDialog = document.getElementById("email-dialog");
const closeEmailDialogButton = document.getElementById("close-email-dialog");
const emailForm = document.getElementById("email-form");
const saveEmailButton = document.getElementById("save-email");
const smtpHost = document.getElementById("smtp-host");
const smtpPort = document.getElementById("smtp-port");
const smtpSecurity = document.getElementById("smtp-security");
const smtpUsername = document.getElementById("smtp-username");
const smtpPassword = document.getElementById("smtp-password");
const smtpSenderEmail = document.getElementById("smtp-sender-email");
const smtpSenderName = document.getElementById("smtp-sender-name");
const smtpAdministratorEmail = document.getElementById("smtp-administrator-email");
const alertMobileTargets = document.getElementById("alert-mobile-targets");
const smtpTestRecipient = document.getElementById("smtp-test-recipient");
const testEmailButton = document.getElementById("test-email");
const emailStatus = document.getElementById("email-status");
let availableMobileAlertTargets = [];
let savedMobileAlertTargets = new Set();
const confirmDialog = document.getElementById("confirm-dialog");
const confirmMessage = document.getElementById("confirm-message");
const closeConfirmDialogButton = document.getElementById(
  "close-confirm-dialog",
);
const cancelConfirmButton = document.getElementById("cancel-confirm");
const acceptConfirmButton = document.getElementById("accept-confirm");

let pages = [];
let discovery = {entities: []};
let currentPage = null;
let editingExisting = false;
let accessServiceApiConfigured = false;
let emailConfigured = false;
let registeredNotificationOptions = [];
let access_linkMaxLifetimeDays = 3;
let idWasManuallyEdited = false;
let applicationReady = false;
let activityGuests = [];
let pageSecurityEvents = [];
let selectedActivityGuest = null;
const selections = new Map();
const customNames = new Map();
const cameraRefreshIntervals = new Map();
let selectionOrder = [];
let pickerBrowseMode = "type";
let activePickerCategory = null;
let confirmationResolver = null;

function settleConfirmation(accepted) {
  if (!confirmationResolver) return;
  const resolve = confirmationResolver;
  confirmationResolver = null;
  confirmDialog.close();
  resolve(accepted);
}

function confirmAction(message) {
  if (confirmationResolver) {
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    confirmationResolver = resolve;
    confirmMessage.textContent = message;
    confirmDialog.showModal();
    acceptConfirmButton.focus();
  });
}

closeConfirmDialogButton.addEventListener("click", () => {
  settleConfirmation(false);
});
cancelConfirmButton.addEventListener("click", () => {
  settleConfirmation(false);
});
acceptConfirmButton.addEventListener("click", () => {
  settleConfirmation(true);
});
confirmDialog.addEventListener("cancel", (event) => {
  event.preventDefault();
  settleConfirmation(false);
});
confirmDialog.addEventListener("click", (event) => {
  if (event.target === confirmDialog) {
    settleConfirmation(false);
  }
});

configureEmailButton.addEventListener("click", () => {
  openEmailSettings().catch((error) => setStatus(`Error: ${error.message}`, "error"));
});
closeEmailDialogButton.addEventListener("click", () => emailDialog.close());
emailForm.addEventListener("submit", saveEmailSettings);
testEmailButton.addEventListener("click", sendTestEmail);
activityNotificationsInput.addEventListener("change", () => {
  activityNotificationOptions.classList.toggle(
    "hidden", !activityNotificationsInput.checked,
  );
});
configureNotificationsButton.addEventListener("click", () => {
  userDialog.close();
  openEmailSettings().catch((error) => setStatus(`Error: ${error.message}`, "error"));
});

function renderNotificationTargets(options) {
  registeredNotificationOptions = options;
  notificationTargets.replaceChildren();
  for (const option of options) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "notification-target";
    input.value = option.value;
    const text = document.createElement("span");
    text.textContent = option.label;
    label.append(input, text);
    notificationTargets.appendChild(label);
  }
  if (!options.length) {
    const note = document.createElement("small");
    note.textContent = "No alert destinations are configured. Add an administrator email below, or register a Home Assistant Companion App device.";
    notificationTargets.appendChild(note);
  }
  configureNotificationsButton.classList.toggle("hidden", options.length > 0);
}

async function loadNotificationOptions() {
  const response = await adminApi.fetch("api/admin/notification-options", {cache: "no-store"});
  const data = await responseJson(response, "Could not load notification options");
  if (!response.ok) throw new Error(data.error || "Could not load notification options");
  const options = [];
  if (data.email?.configured) {
    options.push({value: "email", label: `Email · ${data.email.address}`});
  }
  for (const target of data.mobile_targets || []) {
    options.push({value: target, label: target.replace("notify.mobile_app_", "Mobile · ").replaceAll("_", " ")});
  }
  renderNotificationTargets(options);
  gatewayNotifications.textContent = options.length
    ? `${options.length} configured`
    : "Setup required";
}

async function responseJson(response, fallback) {
  const contentType = response.headers.get("content-type") || "";
  const body = await response.text();

  try {
    return JSON.parse(body);
  } catch (error) {
    const detail = contentType
      ? `HTTP ${response.status} returned ${contentType}`
      : `HTTP ${response.status} returned a non-JSON response`;
    throw new Error(`${fallback}: ${detail}`);
  }
}

async function waitForConnectionReset(timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await adminApi.fetch(
        `setup/status?transition=${Date.now()}`,
        {cache: "no-store"},
      );
      const result = await response.json();
      if (response.ok && result.enrolled === false) {
        return true;
      }
    } catch (_error) {
      // The upstream is expected to be briefly unavailable while it swaps.
    }
    await new Promise((resolve) => window.setTimeout(resolve, 500));
  }
  return false;
}

function openSetupPage() {
  // The same authenticated Ingress view loads the authoritative setup document.
  const setupUrl = new URL("admin", document.baseURI);
  setupUrl.searchParams.set("reset", String(Date.now()));
  window.location.replace(setupUrl.toString());
}

function renderInvitationDelivery(result, sharingContent, delivery) {
  if (!delivery?.requested) {
    result.append(sharingContent);
    return;
  }
  const status = document.createElement("div");
  status.className = `invitation-delivery-status${delivery.sent ? "" : " warning"}`;
  const heading = document.createElement("strong");
  heading.textContent = delivery.sent ? "Invitation email submitted" : "Email delivery could not be confirmed";
  const detail = document.createElement("p");
  detail.textContent = delivery.sent
    ? "Your SMTP provider accepted the invitation. Backup sharing options remain available below."
    : "The invitation is saved. Use a sharing option below, then check your email configuration.";
  status.append(heading, detail);
  result.append(status);
  if (delivery.sent) {
    const fallback = document.createElement("details");
    fallback.className = "invitation-sharing-fallback";
    const summary = document.createElement("summary");
    summary.textContent = "Show backup sharing options";
    fallback.append(summary, sharingContent);
    result.append(fallback);
  } else {
    result.append(sharingContent);
  }
}

async function resetServiceConnection() {
  confirmResetButton.disabled = true;
  resetStatus.className = "status";
  resetStatus.textContent =
    "Revoking guests and resetting the OpenNHP Service connection…";
  setStatus("Revoking guests and resetting the OpenNHP Service connection…");
  try {
    let response;
    try {
      response = await adminApi.fetch("api/admin/connection/reset", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({confirmation: resetConfirmationInput.value}),
      });
    } catch (error) {
      // A dropped response is not proof of reset: confirm the native setup state.
      if (await waitForConnectionReset()) {
        openSetupPage();
        return;
      }
      throw error;
    }
    const data = await responseJson(
      response,
      "Could not reset the OpenNHP Service connection",
    );
    if (!response.ok) {
      throw new Error(data.error || "Could not reset the OpenNHP Service connection");
    }
    resetDialog.close();
    const cleanupNote = data.remote_failures.length
      ? ` ${data.remote_failures.length} remote AccessLink cleanup attempt(s) failed; local access is still revoked.`
      : "";
    setStatus(
      `Revoked ${data.grants_revoked} guest link(s). Pages were preserved. ` +
      `Reconnecting…${cleanupNote}`,
      "success",
    );
    if (await waitForConnectionReset()) {
      openSetupPage();
    } else {
      setStatus(
        "The reset completed, but onboarding is taking longer than expected. " +
        "Reopen Access Pages from the sidebar.",
        "error",
      );
    }
  } catch (error) {
    resetStatus.className = "status error";
    resetStatus.textContent = `Error: ${error.message}`;
    setStatus(`Error: ${error.message}`, "error");
    confirmResetButton.disabled =
      resetConfirmationInput.value !== "RESET";
  }
}

async function openAdminPreview(pageId) {
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(pageId)}/preview`,
    {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: "{}",
    },
  );
  const data = await responseJson(response, "Could not create preview");

  if (!response.ok) {
    throw new Error(data.error || "Could not create preview");
  }

  // Home Assistant's mobile app may open a new window in a separate WebView
  // that does not inherit the authenticated Ingress session. Staying in the
  // current view preserves that session; the Back action returns to admin.
  window.location.assign(data.preview_url);
}

function setStatus(message, kind = "") {
  statusBox.className = `status ${kind}`.trim();
  statusBox.textContent = message;
}

async function loadGatewayStatus() {
  try {
    const response = await adminApi.fetch("health", {cache: "no-store"});
    const data = await responseJson(
      response,
      "Could not load Gateway status",
    );
    if (!response.ok) {
      throw new Error(data.error || "Gateway health check failed");
    }

    gatewayVersion.textContent = data.version || "Unknown";
    document.getElementById("gateway-device-data").textContent = data.device_data === "homeassistant"
      ? "Home Assistant" : "Home Assistant setup required";
    gatewayHealth.textContent =
      data.status === "ok" ? "Online" : "Unavailable";
    gatewayService.textContent = data.access_service_api_configured
      ? "Configured"
      : "Setup required";
    gatewayEmail.textContent = data.email_configured
      ? "Configured"
      : "Not configured";
    emailConfigured = Boolean(data.email_configured);
    updateInvitationDelivery();
    try {
      await loadNotificationOptions();
    } catch (_error) {
      renderNotificationTargets([]);
      gatewayNotifications.textContent = "Unavailable";
    }
    gatewayPages.textContent = String(data.page_count ?? pages.length);
    const connectorTotal = Number(data.connectors?.total ?? 0);
    const connectorActive = Number(data.connectors?.active ?? 0);
    const connectorDormant = Math.max(0, connectorTotal - connectorActive);
    gatewayConnectors.textContent =
      `${connectorActive} active · ${connectorDormant} dormant · ${connectorTotal} total`;
  } catch (_error) {
    gatewayVersion.textContent = "Unknown";
    gatewayHealth.textContent = "Unavailable";
    gatewayService.textContent = "Unknown";
    gatewayEmail.textContent = "Unknown";
    gatewayNotifications.textContent = "Unknown";
    gatewayPages.textContent = String(pages.length);
    gatewayConnectors.textContent = "Unknown";
  }

  updateGatewayCounts();
}

function setEmailStatus(message, kind = "") {
  emailStatus.className = `status ${kind}`.trim();
  emailStatus.textContent = message;
}

async function testMobileAlertTarget(target, button) {
  button.disabled = true;
  const originalText = button.textContent;
  button.textContent = "Sending…";
  try {
    const response = await adminApi.fetch("api/admin/alerts/test", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target}),
    });
    const data = await responseJson(response, "Could not send mobile test");
    if (!response.ok) throw new Error(data.error || "Could not send mobile test");
    button.textContent = "Sent ✓";
    setEmailStatus(`Test notification sent to ${target}.`, "success");
    setTimeout(() => { button.textContent = originalText; }, 1800);
  } catch (error) {
    button.textContent = originalText;
    setEmailStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function renderMobileAlertTargets() {
  alertMobileTargets.replaceChildren();
  for (const target of availableMobileAlertTargets) {
    const row = document.createElement("div");
    row.className = "mobile-alert-row";
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "configured-mobile-alert-target";
    input.value = target;
    input.checked = savedMobileAlertTargets.has(target);
    const text = document.createElement("span");
    text.textContent = target.replace("notify.mobile_app_", "Mobile · ").replaceAll("_", " ");
    label.append(input, text);
    const testButton = document.createElement("button");
    testButton.type = "button";
    testButton.className = "secondary";
    testButton.textContent = "Send test";
    testButton.disabled = !savedMobileAlertTargets.has(target);
    testButton.title = testButton.disabled ? "Save this recipient before testing" : "";
    testButton.addEventListener("click", () => testMobileAlertTarget(target, testButton));
    row.append(label, testButton);
    alertMobileTargets.appendChild(row);
  }
  if (!availableMobileAlertTargets.length) {
    const note = document.createElement("small");
    note.textContent = "No notify.mobile_app_* targets were discovered in Home Assistant.";
    alertMobileTargets.appendChild(note);
  }
}

async function openEmailSettings() {
  setEmailStatus("Loading email settings…");
  emailDialog.showModal();
  const response = await adminApi.fetch("api/admin/email/config", {
    cache: "no-store",
  });
  const data = await responseJson(response, "Could not load email settings");
  if (!response.ok) {
    setEmailStatus(data.error || "Could not load email settings", "error");
    return;
  }
  smtpHost.value = data.host || "";
  smtpPort.value = String(data.port || 587);
  smtpSecurity.value = data.security || "starttls";
  smtpUsername.value = data.username || "";
  smtpPassword.value = "";
  smtpSenderEmail.value = data.sender_email || "";
  smtpSenderName.value = data.sender_name || "Access Pages";
  smtpAdministratorEmail.value = data.administrator_email || data.sender_email || "";
  const notificationResponse = await adminApi.fetch("api/admin/notification-options", {
    cache: "no-store",
  });
  const notificationData = await responseJson(
    notificationResponse,
    "Could not load mobile alert destinations",
  );
  if (!notificationResponse.ok) {
    setEmailStatus(notificationData.error || "Could not load mobile alert destinations", "error");
    return;
  }
  availableMobileAlertTargets = notificationData.available_mobile_targets || [];
  savedMobileAlertTargets = new Set(notificationData.mobile_targets || []);
  renderMobileAlertTargets();
  setEmailStatus(data.configured
    ? "Email delivery is configured. A blank password keeps the saved password."
    : "Enter the SMTP submission settings supplied by your email provider.");
}

async function saveEmailSettings(event) {
  event.preventDefault();
  setEmailStatus("Saving email settings…");
  saveEmailButton.disabled = true;
  saveEmailButton.textContent = "Saving…";
  const response = await adminApi.fetch("api/admin/email/config", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      host: smtpHost.value,
      port: Number(smtpPort.value),
      security: smtpSecurity.value,
      username: smtpUsername.value,
      password: smtpPassword.value,
      sender_email: smtpSenderEmail.value,
      sender_name: smtpSenderName.value,
      administrator_email: smtpAdministratorEmail.value,
    }),
  });
  const data = await responseJson(response, "Could not save email settings");
  if (!response.ok) {
    setEmailStatus(data.error || "Could not save email settings", "error");
    saveEmailButton.disabled = false;
    saveEmailButton.textContent = "Save settings";
    return;
  }
  const alertsResponse = await adminApi.fetch("api/admin/alerts/config", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      mobile_targets: [...document.querySelectorAll(
        'input[name="configured-mobile-alert-target"]:checked',
      )].map((input) => input.value),
    }),
  });
  const alertsData = await responseJson(alertsResponse, "Could not save alert destinations");
  if (!alertsResponse.ok) {
    setEmailStatus(alertsData.error || "Could not save alert destinations", "error");
    saveEmailButton.disabled = false;
    saveEmailButton.textContent = "Save settings";
    return;
  }
  savedMobileAlertTargets = new Set(alertsData.mobile_targets || []);
  renderMobileAlertTargets();
  smtpPassword.value = "";
  gatewayEmail.textContent = "Configured";
  emailConfigured = true;
  updateInvitationDelivery();
  setEmailStatus("Local SMTP settings saved for invitations and owner alerts. Guest verification is handled by OpenNHP Service.", "success");
  saveEmailButton.textContent = "Saved ✓";
  setTimeout(() => {
    saveEmailButton.disabled = false;
    saveEmailButton.textContent = "Save settings";
  }, 1800);
  await loadNotificationOptions();
}

async function sendTestEmail() {
  setEmailStatus("Sending test email…");
  testEmailButton.disabled = true;
  try {
    const response = await adminApi.fetch("api/admin/email/test", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({recipient: smtpTestRecipient.value}),
    });
    const data = await responseJson(response, "Could not send test email");
    if (!response.ok) throw new Error(data.error || "Could not send test email");
    setEmailStatus("Test email sent.", "success");
  } catch (error) {
    setEmailStatus(error.message, "error");
  } finally {
    testEmailButton.disabled = false;
  }
}

function updateGatewayCounts() {
  const guestCount = pages.reduce(
    (total, page) => total + Number(page.grant_count || 0),
    0,
  );
  gatewayPages.textContent = String(pages.length);
  gatewayGuests.textContent = String(guestCount);
}

function slugify(value) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function humanize(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function resourceId(entityId) {
  return entityId
    .toLowerCase()
    .replace(".", "_")
    .replace(/[^a-z0-9_-]/g, "_")
    .slice(0, 64);
}

function showDashboard() {
  editor.classList.add("hidden");
  users.classList.add("hidden");
  dashboard.classList.remove("hidden");
  newPageButton.classList.remove("hidden");
  currentPage = null;
  // Preserve the Supervisor Ingress prefix when returning to the dashboard.
  history.replaceState(null, "", location.pathname);
}

function showEditor() {
  dashboard.classList.add("hidden");
  users.classList.add("hidden");
  editor.classList.remove("hidden");
  newPageButton.classList.add("hidden");
}

function showUsers() {
  dashboard.classList.add("hidden");
  editor.classList.add("hidden");
  users.classList.remove("hidden");
  newPageButton.classList.add("hidden");
}

function renderPageList() {
  pageList.replaceChildren();

  if (!pages.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = `
      <h2>No access pages yet</h2>
      <p>Create a page, choose its controls, then point a AccessLink at it.</p>
    `;

    const button = document.createElement("button");
    button.type = "button";
    button.className = "primary";
    button.textContent = "+ Create first page";
    button.disabled = !applicationReady;
    button.addEventListener("click", createNewPage);
    empty.appendChild(button);
    pageList.appendChild(empty);
    return;
  }

  pages.forEach((page) => {
    const card = document.createElement("article");
    card.className = "page-card";

    const copy = document.createElement("div");
    copy.className = "page-copy";

    const name = document.createElement("h2");
    name.textContent = page.title;

    const description = document.createElement("p");
    description.textContent =
      page.description || "No guest description.";

    const metadata = document.createElement("div");
    metadata.className = "page-meta";

    const path = document.createElement("code");
    path.textContent = page.access_path;

    const count = document.createElement("span");
    count.textContent =
      `${page.resource_count} ${page.resource_count === 1 ? "resource" : "resources"}`;

    const userCount = document.createElement("span");
    userCount.textContent =
      `${page.grant_count || 0} ${(page.grant_count || 0) === 1 ? "guest" : "guests"}`;

    metadata.append(path, count, userCount);
    copy.append(name, description, metadata);

    const actions = document.createElement("div");
    actions.className = "page-card-actions";

    const open = document.createElement("button");
    open.type = "button";
    open.className = "primary";
    open.textContent = "Edit";
    open.addEventListener("click", () => editPage(page.id));

    const preview = document.createElement("button");
    preview.type = "button";
    preview.className = "secondary link-button";
    preview.textContent = "Preview";
    preview.addEventListener("click", () => {
      openAdminPreview(page.id).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });

    const manageUsersButton = document.createElement("button");
    manageUsersButton.type = "button";
    manageUsersButton.className = "secondary";
    manageUsersButton.textContent = "Guests";
    manageUsersButton.addEventListener("click", () => manageUsers(page.id));

    actions.append(open, preview, manageUsersButton);
    card.append(copy, actions);
    pageList.appendChild(card);
  });
}

function formatType(value) {
  return String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function loadSelections(page) {
  selections.clear();
  customNames.clear();
  cameraRefreshIntervals.clear();
  selectionOrder = [];

  page.resources.forEach((resource) => {
    selections.set(
      resource.entity_id,
      new Set(resource.actions.map((action) => action.service)),
    );
    customNames.set(resource.entity_id, resource.name);
    if (resource.domain === "camera") {
      cameraRefreshIntervals.set(
        resource.entity_id,
        resource.camera_refresh_interval ?? 30,
      );
    }
    selectionOrder.push(resource.entity_id);
  });
}

function selectedResourceCount() {
  return [...selections.values()]
    .filter((actions) => actions.size > 0)
    .length;
}

function updateSelectionSummary() {
  selectedCount.textContent = selectedResourceCount();
}

function updateSelection(entityId, service, checked, defaultName = "") {
  const wasSelected = selections.has(entityId);
  if (!selections.has(entityId)) {
    selections.set(entityId, new Set());
  }

  const actions = selections.get(entityId);

  if (checked) {
    actions.add(service);
    if (!wasSelected) {
      selectionOrder.push(entityId);
    }
    if (!customNames.has(entityId)) {
      customNames.set(entityId, defaultName || entityId);
    }
  } else {
    actions.delete(service);
  }

  if (!actions.size) {
    selections.delete(entityId);
    customNames.delete(entityId);
    cameraRefreshIntervals.delete(entityId);
    selectionOrder = selectionOrder.filter((item) => item !== entityId);
  }

  updateSelectionSummary();
  renderCatalog();
  renderPicker();
}

function moveSelection(entityId, targetIndex) {
  const currentIndex = selectionOrder.indexOf(entityId);
  if (currentIndex < 0) return;

  const boundedIndex = Math.max(
    0,
    Math.min(targetIndex, selectionOrder.length - 1),
  );
  if (currentIndex === boundedIndex) return;

  selectionOrder.splice(currentIndex, 1);
  selectionOrder.splice(boundedIndex, 0, entityId);
  renderCatalog();
}

function renderCatalog() {
  const entityMap = new Map(
    discovery.entities.map((entity) => [entity.entity_id, entity]),
  );
  const entities = selectionOrder
    .map((entityId) => entityMap.get(entityId))
    .filter(Boolean);
  catalog.replaceChildren();

  if (!entities.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.innerHTML = `
      <h2>No resources selected</h2>
      <p>Add only the Home Assistant entities this guest page needs.</p>
    `;
    const addButton = document.createElement("button");
    addButton.type = "button";
    addButton.className = "primary";
    addButton.textContent = "+ Add resources";
    addButton.addEventListener("click", openPicker);
    empty.appendChild(addButton);
    catalog.appendChild(empty);
    return;
  }

  const grid = document.createElement("div");
  grid.className = "entity-grid";
  entities.forEach((entity, index) => {
      const card = document.createElement("article");
      card.className = "entity-card selected";
      card.dataset.entityId = entity.entity_id;

      const orderControls = document.createElement("div");
      orderControls.className = "entity-order-controls";

      const dragHandle = document.createElement("button");
      dragHandle.type = "button";
      dragHandle.className = "drag-handle";
      dragHandle.draggable = true;
      dragHandle.textContent = "⋮⋮";
      dragHandle.title = "Drag to reorder";
      dragHandle.setAttribute("aria-label", `Drag ${entity.name} to reorder`);
      dragHandle.addEventListener("dragstart", (event) => {
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", entity.entity_id);
        card.classList.add("dragging");
      });
      dragHandle.addEventListener("dragend", () => {
        card.classList.remove("dragging");
        document.querySelectorAll(".entity-card.drag-over")
          .forEach((item) => item.classList.remove("drag-over"));
      });

      const up = document.createElement("button");
      up.type = "button";
      up.className = "secondary order-button";
      up.textContent = "↑";
      up.title = "Move up";
      up.setAttribute("aria-label", `Move ${entity.name} up`);
      up.disabled = index === 0;
      up.addEventListener("click", () => moveSelection(entity.entity_id, index - 1));

      const down = document.createElement("button");
      down.type = "button";
      down.className = "secondary order-button";
      down.textContent = "↓";
      down.title = "Move down";
      down.setAttribute("aria-label", `Move ${entity.name} down`);
      down.disabled = index === entities.length - 1;
      down.addEventListener("click", () => moveSelection(entity.entity_id, index + 1));

      orderControls.append(dragHandle, up, down);
      card.appendChild(orderControls);
      card.addEventListener("dragover", (event) => {
        event.preventDefault();
        event.dataTransfer.dropEffect = "move";
        card.classList.add("drag-over");
      });
      card.addEventListener("dragleave", () => card.classList.remove("drag-over"));
      card.addEventListener("drop", (event) => {
        event.preventDefault();
        card.classList.remove("drag-over");
        const draggedId = event.dataTransfer.getData("text/plain");
        if (draggedId && draggedId !== entity.entity_id) {
          moveSelection(draggedId, index);
        }
      });

      const header = document.createElement("div");
      header.className = "entity-heading";

      const identity = document.createElement("div");
      const name = document.createElement("h3");
      name.textContent = entity.name;
      const entityId = document.createElement("code");
      entityId.textContent = entity.entity_id;
      identity.append(name, entityId);

      const state = document.createElement("span");
      state.className = "state";
      state.textContent = entity.state;

      header.append(identity, state);
      card.appendChild(header);

      const type = document.createElement("span");
      type.className = "entity-type";
      type.textContent = formatType(entity.type || entity.domain);
      card.appendChild(type);

      const actionList = document.createElement("div");
      actionList.className = "action-list";

      entity.actions.forEach((action) => {
        const label = document.createElement("label");
        label.className = "action-option";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked =
          selections.get(entity.entity_id)?.has(action.service) || false;

        checkbox.addEventListener("change", () => {
          updateSelection(
            entity.entity_id,
            action.service,
            checkbox.checked,
            entity.name,
          );
        });

        const actionText = document.createElement("span");
        const actionName = document.createElement("strong");
        actionName.textContent = action.name;
        const serviceName = document.createElement("code");
        serviceName.textContent = action.service === "view"
          ? "Read-only display"
          : `${entity.domain}.${action.service}`;
        actionText.append(actionName, serviceName);

        label.append(checkbox, actionText);
        actionList.appendChild(label);
      });

      card.appendChild(actionList);

      const nameEditor = document.createElement("label");
      nameEditor.className = "custom-name-editor";

        const nameLabel = document.createElement("span");
        nameLabel.textContent = "Guest display name";

        const nameInput = document.createElement("input");
        nameInput.type = "text";
        nameInput.maxLength = 100;
        nameInput.value =
          customNames.get(entity.entity_id) || entity.name;
        nameInput.placeholder = entity.name;

        nameInput.addEventListener("input", () => {
          customNames.set(
            entity.entity_id,
            nameInput.value,
          );
        });

      nameEditor.append(nameLabel, nameInput);
      card.appendChild(nameEditor);

      if (entity.domain === "camera") {
        const refreshEditor = document.createElement("label");
        refreshEditor.className = "custom-name-editor";
        const refreshLabel = document.createElement("span");
        refreshLabel.textContent = "Still-image refresh";
        const refreshSelect = document.createElement("select");
        for (const [value, label] of [
          [15, "15 seconds"], [30, "30 seconds"], [60, "1 minute"],
          [120, "2 minutes"], [300, "5 minutes"], [0, "Manual only"],
        ]) {
          const option = document.createElement("option");
          option.value = String(value);
          option.textContent = label;
          refreshSelect.appendChild(option);
        }
        refreshSelect.value = String(cameraRefreshIntervals.get(entity.entity_id) ?? 30);
        cameraRefreshIntervals.set(entity.entity_id, Number(refreshSelect.value));
        refreshSelect.addEventListener("change", () => {
          cameraRefreshIntervals.set(entity.entity_id, Number(refreshSelect.value));
        });
        refreshEditor.append(refreshLabel, refreshSelect);
        card.appendChild(refreshEditor);
      } else {
        cameraRefreshIntervals.delete(entity.entity_id);
      }

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "remove-resource";
      remove.textContent = "Remove resource";
      remove.addEventListener("click", () => {
        selections.delete(entity.entity_id);
        customNames.delete(entity.entity_id);
        cameraRefreshIntervals.delete(entity.entity_id);
        selectionOrder = selectionOrder.filter(
          (item) => item !== entity.entity_id,
        );
        updateSelectionSummary();
        renderCatalog();
        renderPicker();
      });
      card.appendChild(remove);

      grid.appendChild(card);
  });
  catalog.appendChild(grid);
}

function pickerEntityMatches(entity, query) {
  if (
    activePickerCategory !== null
    && activePickerCategory !== ""
  ) {
    const category = pickerBrowseMode === "target"
      ? (entity.area_id || "__unassigned")
      : (entity.type || entity.domain || "unknown");
    if (category !== activePickerCategory) {
      return false;
    }
  }
  const haystack = [
    entity.name,
    entity.entity_id,
    entity.state,
    entity.domain,
    entity.type,
  ].join(" ").toLowerCase();
  return !query || haystack.includes(query);
}

function renderPicker() {
  pickerTypes.setAttribute(
    "aria-label",
    pickerBrowseMode === "target"
      ? "Home Assistant areas"
      : "Entity types",
  );
  const categoryCounts = new Map();
  const categoryLabels = new Map();
  discovery.entities.forEach((entity) => {
    const category = pickerBrowseMode === "target"
      ? (entity.area_id || "__unassigned")
      : (entity.type || entity.domain || "unknown");
    const label = pickerBrowseMode === "target"
      ? (entity.area_name || "Not assigned to an area")
      : formatType(entity.type || entity.domain);
    categoryCounts.set(
      category,
      (categoryCounts.get(category) || 0) + 1,
    );
    categoryLabels.set(category, label);
  });

  pickerTypes.replaceChildren();
  const categoryEntries = [
    ["", "All supported", discovery.entities.length],
    ...[...categoryCounts.entries()]
      .map(([category, count]) => [
        category,
        categoryLabels.get(category),
        count,
      ])
      .sort((a, b) => a[1].localeCompare(b[1])),
  ];

  categoryEntries.forEach(([category, label, count]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "picker-type";
    button.classList.toggle(
      "active",
      category === activePickerCategory,
    );
    const typeName = document.createElement("span");
    typeName.textContent = label;
    const typeCount = document.createElement("small");
    typeCount.textContent = count;
    button.append(typeName, typeCount);
    button.addEventListener("click", () => {
      activePickerCategory = category;
      renderPicker();
    });
    pickerTypes.appendChild(button);
  });

  const query = pickerSearchInput.value.trim().toLowerCase();
  if (activePickerCategory === null && !query) {
    pickerResults.replaceChildren();
    const prompt = document.createElement("div");
    prompt.className = "picker-prompt";
    const title = document.createElement("h3");
    title.textContent = pickerBrowseMode === "target"
      ? "Select a Home Assistant area"
      : "Select an entity type";
    const description = document.createElement("p");
    description.textContent =
      `Choose ${pickerBrowseMode === "target" ? "an area" : "a type"} ` +
      "on the left or search across all supported entities.";
    prompt.append(title, description);
    pickerResults.appendChild(prompt);
    return;
  }

  const entities = discovery.entities.filter(
    (entity) => pickerEntityMatches(entity, query),
  );
  pickerResults.replaceChildren();

  const heading = document.createElement("div");
  heading.className = "picker-results-heading";
  const title = document.createElement("h3");
  title.textContent = activePickerCategory
    ? (
      pickerBrowseMode === "target"
        ? categoryLabels.get(activePickerCategory)
        : formatType(activePickerCategory)
    )
    : "All supported entities";
  const count = document.createElement("span");
  count.textContent = `${entities.length} available`;
  heading.append(title, count);
  pickerResults.appendChild(heading);

  if (!entities.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No matching entities.";
    pickerResults.appendChild(empty);
    return;
  }

  entities.forEach((entity) => {
    const row = document.createElement("label");
    row.className = "picker-entity";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selections.has(entity.entity_id);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        if (!selections.has(entity.entity_id)) {
          selectionOrder.push(entity.entity_id);
        }
        selections.set(
          entity.entity_id,
          new Set(entity.actions.map((action) => action.service)),
        );
        customNames.set(entity.entity_id, entity.name);
      } else {
        selections.delete(entity.entity_id);
        customNames.delete(entity.entity_id);
        cameraRefreshIntervals.delete(entity.entity_id);
        selectionOrder = selectionOrder.filter(
          (item) => item !== entity.entity_id,
        );
      }
      updateSelectionSummary();
      renderCatalog();
    });

    const copy = document.createElement("span");
    const name = document.createElement("strong");
    name.textContent = entity.name;
    const details = document.createElement("small");
    details.textContent = [
      entity.entity_id,
      entity.state,
      entity.area_name,
    ].filter(Boolean).join(" · ");
    copy.append(name, details);
    const type = document.createElement("span");
    type.className = "picker-entity-type";
    type.textContent = formatType(entity.type || entity.domain);
    row.append(checkbox, copy, type);
    pickerResults.appendChild(row);
  });
}

function openPicker() {
  pickerSearchInput.value = "";
  activePickerCategory = null;
  const policy = discovery.policy || {};
  const scope = policy.feature_profile === "sensors_lights" ? "Sensor/light pilot. " : "";
  if (policy.restricted) {
    const limits = [
      policy.include_areas?.length
        ? `areas: ${policy.include_areas.join(", ")}`
        : "",
      policy.include_device_classes?.length
        ? `types: ${policy.include_device_classes.join(", ")}`
        : "",
      policy.include_domains?.length
        ? `domains: ${policy.include_domains.join(", ")}`
        : "",
      policy.include_entities?.length
        ? `${policy.include_entities.length} explicit entities`
        : "",
    ].filter(Boolean);
    pickerPolicy.textContent =
      scope + `Choices restricted by configuration (${limits.join("; ")}).`;
  } else {
    pickerPolicy.textContent =
      scope + "Showing every entity supported by the gateway.";
  }
  renderPicker();
  pickerDialog.showModal();
  pickerSearchInput.focus();
}

function blankPage() {
  return {
    id: "",
    title: "",
    description: "",
    proximity: {enabled: false, radius_meters: 500},
    resources: [],
    access_grants: [],
  };
}


function selectedLifetime() {
  const selected = document.querySelector(
    'input[name="lifetime"]:checked'
  )?.value || "24h";
  if (selected !== "custom") {
    return selected;
  }

  const amount = Number(customLifetimeValue.value);
  if (!Number.isInteger(amount) || amount < 1) {
    throw new Error("Enter a whole-number custom lifetime.");
  }

  const secondsPerUnit = {
    m: 60,
    h: 60 * 60,
    d: 24 * 60 * 60,
  };
  const seconds = amount * secondsPerUnit[customLifetimeUnit.value];
  if (seconds > access_linkMaxLifetimeDays * 24 * 60 * 60) {
    throw new Error(
      `Lifetime exceeds the configured ${access_linkMaxLifetimeDays}-day maximum.`,
    );
  }
  return `${amount}${customLifetimeUnit.value}`;
}

function updateCustomLifetimeLimit() {
  const maximums = {
    m: access_linkMaxLifetimeDays * 24 * 60,
    h: access_linkMaxLifetimeDays * 24,
    d: access_linkMaxLifetimeDays,
  };
  customLifetimeValue.max = String(
    maximums[customLifetimeUnit.value],
  );
}

function configureLifetimeOptions() {
  const maximumSeconds = access_linkMaxLifetimeDays * 24 * 60 * 60;
  const choices = document.querySelectorAll(
    'input[name="lifetime"][data-seconds]',
  );
  choices.forEach((choice) => {
    const unavailable = Number(choice.dataset.seconds) > maximumSeconds;
    choice.disabled = unavailable;
    choice.closest("label").title = unavailable
      ? `Exceeds the configured ${access_linkMaxLifetimeDays}-day maximum`
      : "";
  });

  const selected = document.querySelector(
    'input[name="lifetime"]:checked',
  );
  if (selected?.disabled) {
    [...choices]
      .filter((choice) => !choice.disabled)
      .at(-1)
      ?.click();
  }

  lifetimeLimit.textContent =
    `Maximum configured lifetime: ${access_linkMaxLifetimeDays} ` +
    `${access_linkMaxLifetimeDays === 1 ? "day" : "days"}. ` +
    "Longer invitations are not available with this service configuration.";
  updateCustomLifetimeLimit();
}

document.querySelectorAll('input[name="lifetime"]').forEach((choice) => {
  choice.addEventListener("change", () => {
    customLifetime.classList.toggle(
      "hidden",
      choice.value !== "custom" || !choice.checked,
    );
    if (choice.value === "custom" && choice.checked) {
      customLifetimeValue.focus();
    }
  });
});

customLifetimeUnit.addEventListener("change", updateCustomLifetimeLimit);

function formatExpiry(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString();
}

function legacyCopyText(value, button) {
  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.left = "-9999px";
  input.style.top = "0";
  const container = button.closest("dialog") || document.body;
  container.appendChild(input);
  input.focus();
  input.select();
  input.setSelectionRange(0, input.value.length);
  try {
    return document.execCommand("copy");
  } finally {
    input.remove();
  }
}

async function copyText(value, button) {
  // Run the synchronous path first while the original click still carries
  // browser user activation. Waiting for a rejected Clipboard API promise can
  // consume that activation before execCommand gets a chance to run.
  let copied = legacyCopyText(value, button);
  if (!copied && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    copied = true;
  }
  if (!copied) {
    throw new Error(
      "Browser blocked copying; select the displayed link manually.",
    );
  }
  const original = button.textContent;
  button.textContent = "Copied";
  setTimeout(() => {
    button.textContent = original;
  }, 1400);
}

function shareMessage(guestName, activationUrl) {
  return [
    `Access Pages for ${guestName}`,
    "",
    "Open this private OpenNHP Service link:",
    activationUrl,
    "",
    "This link grants access. Do not forward it.",
  ].join("\n");
}

function qrCodeSvg(value, label) {
  if (!window.qrcodegen?.QrCode) {
    throw new Error("Local QR encoder did not load.");
  }
  const qr = window.qrcodegen.QrCode.encodeText(
    value,
    window.qrcodegen.QrCode.Ecc.MEDIUM,
  );
  const border = 4;
  const dimension = qr.size + border * 2;
  const namespace = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(namespace, "svg");
  svg.classList.add("share-qr-code");
  svg.setAttribute("viewBox", `0 0 ${dimension} ${dimension}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  svg.setAttribute("shape-rendering", "crispEdges");

  const background = document.createElementNS(namespace, "rect");
  background.setAttribute("width", "100%");
  background.setAttribute("height", "100%");
  background.setAttribute("fill", "#fff");

  let modules = "";
  for (let y = 0; y < qr.size; y += 1) {
    for (let x = 0; x < qr.size; x += 1) {
      if (qr.getModule(x, y)) {
        modules += `M${x + border},${y + border}h1v1h-1z`;
      }
    }
  }
  const foreground = document.createElementNS(namespace, "path");
  foreground.setAttribute("d", modules);
  foreground.setAttribute("fill", "#000");
  svg.append(background, foreground);
  return svg;
}

function buildSharePanel(guestName, activationUrl) {
  const panel = document.createElement("section");
  panel.className = "link-sharing";

  const heading = document.createElement("h3");
  heading.textContent = "Share an Access Page";
  const explanation = document.createElement("p");
  explanation.className = "share-note";
  explanation.textContent = navigator.share
    ? "Use Share to choose Messages, Mail, AirDrop, or another app. QR codes " +
      "are created on this device. These sharing buttons use your chosen app."
    : "QR codes are created on this device. Email opens with the message " +
      "filled in. Text opens Messages and copies the message for you to paste. " +
      "These sharing buttons use your email or messaging app. SMTP delivery is selected when creating the invitation.";

  const message = shareMessage(guestName, activationUrl);
  const actions = document.createElement("div");
  actions.className = "share-actions";

  if (navigator.share) {
    const nativeShare = document.createElement("button");
    nativeShare.type = "button";
    nativeShare.className = "primary";
    nativeShare.textContent = "Share…";
    nativeShare.addEventListener("click", async () => {
      try {
        await navigator.share({
          title: `Access Pages for ${guestName}`,
          text: message,
        });
      } catch (error) {
        if (error.name !== "AbortError") {
          setStatus(`Share failed: ${error.message}`, "error");
        }
      }
    });
    actions.appendChild(nativeShare);
  }

  const qrToggle = document.createElement("button");
  qrToggle.type = "button";
  qrToggle.className = "secondary";
  qrToggle.textContent = "Show QR codes";

  const qrGrid = document.createElement("div");
  qrGrid.className = "share-qr-grid hidden";
  [["Access Pages AccessLink", activationUrl]].forEach(([title, value]) => {
    const card = document.createElement("figure");
    card.className = "share-qr-card";
    const caption = document.createElement("figcaption");
    caption.textContent = title;
    card.append(qrCodeSvg(value, `${title} QR code`), caption);
    qrGrid.appendChild(card);
  });
  qrToggle.addEventListener("click", () => {
    const isHidden = qrGrid.classList.toggle("hidden");
    qrToggle.textContent = isHidden ? "Show QR codes" : "Hide QR codes";
  });
  actions.appendChild(qrToggle);

  panel.append(heading, explanation, actions, qrGrid);

  if (!navigator.share) {
    const recipients = document.createElement("div");
    recipients.className = "share-recipients";

    const emailLabel = document.createElement("label");
    emailLabel.textContent = "Email recipient (optional)";
    const emailInput = document.createElement("input");
    emailInput.type = "email";
    emailInput.autocomplete = "email";
    emailInput.placeholder = "guest@example.com";
    const emailLink = document.createElement("a");
    emailLink.className = "link-button secondary";
    emailLink.target = "_top";
    emailLink.textContent = "Compose email";
    const updateEmailHref = () => {
      const recipient = emailInput.value.trim();
      const subject = `Access Pages for ${guestName}`;
      emailLink.href =
        `mailto:${encodeURIComponent(recipient)}?subject=${encodeURIComponent(subject)}` +
        `&body=${encodeURIComponent(message)}`;
    };
    emailInput.addEventListener("input", updateEmailHref);
    updateEmailHref();
    emailLink.addEventListener("click", (event) => {
      if (emailInput.value && !emailInput.checkValidity()) {
        event.preventDefault();
        emailInput.reportValidity();
      }
    });
    emailLabel.appendChild(emailInput);

    const phoneLabel = document.createElement("label");
    phoneLabel.textContent = "Mobile number (optional)";
    const phoneInput = document.createElement("input");
    phoneInput.type = "tel";
    phoneInput.autocomplete = "tel";
    phoneInput.inputMode = "tel";
    phoneInput.placeholder = "+1 555 555 0123";
    const smsLink = document.createElement("a");
    smsLink.className = "link-button secondary";
    smsLink.target = "_top";
    smsLink.textContent = "Open Messages + copy";
    const updateSmsHref = () => {
      const recipient = phoneInput.value.trim().replace(/[^+0-9]/g, "");
      smsLink.href = `sms:${recipient}`;
    };
    phoneInput.addEventListener("input", updateSmsHref);
    updateSmsHref();
    smsLink.addEventListener("click", () => {
      if (!legacyCopyText(message, smsLink)) {
        setStatus(
          "Messages opened, but copying was blocked. Copy the links manually.",
          "error",
        );
      }
    });
    phoneLabel.appendChild(phoneInput);

    recipients.append(emailLabel, emailLink, phoneLabel, smsLink);
    panel.appendChild(recipients);
  }
  return panel;
}

function renderAccessGrants(page) {
  const grants = page?.access_grants || [];
  grantCount.textContent = String(grants.length);
  grantList.replaceChildren();
  revokeAccessLinksButton.disabled = grants.length === 0;
  renderRevokedGuests();

  if (!grants.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent =
      "No AccessLinks have been generated for this page.";
    grantList.appendChild(empty);
    return;
  }

  grants.forEach((grant) => {
    const card = document.createElement("article");
    card.className = "grant-card";

    const copy = document.createElement("div");
    copy.className = "grant-copy";

    const heading = document.createElement("strong");
    heading.textContent = grant.label || "Unnamed guest";

    const details = document.createElement("span");
    details.textContent =
      `${grant.lifetime || "Custom"} · expires ${formatExpiry(grant.expires_at)}` +
      (grant.one_time_use ? " · one-time use" : "") +
      (grant.verification_method && grant.verification_method !== "none" ? " · NHP before access: " + (grant.verification_method === "google_or_email" ? "Google or email code" : grant.verification_method) : "") +
      (grant.verification_required ? " · email verified" : "");

    copy.append(heading, details);

    const actions = document.createElement("div");
    actions.className = "grant-actions";

    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.className = "secondary";
    copyButton.textContent = "Copy activation";
    copyButton.addEventListener("click", () => {
      copyText(grant.access_link_url, copyButton).catch((error) => {
        setStatus(`Copy failed: ${error.message}`, "error");
      });
    });

    const revokeButton = document.createElement("button");
    revokeButton.type = "button";
    revokeButton.className = "danger";
    revokeButton.textContent = "Revoke this link";
    revokeButton.addEventListener("click", () => {
      revokeGrant(grant).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });

    const activityButton = document.createElement("button");
    activityButton.type = "button";
    activityButton.className = "secondary";
    activityButton.textContent = "View activity";
    activityButton.addEventListener("click", () => {
      openGuestActivity(grant.id).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });

    actions.append(activityButton, copyButton, revokeButton);
    card.append(copy, actions);
    grantList.appendChild(card);
  });
}

function renderRevokedGuests() {
  const revoked = activityGuests.filter((guest) => guest.revoked_at);
  revokedCount.textContent = String(revoked.length);
  revokedList.replaceChildren();

  if (!revoked.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No retained revoked-guest history.";
    revokedList.appendChild(empty);
    return;
  }

  revoked.forEach((guest) => {
    const expired = pageSecurityEvents.some(
      (entry) => entry.grant_id === guest.grant_id &&
        entry.event_type === "guest_access_expired",
    );
    const card = document.createElement("article");
    card.className = "grant-card revoked-grant";
    const copy = document.createElement("div");
    copy.className = "grant-copy";
    const heading = document.createElement("strong");
    heading.textContent = guest.label || "Unnamed guest";
    const details = document.createElement("span");
    details.textContent =
      `${expired ? "Expired" : "Revoked"} ${formatExpiry(guest.revoked_at)} · ` +
      `${guest.action_count} action${guest.action_count === 1 ? "" : "s"}`;
    copy.append(heading, details);

    const viewButton = document.createElement("button");
    viewButton.type = "button";
    viewButton.className = "secondary";
    viewButton.textContent = "View activity";
    viewButton.addEventListener("click", () => {
      openGuestActivity(guest.grant_id).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });
    card.append(copy, viewButton);
    revokedList.appendChild(card);
  });
}

function securityEventDescription(entry) {
  const details = entry.details || {};
  const guest = entry.guest_label ? ` · ${entry.guest_label}` : "";
  const context = [
    details.resource_id,
    details.action_id && humanize(details.action_id),
  ].filter(Boolean).join(" · ");
  return {
    title: `${humanize(entry.event_type)}${guest}`,
    context: context || humanize(details.reason || "Gateway protection"),
  };
}

function renderSecurityEvents() {
  securityEventCount.textContent = String(pageSecurityEvents.length);
  securityEventList.replaceChildren();
  if (!pageSecurityEvents.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No security events recorded for this page.";
    securityEventList.appendChild(empty);
    return;
  }
  pageSecurityEvents.forEach((entry) => {
    const description = securityEventDescription(entry);
    const row = document.createElement("article");
    row.className = "activity-entry security-event-entry";
    const heading = document.createElement("strong");
    heading.textContent = description.title;
    const metadata = document.createElement("span");
    metadata.textContent = formatExpiry(entry.occurred_at);
    const context = document.createElement("small");
    context.textContent = description.context;
    row.append(heading, metadata, context);
    securityEventList.appendChild(row);
  });
}

async function loadGuestActivitySummaries(pageId) {
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(pageId)}/activity`,
    {cache: "no-store"},
  );
  const data = await responseJson(response, "Could not load guest activity");
  if (!response.ok) {
    throw new Error(data.error || "Could not load guest activity");
  }
  activityGuests = data.guests || [];
  pageSecurityEvents = data.security_events || [];
  renderSecurityEvents();
}

function activityParameters(parameters) {
  const entries = Object.entries(parameters || {});
  return entries.length
    ? entries.map(([key, value]) => `${humanize(key)}: ${value}`).join(" · ")
    : "No parameters";
}

async function openGuestActivity(grantId) {
  if (!currentPage) return;
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(currentPage.id)}/activity/` +
      encodeURIComponent(grantId),
    {cache: "no-store"},
  );
  const data = await responseJson(response, "Could not load guest activity");
  if (!response.ok) {
    throw new Error(data.error || "Could not load guest activity");
  }

  selectedActivityGuest = data.guest;
  activityTitle.textContent = data.guest.label || "Unnamed guest";
  const expired = (data.security_events || []).some(
    (entry) => entry.event_type === "guest_access_expired",
  );
  activitySummary.textContent = data.guest.revoked_at
    ? `${expired ? "Expired" : "Revoked"} ${formatExpiry(data.guest.revoked_at)}. History is automatically deleted after 30 days.`
    : `Active access · expires ${formatExpiry(data.guest.expires_at)}.`;
  deleteActivityButton.classList.toggle(
    "hidden",
    !data.guest.revoked_at,
  );
  activityList.replaceChildren();

  if (!data.actions.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No actions recorded for this guest.";
    activityList.appendChild(empty);
  } else {
    data.actions.forEach((entry) => {
      const row = document.createElement("article");
      row.className = `activity-entry ${entry.outcome}`;
      const heading = document.createElement("strong");
      heading.textContent = `${entry.entity_name} · ${humanize(entry.action_id)}`;
      const metadata = document.createElement("span");
      metadata.textContent =
        `${formatExpiry(entry.occurred_at)} · ${entry.outcome}`;
      const parameters = document.createElement("small");
      parameters.textContent = activityParameters(entry.parameters);
      row.append(heading, metadata, parameters);
      if (entry.error) {
        const error = document.createElement("small");
        error.className = "activity-error";
        error.textContent = entry.error;
        row.appendChild(error);
      }
      activityList.appendChild(row);
    });
  }
  (data.security_events || []).forEach((entry) => {
    const description = securityEventDescription(entry);
    const row = document.createElement("article");
    row.className = "activity-entry security-event-entry";
    const heading = document.createElement("strong");
    heading.textContent = description.title;
    const metadata = document.createElement("span");
    metadata.textContent = formatExpiry(entry.occurred_at);
    const context = document.createElement("small");
    context.textContent = description.context;
    row.append(heading, metadata, context);
    activityList.appendChild(row);
  });
  activityDialog.showModal();
}

async function deleteSelectedActivity() {
  if (!currentPage || !selectedActivityGuest?.revoked_at) return;
  if (!await confirmAction(
    "Permanently delete this revoked guest and all of their activity history?",
  )) {
    return;
  }
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(currentPage.id)}/activity/` +
      encodeURIComponent(selectedActivityGuest.grant_id),
    {method: "DELETE"},
  );
  const data = await responseJson(response, "Could not delete guest record");
  if (!response.ok) {
    throw new Error(data.error || "Could not delete guest record");
  }
  activityDialog.close();
  selectedActivityGuest = null;
  await loadGuestActivitySummaries(currentPage.id);
  renderAccessGrants(currentPage);
  setStatus("Revoked guest and activity history deleted.", "success");
}

function openUserDialog() {
  sendInvitationEmailInput.checked = false;
  invitationEmailInput.value = "";
  updateInvitationDelivery();
  oneTimeUseInput.checked = true;
  nhpVerificationInput.value = verificationMethods.google_or_email ? "google_or_email" : "none";
  updateNhpVerification();
  access_linkLabelInput.value = "";
  activityNotificationsInput.checked = false;
  activityNotificationOptions.classList.add("hidden");
  verificationEmailInput.value = "";
  verificationEmailField.classList.add("hidden");
  access_linkResult.classList.add("hidden");
  userDialog.showModal();
  void loadVerificationStatus();
  access_linkLabelInput.focus();
}

async function generateAccessLink() {
  if (generateAccessLinkButton.disabled) return;
  if (!currentPage || !editingExisting) {
    setStatus("Save the page before generating a AccessLink.", "error");
    return;
  }

  if (!accessServiceApiConfigured) {
    setStatus(
      "The Guest Gateway is not connected to the OpenNHP Service.",
      "error",
    );
    return;
  }

  const userName = access_linkLabelInput.value.trim();
  if (!userName) {
    setStatus("Enter a guest name before creating the link.", "error");
    access_linkLabelInput.focus();
    return;
  }

  if (nhpVerificationInput.value !== "none" && (!verificationEmailInput.value.trim() || !verificationEmailInput.checkValidity())) {
    setStatus("Enter the invited guest email for verification.", "error");
    verificationEmailInput.focus();
    return;
  }

  if (verificationMethods[nhpVerificationInput.value] !== true) {
    setStatus("The selected verification method is unavailable. Refresh verification options before creating this invitation.", "error");
    return;
  }
  const verificationEmail = verificationEmailInput.value.trim();
  const notificationSettings = activityNotificationsInput.checked ? {
    targets: [...document.querySelectorAll('input[name="notification-target"]:checked')].map((input) => input.value),
    events: [...document.querySelectorAll('input[name="notification-event"]:checked')].map((input) => input.value),
  } : null;
  if (activityNotificationsInput.checked && !notificationSettings.targets.length) {
    setStatus("Choose a configured email or mobile notification target.", "error");
    activityNotificationOptions.classList.remove("hidden");
    return;
  }
  if (activityNotificationsInput.checked && !notificationSettings.events.length) {
    setStatus("Choose at least one guest activity to be notified about.", "error");
    return;
  }

  const invitationEmail = invitationEmailInput.value.trim().toLowerCase();
  if (sendInvitationEmailInput.checked) {
    if (!emailConfigured || !invitationEmail || !invitationEmailInput.checkValidity()) {
      setStatus("Configure local SMTP and enter the invitation recipient.", "error");
      invitationEmailInput.focus();
      return;
    }
    if (nhpVerificationInput.value !== "none" && invitationEmail !== verificationEmail.toLowerCase()) {
      setStatus("Send the invitation to the email selected for guest verification.", "error");
      invitationEmailInput.focus();
      return;
    }
  }

  generateAccessLinkButton.disabled = true;
  setStatus(`Creating access for ${userName}…`);
  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(currentPage.id)}/access-links`,
      {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          label: userName,
          lifetime: selectedLifetime(),
          one_time_use: oneTimeUseInput.checked,
          verification_email: verificationEmail,
          verification_method: nhpVerificationInput.value,
          send_invitation_email: sendInvitationEmailInput.checked,
          invitation_email: sendInvitationEmailInput.checked ? invitationEmail : "",
          notifications: notificationSettings,
        }),
      },
    );
    const data = await responseJson(response, "Could not generate AccessLink");

    if (!response.ok) {
      throw new Error(data.error || "Could not generate AccessLink");
    }

    currentPage.access_grants = [
      data.grant,
      ...(currentPage.access_grants || []),
    ];

    access_linkResult.replaceChildren();

    const activationLabel = document.createElement("strong");
    activationLabel.textContent = "Access Pages link";

    const activationLink = document.createElement("textarea");
    activationLink.className = "copy-value";
    activationLink.readOnly = true;
    activationLink.rows = 2;
    activationLink.value = data.grant.access_link_url;
    activationLink.setAttribute("aria-label", "Activation AccessLink");
    activationLink.addEventListener("focus", () => activationLink.select());

    const activationButton = document.createElement("button");
    activationButton.type = "button";
    activationButton.className = "secondary";
    activationButton.textContent = "Copy guest link";
    activationButton.addEventListener("click", () => {
      copyText(data.grant.access_link_url, activationButton).catch((error) => {
        setStatus(`Copy failed: ${error.message}`, "error");
      });
    });

    const activationRow = document.createElement("div");
    activationRow.className = "access_link-result-row";
    activationRow.append(
      activationLabel,
      activationLink,
      activationButton,
    );

    const sharePanel = buildSharePanel(
      userName,
      data.grant.access_link_url,
    );
    const sharingContent = document.createElement("div");
    sharingContent.className = "access_link-sharing-content";
    sharingContent.append(activationRow, sharePanel);

    renderInvitationDelivery(access_linkResult, sharingContent, data.email_delivery);
    access_linkResult.classList.remove("hidden");
    access_linkResult.classList.remove("result-reveal");
    void access_linkResult.offsetWidth;
    access_linkResult.classList.add("result-reveal");
    window.requestAnimationFrame(() => {
      access_linkResult.scrollIntoView({behavior: "smooth", block: "nearest"});
      access_linkResult.focus({preventScroll: true});
    });

    access_linkLabelInput.value = "";
    await loadPages();
    await loadGuestActivitySummaries(currentPage.id);
    renderAccessGrants(currentPage);
    if (data.email_delivery?.requested && !data.email_delivery.sent) {
      setStatus(`Guest link created for ${userName}, but email delivery could not be confirmed. Use the sharing options.`, "error");
    } else {
      setStatus(
        `Guest link created for ${userName}. Access expires ${formatExpiry(data.grant.expires_at)}.`,
        "success",
      );
    }
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    generateAccessLinkButton.disabled = false;
  }
}

async function revokeGrant(grant) {
  if (!currentPage || !editingExisting) return;

  const name = grant.label || "this access link";
  const confirmed = await confirmAction(
    `Revoke ${name}? This guest's gateway access and OpenNHP Service AccessLink will stop working.`,
  );
  if (!confirmed) return;

  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(currentPage.id)}/access-links/${encodeURIComponent(grant.id)}`,
    {
      method: "DELETE",
    },
  );
  const data = await responseJson(response, "Could not revoke access link");
  if (!response.ok) {
    if (data.local_access_revoked) {
      currentPage.access_grants = (currentPage.access_grants || []).filter(
        (item) => item.id !== grant.id,
      );
      await loadPages();
      await loadGuestActivitySummaries(currentPage.id);
      renderAccessGrants(currentPage);
      setStatus(
        `Gateway access was revoked, but OpenNHP Service revocation failed: ${
          data.remote_error || data.error || "unknown error"
        }`,
        "error",
      );
      return;
    }
    throw new Error(data.error || "Could not revoke access link");
  }

  currentPage.access_grants = (currentPage.access_grants || []).filter(
    (item) => item.id !== grant.id,
  );
  await loadPages();
  await loadGuestActivitySummaries(currentPage.id);
  renderAccessGrants(currentPage);
  setStatus(
    "This gateway token and OpenNHP Service AccessLink have been revoked. Other links are unchanged.",
    "success",
  );
}

async function revokeAllAccessLinks() {
  if (!currentPage || !editingExisting) return;

  const confirmed = await confirmAction(
    "Revoke every gateway token for this page? Existing AccessLinks will stop working immediately.",
  );
  if (!confirmed) return;

  revokeAccessLinksButton.disabled = true;
  setStatus("Revoking page access…");

  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(currentPage.id)}/access-links`,
      {
        method: "DELETE",
      },
    );
    const data = await responseJson(response, "Could not revoke access");

    if (!response.ok) {
      throw new Error(data.error || "Could not revoke access");
    }

    currentPage.access_grants = [];
    access_linkResult.classList.add("hidden");
    await loadPages();
    await loadGuestActivitySummaries(currentPage.id);
    renderAccessGrants(currentPage);
    setStatus(
      `Revoked ${data.revoked_count} access link${data.revoked_count === 1 ? "" : "s"}.`,
      "success",
    );
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    revokeAccessLinksButton.disabled = false;
  }
}

function prepareEditor(page, existing) {
  currentPage = page;
  editingExisting = existing;
  idWasManuallyEdited = existing;

  titleInput.value = page.title;
  pageIdInput.value = page.id;
  pageIdInput.disabled = existing;
  descriptionInput.value = page.description || "";
  proximityEnabledInput.checked = Boolean(page.proximity?.enabled);
  proximityEnabledInput.disabled = discovery.policy?.feature_profile === "sensors_lights" && !proximityEnabledInput.checked;
  proximityEnabledInput.closest(".proximity-settings").classList.toggle("hidden", discovery.policy?.feature_profile === "sensors_lights" && !proximityEnabledInput.checked);
  proximityRadiusInput.value = page.proximity?.radius_meters || 500;
  proximityRadiusField.classList.toggle(
    "hidden",
    !proximityEnabledInput.checked,
  );

  deleteButton.classList.toggle("hidden", !existing);
  previewLink.classList.toggle("hidden", !existing);
  editorUsersButton.classList.toggle("hidden", !existing);
  editorUsersBottomButton.classList.toggle("hidden", !existing);
  previewLink.removeAttribute("href");

  loadSelections(page);
  updateSelectionSummary();
  renderCatalog();
  showEditor();

  setStatus(
    existing
      ? `Editing “${page.title}”.`
      : "Create a page and choose the controls it should expose.",
  );
}

async function manageUsers(pageId) {
  setStatus("Loading guests…");

  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(pageId)}`,
      {
        cache: "no-store",
      },
    );
    const data = await responseJson(response, "Could not load page guests");

    if (!response.ok) {
      throw new Error(data.error || "Could not load page guests");
    }

    currentPage = data;
    editingExisting = true;
    usersTitle.textContent = data.title;
    access_linkLabelInput.value = "";
    access_linkResult.classList.add("hidden");
    await loadGuestActivitySummaries(data.id);
    renderAccessGrants(data);
    showUsers();
    setStatus(
      `${data.access_grants.length} ${data.access_grants.length === 1 ? "guest" : "guests"} configured for “${data.title}”.`,
      "success",
    );
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  }
}

function createNewPage() {
  prepareEditor(blankPage(), false);
}

async function editPage(pageId) {
  setStatus("Loading page…");

  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(pageId)}`,
      {
        cache: "no-store",
      },
    );
    const data = await responseJson(response, "Could not load page");

    if (!response.ok) {
      throw new Error(data.error || "Could not load page");
    }

    prepareEditor(data, true);
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  }
}

function buildPagePayload() {
  const entityMap = new Map(
    discovery.entities.map((entity) => [entity.entity_id, entity])
  );

  const resources = [];

  selectionOrder.forEach((entityId) => {
    const services = selections.get(entityId);
    if (!services) return;
    const entity = entityMap.get(entityId);
    if (!entity) return;

    const actions = entity.actions
      .filter((action) => services.has(action.service))
      .map((action) => ({
        id: action.service,
        name: action.name,
        service: action.service,
      }));

    if (!actions.length) return;

    const resource = {
      id: resourceId(entity.entity_id),
      name: (
        customNames.get(entity.entity_id) ||
        entity.name ||
        entity.entity_id
      ).trim(),
      entity_id: entity.entity_id,
      domain: entity.domain,
      actions,
    };
    if (entity.domain === "camera") {
      resource.camera_refresh_interval = cameraRefreshIntervals.get(entityId) ?? 30;
    }
    resources.push(resource);
  });

  return {
    id: pageIdInput.value.trim(),
    title: titleInput.value.trim(),
    description: descriptionInput.value.trim(),
    proximity: {
      enabled: proximityEnabledInput.checked,
      radius_meters: Number(proximityRadiusInput.value),
    },
    resources,
  };
}

proximityEnabledInput.addEventListener("change", () => {
  proximityRadiusField.classList.toggle(
    "hidden",
    !proximityEnabledInput.checked,
  );
});

async function savePage() {
  const payload = buildPagePayload();

  if (!payload.title) {
    setStatus("Enter a page name.", "error");
    titleInput.focus();
    return;
  }

  if (!payload.id) {
    setStatus("Enter a page ID.", "error");
    pageIdInput.focus();
    return;
  }

  saveButton.disabled = true;
  saveBottomButton.disabled = true;
  setStatus("Saving page…");

  try {
    const endpoint = editingExisting
      ? `api/admin/pages/${encodeURIComponent(currentPage.id)}`
      : "api/admin/pages";

    const response = await adminApi.fetch(endpoint, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });

    const data = await responseJson(response, "Could not save page");

    if (!response.ok) {
      throw new Error(data.error || "Could not save page");
    }

    editingExisting = true;
    currentPage = data;
    pageIdInput.disabled = true;
    deleteButton.classList.remove("hidden");
    previewLink.classList.remove("hidden");
    previewLink.removeAttribute("href");

    await loadPages();
    prepareEditor(data, true);
    setStatus(
      "Saved. Preparing the page Connector; first-time setup may take a moment. " +
      "It will remain warm for 10 minutes while waiting for a guest.",
      "success",
    );
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    saveButton.disabled = false;
    saveBottomButton.disabled = false;
  }
}

async function deletePage() {
  if (!currentPage || !editingExisting) return;

  const userCount = currentPage.access_grants?.length || 0;
  const confirmed = await confirmAction(
    `Delete the access page “${currentPage.title}”? ` +
    `${userCount} ${userCount === 1 ? "guest link" : "guest links"} will be revoked.`,
  );

  if (!confirmed) return;

  deleteButton.disabled = true;
  setStatus("Deleting page…");

  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(currentPage.id)}`,
      {
        method: "DELETE",
      },
    );
    const data = await responseJson(response, "Could not delete page");

    if (!response.ok && !data.page_deleted) {
      throw new Error(data.error || "Could not delete page");
    }

    await loadPages();
    showDashboard();
    renderPageList();
    if (data.remote_failures?.length) {
      setStatus(
        `Page deleted and local access revoked, but ${data.remote_failures.length} OpenNHP Service AccessLink ` +
        `${data.remote_failures.length === 1 ? "revocation" : "revocations"} failed.`,
        "error",
      );
    } else {
      setStatus(
        `Page deleted and ${userCount} ${userCount === 1 ? "guest link" : "guest links"} revoked.`,
        "success",
      );
    }
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    deleteButton.disabled = false;
  }
}

async function loadPages() {
  const response = await adminApi.fetch("api/admin/pages", {
    cache: "no-store",
  });
  const data = await responseJson(response, "Could not load pages");

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error(
        "Valid admin token required. Open /admin?token=YOUR_ADMIN_TOKEN.",
      );
    }
    throw new Error(data.error || "Could not load pages");
  }

  pages = data.pages;
  updateGatewayCounts();
  accessServiceApiConfigured = Boolean(data.access_service_api_configured);
  access_linkMaxLifetimeDays = Number(data.access_link_max_lifetime_days) || 30;
  configureLifetimeOptions();
  renderPageList();
}

async function loadDiscovery(force = false) {
  const response = await adminApi.fetch(
    force ? "api/admin/discovery?refresh=1" : "api/admin/discovery",
    {
    cache: "no-store",
    },
  );
  const data = await responseJson(response, "Discovery failed");

  if (!response.ok) {
    throw new Error(data.error || "Discovery failed");
  }

  discovery = data;
  renderPicker();
}

async function loadApplication() {
  setStatus("Loading pages and Home Assistant entities…");
  newPageButton.disabled = true;

  try {
    await Promise.all([loadPages(), loadDiscovery()]);
    await loadGatewayStatus();
    applicationReady = true;
    newPageButton.disabled = false;
    renderPageList();
    showDashboard();
    setStatus(
      `${pages.length} ${pages.length === 1 ? "page" : "pages"} configured. ` +
      `${discovery.entity_count} controllable Home Assistant entities available.`,
      "success",
    );
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  }
}

titleInput.addEventListener("input", () => {
  if (!editingExisting && !idWasManuallyEdited) {
    pageIdInput.value = slugify(titleInput.value);
  }
});

pageIdInput.addEventListener("input", () => {
  idWasManuallyEdited = true;
  pageIdInput.value = slugify(pageIdInput.value);
});

newPageButton.addEventListener("click", createNewPage);
backButton.addEventListener("click", showDashboard);
usersBackButton.addEventListener("click", showDashboard);
usersEditButton.addEventListener("click", () => {
  if (currentPage) editPage(currentPage.id);
});
usersPreviewButton.addEventListener("click", () => {
  if (!currentPage) return;
  openAdminPreview(currentPage.id).catch((error) => {
    setStatus(`Error: ${error.message}`, "error");
  });
});
editorUsersButton.addEventListener("click", () => {
  if (currentPage) manageUsers(currentPage.id);
});
editorUsersBottomButton.addEventListener("click", () => {
  if (currentPage) manageUsers(currentPage.id);
});
addUserButton.addEventListener("click", openUserDialog);
closeUserDialogButton.addEventListener("click", () => userDialog.close());
closeActivityDialogButton.addEventListener(
  "click",
  () => activityDialog.close(),
);
deleteActivityButton.addEventListener("click", () => {
  deleteSelectedActivity().catch((error) => {
    setStatus(`Error: ${error.message}`, "error");
  });
});
activityDialog.addEventListener("click", (event) => {
  if (event.target === activityDialog) {
    activityDialog.close();
  }
});
saveButton.addEventListener("click", savePage);
saveBottomButton.addEventListener("click", savePage);
deleteButton.addEventListener("click", deletePage);
generateAccessLinkButton.addEventListener("click", generateAccessLink);
revokeAccessLinksButton.addEventListener("click", revokeAllAccessLinks);
openPickerButton.addEventListener("click", openPicker);
closePickerButton.addEventListener("click", () => pickerDialog.close());
pickerDoneButton.addEventListener("click", () => pickerDialog.close());
pickerSearchInput.addEventListener("input", renderPicker);
pickerTargetTab.addEventListener("click", () => {
  pickerBrowseMode = "target";
  activePickerCategory = null;
  pickerTargetTab.classList.add("active");
  pickerTargetTab.setAttribute("aria-selected", "true");
  pickerTypeTab.classList.remove("active");
  pickerTypeTab.setAttribute("aria-selected", "false");
  renderPicker();
});
pickerTypeTab.addEventListener("click", () => {
  pickerBrowseMode = "type";
  activePickerCategory = null;
  pickerTypeTab.classList.add("active");
  pickerTypeTab.setAttribute("aria-selected", "true");
  pickerTargetTab.classList.remove("active");
  pickerTargetTab.setAttribute("aria-selected", "false");
  renderPicker();
});
pickerDialog.addEventListener("click", (event) => {
  if (event.target === pickerDialog) {
    pickerDialog.close();
  }
});
userDialog.addEventListener("click", (event) => {
  if (event.target === userDialog) {
    userDialog.close();
  }
});
openResetDialogButton.addEventListener("click", () => {
  resetConfirmationInput.value = "";
  resetStatus.className = "status";
  resetStatus.textContent = "";
  confirmResetButton.disabled = true;
  resetDialog.showModal();
  resetConfirmationInput.focus();
});
closeResetDialogButton.addEventListener("click", () => resetDialog.close());
cancelResetButton.addEventListener("click", () => resetDialog.close());
resetConfirmationInput.addEventListener("input", () => {
  confirmResetButton.disabled = resetConfirmationInput.value !== "RESET";
});
confirmResetButton.addEventListener("click", resetServiceConnection);
resetDialog.addEventListener("click", (event) => {
  if (event.target === resetDialog) {
    resetDialog.close();
  }
});

refreshButton.addEventListener("click", async () => {
  refreshButton.disabled = true;
  setStatus("Refreshing from Home Assistant…");

  try {
    await loadDiscovery(true);
    renderCatalog();
    setStatus(
      `Loaded ${discovery.entity_count} controllable entities.`,
      "success",
    );
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    refreshButton.disabled = false;
  }
});

loadApplication();

previewLink.addEventListener("click", (event) => {
  event.preventDefault();
  if (!currentPage?.id || !editingExisting) return;
  openAdminPreview(currentPage.id).catch((error) => {
    setStatus(`Error: ${error.message}`, "error");
  });
});
