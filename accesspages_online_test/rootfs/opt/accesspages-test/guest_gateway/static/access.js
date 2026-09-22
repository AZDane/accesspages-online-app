import {createAccessApi, AccessConnectionError} from "./access-api.js";

const title = document.getElementById("title");
const description = document.getElementById("description");
const resources = document.getElementById("resources");
const statusBox = document.getElementById("status");
const previewToolbar = document.getElementById("preview-toolbar");
const previewBackButton = document.getElementById("preview-back");
const proximityDialog = document.getElementById("proximity-dialog");
const proximityCancelButton = document.getElementById("proximity-cancel");
const proximityContinueButton = document.getElementById("proximity-continue");
const verificationDialog = document.getElementById("verification-dialog");
const verificationForm = document.getElementById("verification-form");
const verificationCode = document.getElementById("verification-code");
const verificationMessage = document.getElementById("verification-message");
const verificationStatus = document.getElementById("verification-status");
const sendVerificationButton = document.getElementById("send-verification");
const pasteVerificationButton = document.getElementById("paste-verification");

const POLL_INTERVAL_MS = 3000;
const accessApi = createAccessApi();

let currentPageId = "";
let pollTimer = null;
let commandInProgress = false;
let accessEnded = false;
let connectionUnavailable = false;
let statusRequest = null;
let connectionFailures = 0;
let lastStatusCheckedAt = 0;
let wasHidden = document.hidden;
let verificationPending = false;
let verificationCodeRequested = false;
let verificationSubmitting = false;
let resendConfirmationTimer = null;
let resendRevealTimer = null;
let resendCountdownTimer = null;
let resendAvailableAt = 0;
let proximityPolicy = {required: false, verification_ttl_seconds: 300};
let cachedProximity = null;
let proximityDisclosureAccepted = false;
const parameterDrafts = new Map();
const cameraFrames = new Map();

class AccessEndedError extends Error {}

async function responseData(response) {
  const text = await response.text();
  if (!text.trim()) {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    return {error: text.trim()};
  }
}

function responseError(
  response,
  data,
  fallback,
  accessEndedStatuses = [401, 410],
) {
  const message = typeof data.error === "string" && data.error.trim()
    ? data.error.trim()
    : fallback;

  if (accessEndedStatuses.includes(response.status)) {
    return new AccessEndedError(message);
  }
  if (response.status >= 500) return new AccessConnectionError(message);
  return new Error(message);
}

function clearCachedControls() {
  resources.replaceChildren();
  parameterDrafts.clear();
  cameraFrames.forEach(({image, timer, imageUrl}) => {
    clearTimeout(timer);
    image.removeAttribute("src");
    if (imageUrl) URL.revokeObjectURL(imageUrl);
  });
  cameraFrames.clear();
  setPageButtonsDisabled(true);
}

function pauseCameraRefresh() {
  cameraFrames.forEach((frame) => {
    clearTimeout(frame.timer);
    frame.timer = null;
  });
}

function resumeCameraRefresh() {
  cameraFrames.forEach((frame) => frame.resume?.());
}

function showConnectionUnavailable(error) {
  if (accessEnded) return;
  connectionUnavailable = true;
  connectionFailures = Math.min(connectionFailures + 1, 5);
  clearCachedControls();
  statusBox.className = "status error";
  statusBox.textContent = `${error.message} Controls are unavailable. Retrying status…`;
}

function endAccess() {
  accessEnded = true;
  clearTimeout(pollTimer);
  clearCachedControls();
  statusBox.className = "status error";
  statusBox.textContent =
    "This access link has expired or been revoked.";
}

function adminRootUrl() {
  const accessMarker = "/access/";
  const markerIndex = window.location.pathname.lastIndexOf(accessMarker);
  const rootPath = markerIndex >= 0
    ? window.location.pathname.slice(0, markerIndex + 1)
    : "/";
  return new URL(rootPath, window.location.origin).toString();
}

function configurePreviewToolbar() {
  const isPreview = new URLSearchParams(window.location.search)
    .has("preview_token");

  previewToolbar.classList.toggle("hidden", !isPreview);
  if (!isPreview) {
    return;
  }

  previewBackButton.addEventListener("click", () => {
    if (document.referrer) {
      const referrer = new URL(document.referrer);
      if (referrer.origin === window.location.origin) {
        window.history.back();
        return;
      }
    }

    window.location.assign(adminRootUrl());
  });
}

configurePreviewToolbar();


function pageIdFromPath() {
  const boundPageId = document.documentElement.dataset.pageId || "";
  if (boundPageId) return boundPageId;
  const parts = window.location.pathname
    .split("/")
    .filter(Boolean);
  const accessIndex = parts.lastIndexOf("access");

  return accessIndex >= 0 && accessIndex === parts.length - 2
    ? parts[accessIndex + 1]
    : "";
}

function renderCameraFrame(page, resource, card) {
  if (resource.domain !== "camera") return;

  let frame = cameraFrames.get(resource.id);
  if (!frame) {
    const image = document.createElement("img");
    image.className = "camera-image";
    image.alt = `Current view from ${resource.name}`;
    image.decoding = "async";
    const feedback = document.createElement("span");
    feedback.className = "camera-refresh-status";
    feedback.setAttribute("role", "status");
    frame = {image, feedback, timer: null, loading: false, interval: null};
    image.addEventListener("load", () => {
      frame.loading = false;
      frame.feedback.textContent = "Image refreshed";
    });
    image.addEventListener("error", () => {
      frame.loading = false;
      frame.feedback.textContent = "Image refresh failed; try again shortly";
    });
    cameraFrames.set(resource.id, frame);
  }

  const interval = resource.camera_refresh_interval ?? 30;
  const refreshImage = async () => {
    if (frame.loading || accessEnded || document.hidden || !navigator.onLine || !cameraFrames.has(resource.id)) return;
    frame.loading = true;
    frame.feedback.textContent = "Refreshing image…";
    try {
      const response = await accessApi.cameraFrame(page.id, resource.id, Date.now());
      if (!response.ok) throw responseError(response, {}, "Image refresh failed");
      const blob = await response.blob();
      if (accessEnded || document.hidden || cameraFrames.get(resource.id) !== frame) return;
      if (frame.imageUrl) URL.revokeObjectURL(frame.imageUrl);
      frame.imageUrl = URL.createObjectURL(blob);
      frame.image.src = frame.imageUrl;
    } catch (error) {
      if (error instanceof AccessEndedError) endAccess();
      else if (error instanceof AccessConnectionError) showConnectionUnavailable(error);
      else frame.feedback.textContent = "Image refresh failed; try again shortly";
    } finally {
      frame.loading = false;
    }
  };
  if (!frame.image.getAttribute("src")) refreshImage();
  const schedule = () => {
    if (frame.timer || frame.interval <= 0 || document.hidden || accessEnded ||
        !cameraFrames.has(resource.id)) return;
    frame.timer = setTimeout(() => {
      frame.timer = null;
      refreshImage();
      schedule();
    }, frame.interval * 1000);
  };
  frame.resume = () => {
    if (!frame.image.getAttribute("src")) refreshImage();
    schedule();
  };
  if (frame.interval !== interval) {
    clearTimeout(frame.timer);
    frame.timer = null;
    frame.interval = interval;
    schedule();
  }

  const figure = document.createElement("figure");
  figure.className = "camera-frame";
  figure.appendChild(frame.image);
  const caption = document.createElement("figcaption");
  const labels = new Map([
    [0, "manually"], [15, "every 15 seconds"], [30, "every 30 seconds"],
    [60, "every 1 minute"], [120, "every 2 minutes"], [300, "every 5 minutes"],
  ]);
  caption.textContent = `Still image · refreshes ${labels.get(interval)} · not stored`;
  figure.appendChild(caption);
  const refreshButton = document.createElement("button");
  refreshButton.type = "button";
  refreshButton.className = "secondary camera-refresh";
  refreshButton.textContent = "Refresh image";
  refreshButton.setAttribute("aria-label", `Refresh image from ${resource.name}`);
  refreshButton.addEventListener("click", refreshImage);
  figure.appendChild(refreshButton);
  figure.appendChild(frame.feedback);
  card.appendChild(figure);
}

function humanize(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function statusDetails(resource) {
  const state = resource.state || "unavailable";
  const attributes = resource.state_attributes || {};
  let primary = humanize(state);
  let secondary = "";

  if (resource.domain === "cover") {
    const position = attributes.current_position;
    if (Number.isFinite(position)) {
      secondary = `${position}% open`;
    }
  }

  if (resource.domain === "fan") {
    const percentage = attributes.percentage;
    if (Number.isFinite(percentage)) {
      secondary = `${percentage}% speed`;
    }
  }

  if (resource.domain === "sensor") {
    const unit = attributes.unit_of_measurement || "";
    primary = `${state}${unit ? ` ${unit}` : ""}`;
    secondary = attributes.device_class
      ? humanize(attributes.device_class)
      : "";
  }

  if (resource.domain === "climate") {
    const current = attributes.current_temperature;
    const target = attributes.temperature;
    const unit = attributes.temperature_unit || attributes.unit_of_measurement || "°";

    if (Number.isFinite(current)) {
      primary = `${current}${unit}`;
    }

    const details = [];
    if (attributes.hvac_action) {
      details.push(humanize(attributes.hvac_action));
    }
    if (Number.isFinite(target)) {
      details.push(`Set to ${target}${unit}`);
    }
    secondary = details.join(" · ");
  }

  if (resource.domain === "binary_sensor") {
    const active = state === "on";
    const labels = {
      door: ["Open", "Closed"],
      garage_door: ["Open", "Closed"],
      window: ["Open", "Closed"],
      opening: ["Open", "Closed"],
      lock: ["Unlocked", "Locked"],
      motion: ["Motion detected", "Clear"],
      occupancy: ["Occupied", "Clear"],
      presence: ["Present", "Away"],
      moisture: ["Wet", "Dry"],
      smoke: ["Smoke detected", "Clear"],
      gas: ["Gas detected", "Clear"],
      problem: ["Problem", "OK"],
      safety: ["Unsafe", "Safe"],
      connectivity: ["Connected", "Disconnected"],
      battery: ["Low", "Normal"],
      running: ["Running", "Stopped"],
    };
    const pair = labels[attributes.device_class] || ["On", "Off"];
    primary = active ? pair[0] : pair[1];
  }

  if (resource.domain === "calendar") {
    primary = attributes.message || humanize(state);
    secondary = [attributes.start_time, attributes.end_time]
      .filter(Boolean)
      .map((value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
      })
      .join(" – ");
  }

  if (resource.domain === "person" || resource.domain === "device_tracker") {
    primary = attributes.location_name || humanize(state);
    if (
      Number.isFinite(attributes.latitude) &&
      Number.isFinite(attributes.longitude)
    ) {
      secondary = `${attributes.latitude.toFixed(4)}, ${attributes.longitude.toFixed(4)}`;
    }
  }

  if (resource.domain === "weather") {
    const temperature = attributes.temperature;
    const unit = attributes.temperature_unit || attributes.unit_of_measurement || "";
    secondary = Number.isFinite(temperature)
      ? `${temperature}${unit}`
      : "";
  }

  if (resource.domain === "media_player") {
    primary = attributes.media_title || humanize(state);
    secondary = [attributes.media_artist, attributes.source]
      .filter(Boolean)
      .join(" · ");
  }

  if (
    (resource.domain === "script" || resource.domain === "scene") &&
    attributes.last_triggered
  ) {
    const date = new Date(attributes.last_triggered);
    if (!Number.isNaN(date.getTime())) {
      secondary = `Last run ${date.toLocaleString()}`;
    }
  }

  return {
    primary,
    secondary,
    stateClass: String(state)
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "-"),
  };
}

function normalizedActionId(action) {
  return String(action.id || "")
    .toLowerCase()
    .replaceAll("-", "_");
}

function isUnavailableState(state) {
  return state === "unavailable" || state === "unknown";
}

function actionVisibility(resource, action) {
  const state = String(resource.state || "unknown").toLowerCase();
  const domain = String(resource.domain || "").toLowerCase();
  const actionId = normalizedActionId(action);

  if (domain === "button" || domain === "input_button") {
    return {
      visible: true,
      disabled: false,
    };
  }

  if (isUnavailableState(state)) {
    return {
      visible: true,
      disabled: true,
      reason: "Entity unavailable",
    };
  }

  if (domain === "lock") {
    if (state === "locked") {
      return {
        visible: true,
        disabled: actionId === "lock",
        reason: actionId === "lock" ? "Already locked" : "",
      };
    }

    if (state === "unlocked") {
      return {
        visible: true,
        disabled: actionId === "unlock",
        reason: actionId === "unlock" ? "Already unlocked" : "",
      };
    }

    if (state === "locking" || state === "unlocking") {
      return {
        visible: true,
        disabled: true,
        reason: humanize(state),
      };
    }
  }

  if (
    domain === "light" ||
    domain === "switch" ||
    domain === "input_boolean" ||
    domain === "fan"
  ) {
    if (state === "on") {
      return {
        visible: true,
        disabled: actionId === "turn_on" || actionId === "on",
        reason:
          actionId === "turn_on" || actionId === "on"
            ? "Already on"
            : "",
      };
    }

    if (state === "off") {
      return {
        visible: true,
        disabled: actionId === "turn_off" || actionId === "off",
        reason:
          actionId === "turn_off" || actionId === "off"
            ? "Already off"
            : "",
      };
    }
  }

  if (domain === "cover") {
    const isOpen = actionId === "open_cover" || actionId === "open";
    const isClose = actionId === "close_cover" || actionId === "close";
    const isStop = actionId === "stop_cover" || actionId === "stop";

    if (state === "open") {
      return {
        visible: true,
        disabled: isOpen || isStop,
        reason: isOpen ? "Already open" : (isStop ? "Not moving" : ""),
      };
    }

    if (state === "closed") {
      return {
        visible: true,
        disabled: isClose || isStop,
        reason: isClose ? "Already closed" : (isStop ? "Not moving" : ""),
      };
    }

    if (state === "opening" || state === "closing") {
      return {
        visible: true,
        disabled: !isStop,
        reason: isStop ? "" : humanize(state),
      };
    }
  }

  if (domain === "vacuum") {
    if (state === "cleaning" || state === "returning") {
      return {
        visible: true,
        disabled:
          actionId !== "stop" &&
          actionId !== "pause" &&
          actionId !== "return_to_base",
        reason:
          actionId !== "stop" &&
          actionId !== "pause" &&
          actionId !== "return_to_base"
            ? humanize(state)
            : "",
      };
    }

    if (state === "docked" || state === "idle" || state === "paused") {
      return {
        visible: true,
        disabled:
          actionId !== "start" &&
          actionId !== "clean_spot",
        reason:
          actionId !== "start" && actionId !== "clean_spot"
            ? humanize(state)
            : "",
      };
    }
  }

  // Scripts, scenes, buttons, climate actions, and any domain without
  // a safe state rule continue to use the administrator-approved list.
  return {
    visible: true,
    disabled: false,
  };
}

function visibleActions(resource) {
  const parameterizedActions = new Set([
    "set_percentage",
    "set_value",
    "select_option",
    "volume_set",
  ]);
  return resource.actions
    .filter((action) => normalizedActionId(action) !== "view")
    .filter((action) => !parameterizedActions.has(normalizedActionId(action)))
    .filter((action) => !(
      resource.domain === "fan" &&
      resource.capabilities?.fan_percentage &&
      ["turn_on", "turn_off"].includes(normalizedActionId(action))
    ))
    .map((action) => ({
      action,
      behavior: actionVisibility(resource, action),
    }))
    .filter((item) => item.behavior.visible);
}

function renderParameterControls(page, resource, card) {
  const capabilities = resource.capabilities || {};
  const controls = document.createElement("div");
  controls.className = "parameter-controls";

  const addChoices = ({
    labelText,
    values,
    currentValue,
    action,
    payloadKey,
    format = (value) => String(value),
    offAction = null,
    isOff = false,
  }) => {
    if (!action || !values.length) return;
    const group = document.createElement("div");
    group.className = "parameter-group discrete-parameter";
    const label = document.createElement("span");
    label.textContent = labelText;
    const choices = document.createElement("div");
    choices.className = "choice-buttons";

    if (offAction) {
      const off = document.createElement("button");
      off.type = "button";
      off.textContent = "Off";
      off.disabled = isOff;
      off.classList.toggle("active", isOff);
      off.addEventListener("click", () => {
        runAction(page.id, resource.id, offAction.id, off, {});
      });
      choices.appendChild(off);
    }

    values.forEach((choice) => {
      const selected = !isOff && (
        typeof choice === "number"
          ? Number(choice) === Number(currentValue)
          : choice === currentValue
      );
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = format(choice);
      button.disabled = selected;
      button.classList.toggle("active", selected);
      button.addEventListener("click", () => {
        runAction(
          page.id,
          resource.id,
          action.id,
          button,
          {[payloadKey]: choice},
        );
      });
      choices.appendChild(button);
    });

    group.append(label, choices);
    controls.appendChild(group);
  };

  const addRange = ({
    action,
    labelText,
    minimum,
    maximum,
    step,
    value,
    payloadKey,
    payloadValue = (raw) => Number(raw),
    displayValue = (raw) => String(raw),
  }) => {
    if (!action || !Number.isFinite(value)) return;
    const draftKey =
      `${page.id}:${resource.id}:${action.id}:${payloadKey}`;
    const draft = parameterDrafts.get(draftKey);
    const initialValue = draft ?? value;
    const group = document.createElement("div");
    group.className = "parameter-group range-parameter";
    group.classList.toggle("dirty", draft !== undefined);
    const label = document.createElement("label");
    label.textContent = labelText;
    const output = document.createElement("output");
    output.textContent = displayValue(initialValue);
    const input = document.createElement("input");
    input.type = "range";
    input.min = String(minimum);
    input.max = String(maximum);
    input.step = String(step);
    input.value = String(initialValue);
    const actions = document.createElement("div");
    actions.className = "parameter-actions";
    input.addEventListener("input", () => {
      parameterDrafts.set(draftKey, input.value);
      group.classList.add("dirty");
      cancel.disabled = false;
      output.textContent = displayValue(input.value);
    });
    const apply = document.createElement("button");
    apply.type = "button";
    apply.textContent = "Apply";
    apply.addEventListener("click", () => {
      runAction(
        page.id,
        resource.id,
        action.id,
        apply,
        {[payloadKey]: payloadValue(input.value)},
        {
          onSuccess: () => parameterDrafts.delete(draftKey),
        },
      );
    });
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "secondary";
    cancel.textContent = "Cancel";
    cancel.disabled = draft === undefined;
    cancel.addEventListener("click", () => {
      parameterDrafts.delete(draftKey);
      input.value = String(value);
      output.textContent = displayValue(value);
      group.classList.remove("dirty");
      cancel.disabled = true;
    });
    label.append(" ", output);
    actions.append(apply, cancel);
    group.append(label, input, actions);
    controls.appendChild(group);
  };

  if (resource.domain === "number" || resource.domain === "input_number") {
    const number = capabilities.number;
    if (!number) return false;
    const action = approvedAction(resource, "set_value");
    if (number.values?.length) {
      addChoices({
        action,
        labelText: "Value",
        values: number.values,
        currentValue: number.value,
        payloadKey: "value",
      });
    } else {
      addRange({
        action,
        labelText: "Value",
        minimum: number.min,
        maximum: number.max,
        step: number.step,
        value: number.value,
        payloadKey: "value",
      });
    }
  }

  if (resource.domain === "fan") {
    const percentageAction = approvedAction(resource, "set_percentage");
    const fan = capabilities.fan_percentage;
    if (percentageAction && fan && fan.values.length) {
      if (fan.values.length <= 6) {
        addChoices({
          action: percentageAction,
          labelText: "Speed",
          values: fan.values,
          currentValue: fan.value,
          payloadKey: "percentage",
          format: (value) => `${value}%`,
          offAction: approvedAction(resource, "turn_off"),
          isOff: resource.state === "off",
        });
      } else {
        const selectedIndex = fan.values.reduce(
          (best, level, index) => (
            Math.abs(level - fan.value) <
            Math.abs(fan.values[best] - fan.value)
              ? index
              : best
          ),
          0,
        );
        addRange({
          action: percentageAction,
          labelText: "Speed %",
          minimum: 1,
          maximum: fan.values.length,
          step: 1,
          value: selectedIndex + 1,
          payloadKey: "percentage",
          payloadValue: (raw) => (
            fan.values[Number.parseInt(raw, 10) - 1]
          ),
          displayValue: (raw) => (
            `${fan.values[Number.parseInt(raw, 10) - 1]}`
          ),
        });
      }
    }
  }

  if (resource.domain === "light" && approvedAction(resource, "turn_on")) {
    const brightness = capabilities.brightness;
    if (brightness) {
      addRange({
        action: approvedAction(resource, "turn_on"),
        labelText: "Brightness %",
        minimum: brightness.min,
        maximum: brightness.max,
        step: brightness.step,
        value: brightness.value,
        payloadKey: "brightness_pct",
        payloadValue: (raw) => Number.parseInt(raw, 10),
      });
    }
  }

  if (resource.domain === "media_player") {
    const volume = capabilities.volume;
    if (volume) {
      addRange({
        action: approvedAction(resource, "volume_set"),
        labelText: "Volume %",
        minimum: volume.min,
        maximum: volume.max,
        step: volume.step,
        value: volume.value,
        payloadKey: "volume_level",
        payloadValue: (raw) => Number(raw) / 100,
      });
    }
  }

  if (resource.domain === "select" || resource.domain === "input_select") {
    const action = approvedAction(resource, "select_option");
    const selectCapability = capabilities.select;
    const options = selectCapability?.options || [];
    if (action && options.length) {
      if (options.length <= 6) {
        addChoices({
          action,
          labelText: "Option",
          values: options,
          currentValue: selectCapability.value,
          payloadKey: "option",
        });
        if (!controls.childElementCount) return false;
        card.appendChild(controls);
        return true;
      }
      const group = document.createElement("label");
      group.className = "parameter-group";
      group.textContent = "Option";
      const select = document.createElement("select");
      select.setAttribute("aria-label", `${resource.name} option`);
      options.forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        option.selected = value === selectCapability.value;
        select.appendChild(option);
      });
      select.addEventListener("change", () => {
        runAction(
          page.id,
          resource.id,
          action.id,
          select,
          {option: select.value},
        );
      });
      group.appendChild(select);
      controls.appendChild(group);
    }
  }

  if (!controls.childElementCount) return false;
  card.appendChild(controls);
  return true;
}

function createActionButton(pageId, resource, action, behavior) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = action.name;
  button.disabled = Boolean(behavior?.disabled);

  if (behavior?.reason) {
    button.title = behavior.reason;
    button.setAttribute("aria-label", `${action.name}: ${behavior.reason}`);
  }

  button.addEventListener("click", () => {
    runAction(pageId, resource.id, action.id, button, {});
  });

  return button;
}

function approvedAction(resource, service) {
  return resource.actions.find(
    (action) => normalizedActionId(action) === service,
  );
}

function renderClimateControls(page, resource, card) {
  const climate = resource.capabilities?.climate || {};
  const temperatureAction = approvedAction(resource, "set_temperature");
  const modeAction = approvedAction(resource, "set_hvac_mode");
  const temperature = climate.temperature;
  const unit = temperature?.unit || "°";

  const controls = document.createElement("div");
  controls.className = "climate-controls";

  if (temperatureAction && temperature) {
    const minimum = temperature.min;
    const maximum = temperature.max;
    const step = temperature.step;
    const target = temperature.value;

    const group = document.createElement("div");
    group.className = "climate-group";

    const label = document.createElement("span");
    label.className = "climate-label";
    label.textContent = "Target temperature";

    const adjuster = document.createElement("div");
    adjuster.className = "temperature-adjuster";

    const minus = document.createElement("button");
    minus.type = "button";
    minus.className = "temperature-button";
    minus.textContent = "−";
    minus.setAttribute("aria-label", "Decrease target temperature");

    const value = document.createElement("strong");
    value.className = "temperature-value";
    value.textContent = Number.isFinite(target) ? `${target}${unit}` : `—${unit}`;

    const plus = document.createElement("button");
    plus.type = "button";
    plus.className = "temperature-button";
    plus.textContent = "+";
    plus.setAttribute("aria-label", "Increase target temperature");

    const sendTemperature = (direction, button) => {
      const current = target;
      if (!Number.isFinite(current)) return;
      let next = current + (direction * step);
      if (Number.isFinite(minimum)) next = Math.max(minimum, next);
      if (Number.isFinite(maximum)) next = Math.min(maximum, next);
      const decimals = String(step).includes(".")
        ? String(step).split(".")[1].length
        : 0;
      next = Number(next.toFixed(decimals));
      runAction(
        page.id,
        resource.id,
        temperatureAction.id,
        button,
        {temperature: next},
      );
    };

    minus.addEventListener("click", () => sendTemperature(-1, minus));
    plus.addEventListener("click", () => sendTemperature(1, plus));

    adjuster.append(minus, value, plus);
    group.append(label, adjuster);
    controls.appendChild(group);
  }

  if (modeAction) {
    const modes = Array.isArray(climate.hvac_modes)
      ? climate.hvac_modes
      : [];

    if (modes.length) {
      const group = document.createElement("div");
      group.className = "climate-group";

      const label = document.createElement("span");
      label.className = "climate-label";
      label.textContent = "Mode";

      if (modes.length <= 6) {
        const choices = document.createElement("div");
        choices.className = "choice-buttons";
        modes.forEach((mode) => {
          const selected = mode === resource.state;
          const button = document.createElement("button");
          button.type = "button";
          button.textContent = humanize(mode);
          button.disabled = selected;
          button.classList.toggle("active", selected);
          button.addEventListener("click", () => {
            runAction(
              page.id,
              resource.id,
              modeAction.id,
              button,
              {hvac_mode: mode},
            );
          });
          choices.appendChild(button);
        });
        group.append(label, choices);
      } else {
        const select = document.createElement("select");
        select.className = "climate-select";
        select.setAttribute("aria-label", "HVAC mode");

        modes.forEach((mode) => {
          const option = document.createElement("option");
          option.value = mode;
          option.textContent = humanize(mode);
          option.selected = mode === resource.state;
          select.appendChild(option);
        });

        select.addEventListener("change", () => {
          runAction(
            page.id,
            resource.id,
            modeAction.id,
            select,
            {hvac_mode: select.value},
          );
        });
        group.append(label, select);
      }
      controls.appendChild(group);
    }
  }

  if (controls.childElementCount) {
    card.appendChild(controls);
    return true;
  }

  return false;
}

function render(page) {
  proximityPolicy = page.proximity || {
    required: false,
    verification_ttl_seconds: 300,
  };
  document.title = page.title;
  title.textContent = page.title;
  description.textContent =
    page.description ||
    "Only the controls approved for this link are available.";

  resources.replaceChildren();
  const activeCameraIds = new Set(
    page.resources
      .filter((resource) => resource.domain === "camera")
      .map((resource) => resource.id),
  );
  cameraFrames.forEach(({image, timer, imageUrl}, resourceId) => {
    if (!activeCameraIds.has(resourceId)) {
      clearTimeout(timer);
      image.removeAttribute("src");
      if (imageUrl) URL.revokeObjectURL(imageUrl);
      cameraFrames.delete(resourceId);
    }
  });

  if (!page.resources.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent =
      "No controls have been assigned to this access page.";
    resources.appendChild(empty);
    return;
  }

  page.resources.forEach((resource) => {
    const hasCallableAction = resource.actions.some(
      (action) => normalizedActionId(action) !== "view",
    );
    const card = document.createElement("article");
    card.className = "resource-card";
    if (!hasCallableAction) {
      card.classList.add("read-only-resource");
      if (resource.domain !== "camera") {
        card.classList.add("compact-read-only-resource");
      }
    }

    const header = document.createElement("div");
    header.className = "resource-header";

    const identity = document.createElement("div");
    identity.className = "resource-identity";

    const heading = document.createElement("h2");
    heading.textContent = resource.name;

    identity.appendChild(heading);

    const details = statusDetails(resource);
    const state = document.createElement("div");
    state.className = `entity-state state-${details.stateClass}`;

    const stateDot = document.createElement("span");
    stateDot.className = "state-dot";
    stateDot.setAttribute("aria-hidden", "true");

    const stateCopy = document.createElement("div");

    const primary = document.createElement("strong");
    primary.textContent = details.primary;

    stateCopy.appendChild(primary);

    if (details.secondary) {
      const secondary = document.createElement("span");
      secondary.textContent = details.secondary;
      stateCopy.appendChild(secondary);
    }

    state.append(stateDot, stateCopy);
    header.append(identity, state);
    card.appendChild(header);

    renderCameraFrame(page, resource, card);

    if (resource.domain === "climate" && renderClimateControls(page, resource, card)) {
      resources.appendChild(card);
      return;
    }

    const actionGrid = document.createElement("div");
    actionGrid.className = "action-grid";
    const hasParameterControls = renderParameterControls(page, resource, card);

    if (!hasCallableAction) {
      resources.appendChild(card);
      return;
    }

    const smartActions = visibleActions(resource);

    smartActions.forEach(({action, behavior}) => {
      actionGrid.appendChild(
        createActionButton(
          page.id,
          resource,
          action,
          behavior,
        ),
      );
    });

    if (!smartActions.length && !hasParameterControls) {
      const noAction = document.createElement("div");
      noAction.className = "no-action";
      noAction.textContent =
        resource.state === "opening" ||
        resource.state === "closing"
          ? "This device is currently moving."
          : "No action is needed for the current state.";
      actionGrid.appendChild(noAction);
    }

    if (actionGrid.childElementCount) {
      card.appendChild(actionGrid);
    }
    resources.appendChild(card);
  });
}

function explainProximity() {
  if (proximityDisclosureAccepted) {
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    const finish = (accepted) => {
      proximityDialog.close();
      proximityCancelButton.removeEventListener("click", cancel);
      proximityContinueButton.removeEventListener("click", proceed);
      proximityDialog.removeEventListener("cancel", cancel);
      if (accepted) proximityDisclosureAccepted = true;
      resolve(accepted);
    };
    const cancel = (event) => {
      event?.preventDefault();
      finish(false);
    };
    const proceed = () => finish(true);
    proximityCancelButton.addEventListener("click", cancel);
    proximityContinueButton.addEventListener("click", proceed);
    proximityDialog.addEventListener("cancel", cancel);
    proximityDialog.showModal();
  });
}

function browserLocation() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("This browser does not support location checks."));
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (position) => resolve({
        latitude: position.coords.latitude,
        longitude: position.coords.longitude,
        accuracy_meters: position.coords.accuracy,
        measured_at: position.timestamp / 1000,
      }),
      (error) => {
        const messages = {
          1: "Location permission was denied. Enable it to use controls.",
          2: "Your location is currently unavailable.",
          3: "The location check timed out. Try again.",
        };
        reject(new Error(messages[error.code] || "Could not check your location."));
      },
      {enableHighAccuracy: true, timeout: 10000, maximumAge: 0},
    );
  });
}

async function actionProximity() {
  if (!proximityPolicy.required) return null;
  if (cachedProximity && cachedProximity.expiresAt > Date.now()) {
    return cachedProximity.reading;
  }
  const accepted = await explainProximity();
  if (!accepted) throw new Error("Location is required to use controls.");
  statusBox.className = "status";
  statusBox.textContent = "Checking that you’re near the home…";
  const reading = await browserLocation();
  cachedProximity = {
    reading,
    expiresAt: Date.now() + (
      Number(proximityPolicy.verification_ttl_seconds || 300) * 1000
    ),
  };
  return reading;
}

function setPageButtonsDisabled(disabled) {
  document.querySelectorAll(
    ".action-grid button, .climate-controls button, " +
    ".climate-controls select, .parameter-controls button, " +
    ".parameter-controls select, .parameter-controls input",
  )
    .forEach((control) => {
      if (disabled) {
        control.dataset.commandWasDisabled = control.disabled ? "1" : "0";
        control.disabled = true;
      } else if (control.dataset.commandWasDisabled !== undefined) {
        control.disabled = control.dataset.commandWasDisabled === "1";
        delete control.dataset.commandWasDisabled;
      }
    });
}

async function fetchPage(options = {}) {
  if (statusRequest) return statusRequest;
  statusRequest = fetchPageSnapshot(options);
  try { return await statusRequest; } finally { statusRequest = null; }
}

async function fetchPageSnapshot({showLoading = false} = {}) {
  if (!currentPageId || commandInProgress || accessEnded) {
    return;
  }

  if (showLoading) {
    statusBox.className = "status";
    statusBox.textContent = "Loading available controls…";
  }

  const response = await accessApi.fetchPage(currentPageId);
  const data = await responseData(response);
  if (accessEnded || commandInProgress || !navigator.onLine) return;

  if (!response.ok) {
    if (response.status === 403 && data.verification_required) {
      verificationPending = true;
      clearTimeout(pollTimer);
      verificationMessage.textContent =
        `A verification code will be sent to ${data.email_hint || "your email"}.`;
      if (!verificationDialog.open) verificationDialog.showModal();
      if (!verificationCodeRequested) {
        verificationCodeRequested = true;
        requestVerificationCode(false);
      }
      return;
    }
    throw responseError(
      response,
      data,
      "Could not load access page",
      [401, 403, 404, 410],
    );
  }

  connectionUnavailable = false;
  connectionFailures = 0;
  lastStatusCheckedAt = Date.now();
  render(data);
  verificationPending = false;
  if (verificationDialog.open) verificationDialog.close();

  const refreshed = data.refreshed_at
    ? new Date(data.refreshed_at)
    : null;

  statusBox.className = "status connected";
  statusBox.textContent =
    refreshed && !Number.isNaN(refreshed.getTime())
      ? `Live status · updated ${refreshed.toLocaleTimeString()}`
      : "Live status connected";
}

async function runAction(
  pageId,
  resourceId,
  actionId,
  button,
  payload = {},
  {onSuccess = null} = {},
) {
  if (accessEnded || connectionUnavailable || commandInProgress) return;
  const isSelect = button.tagName === "SELECT";
  const originalText = isSelect ? "" : button.textContent;
  commandInProgress = true;
  clearTimeout(pollTimer);
  setPageButtonsDisabled(true);

  if (!isSelect) {
    button.textContent = "Working…";
  }
  statusBox.className = "status";
  statusBox.textContent = "Sending command to Home Assistant…";

  try {
    const proximity = await actionProximity();
    const requestPayload = proximity
      ? {...payload, proximity}
      : payload;
    const response = await accessApi.runAction(
      pageId,
      resourceId,
      actionId,
      requestPayload,
    );

    const data = await responseData(response);

    if (!response.ok) {
      throw responseError(response, data, "Command failed");
    }

    commandInProgress = false;
    if (statusRequest) await statusRequest.catch(() => {});
    if (accessEnded || connectionUnavailable || !navigator.onLine) return;
    await fetchPage();
    if (!accessEnded && !connectionUnavailable) onSuccess?.();
  } catch (error) {
    if (error instanceof AccessEndedError) {
      endAccess();
    } else if (error instanceof AccessConnectionError) {
      showConnectionUnavailable(error);
    } else {
      statusBox.className = "status error";
      statusBox.textContent = `Error: ${error.message}`;
    }
  } finally {
    commandInProgress = false;
    if (!isSelect) {
      button.textContent = originalText;
    }
    if (!accessEnded) {
      if (!connectionUnavailable) setPageButtonsDisabled(false);
      schedulePoll();
    }
  }
}

function schedulePoll() {
  clearTimeout(pollTimer);
  pollTimer = null;
  if (accessEnded || verificationPending || document.hidden || !navigator.onLine) return;
  const delay = Math.min(60000, POLL_INTERVAL_MS * (2 ** connectionFailures));
  pollTimer = setTimeout(poll, delay);
}

async function verificationRequest(action, payload = {}) {
  const response = await accessApi.verification(currentPageId, action, payload);
  const data = await responseData(response);
  if (!response.ok) throw new Error(data.error || "Verification failed");
  return data;
}

function updateResendAvailability() {
  clearTimeout(resendCountdownTimer);
  const remaining = Math.max(0, Math.ceil((resendAvailableAt - Date.now()) / 1000));
  sendVerificationButton.classList.remove("confirm-resend");
  sendVerificationButton.disabled = remaining > 0;
  sendVerificationButton.textContent = remaining > 0
    ? `Send new code in ${remaining}s`
    : "Send new code";
  if (remaining > 0) {
    resendCountdownTimer = window.setTimeout(updateResendAvailability, 1000);
  }
}

function showResendOption() {
  clearTimeout(resendRevealTimer);
  sendVerificationButton.classList.remove("hidden");
  updateResendAvailability();
}

function reconcileResendOption() {
  if (!verificationPending || resendAvailableAt <= 0) return;
  clearTimeout(resendRevealTimer);
  const remaining = resendAvailableAt - Date.now();
  if (remaining <= 0) {
    showResendOption();
    return;
  }
  resendRevealTimer = window.setTimeout(showResendOption, remaining);
}

function scheduleResendOption() {
  resendAvailableAt = Date.now() + 60000;
  sendVerificationButton.classList.add("hidden");
  clearTimeout(resendCountdownTimer);
  reconcileResendOption();
}

async function requestVerificationCode(replace) {
  sendVerificationButton.disabled = true;
  let sent = false;
  verificationStatus.className = "status";
  verificationStatus.textContent = replace
    ? "Sending a new code…"
    : "Checking for a verification code…";
  try {
    const result = await verificationRequest("send", {replace});
    sent = result.sent === true;
    verificationStatus.className = "status success";
    verificationStatus.textContent = sent
      ? "Code sent. It expires in 10 minutes."
      : "Use the code already sent to your email. A new code can be requested after one minute.";
    scheduleResendOption();
    verificationCode.focus();
  } catch (error) {
    verificationCodeRequested = false;
    resendAvailableAt = 0;
    showResendOption();
    verificationStatus.className = "status error";
    verificationStatus.textContent = error.message;
  } finally {
    if (sent) verificationCodeRequested = true;
  }
}

sendVerificationButton.addEventListener("click", async () => {
  if (!sendVerificationButton.classList.contains("confirm-resend")) {
    sendVerificationButton.classList.add("confirm-resend");
    sendVerificationButton.textContent = "Tap again to replace code";
    verificationStatus.className = "status warning";
    verificationStatus.textContent =
      "A new email will invalidate the code you already received.";
    clearTimeout(resendConfirmationTimer);
    resendConfirmationTimer = window.setTimeout(() => {
      sendVerificationButton.classList.remove("confirm-resend");
      sendVerificationButton.textContent = "Send new code";
    }, 6000);
    return;
  }
  clearTimeout(resendConfirmationTimer);
  sendVerificationButton.classList.remove("confirm-resend");
  await requestVerificationCode(true);
});

pasteVerificationButton.addEventListener("click", async () => {
  if (!navigator.clipboard?.readText) {
    verificationCode.focus();
    verificationStatus.className = "status";
    verificationStatus.textContent =
      "Press and hold the code field, then choose Paste.";
    return;
  }
  try {
    const value = (await navigator.clipboard.readText()).trim();
    const match = value.match(/(?:^|\D)(\d{6})(?:\D|$)/);
    if (!match) throw new Error("The clipboard does not contain a 6-digit code.");
    verificationCode.value = match[1];
    verificationStatus.className = "status success";
    verificationStatus.textContent = "Code pasted. Verifying…";
    verificationForm.requestSubmit();
  } catch (error) {
    verificationCode.focus();
    verificationStatus.className = "status error";
    verificationStatus.textContent =
      error.message || "Could not read the clipboard. Paste into the code field instead.";
  }
});

verificationCode.addEventListener("input", () => {
  verificationCode.value = verificationCode.value.replace(/\D/g, "").slice(0, 6);
  if (verificationCode.value.length === 6 && !verificationSubmitting) {
    verificationForm.requestSubmit();
  }
});

verificationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (verificationSubmitting || !/^\d{6}$/.test(verificationCode.value)) return;
  verificationSubmitting = true;
  verificationStatus.className = "status";
  verificationStatus.textContent = "Verifying…";
  try {
    await verificationRequest("verify", {code: verificationCode.value});
    verificationCode.value = "";
    verificationPending = false;
    verificationDialog.close();
    await fetchPage({showLoading: true});
    schedulePoll();
  } catch (error) {
    verificationStatus.className = "status error";
    verificationStatus.textContent = error.message;
    showResendOption();
  } finally {
    verificationSubmitting = false;
  }
});

async function poll() {
  clearTimeout(pollTimer);
  if (statusRequest || commandInProgress || verificationPending || document.hidden || !navigator.onLine || accessEnded) return;
  try {
    await fetchPage();
  } catch (error) {
    if (error instanceof AccessEndedError) {
      endAccess();
    } else if (error instanceof AccessConnectionError) {
      showConnectionUnavailable(error);
    } else {
      showConnectionUnavailable(new AccessConnectionError("Connection lost — access unavailable."));
    }
  } finally {
    schedulePoll();
  }
}

async function load() {
  currentPageId = pageIdFromPath();

  if (!currentPageId) {
    statusBox.className = "status error";
    statusBox.textContent = "Invalid access-page address.";
    return;
  }

  try {
    await fetchPage({showLoading: true});
    schedulePoll();
  } catch (error) {
    if (error instanceof AccessEndedError) {
      endAccess();
    } else if (error instanceof AccessConnectionError) {
      showConnectionUnavailable(error);
    } else {
      showConnectionUnavailable(error);
      schedulePoll();
    }
  }
}

function resumeStatusChecks() {
  if (accessEnded || verificationPending || document.hidden || !navigator.onLine) return;
  if (Date.now() - lastStatusCheckedAt >= POLL_INTERVAL_MS) {
    poll();
  } else {
    schedulePoll();
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden === wasHidden) return;
  wasHidden = document.hidden;
  if (document.hidden) {
    pauseCameraRefresh();
    schedulePoll();
  } else if (!accessEnded) {
    reconcileResendOption();
    resumeCameraRefresh();
    poll();
  }
});

for (const event of ["pageshow", "focus"]) {
  window.addEventListener(event, () => {
    reconcileResendOption();
    resumeStatusChecks();
  });
}

window.addEventListener("offline", () => {
  clearTimeout(pollTimer);
  if (!accessEnded) showConnectionUnavailable(new AccessConnectionError("You are offline."));
});
window.addEventListener("online", () => {
  resumeStatusChecks();
});

load();
