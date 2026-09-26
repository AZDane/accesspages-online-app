export class AccessConnectionError extends Error {}

async function boundedRequest(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await window.fetch(url, {
      ...options,
      credentials: "same-origin",
      redirect: "error",
      signal: controller.signal,
    });
    // Keep the deadline active through the body, not just response headers.
    const body = await response.arrayBuffer();
    return new Response(body.byteLength ? body : null, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch {
    throw new AccessConnectionError("Connection lost — access unavailable.");
  } finally {
    clearTimeout(timer);
  }
}

function authorizationQuery(location) {
  const source = new URLSearchParams(location.search);
  const result = new URLSearchParams();

  if (source.get("access_token")) {
    result.set("access_token", source.get("access_token"));
  } else if (source.get("preview_token")) {
    result.set("preview_token", source.get("preview_token"));
  }

  const encoded = result.toString();
  return encoded ? `?${encoded}` : "";
}

export function createAccessApi(location = window.location) {
  // The module and API share the app's mount point, including HA Ingress.
  const prefix = new URL("../api/access", import.meta.url).pathname;
  // Pin this document to its own admission. This public selector grants no
  // access without its matching HttpOnly cookie and live server-side grant.
  const session = new URLSearchParams((location.hash || "").slice(1)).get("session");

  function requestHeaders(extra = {}) {
    const headers = {...extra};
    if (/^[a-f0-9]{32}$/.test(session || "")) headers["X-NHP-Session"] = session;
    return headers;
  }

  function actionHeaders() {
    const headers = requestHeaders({"Content-Type": "application/json"});
    const csrf = document.querySelector('meta[name="access-pages-csrf"]')?.content;
    if (csrf) headers["X-Access-Pages-CSRF"] = csrf;
    return headers;
  }

  function path(pageId, suffix = "") {
    return `${prefix}/${encodeURIComponent(pageId)}${suffix}`;
  }

  function authorizedPath(pageId, suffix = "") {
    return path(pageId, suffix) + authorizationQuery(location);
  }

  return Object.freeze({
    cameraUrl(pageId, resourceId, frame) {
      const target = authorizedPath(
        pageId,
        `/camera/${encodeURIComponent(resourceId)}`,
      );
      const separator = target.includes("?") ? "&" : "?";
      return `${target}${separator}frame=${frame}`;
    },
    cameraFrame(pageId, resourceId, frame) {
      return boundedRequest(this.cameraUrl(pageId, resourceId, frame), {cache: "no-store", headers: requestHeaders()});
    },
    fetchPage(pageId) {
      return boundedRequest(authorizedPath(pageId), {cache: "no-store", headers: requestHeaders()});
    },
    runAction(pageId, resourceId, actionId, payload) {
      return boundedRequest(
        authorizedPath(
          pageId,
          `/${encodeURIComponent(resourceId)}/${encodeURIComponent(actionId)}`,
        ),
        {
          method: "POST",
          headers: actionHeaders(),
          body: JSON.stringify(payload),
        },
      );
    },
    verification(pageId, action, payload) {
      return boundedRequest(
        authorizedPath(pageId, `/verification/${action}`),
        {
          method: "POST",
          headers: actionHeaders(),
          body: JSON.stringify(payload),
        },
      );
    },
  });
}
