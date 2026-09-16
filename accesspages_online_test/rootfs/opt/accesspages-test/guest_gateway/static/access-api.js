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

  function actionHeaders() {
    const headers = {"Content-Type": "application/json"};
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
    fetchPage(pageId) {
      return window.fetch(authorizedPath(pageId), {cache: "no-store"});
    },
    runAction(pageId, resourceId, actionId, payload) {
      return window.fetch(
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
      return window.fetch(
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
