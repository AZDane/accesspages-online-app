export function createAdminApi(adminToken) {
  return Object.freeze({
    async fetch(path, options = {}) {
      const headers = new Headers(options.headers || {});
      const csrf = globalThis.document?.querySelector('meta[name="access-pages-csrf"]')?.content;
      if (csrf) headers.set('X-Access-Pages-CSRF', csrf);
      if (adminToken) {
        headers.set("X-Admin-Token", adminToken);
      }

      return window.fetch(path, {...options, headers});
    },
  });
}
