"""Trusted TLS frontend: immutable guest assets and page-scoped API forwarding."""
import hashlib
from pathlib import Path


def nginx_config(root, gateway, host, workers, resources, *, port=8444):
    root, gateway = Path(root), Path(gateway)
    maps, servers = [], []
    for page, record in sorted(workers.items()):
        routes = [r for r in resources if r["page_id"] == page and r["instance_id"] == record["instance_id"]]
        if not routes:
            continue
        uid = record['uid']
        prefix = '__Host-nhp_guest_' + hashlib.sha256(page.encode()).hexdigest()[:24] + '_'
        # Match the exact admission selected by this document, even when the
        # browser has several cookies for this page and other pages together.
        pattern = r'^([a-f0-9]{32})[|](?:[^;]*;[ ]*)*(' + prefix + r'\1=[A-Za-z0-9_-]{43})(?:;|$)'
        maps.append(f'map "$http_x_nhp_session|$http_cookie" $page_cookie_{uid} {{ default ""; "~{pattern.replace(chr(92), chr(92)*2)}" $2; }}')
        for route in routes:
            proxy = f'''proxy_pass http://unix:{root}/workers/{uid}/http/api.sock;
   proxy_pass_request_headers off;
   proxy_set_header Host $http_host;
   proxy_set_header Content-Type $http_content_type;
   proxy_set_header Origin $http_origin;
   proxy_set_header X-NHP-Session $http_x_nhp_session;
   proxy_set_header X-NHP-Resource {route['resource_id']};
   proxy_set_header Cookie $page_cookie_{uid};
   proxy_hide_header Set-Cookie;
   proxy_hide_header Clear-Site-Data;
   proxy_hide_header Location;
   proxy_hide_header Refresh;
   proxy_hide_header Content-Type;
   proxy_hide_header Content-Security-Policy;
   proxy_hide_header X-Content-Type-Options;
   proxy_hide_header Referrer-Policy;
   proxy_hide_header Cache-Control;
   proxy_ignore_headers X-Accel-Redirect X-Accel-Expires X-Accel-Limit-Rate X-Accel-Buffering X-Accel-Charset;
   add_header Content-Type $api_content_type always;
   add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'; sandbox" always;
   add_header X-Content-Type-Options nosniff always;
   add_header Referrer-Policy no-referrer always;
   add_header Cache-Control no-store always;'''
            locations = [
                f'location = /access/{page} {{ alias {root}/public/guest-shells/{uid}.html; default_type text/html; }}',
                f'location = /api/access/{page} {{ {proxy} }}',
                f'location ^~ /api/access/{page}/ {{ {proxy} }}',
            ]
            servers.append(f'''server {{ listen 127.0.0.1:{route['port']} ssl default_server; ssl_reject_handshake on; return 421; }}
 server {{
  listen 127.0.0.1:{route['port']} ssl;
  server_name {route['host']};
  ssl_certificate {root}/tls/guest.crt;
  ssl_certificate_key {root}/tls/guest.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  if ($ssl_server_name != "{route['host']}") {{ return 421; }}
  if ($host != "{route['host']}") {{ return 421; }}
  client_max_body_size 32k;
  add_header Cache-Control no-store always;
  add_header X-Content-Type-Options nosniff always;
  add_header Referrer-Policy no-referrer always;
  add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'" always;
  location = /handoff {{
   proxy_pass http://unix:{root}/handoff/http.sock;
   proxy_pass_request_headers off;
   proxy_set_header Host $http_host;
   proxy_set_header Origin $http_origin;
   proxy_set_header Content-Type $http_content_type;
   proxy_set_header X-NHP-Resource {route['resource_id']};
  }}
  location /static/ {{ alias {gateway}/static/; }}
  {chr(10).join(locations)}
  location / {{ return 404; }}
 }}''')
    return f'''pid {root}/tls/nginx.pid;
error_log stderr warn;
events {{ worker_connections 128; }}
http {{
 include /etc/nginx/mime.types;
 default_type application/octet-stream;
 server_names_hash_bucket_size 256;
 client_body_temp_path {root}/tls/body;
 proxy_temp_path {root}/tls/proxy;
 fastcgi_temp_path {root}/tls/fastcgi;
 uwsgi_temp_path {root}/tls/uwsgi;
 scgi_temp_path {root}/tls/scgi;
 access_log off;
 client_header_timeout 10s;
 client_body_timeout 10s;
 proxy_read_timeout 15s;
 map $upstream_http_content_type $camera_content_type {{
  default application/octet-stream;
  image/jpeg image/jpeg; image/jpg image/jpeg; image/png image/png; image/webp image/webp;
 }}
 map $uri $api_content_type {{ default application/json; ~^/api/access/[^/]+/camera/ $camera_content_type; }}
 {chr(10).join(maps)}
 server {{ listen 127.0.0.1:{port} ssl default_server; ssl_reject_handshake on; return 421; }}
 server {{
  listen 127.0.0.1:{port} ssl;
  server_name {host};
  ssl_certificate {root}/tls/guest.crt;
  ssl_certificate_key {root}/tls/guest.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  location = /health {{ default_type text/plain; return 200 'ok'; }}
  location / {{ return 404; }}
 }}
 {chr(10).join(servers)}
}}
'''
