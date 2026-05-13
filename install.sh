#!/usr/bin/env bash
set -euo pipefail

# ── 全局变量 ──
BASE_DIR=/etc/sing-box
CONF_JSON=$BASE_DIR/config.json
LANDINGS_JSON=$BASE_DIR/landings
PROFILE_JSON=$BASE_DIR/profile
ACCOUNT_FILE=$BASE_DIR/account.env
NGINX_CONF=/etc/nginx/nginx.conf

SUB_DIR=/srv/www/subscribe
SUB_TOKEN_FILE=$BASE_DIR/sub_token
WEB_REPO="https://raw.githubusercontent.com/carlyle12138/sites/main"

CURRENT_ROLE=""
PUBLIC_IP=""
LOCATION_TAG="Other"

CF_Token=""
CF_Zone_ID=""
ACME_EMAIL=""

# ── 辅助函数 ──
info() { echo -e "\e[36m[INFO]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
die()  { echo -e "\e[31m[ERR ]\e[0m $*"; exit 1; }
jq_inplace() {
  local file="$1"; shift
  local t; t=$(mktemp)
  jq "$@" "$file" > "$t" && mv "$t" "$file"
}

[[ $EUID -ne 0 ]] && die "请以 root 权限运行本脚本"

# ── 路径辅助 ──
cert_path_for() { echo "/etc/ssl/private/${1}_fullchain.pem"; }
key_path_for()  { echo "/etc/ssl/private/${1}_key.pem"; }
ca_path_for()   { echo "/etc/ssl/private/${1}_ca.pem"; }

# ── 账户读取/保存 ──
load_account() {
  if [[ ! -f $ACCOUNT_FILE ]]; then
    read -rp "请输入 Cloudflare Token: " CF_Token
    read -rp "请输入 CF_Zone_ID: " CF_Zone_ID
    save_account
  fi
  set -a; source "$ACCOUNT_FILE"; set +a
}
save_account() {
  cat >"$ACCOUNT_FILE" <<EOF
CF_Token="$CF_Token"
CF_Zone_ID="$CF_Zone_ID"
ACME_EMAIL="$ACME_EMAIL"
EOF
  chmod 600 "$ACCOUNT_FILE"
}

# ── 安装依赖 ──
install_pkgs() {
  apt update
  apt install -y curl jq uuid-runtime gnupg2 ca-certificates lsb-release openssl
}
install_nginx() {
  command -v nginx >/dev/null && return
  . /etc/os-release || true
  local distro=${ID:-debian} keyring_pkg
  case "$distro" in
    ubuntu) keyring_pkg="ubuntu-keyring" ;;
    debian) keyring_pkg="debian-archive-keyring" ;;
    *)      warn "未知发行版($distro)，将尝试使用 Debian 仓库方式安装"
            keyring_pkg="debian-archive-keyring"; distro="debian" ;;
  esac
  apt install -y curl gnupg2 ca-certificates lsb-release "$keyring_pkg"
  curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/$distro $(lsb_release -cs) nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
  echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx
  apt update && apt install -y nginx
}
install_singbox() {
  command -v sing-box >/dev/null && return
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
  chmod a+r /etc/apt/keyrings/sagernet.asc
  cat <<EOF | tee /etc/apt/sources.list.d/sagernet.sources
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
  apt update
  apt install -y sing-box
}
install_acme() {
  if [[ -d ~/.acme.sh ]]; then
    . ~/.acme.sh/acme.sh.env
    return
  fi
  if [[ -z ${ACME_EMAIL:-} ]]; then
    read -rp "请输入用于申请证书的邮箱: " ACME_EMAIL
  fi
  set +u
  curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
  set -u
  . ~/.acme.sh/acme.sh.env
}

# ── Cloudflare DNS ──
cf_api() {
  curl -sSL -X "$1" \
    -H "Authorization: Bearer $CF_Token" \
    -H "Content-Type: application/json" \
    ${3:+--data "$3"} \
    "https://api.cloudflare.com/client/v4/$2"
}
create_dns_record() {
  detect_self_geo
  local sub resp domain record_id
  sub=$(sing-box generate rand 8 --hex)
  resp=$(cf_api POST "zones/$CF_Zone_ID/dns_records" \
    "{\"type\":\"A\",\"name\":\"$sub\",\"content\":\"$PUBLIC_IP\",\"ttl\":1,\"proxied\":false}")
  if [[ $(jq -r .success <<<"$resp") != true ]]; then
    die "创建 DNS 记录失败: $resp"
  fi
  domain=$(jq -r .result.name <<<"$resp")
  record_id=$(jq -r .result.id <<<"$resp")
  echo "$record_id" >"$BASE_DIR/dns_${domain}.id"
  info "已创建 DNS：$domain → $PUBLIC_IP" >&2
  echo "$domain"
}
delete_dns_record() {
  local domain="$1"
  local id_file="$BASE_DIR/dns_${domain}.id"
  if [[ -f $id_file ]]; then
    local id
    id=$(<"$id_file")
    cf_api DELETE "zones/$CF_Zone_ID/dns_records/$id" >/dev/null || true
    rm -f "$id_file"
    info "已删除 DNS：$domain"
  fi
}
cleanup_all_dns() {
  # 旧版 record.id
  if [[ -f $BASE_DIR/record.id ]]; then
    local id
    id=$(<"$BASE_DIR/record.id")
    cf_api DELETE "zones/$CF_Zone_ID/dns_records/$id" >/dev/null || true
    rm -f "$BASE_DIR/record.id"
  fi
  # 扫描所有 dns_{domain}.id 文件
  local id_file domain
  for id_file in "$BASE_DIR"/dns_*.id; do
    [[ -f $id_file ]] || continue
    domain=$(basename "$id_file" .id)
    domain=${domain#dns_}
    delete_dns_record "$domain"
  done
}

# ── 地理信息 ──
detect_self_geo() {
  local g cc ip
  g=$(curl -4s --max-time 6 "https://api.ip2location.io/" || true)
  if [[ -n $g ]] && echo "$g" | jq -e . >/dev/null 2>&1; then
    cc=$(echo "$g" | jq -r '.country_code // empty')
    ip=$(echo "$g" | jq -r '.ip // empty')
    [[ -n $cc ]] && LOCATION_TAG="$cc"
    [[ -n $ip ]] && PUBLIC_IP="$ip"
  fi
}
lookup_geo() {
  local g cc
  g=$(curl -4s --max-time 6 "https://api.ip2location.io/?ip=${1}" || true)
  if [[ -n $g ]] && echo "$g" | jq -e . >/dev/null 2>&1; then
    cc=$(echo "$g" | jq -r '.country_code // empty')
    if [[ -n $cc ]]; then echo "$cc"; return; fi
  fi
  echo "Other"
}

# ── 证书 ──
issue_cert_for_domain() {
  local domain="$1"
  echo
  echo "请选择签发 CA："
  echo "  1) ZeroSSL (默认)"
  echo "  2) Let's Encrypt"
  read -rp "请输入序号 [1]: " ca_choice
  local ca_server
  case "${ca_choice:-}" in
    2) ca_server="letsencrypt" ;;
    *) ca_server="zerossl" ;;
  esac
  info "使用 $ca_server 为 $domain 申请证书..."
  ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$domain" --server "$ca_server"
  ~/.acme.sh/acme.sh --install-cert -d "$domain" \
    --key-file "$(key_path_for "$domain")" \
    --fullchain-file "$(cert_path_for "$domain")" \
    --ca-file "$(ca_path_for "$domain")" \
    --reloadcmd "systemctl force-reload nginx"
}

# ── Profile 管理 ──
load_profile() {
  if [[ ! -f $PROFILE_JSON ]]; then
    migrate_profile
  fi
  [[ -f $PROFILE_JSON ]] || return 1
  CURRENT_ROLE=$(jq -r '.role' "$PROFILE_JSON")
}
migrate_profile() {
  [[ -f $PROFILE_JSON ]] && return
  [[ -f $CONF_JSON ]] || return
  local domain uuid priv pub sid port
  domain=$(jq -r '.inbounds[0].tls.server_name // empty' "$CONF_JSON")
  uuid=$(jq -r '.inbounds[0].users[0].uuid // empty' "$CONF_JSON")
  priv=$(jq -r '.inbounds[0].tls.reality.private_key // empty' "$CONF_JSON")
  sid=$(jq -r '.inbounds[0].tls.reality.short_id[0] // empty' "$CONF_JSON")
  port=$(jq -r '.inbounds[0].listen_port // 30000' "$CONF_JSON")
  pub=""
  [[ -f $BASE_DIR/reality_public_key ]] && pub=$(<"$BASE_DIR/reality_public_key")
  if [[ -n $domain ]]; then
    [[ -f $BASE_DIR/record.id && ! -f $BASE_DIR/dns_${domain}.id ]] && \
      cp "$BASE_DIR/record.id" "$BASE_DIR/dns_${domain}.id"
    local old_key="/etc/ssl/private/key.pem" old_cert="/etc/ssl/private/fullchain.pem" old_ca="/etc/ssl/private/ca.pem"
    [[ -f $old_key  && ! -f $(key_path_for "$domain")  ]] && cp "$old_key"  "$(key_path_for "$domain")"
    [[ -f $old_cert && ! -f $(cert_path_for "$domain") ]] && cp "$old_cert" "$(cert_path_for "$domain")"
    [[ -f $old_ca   && ! -f $(ca_path_for "$domain")   ]] && cp "$old_ca"   "$(ca_path_for "$domain")"
  fi
  mkdir -p "$BASE_DIR"
  jq -n --arg role "relay" --arg proto "vless-reality" --argjson port "$port" \
    --arg domain "$domain" --arg uuid "$uuid" \
    --arg priv "$priv" --arg pub "$pub" --arg sid "$sid" \
    '{role:$role,inbounds:[{protocol:$proto,listen_port:$port,domain:$domain,uuid:$uuid,private_key:$priv,public_key:$pub,short_id:$sid}]}' \
    --indent 2 >"$PROFILE_JSON"
  info "已从现有配置迁移生成 profile"
}
next_listen_port() {
  local max=29999
  if [[ $CURRENT_ROLE == "landing" ]]; then max=1079; fi
  if [[ -f $PROFILE_JSON ]]; then
    while read -r p; do
      (( p > max )) && max=$p
    done < <(jq -r '.inbounds[].listen_port' "$PROFILE_JSON")
  fi
  echo $((max + 1))
}
get_primary_domain() {
  jq -r '.inbounds | map(select(.protocol=="vless-reality")) | .[0].domain // empty' "$PROFILE_JSON"
}

# ── 协议参数生成 ──
gen_params_vless_reality() {
  local domain="$1" port="$2"
  local uuid kp priv pub sid
  uuid=$(uuidgen)
  kp=$(sing-box generate reality-keypair)
  priv=$(awk '/PrivateKey/ {print $2}' <<<"$kp")
  pub=$(awk '/PublicKey/  {print $2}' <<<"$kp")
  sid=$(sing-box generate rand 8 --hex)
  jq -n --arg proto "vless-reality" --argjson port "$port" \
    --arg domain "$domain" --arg uuid "$uuid" \
    --arg priv "$priv" --arg pub "$pub" --arg sid "$sid" \
    '{protocol:$proto,listen_port:$port,domain:$domain,uuid:$uuid,private_key:$priv,public_key:$pub,short_id:$sid}'
}
gen_params_anytls() {
  local domain="$1" port="$2"
  local password
  password=$(sing-box generate rand 16 --hex)
  jq -n --arg proto "anytls" --argjson port "$port" \
    --arg domain "$domain" --arg password "$password" \
    '{protocol:$proto,listen_port:$port,domain:$domain,password:$password}'
}
gen_params_socks() {
  local port="$1" user="" password=""
  read -rp "请输入 SOCKS 用户名: " user
  read -rp "请输入 SOCKS 密码: " password
  jq -n --arg proto "socks" --argjson port "$port" \
    --arg user "$user" --arg password "$password" \
    '{protocol:$proto,listen_port:$port,username:$user,password:$password}'
}
gen_params_ss2022() {
  local port="$1"
  local password
  password=$(openssl rand -base64 16)
  jq -n --arg proto "ss2022" --argjson port "$port" \
    --arg method "2022-blake3-aes-128-gcm" --arg password "$password" \
    '{protocol:$proto,listen_port:$port,method:$method,password:$password}'
}
gen_params_wireguard() {
  local port="$1" priv="$2" addr="$3" peer_pub="$4" peer_allowed="$5"
  jq -n --arg proto "wireguard" --argjson port "$port" \
    --arg priv "$priv" --arg addr "$addr" \
    --arg peer_pub "$peer_pub" --arg peer_allowed "$peer_allowed" \
    '{protocol:$proto,listen_port:$port,private_key:$priv,address:$addr,peer_public_key:$peer_pub,peer_allowed_ips:$peer_allowed}'
}

# ── Sing-box inbound 生成 ──
build_relay_users_vless() {
  local ib_json="$1"
  local uuid users
  uuid=$(jq -r .uuid <<<"$ib_json")
  users=$(jq -n --arg uuid "$uuid" '[{"name":"direct","uuid":$uuid,"flow":"xtls-rprx-vision"}]')
  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r row; do
      local tag l_uuid u
      tag=$(jq -r .tag <<<"$row")
      l_uuid=$(jq -r .uuid <<<"$row")
      u=$(jq -n --arg name "$tag" --arg uuid "$l_uuid" '{"name":$name,"uuid":$uuid,"flow":"xtls-rprx-vision"}')
      users=$(jq -n --argjson a "$users" --argjson b "$u" '$a + [$b]')
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi
  echo "$users"
}
build_relay_users_anytls() {
  local ib_json="$1"
  local password users
  password=$(jq -r .password <<<"$ib_json")
  users=$(jq -n --arg pw "$password" '[{"name":"direct","password":$pw}]')
  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r row; do
      local tag l_uuid u
      tag=$(jq -r .tag <<<"$row")
      l_uuid=$(jq -r .uuid <<<"$row")
      u=$(jq -n --arg name "$tag" --arg pw "$l_uuid" '{"name":$name,"password":$pw}')
      users=$(jq -n --argjson a "$users" --argjson b "$u" '$a + [$b]')
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi
  echo "$users"
}
gen_singbox_inbound() {
  local ib_json="$1"
  local proto
  proto=$(jq -r .protocol <<<"$ib_json")
  case "$proto" in
    vless-reality)
      local domain port priv sid users tag
      domain=$(jq -r .domain <<<"$ib_json")
      port=$(jq -r .listen_port <<<"$ib_json")
      priv=$(jq -r .private_key <<<"$ib_json")
      sid=$(jq -r .short_id <<<"$ib_json")
      tag="vless-in-${port}"
      users=$(build_relay_users_vless "$ib_json")
      jq -n --arg sn "$domain" --arg pk "$priv" --arg sid "$sid" \
        --argjson port "$port" --argjson users "$users" --arg tag "$tag" \
        '{type:"vless",tag:$tag,listen:"127.0.0.1",listen_port:$port,users:$users,tls:{enabled:true,server_name:$sn,reality:{enabled:true,handshake:{server:"127.0.0.1",server_port:8443},private_key:$pk,short_id:[$sid]}}}'
    ;;
    anytls)
      local domain port users kp cp tag
      domain=$(jq -r .domain <<<"$ib_json")
      port=$(jq -r .listen_port <<<"$ib_json")
      tag="anytls-in-${port}"
      users=$(build_relay_users_anytls "$ib_json")
      kp=$(key_path_for "$domain")
      cp=$(cert_path_for "$domain")
      local padding_scheme
      padding_scheme=$(jq -n '[
        "stop=12",
        "0=80-180",
        "1=150-500,c,300-800",
        "2=200-600,c,600-1200,c,700-1400,c,500-1000",
        "3=100-350,c,500-1200",
        "4=300-900,c,400-1000",
        "5=400-1100",
        "6=300-700,c,600-1000",
        "7=500-1200",
        "8=200-800",
        "9=400-1000",
        "10=300-900",
        "11=200-700"
      ]')
      jq -n --arg sn "$domain" --argjson port "$port" --argjson users "$users" \
        --arg kp "$kp" --arg cp "$cp" --argjson ps "$padding_scheme" --arg tag "$tag" \
        '{type:"anytls",tag:$tag,listen:"127.0.0.1",listen_port:$port,users:$users,tls:{enabled:true,server_name:$sn,key_path:$kp,certificate_path:$cp},padding_scheme:$ps}'
    ;;
    socks)
      local port user password tag
      port=$(jq -r .listen_port <<<"$ib_json")
      tag="socks-in-${port}"
      user=$(jq -r .username <<<"$ib_json")
      password=$(jq -r .password <<<"$ib_json")
      jq -n --argjson port "$port" --arg user "$user" --arg pw "$password" --arg tag "$tag" \
        '{type:"socks",tag:$tag,listen:"0.0.0.0",listen_port:$port,users:[{username:$user,password:$pw}]}'
    ;;
    ss2022)
      local port method password tag
      port=$(jq -r .listen_port <<<"$ib_json")
      tag="ss-in-${port}"
      method=$(jq -r .method <<<"$ib_json")
      password=$(jq -r .password <<<"$ib_json")
      jq -n --argjson port "$port" --arg method "$method" --arg pw "$password" --arg tag "$tag" \
        '{type:"shadowsocks",tag:$tag,listen:"0.0.0.0",listen_port:$port,method:$method,password:$pw}'
    ;;
    wireguard)
      local port priv addr peer_pub peer_allowed tag
      port=$(jq -r .listen_port <<<"$ib_json")
      tag="wg-ep-${port}"
      priv=$(jq -r .private_key <<<"$ib_json")
      addr=$(jq -r .address <<<"$ib_json")
      peer_pub=$(jq -r .peer_public_key <<<"$ib_json")
      peer_allowed=$(jq -r .peer_allowed_ips <<<"$ib_json")
      jq -n --argjson port "$port" --arg priv "$priv" --arg addr "$addr" \
        --arg peer_pub "$peer_pub" --arg peer_allowed "$peer_allowed" --arg tag "$tag" \
        '{type:"wireguard",tag:$tag,system:true,name:"wg0",mtu:1420,address:[$addr],private_key:$priv,listen_port:$port,peers:[{public_key:$peer_pub,allowed_ips:[$peer_allowed]}]}'
    ;;
  esac
}

# ── 配置生成 ──
write_nginx() {
  [[ $CURRENT_ROLE == "landing" ]] && return
  load_profile || die "缺少 profile 配置"

  local upstreams="" map_entries="" http_servers="" http_redirects=""
  local first_ca=""
  while read -r ib; do
    local proto domain port tag_name
    proto=$(jq -r .protocol <<<"$ib")
    domain=$(jq -r .domain <<<"$ib")
    port=$(jq -r .listen_port <<<"$ib")
    tag_name="${proto//-/_}_${port}"
    upstreams+="  upstream singbox_${tag_name} { server 127.0.0.1:${port}; }
"
    map_entries+="    ${domain}  singbox_${tag_name};
"
    if [[ $proto == "vless-reality" ]]; then
      [[ -z $first_ca ]] && first_ca=$(ca_path_for "$domain")
      http_servers+="
  server {
    listen 127.0.0.1:8443 ssl;
    http2 on;
    server_name ${domain};
    root /srv/www;
    index index.html;
    ssl_certificate $(cert_path_for "$domain");
    ssl_certificate_key $(key_path_for "$domain");
    access_log off;
    location /subscribe/ { try_files \$uri =403; }
    location / { try_files \$uri \$uri/ =404; }
  }"
      http_redirects+="
  server { listen 80; server_name ${domain}; return 301 https://\$host\$request_uri; }"
    fi
  done < <(jq -c '.inbounds[]' "$PROFILE_JSON")

  upstreams+="  upstream web_backend { server 127.0.0.1:8443; }"
  map_entries+="    default         web_backend;"

  if [[ -z $http_servers ]]; then
    http_servers="
  server { listen 127.0.0.1:8443 default_server; return 444; }"
  fi

  local tmp_conf
  tmp_conf=$(mktemp)
  cat >"$tmp_conf" <<EOF
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
  use epoll;
  worker_connections 8192;
  multi_accept on;
}

stream {
${upstreams}
  map \$ssl_preread_server_name \$backend {
${map_entries}
  }

  server {
    listen 443 reuseport;
    listen [::]:443 reuseport;
    proxy_pass \$backend;
    ssl_preread on;
    proxy_timeout 300s;
    proxy_connect_timeout 10s;
  }
}

http {
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;

  ssl_session_timeout 1h;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ssl_buffer_size 4k;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_stapling on;
  ssl_stapling_verify on;${first_ca:+
  ssl_trusted_certificate ${first_ca};}
  resolver 8.8.8.8 1.1.1.1 valid=60s;
${http_servers}
${http_redirects}
}
EOF
  if nginx -t -c "$tmp_conf" >/dev/null 2>&1; then
    mv "$tmp_conf" "$NGINX_CONF"
    systemctl restart nginx
  else
    warn "Nginx 配置校验失败，保留旧配置"
    nginx -t -c "$tmp_conf" || true
    rm -f "$tmp_conf"
    return 1
  fi
}

rebuild_singbox() {
  load_profile || die "缺少 profile 配置"
  [[ -f $LANDINGS_JSON ]] || echo "[]" >"$LANDINGS_JSON"
  ensure_landings_uuid

  local tmp_conf
  tmp_conf=$(mktemp)

  if [[ $CURRENT_ROLE == "relay" ]]; then
    local inbounds
    inbounds=$(jq -n '[]')
    while read -r ib; do
      local singbox_ib
      singbox_ib=$(gen_singbox_inbound "$ib")
      inbounds=$(jq -n --argjson a "$inbounds" --argjson b "$singbox_ib" '$a + [$b]')
    done < <(jq -c '.inbounds[]' "$PROFILE_JSON")
    local outbounds endpoints routes
    outbounds=$(jq -n '[{"type":"direct","tag":"direct"}]')
    endpoints=$(jq -n '[]')
    routes=$(jq -n '[{"auth_user":"direct","outbound":"direct"}]')
    if [[ $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
      while read -r row; do
        local tag out_tag ob ob_type rt
        tag=$(jq -r .tag <<<"$row")
        ob=$(jq -c '.outbound' <<<"$row")
        out_tag=$(jq -r '.outbound.tag // empty' <<<"$row")
        ob_type=$(jq -r '.outbound.type // empty' <<<"$row")
        [[ -z $out_tag ]] && die "落地配置缺少 outbound.tag: $row"
        if [[ $out_tag != "direct" && -n $ob && $ob != "null" ]]; then
          if [[ $ob_type == "wireguard" ]]; then
            endpoints=$(jq -n --argjson a "$endpoints" --argjson b "$ob" '$a + [$b]')
          else
            outbounds=$(jq -n --argjson a "$outbounds" --argjson b "$ob" '$a + [$b]')
          fi
        fi
        rt=$(jq -n --arg tag "$tag" --arg out "$out_tag" '{"auth_user":$tag,"outbound":$out}')
        routes=$(jq -n --argjson r "$routes" --argjson x "$rt" '$r + [$x]')
      done < <(jq -c '.[]' "$LANDINGS_JSON")
    fi
    local config_expr='{inbounds:$ib,outbounds:$ob,route:{rules:$rt}}'
    if [[ $(jq length <<<"$endpoints") -gt 0 ]]; then
      config_expr='{inbounds:$ib,outbounds:$ob,endpoints:$ep,route:{rules:$rt}}'
    fi
    jq -n --argjson ib "$inbounds" --argjson ob "$outbounds" \
      --argjson ep "$endpoints" --argjson rt "$routes" \
      "$config_expr" --indent 2 >"$tmp_conf"
  else
    # 落地机：inbounds 中的 wireguard 类型放入 endpoints
    local landing_ibs landing_eps
    landing_ibs=$(jq -n '[]')
    landing_eps=$(jq -n '[]')
    while read -r ib; do
      local proto
      proto=$(jq -r .protocol <<<"$ib")
      local singbox_ib
      singbox_ib=$(gen_singbox_inbound "$ib")
      if [[ $proto == "wireguard" ]]; then
        landing_eps=$(jq -n --argjson a "$landing_eps" --argjson b "$singbox_ib" '$a + [$b]')
      else
        landing_ibs=$(jq -n --argjson a "$landing_ibs" --argjson b "$singbox_ib" '$a + [$b]')
      fi
    done < <(jq -c '.inbounds[]' "$PROFILE_JSON")
    local config_expr='{inbounds:$ib,outbounds:[{type:"direct",tag:"direct"}],route:{final:"direct"}}'
    if [[ $(jq length <<<"$landing_eps") -gt 0 ]]; then
      config_expr='{inbounds:$ib,endpoints:$ep,outbounds:[{type:"direct",tag:"direct"}],route:{final:"direct"}}'
    fi
    jq -n --argjson ib "$landing_ibs" --argjson ep "$landing_eps" \
      "$config_expr" --indent 2 >"$tmp_conf"
  fi
  if sing-box check -c "$tmp_conf" >/dev/null 2>&1; then
    mv "$tmp_conf" "$CONF_JSON"
    systemctl restart sing-box
  else
    warn "sing-box 配置校验失败，保留旧配置"
    sing-box check -c "$tmp_conf" || true
    rm -f "$tmp_conf"
    return 1
  fi
}

# ── 订阅 ──
vless_uri() {
  local uuid="$1" label="$2" domain="$3" pub="$4" sid="$5"
  local enc
  enc=$(printf '%s' "$label" | jq -sRr @uri)
  echo "vless://${uuid}@${PUBLIC_IP}:443?encryption=none&security=reality&type=tcp&sni=${domain}&fp=firefox&pbk=${pub}&sid=${sid}&flow=xtls-rprx-vision#${enc}"
}
anytls_uri() {
  local password="$1" label="$2" domain="$3"
  local enc
  enc=$(printf '%s' "$label" | jq -sRr @uri)
  echo "anytls://${password}@${PUBLIC_IP}:443?sni=${domain}#${enc}"
}
ensure_token() {
  if [[ -f $SUB_TOKEN_FILE ]]; then
    token=$(<"$SUB_TOKEN_FILE")
  else
    token=$(uuidgen | tr -d '-')
    echo "$token" > "$SUB_TOKEN_FILE"
  fi
}
renew_token() {
  ensure_token
  local old=$token
  token=$(uuidgen | tr -d '-')
  echo "$token" > "$SUB_TOKEN_FILE"
  rm -f "$SUB_DIR/$old"
}
ensure_landings_uuid() {
  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    local idx=0
    while read -r row; do
      idx=$((idx + 1))
      local lu
      lu=$(jq -r '.uuid // empty' <<<"$row")
      if [[ -z $lu || $lu == "null" ]]; then
        local nu
        nu=$(uuidgen)
        jq_inplace "$LANDINGS_JSON" --indent 2 --argjson i "$((idx - 1))" --arg u "$nu" \
          '.[$i].uuid = $u'
      fi
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi
}
publish_sub() {
  [[ $CURRENT_ROLE == "landing" ]] && { warn "落地机不支持订阅"; return; }
  load_profile || die "缺少 profile 配置"
  mkdir -p "$SUB_DIR"
  ensure_token
  ensure_landings_uuid
  detect_self_geo

  local tmp
  tmp=$(mktemp)

  while read -r ib; do
    local proto domain
    proto=$(jq -r .protocol <<<"$ib")
    domain=$(jq -r .domain <<<"$ib")
    case "$proto" in
      vless-reality)
        local uuid pub sid
        uuid=$(jq -r .uuid <<<"$ib")
        pub=$(jq -r .public_key <<<"$ib")
        sid=$(jq -r .short_id <<<"$ib")
        vless_uri "$uuid" "${LOCATION_TAG}-direct" "$domain" "$pub" "$sid" >>"$tmp"
        if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
          while read -r row; do
            local tag lu q loc
            tag=$(jq -r .tag <<<"$row")
            lu=$(jq -r '.uuid // empty' <<<"$row")
            q=$(jq -r '.outbound.server // empty' <<<"$row")
            if [[ -n $q ]]; then loc=$(lookup_geo "$q"); else loc="Other"; fi
            [[ -n $lu ]] || lu="$uuid"
            vless_uri "$lu" "${loc}-${tag}" "$domain" "$pub" "$sid" >>"$tmp"
          done < <(jq -c '.[]' "$LANDINGS_JSON")
        fi
      ;;
      anytls)
        local password
        password=$(jq -r .password <<<"$ib")
        anytls_uri "$password" "${LOCATION_TAG}-direct" "$domain" >>"$tmp"
        if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
          while read -r row; do
            local tag lu q loc
            tag=$(jq -r .tag <<<"$row")
            lu=$(jq -r '.uuid // empty' <<<"$row")
            q=$(jq -r '.outbound.server // empty' <<<"$row")
            if [[ -n $q ]]; then loc=$(lookup_geo "$q"); else loc="Other"; fi
            [[ -n $lu ]] || lu="$password"
            anytls_uri "$lu" "${loc}-${tag}" "$domain" >>"$tmp"
          done < <(jq -c '.[]' "$LANDINGS_JSON")
        fi
      ;;
    esac
  done < <(jq -c '.inbounds[]' "$PROFILE_JSON")

  base64 -w0 "$tmp" >"$SUB_DIR/$token"
  rm -f "$tmp"
  find "$SUB_DIR" -type f ! -name "$token" -delete
  local primary_domain
  primary_domain=$(get_primary_domain)
  if [[ -n $primary_domain ]]; then
    info "订阅链接：https://${primary_domain}/subscribe/${token}"
  else
    info "订阅已更新"
  fi
}

# ── 落地管理 ──
read_json_input() {
  local -n __ref=$1
  echo "请粘贴 JSON；粘贴完直接回车即可（空行确认）。"
  local buf="" line trimmed
  while IFS= read -r line; do
    if [[ -z "$line" ]]; then
      trimmed=${buf%$'\n'}
      if [[ -n "$trimmed" ]] && echo "$trimmed" | jq -e . >/dev/null 2>&1; then
        buf="$trimmed"; break
      fi
    fi
    buf+="$line"$'\n'
  done
  buf=${buf//$'\r'/}
  if ! echo "$buf" | jq -e . >/dev/null 2>&1; then
    warn "JSON 无效"; return 1
  fi
  __ref="$buf"
}
validate_landing_json() {
  local -n __tag_ref=$1
  local json="$2" exclude_idx="${3:--1}"
  __tag_ref=$(echo "$json" | jq -r '.tag // empty')
  if [[ -z $__tag_ref ]]; then
    warn "JSON 中缺少 tag"; return 1
  fi
  if [[ "$__tag_ref" == "direct" ]]; then
    warn "tag 不可为保留值 direct"; return 1
  fi
  if [[ $exclude_idx -ge 0 ]]; then
    if jq -e --arg t "$__tag_ref" --argjson i "$exclude_idx" \
      'to_entries | map(select(.key != $i) | select((.value.outbound?.tag // "") == $t)) | length > 0' \
      "$LANDINGS_JSON" >/dev/null; then
      warn "tag 已存在"; return 1
    fi
  else
    if jq -e --arg t "$__tag_ref" 'map(select((.outbound?.tag // "") == $t)) | length > 0' \
      "$LANDINGS_JSON" >/dev/null; then
      warn "tag 已存在"; return 1
    fi
  fi
  local tmpc ob_type
  tmpc=$(mktemp)
  ob_type=$(echo "$json" | jq -r '.type // empty')
  if [[ $ob_type == "wireguard" ]]; then
    jq -n --argjson o "$json" '{endpoints: [$o]}' >"$tmpc"
  else
    jq -n --argjson o "$json" '{outbounds: [$o]}' >"$tmpc"
  fi
  if ! sing-box check -c "$tmpc" >/dev/null 2>&1; then
    rm -f "$tmpc"
    warn "sing-box check 未通过"; return 1
  fi
  rm -f "$tmpc"
}
edit_landings() {
  [[ $CURRENT_ROLE == "landing" ]] && { warn "落地机不支持此操作"; return; }
  load_profile || die "缺少 profile 配置"
  mkdir -p "$BASE_DIR"
  [[ -f $LANDINGS_JSON ]] || echo "[]" >"$LANDINGS_JSON"
  echo
  echo "1) 新增落地"
  echo "2) 修改落地"
  echo "3) 删除落地"
  echo "0) 返回菜单"
  read -rp "请选择操作: " act

  case $act in
    1)
      local j o_tag nu
      read_json_input j || return
      validate_landing_json o_tag "$j" || return
      nu=$(uuidgen)
      jq_inplace "$LANDINGS_JSON" --indent 2 \
        --arg t "$o_tag" --arg g "$nu" --argjson o "$j" \
        '. += [{"tag":$t,"uuid":$g,"outbound":$o}]'
    ;;
    2)
      local total idx cur_tag j2 o2_tag
      total=$(jq length "$LANDINGS_JSON")
      if [[ $total -eq 0 ]]; then
        warn "当前没有落地节点可修改"; return
      fi
      echo
      jq -r 'to_entries[] | "\(.key+1)) \(.value.tag)"' "$LANDINGS_JSON"
      read -rp "请输入要修改的序号: " idx
      idx=$((idx-1))
      cur_tag=$(jq -r ".[$idx].tag" "$LANDINGS_JSON" 2>/dev/null) || die "序号无效"
      echo "当前 tag=$cur_tag:"
      read_json_input j2 || return
      validate_landing_json o2_tag "$j2" "$idx" || return
      jq_inplace "$LANDINGS_JSON" --indent 2 \
        --argjson i "$idx" --argjson o "$j2" --arg t "$o2_tag" \
        '.[$i].outbound = $o | .[$i].tag = $t'
    ;;
    3)
      local total_del
      total_del=$(jq length "$LANDINGS_JSON")
      if [[ $total_del -eq 0 ]]; then
        warn "当前没有落地节点可删除"; return
      fi
      echo
      jq -r 'to_entries[] | "\(.key+1)) \(.value.tag)"' "$LANDINGS_JSON"
      read -rp "请输入要删除的序号: " did
      did=$((did-1))
      jq_inplace "$LANDINGS_JSON" --indent 2 "del(.[$did])"
    ;;
    0) return ;;
    *) warn "无效选择" ;;
  esac

  rebuild_singbox
  publish_sub
}

# ── Inbound 管理 ──
add_inbound() {
  load_profile || die "缺少 profile 配置"
  echo
  local port params
  port=$(next_listen_port)

  if [[ $CURRENT_ROLE == "relay" ]]; then
    echo "1) VLESS + Reality + Vision"
    echo "2) AnyTLS"
    echo "0) 返回"
    read -rp "请选择协议: " proto_choice
    local domain
    case "$proto_choice" in
      1)
        load_account
        domain=$(create_dns_record)
        if ! { install_acme && issue_cert_for_domain "$domain"; }; then
          delete_dns_record "$domain"
          die "证书签发失败，已回滚 DNS 记录"
        fi
        params=$(gen_params_vless_reality "$domain" "$port")
      ;;
      2)
        load_account
        domain=$(create_dns_record)
        install_acme
        if ! issue_cert_for_domain "$domain"; then
          delete_dns_record "$domain"
          die "证书签发失败，已回滚 DNS 记录"
        fi
        params=$(gen_params_anytls "$domain" "$port")
      ;;
      0) return ;;
      *) warn "无效选择"; return ;;
    esac
  else
    echo "1) SOCKS"
    echo "2) Shadowsocks 2022"
    echo "3) WireGuard"
    echo "0) 返回"
    read -rp "请选择协议: " proto_choice
    case "$proto_choice" in
      1) params=$(gen_params_socks "$port") ;;
      2) params=$(gen_params_ss2022 "$port") ;;
      3)
        local wg_port wg_priv wg_addr wg_peer_pub wg_peer_allowed
        read -rp "监听端口 [51820]: " wg_port
        wg_port=${wg_port:-51820}
        read -rp "私钥: " wg_priv
        read -rp "隧道地址 (如 10.66.1.1/24): " wg_addr
        read -rp "对端公钥: " wg_peer_pub
        read -rp "对端允许 IP (如 10.66.1.100/32): " wg_peer_allowed
        port=$wg_port
        params=$(gen_params_wireguard "$port" "$wg_priv" "$wg_addr" "$wg_peer_pub" "$wg_peer_allowed")
      ;;
      0) return ;;
      *) warn "无效选择"; return ;;
    esac
  fi

  jq_inplace "$PROFILE_JSON" --indent 2 --argjson p "$params" '.inbounds += [$p]'
  [[ $CURRENT_ROLE == "relay" ]] && write_nginx
  rebuild_singbox
  [[ $CURRENT_ROLE == "relay" ]] && publish_sub
  info "Inbound 已添加"
}
remove_inbound() {
  load_profile || die "缺少 profile 配置"
  local total
  total=$(jq '.inbounds | length' "$PROFILE_JSON")
  if [[ $total -le 1 ]]; then
    warn "至少需要保留一个 inbound"; return
  fi
  echo
  jq -r '.inbounds | to_entries[] | "\(.key+1)) \(.value.protocol) — \(.value.domain // "port:\(.value.listen_port)")"' "$PROFILE_JSON"
  read -rp "请输入要删除的序号: " idx
  idx=$((idx-1))

  local ib_json domain
  ib_json=$(jq -c ".inbounds[$idx]" "$PROFILE_JSON" 2>/dev/null) || { warn "序号无效"; return; }
  domain=$(jq -r '.domain // empty' <<<"$ib_json")
  jq_inplace "$PROFILE_JSON" --indent 2 --argjson i "$idx" 'del(.inbounds[$i])'

  if [[ $CURRENT_ROLE == "relay" && -n $domain ]]; then
    load_account
    delete_dns_record "$domain"
    write_nginx
    rebuild_singbox
    publish_sub
  else
    rebuild_singbox
  fi
  info "Inbound 已删除"
}

# ── WireGuard 配对生成 ──
generate_wg_pairing() {
  load_profile || die "缺少 profile 配置"
  [[ $CURRENT_ROLE == "relay" ]] || { warn "仅线路机支持此操作"; return; }

  local relay_idx landing_idx landing_ip
  read -rp "请输入线路机编号: " relay_idx
  read -rp "请输入落地机编号: " landing_idx
  read -rp "请输入落地机 IP: " landing_ip
  [[ ${relay_idx:-} =~ ^[0-9]+$ ]] || { warn "线路机编号无效"; return; }
  [[ ${landing_idx:-} =~ ^[0-9]+$ ]] || { warn "落地机编号无效"; return; }
  [[ -n ${landing_ip:-} ]] || { warn "落地机 IP 不能为空"; return; }

  if ! command -v sing-box >/dev/null 2>&1; then
    warn "未找到 sing-box"; return
  fi

  local o1 o2 relay_priv relay_pub landing_priv landing_pub
  o1=$(sing-box generate wg-keypair) || { warn "生成线路机密钥失败"; return; }
  relay_priv=$(awk -F': ' '/^PrivateKey:/{print $2}' <<<"$o1")
  relay_pub=$(awk -F': ' '/^PublicKey:/{print $2}' <<<"$o1")
  o2=$(sing-box generate wg-keypair) || { warn "生成落地机密钥失败"; return; }
  landing_priv=$(awk -F': ' '/^PrivateKey:/{print $2}' <<<"$o2")
  landing_pub=$(awk -F': ' '/^PublicKey:/{print $2}' <<<"$o2")

  local host_oct=$((100 + relay_idx))
  local relay_addr="10.66.${landing_idx}.${host_oct}/24"
  local landing_addr="10.66.${landing_idx}.1/24"
  local relay_allowed="10.66.${landing_idx}.${host_oct}/32"
  local wg_tag="wg-${landing_idx}"

  echo
  echo "========== 线路机侧 =========="
  echo "将以下 JSON 粘贴到线路机的 [管理落地 → 新增落地]："
  echo
  jq -n \
    --arg tag "$wg_tag" \
    --arg relay_addr "$relay_addr" \
    --arg relay_priv "$relay_priv" \
    --arg landing_ip "$landing_ip" \
    --arg landing_pub "$landing_pub" \
    '{type:"wireguard",tag:$tag,system:true,name:"wg0",mtu:1420,address:[$relay_addr],private_key:$relay_priv,peers:[{address:$landing_ip,port:51820,public_key:$landing_pub,allowed_ips:["0.0.0.0/0","::/0"],persistent_keepalive_interval:25}]}'
  echo
  echo "========== 落地机侧 =========="
  echo "在落地机上执行全新安装或添加协议时选择 WireGuard，输入以下参数："
  echo "  监听端口: 51820"
  echo "  私钥: $landing_priv"
  echo "  隧道地址: $landing_addr"
  echo "  对端公钥: $relay_pub"
  echo "  对端允许 IP: $relay_allowed"
  echo
  echo "或者直接在落地机上运行以下命令写入 profile："
  echo
  local landing_params
  landing_params=$(jq -n --arg proto "wireguard" --argjson port 51820 \
    --arg priv "$landing_priv" --arg addr "$landing_addr" \
    --arg peer_pub "$relay_pub" --arg peer_allowed "$relay_allowed" \
    '{protocol:$proto,listen_port:$port,private_key:$priv,address:$addr,peer_public_key:$peer_pub,peer_allowed_ips:$peer_allowed}')
  echo "jq --indent 2 --argjson p '${landing_params}' '.inbounds += [\$p]' /etc/sing-box/profile > /tmp/p.tmp && mv /tmp/p.tmp /etc/sing-box/profile && systemctl restart sing-box"
}

# ── 安装流程 ──
full_install() {
  echo
  echo "请选择服务器角色："
  echo "  1) 线路机 (中转节点)"
  echo "  2) 落地机 (出口节点)"
  read -rp "请选择: " role_choice

  case "$role_choice" in
    1)
      CURRENT_ROLE="relay"
      install_pkgs
      install_nginx
      install_singbox
      install_acme
      load_account

      cleanup_all_dns

      echo
      echo "请选择入站协议："
      echo "  1) VLESS + Reality + Vision"
      echo "  2) AnyTLS"
      read -rp "请选择: " proto_choice

      local port=30000 domain params
      case "$proto_choice" in
        1)
          domain=$(create_dns_record)
          if ! issue_cert_for_domain "$domain"; then
            delete_dns_record "$domain"
            die "证书签发失败，已回滚 DNS 记录"
          fi
          params=$(gen_params_vless_reality "$domain" "$port")
        ;;
        2)
          domain=$(create_dns_record)
          if ! issue_cert_for_domain "$domain"; then
            delete_dns_record "$domain"
            die "证书签发失败，已回滚 DNS 记录"
          fi
          params=$(gen_params_anytls "$domain" "$port")
        ;;
        *) die "无效选择" ;;
      esac

      mkdir -p "$BASE_DIR"
      jq -n --arg role "relay" --argjson ib "$params" \
        '{role:$role,inbounds:[$ib]}' --indent 2 >"$PROFILE_JSON"
      echo "[]" >"$LANDINGS_JSON"

      mkdir -p /srv/www
      if [[ ! -s /srv/www/index.html ]]; then
        detect_self_geo
        local total=10
        local id=$(( $(echo "$PUBLIC_IP" | tr -cd '0-9' | tail -c 9) % total + 1 ))
        if curl -fsSL "${WEB_REPO}/site-${id}.html" -o /srv/www/index.html; then
          info "伪装站已下载: site-${id}.html"
        else
          warn "下载伪装站失败，写入默认占位页"
          echo "<h1>Hello</h1>" >/srv/www/index.html
        fi
      fi

      write_nginx
      rebuild_singbox
      publish_sub
    ;;
    2)
      CURRENT_ROLE="landing"
      install_pkgs
      install_singbox

      echo
      echo "请选择入站协议："
      echo "  1) SOCKS"
      echo "  2) Shadowsocks 2022"
      echo "  3) WireGuard"
      read -rp "请选择: " proto_choice

      local port params
      case "$proto_choice" in
        1) port=1080;  params=$(gen_params_socks "$port") ;;
        2) port=8388;  params=$(gen_params_ss2022 "$port") ;;
        3)
          local wg_port wg_priv wg_addr wg_peer_pub wg_peer_allowed
          read -rp "监听端口 [51820]: " wg_port
          wg_port=${wg_port:-51820}
          read -rp "私钥: " wg_priv
          read -rp "隧道地址 (如 10.66.1.1/24): " wg_addr
          read -rp "对端公钥: " wg_peer_pub
          read -rp "对端允许 IP (如 10.66.1.100/32): " wg_peer_allowed
          port=$wg_port
          params=$(gen_params_wireguard "$port" "$wg_priv" "$wg_addr" "$wg_peer_pub" "$wg_peer_allowed")
        ;;
        *) die "无效选择" ;;
      esac

      mkdir -p "$BASE_DIR"
      jq -n --arg role "landing" --argjson ib "$params" \
        '{role:$role,inbounds:[$ib]}' --indent 2 >"$PROFILE_JSON"

      rebuild_singbox
      info "落地机安装完成"
    ;;
    *) warn "无效选择" ;;
  esac
}

update_vless_params() {
  load_profile || die "缺少 profile 配置"
  while read -r idx; do
    local uuid kp priv pub sid
    uuid=$(uuidgen)
    kp=$(sing-box generate reality-keypair)
    priv=$(awk '/PrivateKey/ {print $2}' <<<"$kp")
    pub=$(awk '/PublicKey/  {print $2}' <<<"$kp")
    sid=$(sing-box generate rand 8 --hex)
    jq_inplace "$PROFILE_JSON" --indent 2 --argjson i "$idx" \
      --arg uuid "$uuid" --arg priv "$priv" --arg pub "$pub" --arg sid "$sid" \
      '.inbounds[$i].uuid=$uuid | .inbounds[$i].private_key=$priv | .inbounds[$i].public_key=$pub | .inbounds[$i].short_id=$sid'
  done < <(jq -r '.inbounds | to_entries[] | select(.value.protocol=="vless-reality") | .key' "$PROFILE_JSON")
  rebuild_singbox
  publish_sub
  info "VLESS 参数已更新"
}

show_sub() {
  load_profile || die "缺少 profile 配置"
  ensure_token
  local primary_domain
  primary_domain=$(get_primary_domain)
  if [[ -n $primary_domain ]]; then
    info "订阅链接：https://${primary_domain}/subscribe/${token}"
  else
    warn "无 VLESS 域名，无法生成订阅链接"
  fi
}

show_info() {
  load_profile || die "缺少 profile 配置"
  echo
  echo "角色: $CURRENT_ROLE"
  echo "Inbounds:"
  jq -r '.inbounds[] | "  [\(.protocol)] port=\(.listen_port)\(if .domain then " domain=\(.domain)" else "" end)"' "$PROFILE_JSON"
  if [[ $CURRENT_ROLE == "relay" && -f $LANDINGS_JSON ]]; then
    local lc
    lc=$(jq length "$LANDINGS_JSON")
    echo "落地节点: ${lc} 个"
  fi
}

# ── 主菜单 ──
load_profile 2>/dev/null || true

while :; do
  echo
  if [[ $CURRENT_ROLE == "relay" ]]; then
    echo "===== Reality-Manager (线路机) ====="
    echo " 1) 全新安装"
    echo " 2) 添加入站协议"
    echo " 3) 删除入站协议"
    echo " 4) 管理落地 (Outbound)"
    echo " 5) 生成 WireGuard 配对配置"
    echo " 6) 查看订阅链接"
    echo " 7) 刷新订阅 Token"
    echo " 8) 更新订阅配置"
    echo " 9) 更新 VLESS 参数 (UUID/Reality)"
    echo "10) 查看节点信息"
    echo " 0) 退出"
    read -rp "请选择: " sel
    case $sel in
      1) full_install ;;
      2) add_inbound ;;
      3) remove_inbound ;;
      4) edit_landings ;;
      5) generate_wg_pairing ;;
      6) show_sub ;;
      7) renew_token; publish_sub ;;
      8) publish_sub ;;
      9) update_vless_params ;;
      10) show_info ;;
      0) exit 0 ;;
      *) warn "无效选择" ;;
    esac
  elif [[ $CURRENT_ROLE == "landing" ]]; then
    echo "===== Reality-Manager (落地机) ====="
    echo "1) 全新安装"
    echo "2) 添加入站协议"
    echo "3) 删除入站协议"
    echo "4) 查看节点信息"
    echo "0) 退出"
    read -rp "请选择: " sel
    case $sel in
      1) full_install ;;
      2) add_inbound ;;
      3) remove_inbound ;;
      4) show_info ;;
      0) exit 0 ;;
      *) warn "无效选择" ;;
    esac
  else
    echo "===== Reality-Manager ====="
    echo "1) 全新安装"
    echo "0) 退出"
    read -rp "请选择: " sel
    case $sel in
      1) full_install ;;
      0) exit 0 ;;
      *) warn "无效选择" ;;
    esac
  fi
done
