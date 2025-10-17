#!/usr/bin/env bash
# vless-reality-manager.sh：基于 Nginx-stream + sing-box(VLESS-Vision-Reality) 的部署/维护脚本

set -euo pipefail

# 全局变量
BASE_DIR=/etc/sing-box
CONF_JSON=$BASE_DIR/config.json
LANDINGS_JSON=$BASE_DIR/landings
PUBKEY_FILE=$BASE_DIR/reality_public_key
ACCOUNT_FILE=$BASE_DIR/account.env
NGINX_CONF=/etc/nginx/nginx.conf

KEY_PATH=/etc/ssl/private/key.pem
CERT_PATH=/etc/ssl/private/fullchain.pem
CA_PATH=/etc/ssl/private/ca.pem

SUB_DIR=/srv/www/subscribe
SUB_TOKEN_FILE=$BASE_DIR/sub_token
WEB_REPO="https://raw.githubusercontent.com/carlyle12138/sites/main"

SERVER_DOMAIN=""
CORE_UUID=""
CORE_UUID_NO_DASH=""
CORE_PRIV=""
CORE_PUB=""
SHORT_ID=""
PUBLIC_IP=""
LOCATION_TAG="Other"

CF_Token=""
CF_Zone_ID=""
ACME_EMAIL=""

# 辅助输出
ENDPOINT_TYPES=("wireguard")

info() {
  echo -e "\e[36m[INFO]\e[0m $*"
}
warn() {
  echo -e "\e[33m[WARN]\e[0m $*"
}
die() {
  echo -e "\e[31m[ERR ]\e[0m $*"
  exit 1
}

[[ $EUID -ne 0 ]] && die "请以 root 权限运行本脚本"

# 账户读取/保存
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

# 安装依赖
install_pkgs() {
  apt update
  apt install -y curl jq uuid-runtime gnupg2 ca-certificates lsb-release
}
install_nginx() {
  if command -v nginx >/dev/null; then
    return
  fi

  . /etc/os-release || true
  local DISTRO=${ID:-}
  case "$DISTRO" in
    debian)
      apt install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring
      curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
        | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
      echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
        http://nginx.org/packages/debian $(lsb_release -cs) nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
      echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
        | tee /etc/apt/preferences.d/99nginx
    ;;
    ubuntu)
      apt install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring
      curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
        | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
      echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
        http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
      echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
        | tee /etc/apt/preferences.d/99nginx
    ;;
    *)
      warn "未知发行版($DISTRO)，将尝试使用 Debian 仓库方式安装"
      apt install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring
      curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
        | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
      echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
        http://nginx.org/packages/debian $(lsb_release -cs) nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
    ;;
  esac

  apt update
  apt install -y nginx
}
install_singbox() {
  if command -v sing-box >/dev/null; then
    return
  fi
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

# Cloudflare 相关
cf_api() {
  curl -sSL -X "$1" \
    -H "Authorization: Bearer $CF_Token" \
    -H "Content-Type: application/json" \
    ${3:+--data "$3"} \
    "https://api.cloudflare.com/client/v4/$2"
}
create_dns() {
  fetch_geo
  local sub
  sub=$(sing-box generate rand 8 --hex)
  local resp
  resp=$(cf_api POST "zones/$CF_Zone_ID/dns_records" "{\"type\":\"A\",\"name\":\"$sub\",\"content\":\"$PUBLIC_IP\",\"ttl\":1,\"proxied\":false}")
  if [[ $(jq -r .success <<<"$resp") != true ]]; then
    die "创建 DNS 记录失败: $resp"
  fi
  SERVER_DOMAIN=$(jq -r .result.name <<<"$resp")
  echo "$(jq -r .result.id <<<"$resp")" >"$BASE_DIR/record.id"
  info "已创建 DNS：$SERVER_DOMAIN &rarr; $PUBLIC_IP"
}
delete_dns_if_any() {
  if [[ -f $BASE_DIR/record.id ]]; then
    local id
    id=$(cat "$BASE_DIR/record.id")
    cf_api DELETE "zones/$CF_Zone_ID/dns_records/$id" >/dev/null || true
    rm -f "$BASE_DIR/record.id"
  fi
}

# 地理信息相关
fetch_geo() {
  local q g cc ip
  q="${1:-}"
  if [[ -n $q ]]; then
    g=$(curl -4s --max-time 6 "https://api.ip2location.io/?ip=${q}" || true)
    if [[ -n $g ]] && echo "$g" | jq -e . >/dev/null 2>&1; then
      cc=$(echo "$g" | jq -r '.country_code // empty')
      if [[ -n $cc ]]; then
        echo "$cc"
        return
      fi
    fi
    echo Other
    return
  fi
  g=$(curl -4s --max-time 6 "https://api.ip2location.io/" || true)
  if [[ -n $g ]] && echo "$g" | jq -e . >/dev/null 2>&1; then
    cc=$(echo "$g" | jq -r '.country_code // empty')
    ip=$(echo "$g" | jq -r '.ip // empty')
    [[ -n $cc ]] && LOCATION_TAG="$cc"
    [[ -n $ip ]] && PUBLIC_IP="$ip"
  fi
}

# 证书相关
issue_cert() {
  echo
  echo "请选择签发 CA："
  echo "  1) ZeroSSL (默认)"
  echo "  2) Let's Encrypt"
  read -rp "请输入序号 [1]: " ca_choice
  local ca_server
  case "$ca_choice" in
    2) ca_server="letsencrypt" ;;
    *) ca_server="zerossl" ;;
  esac
  info "使用 $ca_server 申请证书..."
  ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$SERVER_DOMAIN" --server "$ca_server"
  ~/.acme.sh/acme.sh --install-cert -d "$SERVER_DOMAIN" \
    --key-file "$KEY_PATH" \
    --fullchain-file "$CERT_PATH" \
    --ca-file "$CA_PATH" \
    --reloadcmd "systemctl force-reload nginx"
}

# 核心变量生成
gen_core_vars() {
  CORE_UUID=$(uuidgen)
  CORE_UUID_NO_DASH=${CORE_UUID//-/}
  local kp
  kp=$(sing-box generate reality-keypair)
  CORE_PRIV=$(awk '/PrivateKey/ {print $2}' <<<"$kp")
  CORE_PUB=$(awk '/PublicKey/  {print $2}' <<<"$kp")
  SHORT_ID=$(sing-box generate rand 8 --hex)
  echo "$CORE_PUB" >"$PUBKEY_FILE"
}

# 配置保障函数
ensure_domain() {
  if [[ -z $SERVER_DOMAIN ]]; then
    if [[ -f $CONF_JSON ]]; then
      SERVER_DOMAIN=$(jq -r '.inbounds[0].tls.server_name // empty' "$CONF_JSON")
    fi
    if [[ -z $SERVER_DOMAIN && -f $NGINX_CONF ]]; then
      SERVER_DOMAIN=$(grep -m1 -Po 'server_name\s+\K[^;]+' "$NGINX_CONF" || true)
    fi
  fi
}
ensure_core_vars() {
  if [[ -z $CORE_UUID ]]; then
    if [[ ! -f $CONF_JSON ]]; then
      die "缺少 $CONF_JSON，请先安装"
    fi
    CORE_UUID=$(jq -r '.inbounds[0].users[0].uuid' "$CONF_JSON")
    CORE_UUID_NO_DASH=${CORE_UUID//-/}
    CORE_PRIV=$(jq -r '.inbounds[0].tls.reality.private_key' "$CONF_JSON")
    SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$CONF_JSON")
    CORE_PUB=$(<"$PUBKEY_FILE")
  fi
}
ensure_token() {
  if [[ -f $SUB_TOKEN_FILE ]]; then
    token=$(<"$SUB_TOKEN_FILE")
  else
    token=${CORE_UUID_NO_DASH:-$(uuidgen | tr -d '-')}
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
        jq --indent 2 --argjson i "$((idx - 1))" --arg u "$nu" \
          '.[$i].uuid = $u' "$LANDINGS_JSON" > tmp && mv tmp "$LANDINGS_JSON"
      fi
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi
}

# 配置生成
write_nginx() {
  local ups srv
  ups="  upstream singbox_direct {\n    server 127.0.0.1:30000;\n  }\n"
  ups+="  upstream web_backend {\n    server 127.0.0.1:8443;\n  }\n"

  srv="  map \$ssl_preread_server_name \$backend {\n"
  srv+="    $SERVER_DOMAIN  singbox_direct;\n"
  srv+="    default         web_backend;\n"
  srv+="  }\n\n"
  srv+="  server {\n"
  srv+="    listen 443 reuseport;\n"
  srv+="    listen [::]:443 reuseport;\n"
  srv+="    proxy_pass \$backend;\n"
  srv+="    ssl_preread on;\n"
  srv+="    proxy_timeout 300s;\n"
  srv+="    proxy_connect_timeout 10s;\n"
  srv+="  }\n\n"

  cat >"$NGINX_CONF" <<EOF
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
$(printf '%b' "$ups")
$(printf '%b' "$srv")
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
  ssl_stapling_verify on;
  ssl_trusted_certificate $CA_PATH;
  resolver 8.8.8.8 1.1.1.1 valid=60s;

  server {
    listen 127.0.0.1:8443 ssl;
    http2 on;
    server_name $SERVER_DOMAIN;
    root /srv/www;
    index index.html;
    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    access_log off;

    location /subscribe/ {
      try_files \$uri =403;
    }

    location / {
      try_files \$uri \$uri/ =404;
    }
  }

  server {
    listen 80;
    server_name $SERVER_DOMAIN;
    return 301 https://\$host\$request_uri;
  }
}
EOF
  systemctl restart nginx
}

rebuild_singbox() {
  local inbounds outbounds routes inbound ob rt
  ensure_domain
  ensure_core_vars
  ensure_landings_uuid

  local users u
  users=$(jq -n \
    --arg name "direct" \
    --arg uuid "$CORE_UUID" \
    '[{"name":$name,"uuid":$uuid,"flow":"xtls-rprx-vision"}]')

  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r row; do
      local tag l_uuid
      tag=$(jq -r .tag <<<"$row")
      l_uuid=$(jq -r '.uuid // empty' <<<"$row")
      if [[ -z $l_uuid || $l_uuid == "null" ]]; then
        l_uuid=$(uuidgen)
        jq --indent 2 --arg t "$tag" --arg u "$l_uuid" '(.[] | select(.tag==$t)).uuid=$u' "$LANDINGS_JSON" > tmp && mv tmp "$LANDINGS_JSON"
      fi
      u=$(jq -n --arg name "$tag" --arg uuid "$l_uuid" '{"name":$name,"uuid":$uuid,"flow":"xtls-rprx-vision"}')
      users=$(jq -n --argjson a "$users" --argjson b "$u" '$a + [$b]')
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi

  inbound=$(jq -n \
    --arg sn "$SERVER_DOMAIN" \
    --arg pk "$CORE_PRIV" \
    --arg sid "$SHORT_ID" \
    --argjson port 30000 \
    --argjson users "$users" '
    {
      "type":"vless",
      "tag":"vless-direct",
      "listen":"127.0.0.1",
      "listen_port":$port,
      "users": $users,
      "tls":{
        "enabled":true,
        "server_name":$sn,
        "reality":{
          "enabled":true,
          "handshake":{"server":"127.0.0.1","server_port":8443},
          "private_key":$pk,
          "short_id":[$sid]
        }
      }
    }
  ')
  inbounds=$(jq -n --argjson b "$inbound" '[ $b ]')
  outbounds=$(jq -n '[{"type":"direct","tag":"direct"}]')
  endpoints=$(jq -n '[]')
  routes=$(jq -n '[{"auth_user":"direct","outbound":"direct"}]')

  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r row; do
      local tag out_tag
      tag=$(jq -r .tag <<<"$row")
      if jq -e 'has("endpoint")' <<<"$row" >/dev/null; then
        ep=$(jq -c '.endpoint' <<<"$row")
        endpoints=$(jq -n --argjson a "$endpoints" --argjson b "$ep" '$a + [$b]')
        out_tag=$(jq -r '.endpoint.tag // empty' <<<"$row")
        if [[ -z $out_tag ]]; then
          die "落地配置缺少 endpoint.tag: $row"
        fi
      else
        ob=$(jq -c '.outbound' <<<"$row")
        out_tag=$(jq -r '.outbound.tag // empty' <<<"$row")
        if [[ -z $out_tag ]]; then
          die "落地配置缺少 outbound.tag: $row"
        fi
        if [[ $out_tag != "direct" ]]; then
          [[ -n $ob && $ob != "null" ]] && outbounds=$(jq -n --argjson a "$outbounds" --argjson b "$ob" '$a + [$b]')
        fi
      fi
      rt=$(jq -n --arg tag "$tag" --arg out "$out_tag" '{ "auth_user": $tag , "outbound": $out }')
      routes=$(jq -n --argjson r "$routes" --argjson x "$rt" '$r + [$x]')
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi

  jq -n \
    --argjson ib "$inbounds" \
    --argjson ob "$outbounds" \
    --argjson ep "$endpoints" \
    --argjson rt "$routes" \
    '{ "inbounds": $ib, "outbounds": $ob, "endpoints": $ep, "route": { "rules": $rt } }' \
    --indent 2 >"$CONF_JSON"
  systemctl restart sing-box
}

# 订阅管理
publish_sub() {
  mkdir -p "$SUB_DIR"
  ensure_domain
  ensure_core_vars
  ensure_token
  ensure_landings_uuid
  fetch_geo

  local tmp
  tmp=$(mktemp)
  local dlabel denc
  dlabel="${LOCATION_TAG}-direct"
  denc=$(printf '%s' "$dlabel" | jq -sRr @uri)
  echo "vless://${CORE_UUID}@${PUBLIC_IP}:443?encryption=none&security=reality&type=tcp&sni=${SERVER_DOMAIN}&fp=firefox&pbk=${CORE_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision#${denc}" >>"$tmp"

  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r row; do
      local tag loc lu q
      tag=$(jq -r .tag <<<"$row")
      lu=$(jq -r '.uuid // empty' <<<"$row")
      q=$(jq -r '.outbound.server // .endpoint.peers[0].address // empty' <<<"$row")
      if [[ -n $q ]]; then
        loc=$(fetch_geo "$q")
      else
        loc="Other"
      fi
      [[ -n $lu ]] || lu="$CORE_UUID"
      local label enc
      label="${loc}-${tag}"
      enc=$(printf '%s' "$label" | jq -sRr @uri)
      echo "vless://${lu}@${PUBLIC_IP}:443?encryption=none&security=reality&type=tcp&sni=${SERVER_DOMAIN}&fp=firefox&pbk=${CORE_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision#${enc}" >>"$tmp"
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi

  base64 -w0 "$tmp" >"$SUB_DIR/$token"
  rm -f "$tmp"
  find "$SUB_DIR" -type f ! -name "$token" -delete
  info "订阅链接：https://${SERVER_DOMAIN}/subscribe/${token}"
}

# 落地管理
edit_landings() {
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
      echo "请粘贴 JSON；粘贴完直接回车即可（空行确认）。若未识别为有效 JSON，请继续粘贴直至空行确认。"
      j=""
      while IFS= read -r line; do
        if [[ -z "$line" ]]; then
          tmp=${j%$'\n'}
          if [[ -n "$tmp" ]] && echo "$tmp" | jq -e . >/dev/null 2>&1; then
            j="$tmp"
            break
          fi
        fi
        j+="$line"$'\n'
      done
      j=${j//$'\r'/}
      if ! echo "$j" | jq -e . >/dev/null 2>&1; then
        warn "JSON 无效"
        return
      fi
      local o_tag o_type is_ep
      o_tag=$(echo "$j" | jq -r '.tag // empty')
      if [[ -z $o_tag ]]; then
        warn "JSON 中缺少 tag"
        return
      fi
      o_type=$(echo "$j" | jq -r '.type // empty')
      is_ep=0; for _t in "${ENDPOINT_TYPES[@]}"; do [[ "$o_type" == "$_t" ]] && { is_ep=1; break; }; done
      if [[ "$o_tag" == "direct" ]]; then
        warn "tag 不可为保留值 direct"
        return
      fi
      if jq -e --arg t "$o_tag" 'map(select((.outbound?.tag // "") == $t or (.endpoint?.tag // "") == $t)) | length > 0' "$LANDINGS_JSON" >/dev/null; then
        warn "tag 已存在"
        return
      fi
      local tmpc
      tmpc=$(mktemp)
      if [[ $is_ep -eq 1 ]]; then
        jq -n --argjson o "$j" '{endpoints: [$o]}' >"$tmpc"
      else
        jq -n --argjson o "$j" '{outbounds: [$o]}' >"$tmpc"
      fi
      if ! sing-box check -c "$tmpc" >/dev/null 2>&1; then
        rm -f "$tmpc"
        warn "sing-box check 未通过"
        return
      fi
      rm -f "$tmpc"
      local nu
      nu=$(uuidgen)
      if [[ $is_ep -eq 1 ]]; then
        jq --indent 2 \
          --arg t "$o_tag" \
          --arg g "$nu" \
          --argjson o "$j" \
          '. += [{"tag":$t,"uuid":$g,"endpoint":$o}]' \
          "$LANDINGS_JSON" >tmp && mv tmp "$LANDINGS_JSON"
      else
        jq --indent 2 \
          --arg t "$o_tag" \
          --arg g "$nu" \
          --argjson o "$j" \
          '. += [{"tag":$t,"uuid":$g,"outbound":$o}]' \
          "$LANDINGS_JSON" >tmp && mv tmp "$LANDINGS_JSON"
      fi
    ;;
    2)
      local total
      total=$(jq length "$LANDINGS_JSON")
      if [[ $total -eq 0 ]]; then
        warn "当前没有落地节点可修改"
        return
      fi
      echo
      jq -r 'to_entries[] | "\(.key+1)) \(.value.tag)"' "$LANDINGS_JSON"
      read -rp "请输入要修改的序号: " idx
      idx=$((idx-1))
      local cur_tag
      cur_tag=$(jq -r ".[$idx].tag" "$LANDINGS_JSON" 2>/dev/null) || die "序号无效"
      echo "当前 tag=$cur_tag:"
      echo "请粘贴新的 JSON；粘贴完直接回车即可（空行确认）。若未识别为有效 JSON，请继续粘贴，直至空行确认生效。"
      j2=""
      while IFS= read -r line; do
        if [[ -z "$line" ]]; then
          tmp2=${j2%$'\n'}
          if [[ -n "$tmp2" ]] && echo "$tmp2" | jq -e . >/dev/null 2>&1; then
            j2="$tmp2"
            break
          fi
        fi
        j2+="$line"$'\n'
      done
      j2=${j2//$'\r'/}
      if ! echo "$j2" | jq -e . >/dev/null 2>&1; then
        warn "JSON 无效"
        return
      fi
      local o2_tag o2_type is_ep2 tmpc2
      o2_tag=$(echo "$j2" | jq -r '.tag // empty')
      if [[ -z $o2_tag ]]; then
        warn "JSON 中缺少 tag"
        return
      fi
      # 重复 tag 校验（排除自身），覆盖 endpoints/outbounds
      if [[ "$o2_tag" == "direct" ]]; then
        warn "tag 不可为保留值 direct"
        return
      fi
      if jq -e --arg t "$o2_tag" --argjson i "$idx" 'to_entries | map(select(.key != $i) | select((.value.outbound?.tag // "") == $t or (.value.endpoint?.tag // "") == $t)) | length > 0' "$LANDINGS_JSON" >/dev/null; then
        warn "tag 已存在"
        return
      fi
      o2_type=$(echo "$j2" | jq -r '.type // empty')
      is_ep2=0; for _t in "${ENDPOINT_TYPES[@]}"; do [[ "$o2_type" == "$_t" ]] && { is_ep2=1; break; }; done
      tmpc2=$(mktemp)
      if [[ $is_ep2 -eq 1 ]]; then
        jq -n --argjson o "$j2" '{endpoints: [$o]}' >"$tmpc2"
      else
        jq -n --argjson o "$j2" '{outbounds: [$o]}' >"$tmpc2"
      fi
      if ! sing-box check -c "$tmpc2" >/dev/null 2>&1; then
        rm -f "$tmpc2"
        warn "sing-box check 未通过"
        return
      fi
      rm -f "$tmpc2"
      if [[ $is_ep2 -eq 1 ]]; then

        jq --indent 2 \
          --argjson i "$idx" \
          --argjson o "$j2" \
          --arg t "$o2_tag" '
          .[$i].endpoint = $o |
          .[$i].tag = $t |
          del(.[$i].outbound)
        ' "$LANDINGS_JSON" > tmp && mv tmp "$LANDINGS_JSON"
      else
        jq --indent 2 \
          --argjson i "$idx" \
          --argjson o "$j2" \
          --arg t "$o2_tag" '
          .[$i].outbound = $o |
          .[$i].tag = $t |
          del(.[$i].endpoint)
        ' "$LANDINGS_JSON" > tmp && mv tmp "$LANDINGS_JSON"
      fi
    ;;
    3)
      local total_del
      total_del=$(jq length "$LANDINGS_JSON")
      if [[ $total_del -eq 0 ]]; then
        warn "当前没有落地节点可删除"
        return
      fi
      echo
      jq -r 'to_entries[] | "\(.key+1)) \(.value.tag)"' "$LANDINGS_JSON"
      read -rp "请输入要删除的序号: " did
      did=$((did-1))
      jq --indent 2 "del(.[$did])" "$LANDINGS_JSON" > tmp && mv tmp "$LANDINGS_JSON"
    ;;
    0) return ;;
    *) warn "无效选择" ;;
  esac

  ensure_domain
  ensure_core_vars
  ensure_landings_uuid
  write_nginx
  rebuild_singbox
  publish_sub
}

# 主要操作流程
full_install() {
  install_pkgs
  install_nginx
  install_singbox
  install_acme
  load_account
  delete_dns_if_any
  create_dns
  issue_cert
  gen_core_vars
  echo "[]" >"$LANDINGS_JSON"

  mkdir -p /srv/www
  if [[ ! -s /srv/www/index.html ]]; then
    fetch_geo
    local total=10
    local id=$(( $(echo "$PUBLIC_IP" | tr -cd '0-9' | tail -c 9) % total + 1 ))
    local url_html="${WEB_REPO}/site-${id}.html"
    if curl -fsSL "$url_html" -o /srv/www/index.html; then
      info "伪装站已下载: site-${id}.html"
    else
      warn "下载伪装站失败，写入默认占位页"
      echo "<h1>Hello</h1>" >/srv/www/index.html
    fi
  fi

  write_nginx
  rebuild_singbox
  publish_sub
}

update_vless() {
  gen_core_vars
  ensure_domain
  rebuild_singbox
  publish_sub
}

update_domain() {
  load_account
  delete_dns_if_any
  create_dns
  issue_cert
  write_nginx
  rebuild_singbox
  publish_sub
}

show_sub() {
  ensure_domain
  ensure_token
  info "订阅链接：https://${SERVER_DOMAIN}/subscribe/${token}"
}

generate_wg_config() {
  local l_idx d_idx d_ip d_name host_oct
  read -rp "请输入线路机编号: " l_idx
  read -rp "请输入落地机编号: " d_idx
  read -rp "请输入落地机 IP: " d_ip
  read -rp "请输入落地机服务器名称（可选，直接回车跳过）: " d_name

  [[ ${l_idx:-} =~ ^[0-9]+$ ]] || { warn "线路机编号无效"; return; }
  [[ ${d_idx:-} =~ ^[0-9]+$ ]] || { warn "落地机编号无效"; return; }
  host_oct=$((100 + l_idx))

  if ! command -v sing-box >/dev/null 2>&1; then
    warn "未找到 sing-box，请先安装后再试"
    return
  fi

  # 生成密钥对
  local o1 o2 line_priv line_pub land_priv land_pub
  if ! o1=$(sing-box generate wg-keypair 2>/dev/null); then warn "生成线路机密钥失败"; return; fi
  line_priv=$(awk -F': ' '/^PrivateKey: /{print $2}' <<<"$o1")
  line_pub=$(awk -F': ' '/^PublicKey: /{print $2}' <<<"$o1")
  if [[ -z $line_priv || -z $line_pub ]]; then warn "解析线路机密钥失败"; return; fi

  if ! o2=$(sing-box generate wg-keypair 2>/dev/null); then warn "生成落地机密钥失败"; return; fi
  land_priv=$(awk -F': ' '/^PrivateKey: /{print $2}' <<<"$o2")
  land_pub=$(awk -F': ' '/^PublicKey: /{print $2}' <<<"$o2")
  if [[ -z $land_priv || -z $land_pub ]]; then warn "解析落地机密钥失败"; return; fi

  local line_addr land_addr land_allowed
  line_addr="10.66.${d_idx}.${host_oct}/24"
  land_addr="10.66.${d_idx}.1/24"
  land_allowed="10.66.${d_idx}.${host_oct}/32"

  # 构造 JSON
  local line_tag line_name json_line json_land
  if [[ -n $d_name ]]; then
    line_tag="wg-ep${d_idx}-${d_name}"
  else
    line_tag="wg-ep${d_idx}"
  fi
  line_name="wg${d_idx}"

  json_line=$(jq -n \
    --arg tag "$line_tag" \
    --arg name "$line_name" \
    --arg addr "$line_addr" \
    --arg priv "$line_priv" \
    --arg peer_addr "$d_ip" \
    --arg peer_pub "$land_pub" \
    '{
      type: "wireguard",
      tag: $tag,
      system: true,
      name: $name,
      mtu: 1408,
      address: [$addr],
      private_key: $priv,
      peers: [{
        address: $peer_addr,
        port: 51820,
        public_key: $peer_pub,
        allowed_ips: ["0.0.0.0/0", "::/0"],
        persistent_keepalive_interval: 25
      }]
    }')

  local wg_ep
  wg_ep=$(jq -n \
    --arg addr "$land_addr" \
    --arg priv "$land_priv" \
    --arg lpub "$line_pub" \
    --arg allowed "$land_allowed" \
    '{
      type: "wireguard",
      tag: "wg-ep",
      system: true,
      name: "wg0",
      mtu: 1408,
      address: [$addr],
      private_key: $priv,
      listen_port: 51820,
      peers: [{
        public_key: $lpub,
        allowed_ips: [$allowed]
      }]
    }')

  json_land=$(jq -n \
    --argjson ep "$wg_ep" \
    '{
      endpoints: [$ep],
      outbounds: [{
        type: "direct",
        tag: "direct"
      }],
      route: {
        final: "direct"
      }
    }')

  echo
  echo "线路机："
  echo "$json_line"
  echo
  echo "落地机："
  echo "$json_land"
}

# 主菜单
while :; do
  echo
  echo "===== Reality-Manager ====="
  echo "1) 全新安装"
  echo "2) 更新 VLESS (UUID/Reality参数)"
  echo "3) 更新域名 (更换子域名)"
  echo "4) 更新落地 (增加/修改/删除)"
  echo "5) 查看订阅链接"
  echo "6) 刷新订阅Token"
  echo "7) 更新订阅配置"
  echo "8) 生成 WG 配置（仅输出，两端 JSON）"
  echo "0) 退出"
  read -rp "请选择: " sel
  case $sel in
    1) full_install ;;
    2) update_vless ;;
    3) update_domain ;;
    4) edit_landings ;;
    5) show_sub ;;
    6) renew_token; publish_sub ;;
    7) publish_sub ;;
    8) generate_wg_config ;;
    0) exit 0 ;;
    *) warn "无效选择" ;;
  esac
done
