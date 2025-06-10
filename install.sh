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
LOCATION_TAG="其他"

CF_Token=""
CF_Zone_ID=""
ACME_EMAIL=""

# 辅助输出
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
  if [[ -z $PUBLIC_IP ]]; then
    local geo
    geo=$(curl -4s ping0.cc/geo || true)
    PUBLIC_IP=$(sed -n '1p' <<<"$geo")
    local loc
    loc=$(sed -n '2p' <<<"$geo")
    case $loc in
      *香港*) LOCATION_TAG="香港" ;;
      *台湾*) LOCATION_TAG="台湾" ;;
      *日本*) LOCATION_TAG="日本" ;;
      *新加坡*) LOCATION_TAG="新加坡" ;;
      *美国*) LOCATION_TAG="美国" ;;
      *) LOCATION_TAG="其他" ;;
    esac
  fi
}
geo_by_proxy() {
  # 参数：$1=type(socks/http)，$2=server，$3=port，$4=user，$5=pass
  local pf ip_resp l2 try
  if [[ $1 == socks* ]]; then
    pf="socks5h://"
    [[ -n ${4:-} ]] && pf+="$4:$5@"
    pf+="$2:$3"
  else
    pf="http://"
    [[ -n ${4:-} ]] && pf+="$4:$5@"
    pf+="$2:$3"
  fi
  for try in {1..3}; do
    local g
    g=$(curl -4s --max-time 6 --proxy "$pf" ping0.cc/geo 2>/dev/null || true)
    [[ -z $g ]] && break
    ip_resp=$(sed -n '1p' <<<"$g")
    if [[ $ip_resp == "$2" ]]; then
      l2=$(sed -n '2p' <<<"$g")
      case $l2 in
        *香港*) echo 香港 ;;
        *台湾*) echo 台湾 ;;
        *日本*) echo 日本 ;;
        *新加坡*) echo 新加坡 ;;
        *美国*) echo 美国 ;;
        *) echo 落地 ;;
      esac
      return
    fi
  done
  echo 落地
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

# 配置生成
write_nginx() {
  local ups srv idx=0
  ups="  upstream singbox_direct {\n    server 127.0.0.1:30000;\n  }\n"
  ups+="  upstream web_backend {\n    server 127.0.0.1:8443;\n  }\n"

  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r _; do
      idx=$((idx + 1))
      ups+="  upstream singbox_ld${idx} {\n    server 127.0.0.1:$((30000 + idx));\n  }\n"
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi

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

  idx=0
  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r _; do
      idx=$((idx + 1))
      srv+="  server {\n"
      srv+="    listen $((14443 + idx - 1)) reuseport;\n"
      srv+="    listen [::]:$((14443 + idx - 1)) reuseport;\n"
      srv+="    proxy_pass singbox_ld${idx};\n"
      srv+="    ssl_preread on;\n"
      srv+="  }\n\n"
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi

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
  local inbounds outbounds routes inbound ob rt idx=0

  inbounds=$(jq -n \
    --arg uuid "$CORE_UUID" \
    --arg sn "$SERVER_DOMAIN" \
    --arg pk "$CORE_PRIV" \
    --arg sid "$SHORT_ID" \
    --argjson port 30000 '
    [{
      "type":"vless",
      "tag":"vless-direct",
      "listen":"127.0.0.1",
      "listen_port":$port,
      "users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],
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
    }]
  ')
  outbounds=$(jq -n '[{"type":"direct","tag":"direct"}]')
  routes=$(jq -n '[{"inbound":["vless-direct"],"outbound":"direct"}]')

  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    while read -r row; do
      idx=$((idx + 1))
      local tag typ svr prt usr pwd loc_port
      tag=$(jq -r .tag <<<"$row")
      typ=$(jq -r .type <<<"$row")
      svr=$(jq -r .server <<<"$row")
      prt=$(jq -r .port <<<"$row")
      usr=$(jq -r '.username // empty' <<<"$row")
      pwd=$(jq -r '.password // empty' <<<"$row")
      loc_port=$((30000 + idx))

      inbound=$(jq -n \
        --arg tag "$tag" \
        --arg uuid "$CORE_UUID" \
        --arg sn "$SERVER_DOMAIN" \
        --arg pk "$CORE_PRIV" \
        --arg sid "$SHORT_ID" \
        --argjson lp "$loc_port" '
        {
          "type":"vless",
          "tag":("vless-" + $tag),
          "listen":"127.0.0.1",
          "listen_port":$lp,
          "users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],
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
      inbounds=$(jq -n --argjson a "$inbounds" --argjson b "$inbound" '$a + [$b]')
      case $typ in
        socks)
          ob=$(jq -n \
            --arg tag "$tag" \
            --arg svr "$svr" \
            --argjson p "$prt" \
            --arg u "$usr" \
            --arg w "$pwd" '
            {
              "type": "socks",
              "tag": $tag,
              "server": $svr,
              "server_port": $p,
              "version": "5",
              "username": $u,
              "password": $w
            }')
        ;;
        http)
          ob=$(jq -n \
            --arg tag "$tag" \
            --arg svr "$svr" \
            --argjson p "$prt" '
            {
              "type":"http",
              "tag":$tag,
              "server":$svr,
              "server_port":$p
            }')
        ;;
        direct)
          ob=""
        ;;
      esac
      [[ -n $ob ]] && outbounds=$(jq -n --argjson a "$outbounds" --argjson b "$ob" '$a + [$b]')
      rt=$(jq -n --arg tag "$tag" '{ "inbound":["vless-"+$tag],"outbound":$tag }')
      routes=$(jq -n --argjson r "$routes" --argjson x "$rt" '$r + [$x]')
    done < <(jq -c '.[]' "$LANDINGS_JSON")
  fi

  jq -n \
    --argjson ib "$inbounds" \
    --argjson ob "$outbounds" \
    --argjson rt "$routes" \
    '{ "inbounds": $ib, "outbounds": $ob, "route": { "rules": $rt } }' \
    --indent 2 >"$CONF_JSON"
  systemctl restart sing-box
}

# 订阅管理
publish_sub() {
  mkdir -p "$SUB_DIR"
  ensure_domain
  ensure_core_vars
  ensure_token
  fetch_geo

  local tmp
  tmp=$(mktemp)
  echo "vless://${CORE_UUID}@${PUBLIC_IP}:443?encryption=none&security=reality&type=tcp&sni=${SERVER_DOMAIN}&fp=chrome&pbk=${CORE_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision#${LOCATION_TAG}-direct" >>"$tmp"

  if [[ -f $LANDINGS_JSON && $(jq length "$LANDINGS_JSON") -gt 0 ]]; then
    local idx=0
    while read -r row; do
      idx=$((idx + 1))
      local tag typ svr prt usr pwd loc ext
      tag=$(jq -r .tag <<<"$row")
      typ=$(jq -r .type <<<"$row")
      svr=$(jq -r .server <<<"$row")
      prt=$(jq -r .port <<<"$row")
      usr=$(jq -r '.username // empty' <<<"$row")
      pwd=$(jq -r '.password // empty' <<<"$row")
      loc=$(geo_by_proxy "$typ" "$svr" "$prt" "$usr" "$pwd")
      ext=$((14443 + idx - 1))
      echo "vless://${CORE_UUID}@${PUBLIC_IP}:${ext}?encryption=none&security=reality&type=tcp&sni=${SERVER_DOMAIN}&fp=chrome&pbk=${CORE_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision#${loc}-${tag}" >>"$tmp"
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
      read -rp "请输入节点标识 tag(英文): " tag
      echo "1) socks"
      echo "2) http"
      echo "3) direct"
      read -rp "请选择类型: " tnum
      local typ
      case $tnum in
        1) typ="socks" ;;
        2) typ="http" ;;
        3) typ="direct" ;;
        *) warn "无效选择"; return ;;
      esac
      read -rp "请输入服务器地址: " svr
      read -rp "请输入服务器端口: " prt
      if [[ $typ == "socks" ]]; then
        read -rp "用户名(可空): " usr
        read -rp "密码(可空): " pwd
        jq --indent 2 \
          --arg t "$tag" \
          --arg ty "$typ" \
          --arg s "$svr" \
          --argjson p "$prt" \
          --arg u "$usr" \
          --arg w "$pwd" \
          '. += [{"tag":$t,"type":$ty,"server":$s,"port":$p,"username":$u,"password":$w}]' \
          "$LANDINGS_JSON" >tmp && mv tmp "$LANDINGS_JSON"
      else
        jq --indent 2 \
          --arg t "$tag" \
          --arg ty "$typ" \
          --arg s "$svr" \
          --argjson p "$prt" \
          '. += [{"tag":$t,"type":$ty,"server":$s,"port":$p}]' \
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
      local cur_tag cur_srv cur_prt cur_usr cur_pwd
      cur_tag=$(jq -r ".[$idx].tag" "$LANDINGS_JSON" 2>/dev/null) || die "序号无效"
      cur_srv=$(jq -r ".[$idx].server" "$LANDINGS_JSON")
      cur_prt=$(jq -r ".[$idx].port" "$LANDINGS_JSON")
      cur_usr=$(jq -r ".[$idx].username // \"\"" "$LANDINGS_JSON")
      cur_pwd=$(jq -r ".[$idx].password // \"\"" "$LANDINGS_JSON")

      echo "当前 tag=$cur_tag:"
      read -rp "新服务器 [$cur_srv]: " ns
      read -rp "新端口   [$cur_prt]: " np
      read -rp "新用户名 [$cur_usr]: " nu
      read -rp "新密码   [$cur_pwd]: " nw
      ns=${ns:-$cur_srv}
      np=${np:-$cur_prt}
      nu=${nu:-$cur_usr}
      nw=${nw:-$cur_pwd}

      jq --indent 2 \
        --argjson i "$idx" \
        --arg ns "$ns" \
        --argjson np "$np" \
        --arg nu "$nu" \
        --arg nw "$nw" '
        .[$i].server   = $ns |
        .[$i].port     = $np |
        .[$i].username = ($nu | select(. != "")) |
        .[$i].password = ($nw | select(. != ""))
      ' "$LANDINGS_JSON" > tmp && mv tmp "$LANDINGS_JSON"
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

# 主菜单
while :; do
  echo
  echo "===== Reality-Manager ====="
  echo "1) 全新安装"
  echo "2) 更新 VLESS (UUID/Reality参数)"
  echo "3) 更新域名 (更换子域名)"
  echo "4) 更新落地 (增加/修改/删除)"
  echo "5) 查看订阅链接"
  echo "6) 刷新订阅 (仅更新 Token)"
  echo "0) 退出"
  read -rp "请选择: " sel
  case $sel in
    1) full_install ;;
    2) update_vless ;;
    3) update_domain ;;
    4) edit_landings ;;
    5) show_sub ;;
    6) renew_token; publish_sub ;;
    0) exit 0 ;;
    *) warn "无效选择" ;;
  esac
done
