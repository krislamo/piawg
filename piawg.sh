#!/usr/bin/env sh
# SPDX-License-Identifier: 0BSD
# SPDX-FileCopyrightText: 2026 Kris Lamoureux <kris@lamoureux.io>

# Allow local variable scoping, therefore not strictly POSIX
# shellcheck disable=SC3043

msg() { printf '[%s]: %s\n' "${2-INFO}" "$1"; }
info() { [ "$PIAWG_VERBOSE" -eq 1 ] && msg "$1"; }
debug() { [ "$PIAWG_DEBUG" -eq 1 ] && msg "$1" 'DEBUG'; }
warn() { msg "$1" 'WARN'; }
err() {
	msg "$1" 'ERROR'
	exit 1
}

check_http() { [ "$1" = "${2:-200}" ] && return 0 || return 1; }
check_token() { printf '%s\n' "$1" | grep -q '^[0-9A-Fa-f]\{128\}$'; }

_curl() {
	curl -sS --connect-timeout 5 --max-time 20 \
		--retry 5 --retry-delay 2 "$@"
}

bao_curl() {
	local path
	local response
	local error
	local http_code
	local notfound
	local content_type
	notfound=0
	content_type='application/json'
	while getopts "np" opt; do
		case "$opt" in
		n) notfound=1 ;;
		p) content_type='application/merge-patch+json' ;;
		*) err "bao_curl option '$opt' not found" ;;
		esac
	done
	shift $((OPTIND - 1))
	path="$BAO_ADDR/v1/$1"
	shift
	error="Failed request to '$path'"
	if ! response=$(_curl -H "Content-Type: $content_type" \
		-H "X-Vault-Token: $bao_token" -w '\n%{http_code}' "$@" "$path"); then
		err "$error"
	fi
	http_code="$(printf '%s' "$response" | tail -1)"
	if [ "$(check_http "$http_code" "404")" ] && [ "$notfound" -eq 1 ]; then
		info "OpenBao path at $path not found"
		return 4
	fi
	check_http "$http_code" || err "$error"
	printf '%s' "$response" | sed '$d'
}

opn_curl() {
	local path
	local error
	local response
	local http_code
	path="$1"
	shift
	error="Failed request to '$opn_endpoint/$path'"
	if ! response="$(_curl -H 'Content-Type: application/json' \
		-u "$opn_key:$opn_secret" -w '\n%{http_code}' \
		"$@" "$opn_endpoint/$path")"; then
		err "$error"
	fi
	http_code="$(printf '%s' "$response" | tail -1)"
	check_http "$http_code" || err "$error"
	printf '%s' "$response" | sed '$d'
}

pia_addkey() {
	local response
	local key
	local port
	local peer_ip
	local updates
	local server_vip
	# Add pubkey via PIA API and get connection details
	info "Adding '$piawg_pubkey' to PIA server $server_cn"
	if ! response=$(
		_curl -G --resolve "$server_cn:$server_port:$server_ip" \
			--cacert ./ca.rsa.4096.crt \
			--data-urlencode "pt=$pia_token" \
			--data-urlencode "pubkey=$piawg_pubkey" \
			"https://$server_cn:1337/addKey"
	); then
		err "Failed connect to $server_cn to addKey"
	fi
	[ "$(printf '%s' "$response" | jq -r '.status')" != "OK" ] &&
		err "Failed to addKey to $server_cn"
	debug "PIA addKey reply\n$(echo "$response" | jq .)"

	# Update Wireguard config on OPNsense
	updates='{}'
	if [ "$server_ip" != "$piawgsrv_srvaddr" ]; then
		updates="$(printf '%s' "$updates" |
			jq --arg a "$server_ip" '.serveraddress = $a')"
	fi
	key="$(printf '%s' "$response" | jq -r '.server_key')"
	if [ "$key" != "$piawgsrv_pubkey" ]; then
		updates="$(printf '%s' "$updates" | jq --arg k "$key" '.pubkey = $k')"
	fi
	port="$(printf '%s' "$response" | jq -r '.server_port')"
	if [ "$port" != "$piawgsrv_srvport" ]; then
		updates="$(printf '%s' "$updates" |
			jq --arg p "$port" '.serverport = $p')"
	fi
	if [ "$updates" != '{}' ]; then
		updates="$(printf '%s' "$updates" |
			jq --arg s "$piawg_uuid" '.servers = $s')"
		info "Updating connection details of $OPN_IF peer $OPN_PEER"
		debug "$OPN_PEER updates\n$(echo "$updates" | jq .)"
		if [ "$(opn_curl "wireguard/client/setClient/$piawgsrv_uuid" \
			-d "$(printf '%s' "$updates" | jq '{client: .}')" |
			jq -r '.result')" != "saved" ]; then
			err "Failed to update $OPN_PEER pubkey/port"
		fi
	fi
	peer_ip="$(printf '%s' "$response" | jq -r '.peer_ip')"
	if [ "$peer_ip" != "$piawg_tunaddr" ]; then
		info "Updating connection details of $OPN_IF instance"
		if [ "$(opn_curl "wireguard/server/setServer/$piawg_uuid" \
			-d "$(jq -n --arg ip "$peer_ip/32" \
				'{server: {tunneladdress: $ip}}')" |
			jq -r '.result')" != "saved" ]; then
			err "Failed to update $OPN_WG tunnel address to $peer_ip"
		fi
	fi
	info "Reloading Wireguard service"
	if [ "$(opn_curl 'wireguard/service/reconfigure' -d '{}' |
		jq -r '.result')" != "ok" ]; then
		err "Failed to reload Wireguard service"
	fi

	server_vip="$(printf '%s' "$response" | jq -r '.server_vip')"
	info "Updating OpenBao KV server_vip at $BAO_PATH_CONFIG to $server_vip"
	bao_curl -p "$BAO_KV_MOUNT/data/$BAO_PATH_CONFIG" -X PATCH \
		-d "$(jq -n --arg ip "$server_vip" '{data:{server_vip:$ip}}')"

	# Update firewall rule alias
	piawg_ip_alias="$(opn_curl 'firewall/alias/searchItem' -d '{}' |
		jq -r ".rows[] | select(.name == \"$OPN_ALIAS\") | .uuid")"
	info "Updating alias $OPN_ALIAS to $peer_ip"
	piawg_ip_update="$(opn_curl "firewall/alias/setItem/$piawg_ip_alias" \
		-d "$(jq -n --arg ip "$peer_ip" '{alias: {content: $ip}}')")"
	if [ "$(echo "$piawg_ip_update" | jq -r '.result')" != "saved" ]; then
		err "Failed to update $OPN_ALIAS"
	fi
	info "Applying alias update to the firewall"
	if [ "$(opn_curl 'firewall/alias/reconfigure' -d '{}' |
		jq -r '.status')" != "ok" ]; then
		err "Failed to reconfigure the firewall alias $OPN_ALIAS"
	fi
}

check_tunnel() {
	local tunneladdr
	local response
	local peer_status
	tunneladdr="$(opn_curl 'wireguard/server/searchServer' -d '{}' |
		jq -r ".rows[] | select(.name == \"$OPN_IF\") | .tunneladdress")"
	response="$(opn_curl 'wireguard/service/show' -d '{}' |
		jq ".rows[] | select(.name == \"$OPN_PEER\")")"
	peer_status="$(printf '%s' "$response" | jq -r '."peer-status"')"
	[ "$peer_status" != "online" ] && return 1
	if ! ping -c1 -W3 -S "${tunneladdr%/32}" 1.1.1.1 >/dev/null 2>&1; then
		if ! ping -c1 -W3 -S "${tunneladdr%/32}" 8.8.8.8 >/dev/null 2>&1; then
			return 1
		fi
	fi
	return 0
}

# Get a new PIA API token and store
renew_token() {
	local login_response
	local token_response
	local pia_user
	local pia_pass
	local pia_token

	login_response="$(bao_curl "$BAO_KV_MOUNT/data/$BAO_PATH_PIA")"
	pia_user="$(printf '%s' "$login_response" | jq -r '.data.data.username')"
	pia_pass="$(printf '%s' "$login_response" | jq -r '.data.data.password')"
	unset login_response
	if ! token_response="$(_curl -X POST "$PIA_API" \
		-F "username=$pia_user" \
		-F "password=$pia_pass")"; then
		err "Failed to get a new PIA token"
	fi
	unset pia_pass
	unset pia_user
	pia_token="$(echo "$token_response" | jq -r .token)"
	unset token_response
	check_token "$pia_token" || err "Invalid PIA token during renewal attempt"
	bao_curl "$BAO_KV_MOUNT/data/$BAO_PATH_TOKEN" -X POST \
		-d "$(jq -n --arg t "$pia_token" '{data:{token:$t}}')"
	unset pia_token
}

PIAWG_DEBUG=0
PIAWG_VERBOSE=0
while getopts "dv" opt; do
	case $opt in
	d) PIAWG_VERBOSE=1; PIAWG_DEBUG=1 ;;
	v) PIAWG_VERBOSE=1 ;;
	*)
		printf '%s\n' "Usage: $0 [-v]" >&2
		exit 1
		;;
	esac
done
shift $((OPTIND - 1))

# Check for required external commands
for rbin in curl jq openssl; do
	command -v "$rbin" >/dev/null 2>&1 ||
		err "Required binary '$rbin' not found"
done

# Setup config structure
: "${PIAWG_CONF_DIR:=$HOME/.config/piawg}"
: "${PIAWG_CONF:=$PIAWG_CONF_DIR/config}"
[ -d "$HOME/.config" ] || install -d -m 0755 "$HOME/.config"
[ -d "$PIAWG_CONF_DIR" ] || install -d -m 0700 "$PIAWG_CONF_DIR"
if [ ! -f "$PIAWG_CONF" ]; then
	install -m 0600 /dev/null "$PIAWG_CONF"
	cat <<-'EOF' >"$PIAWG_CONF"
		# piawg configuration
		#BAO_ADDR=
		#BAO_ROLE=
		#BAO_SECRET=
	EOF
	info "Created '$PIAWG_CONF' configuration file"
fi

# Source config
if [ -r "$PIAWG_CONF" ]; then
	# shellcheck source=/dev/null
	. "$PIAWG_CONF"
else
	err "Can't find config at '$PIAWG_CONF'"
fi

# Must set these in PIAWG_CONF
: "${BAO_ADDR:?[ERROR]: BAO_ADDR is not set}"
: "${BAO_ROLE:?[ERROR]: BAO_ROLE is not set}"
: "${BAO_SECRET:?[ERROR]: BAO_SECRET is not set}"

# Overridable defaults
_fingerprint=1fd25658456eab3041fba77ccd398ab8124edcc1b8b2fc1d55fdf6b1bbfc9d70
: "${PIA_API:=https://www.privateinternetaccess.com/api/client/v2/token}"
: "${PIA_CRT:=https://www.privateinternetaccess.com/openvpn/ca.rsa.4096.crt}"
: "${PIA_HASH:=$_fingerprint}"
: "${BAO_AUTH_PATH:=approle}"
: "${BAO_KV_MOUNT:=kv}"
: "${BAO_PATH_CONFIG:=piawg/config/wireguard}"
: "${BAO_PATH_OPNSENSE:=piawg/creds/opnsense}"
: "${BAO_PATH_PIA:=piawg/creds/pia}"
: "${BAO_PATH_TOKEN:=piawg/session/token}"
: "${OPN_IF:=PIAwg}"
: "${OPN_PEER:=PIAwg_srv}"
: "${OPN_ALIAS:=PIAwg_IP}"

# Get ephemeral session token from AppRole login
if ! bao_token_reply=$(_curl -H 'Content-Type: application/json' \
	-d "{\"role_id\":\"$BAO_ROLE\",\"secret_id\":\"$BAO_SECRET\"}" \
	"$BAO_ADDR/v1/auth/$BAO_AUTH_PATH/login"); then
	err "Failed to login to '$BAO_ADDR'"
fi
bao_token=$(printf '%s' "$bao_token_reply" | jq -er '.auth.client_token')
unset bao_token_reply
[ -n "$bao_token" ] || err "Failed to get token from '$BAO_ADDR'"

# Get latest PIA token
get_token_reply="$(
	bao_curl -n "$BAO_KV_MOUNT/data/$BAO_PATH_TOKEN"
)" && rc=0 || rc=$?
if [ "$rc" -eq 4 ]; then
	info "Renewing PIA token"
	renew_token
	get_token_reply="$(bao_curl "$BAO_KV_MOUNT/data/$BAO_PATH_TOKEN")"
fi
pia_token="$(printf '%s' "$get_token_reply" | jq -r .data.data.token)"
unset get_token_reply
check_token "$pia_token" || err "Failed to get valid PIA token"

# Download PIA RSA CA certificate
if [ ! -f ./ca.rsa.4096.crt ]; then
	[ -f ./.ca.rsa.4096.crt ] && rm ./.ca.rsa.4096.crt
	info "Downloading PIA's CA certificate"
	_curl -o ./.ca.rsa.4096.crt "$PIA_CRT"
	pia_file_hash="$(openssl x509 -in ./.ca.rsa.4096.crt -outform DER |
		openssl dgst -sha256 -r | awk '{print $1}')"
	[ "$pia_file_hash" != "$PIA_HASH" ] && err "PIA CA fingerprint mismatch"
	mv ./.ca.rsa.4096.crt ./ca.rsa.4096.crt
fi

# Get OPNsense login details
bao_opn_login="$(bao_curl "$BAO_KV_MOUNT/data/$BAO_PATH_OPNSENSE")"
opn_key="$(printf '%s' "$bao_opn_login" | jq -r .data.data.key)"
opn_secret="$(printf '%s' "$bao_opn_login" | jq -r .data.data.secret)"
opn_endpoint="$(printf '%s' "$bao_opn_login" | jq -r .data.data.endpoint)"
opn_endpoint="${opn_endpoint%/}"

# Get OPNsense Wireguard config
opn_if_reply="$(opn_curl 'wireguard/server/searchServer' -d '{}' |
	jq ".rows[] | select(.name == \"$OPN_IF\")")"
piawg_uuid="$(printf '%s' "$opn_if_reply" | jq -r .uuid)"
piawg_pubkey="$(printf '%s' "$opn_if_reply" | jq -r .pubkey)"
piawg_tunaddr="$(printf '%s' "$opn_if_reply" | jq -r .tunneladdress)"
debug "Wireguard instance $OPN_IF\n$(echo "$opn_if_reply" | jq .)"
unset opn_if_reply

opn_peer_reply="$(opn_curl 'wireguard/client/searchClient' -d '{}' |
	jq ".rows[] | select(.name == \"$OPN_PEER\")")"
piawgsrv_uuid="$(printf '%s' "$opn_peer_reply" | jq -r .uuid)"
piawgsrv_pubkey="$(printf '%s' "$opn_peer_reply" | jq -r .pubkey)"
piawgsrv_srvaddr="$(printf '%s' "$opn_peer_reply" | jq -r .serveraddress)"
piawgsrv_srvport="$(printf '%s' "$opn_peer_reply" | jq -r .serverport)"
unset opn_peer_reply

# Get target server IP, common name, and OPNsense WG pubkey
wg_reply="$(bao_curl "$BAO_KV_MOUNT/data/$BAO_PATH_CONFIG")"
server_ip="$(printf '%s' "$wg_reply" | jq -r .data.data.server_ip)"
server_cn="$(printf '%s' "$wg_reply" | jq -r .data.data.server_cn)"
server_port="$(printf '%s' "$wg_reply" | jq -r .data.data.server_port)"
unset wg_reply

# Update to reflect desired state
if [ "$server_ip" != "$piawgsrv_srvaddr" ]; then
	info "Updating $OPN_IF tunnel with new IP $server_ip"
	pia_addkey
	info "Pausing 2 seconds for new tunnel"
	sleep 2
	if check_tunnel; then
		info "New tunnel on $OPN_IF is working"
	else
		err "New tunnel on $OPN_IF is broken"
	fi
else
	if check_tunnel; then
		info "Tunnel on $OPN_IF is working"
	else
		warn "Tunnel on $OPN_IF is broken"
		pia_addkey
		info "Pausing 2 seconds for new tunnel"
		sleep 2
		if check_tunnel; then
			info "New tunnel on $OPN_IF is working"
		else
			err "New tunnel on $OPN_IF is broken"
		fi
	fi
fi
