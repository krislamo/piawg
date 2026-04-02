#!/usr/bin/env sh
# SPDX-License-Identifier: 0BSD
# SPDX-FileCopyrightText: 2026 Kris Lamoureux <kris@lamoureux.io>

# Allow local variable scoping, therefore not strictly POSIX
# shellcheck disable=SC3043

msg() {
	local format
	format='%s'
	OPTIND=1
	while getopts 'f:' opt; do
		case $opt in f) format="$OPTARG" ;; *) return 1 ;; esac
	done
	shift $((OPTIND - 1))
	printf "[%s]: ${format}\n" "${2-INFO}" "$1"
}

info() { [ "$PIAWG_VERBOSE" -eq 1 ] && msg "$1"; }
debug() { [ "$PIAWG_DEBUG" -eq 1 ] && msg "$@" 'DEBUG'; }
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
	OPTIND=1
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
	path="$opn_endpoint/$1"
	shift
	error="Failed request to '$path'"
	if ! response="$(_curl -H 'Content-Type: application/json' \
		-u "$opn_key:$opn_secret" -w '\n%{http_code}' \
		"$@" "$path")"; then
		err "$error"
	fi
	http_code="$(printf '%s' "$response" | tail -1)"
	response="$(printf '%s' "$response" | sed '$d')"
	if ! check_http "$http_code"; then
		error_msg="$(printf '%s' "$response" |
			jq -r '.errorMessage // empty' 2>/dev/null)"
		[ -n "$error_msg" ] && error="$error_msg ($path)"
	fi
	check_http "$http_code" || err "$error"
	printf '%s' "$response"
}

pia_addkey() {
	local response
	local response_gw
	local key
	local port
	local peer_ip
	local updates
	local server_vip
	local gateway_ip
	local gateway_id
	# Add pubkey via PIA API and get connection details
	info "Adding '$piawg_pubkey' to PIA server $server_cn"
	if ! response=$(
		_curl -G --resolve "$server_cn:$server_port:$server_ip" \
			--cacert ./ca.rsa.4096.crt \
			--data-urlencode "pt=$pia_token" \
			--data-urlencode "pubkey=$piawg_pubkey" \
			"https://$server_cn:$server_port/addKey"
	); then
		err "Failed connect to $server_cn to addKey"
	fi
	[ "$(printf '%s' "$response" | jq -r '.status')" != "OK" ] &&
		err "Failed to addKey to $server_cn"
	debug -f 'PIA API addKey response\n%s' "$(echo "$response" | jq .)"

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
		debug -f "$OPN_PEER updates\n%s" "$(echo "$updates" | jq .)"
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

	# Update OpenBao config with response data
	server_vip="$(printf '%s' "$response" | jq -r '.server_vip')"
	info "Update server_vip at $BAO_PATH_CONFIG to $server_vip"
	bao_curl -p "$BAO_KV_MOUNT/data/$BAO_PATH_CONFIG" -X PATCH -d \
		"$(jq -n --arg ip "$server_vip" '{data:{server_vip:$ip}}')" >/dev/null

	# Update gateway address
	if ! response_gw="$(opn_curl \
		'routing/settings/search_gateway' -X POST -d '{}')"; then
		err "Failed to search gateways"
	fi
	debug -f "search_gateway\n%s" "$(printf '%s' "$response_gw" | jq .)"
	gateway_id="$(printf '%s' "$response_gw" | jq -r --arg name "$OPN_GW" \
		'.rows[] | select(.name == $name) | .uuid')"
	gateway_ip="$(printf '%s' "$response_gw" | jq -r --arg name "$OPN_GW" \
		'.rows[] | select(.name == $name) | .gateway')"
	if [ "$gateway_ip" != "$server_vip" ]; then
		info "Updating gateway $OPN_GW address from $gateway_ip to $server_vip"
		if ! update_gw="$(opn_curl \
			"routing/settings/set_gateway/$gateway_id" -X POST \
			-d "$(jq -nc --arg ip "$server_vip" \
				'{gateway_item: {gateway: $ip}}')")"; then
			err "Failed to update gateway ($gateway_id)"
		fi
		if [ "$(printf '%s' "$update_gw" | jq -r '.result')" != "saved" ]; then
			err "Failed to save gateway update"
		fi
		info "Restarting WireGuard interface after gateway update"
		if [ "$(opn_curl "core/service/restart/wireguard/$piawg_uuid" \
			-X POST -d '{}' | jq -r '.result')" != "ok" ]; then
			err "Failed to restart WireGuard interface after gateway update"
		fi
	fi

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

pia_forward() {
	local config
	local server_cn
	local server_vip
	local pf_signature
	local pf_payload
	local pf_port
	local pf_expires
	local pf_sig_reply
	local pf_updated_at
	local pf_update
	local epoch_now
	local epoch_expire
	local epoch_diff
	local bind_resp
	config="$1"
	server_cn="$(printf '%s' "$config" | jq -r '.data.data.server_cn')"
	server_vip="$(printf '%s' "$config" | jq -r '.data.data.server_vip')"
	pf_signature="$(printf '%s' "$config" | jq -r '.data.data.pf_signature')"
	pf_payload="$(printf '%s' "$config" | jq -r '.data.data.pf_payload')"
	pf_port="$(printf '%s' "$config" | jq -r '.data.data.pf_port')"
	pf_expires="$(printf '%s' "$config" | jq -r '.data.data.pf_expires')"
	pf_updated_at="$(printf '%s' "$config" | jq -r '.data.data.pf_updated_at')"
	epoch_now="$(date '+%s')"
	epoch_expire="$(date -j -f '%Y-%m-%dT%H:%M:%S' \
		"${pf_expires%%.*}" '+%s' 2>/dev/null)"
	epoch_diff=$((epoch_now - ${pf_updated_at:-0}))
	if [ -z "$epoch_expire" ] || [ "$epoch_expire" -lt "$epoch_now" ]; then
		info "Requesting new port forward signature"
		if ! pf_sig_reply="$(_curl -G --cacert ./ca.rsa.4096.crt \
			--resolve "$server_cn:19999:$server_vip" \
			--data-urlencode "token=$pia_token" \
			"https://$server_cn:19999/getSignature")"; then
			err "Failed to connect to https://$server_cn:19999/getSignature"
		fi
		debug -f "getSignature\n%s" "$(printf '%s' "$pf_sig_reply" | jq .)"
		[ "$(printf '%s' "$pf_sig_reply" | jq -r '.status')" != "OK" ] &&
			err "getSignature failed"
		pf_signature="$(printf '%s' "$pf_sig_reply" | jq -r '.signature')"
		pf_payload="$(printf '%s' "$pf_sig_reply" | jq -r '.payload')"
		pf_port="$(printf '%s' "$pf_payload" |
			base64 -d 2>/dev/null | jq -r '.port // empty')"
		pf_expires="$(printf '%s' "$pf_payload" |
			base64 -d 2>/dev/null | jq -r '.expires_at // empty')"
		pf_update="$(jq -n --arg v "$pf_signature" '.data.pf_signature = $v')"
		pf_update="$(printf '%s' "$pf_update" |
			jq --arg v "$pf_payload" '.data.pf_payload = $v')"
		pf_update="$(printf '%s' "$pf_update" |
			jq --arg v "$pf_port" '.data.pf_port = $v')"
		pf_update="$(printf '%s' "$pf_update" |
			jq --arg v "$pf_expires" '.data.pf_expires = $v')"
		pf_update="$(printf '%s' "$pf_update" |
			jq --arg v "$(date '+%s')" '.data.pf_updated_at = $v')"
		debug -f "pf_update\n%s" "$(printf '%s' "$pf_update" | jq .)"
		info "Updating $BAO_PATH_CONFIG with pf_port=$pf_port"
		bao_curl -p "$BAO_KV_MOUNT/data/$BAO_PATH_CONFIG" \
			-X PATCH -d "$pf_update" >/dev/null
	elif [ "$epoch_diff" -ge 300 ]; then
		info "Renewing port forward ($epoch_diff/300)"
		if ! bind_resp="$(_curl -G --resolve "${server_cn}:19999:${server_vip}" \
			--data-urlencode "payload=${pf_payload}" \
			--data-urlencode "signature=${pf_signature}" \
			"https://${server_cn}:19999/bindPort")"; then
			err "Failed to bindPort (https://${server_cn}:19999/bindPort)"
		fi
		[ "$(printf '%s' "$bind_resp" | jq -r '.status')" != "OK" ] &&
			err "Failed to get bindPort status"
		debug -f "bind_resp\n%s" "$(printf '%s' "$bind_resp" | jq .)"
		pf_update="$(jq -n --arg v "$(date '+%s')" '.data.pf_updated_at = $v')"
		debug -f "pf_update\n%s" "$(printf '%s' "$pf_update" | jq .)"
		info "Updating pf_updated_at $BAO_PATH_CONFIG"
		bao_curl -p "$BAO_KV_MOUNT/data/$BAO_PATH_CONFIG" \
			-X PATCH -d "$pf_update" >/dev/null
	else
		info "Port forward still valid, updated ${epoch_diff}s ago"
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
OPTIND=1
while getopts "dv" opt; do
	case $opt in
	d)
		PIAWG_VERBOSE=1
		PIAWG_DEBUG=1
		;;
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
: "${OPN_GW:=PIAWG_VPN}"

# Get ephemeral session token from AppRole login
if ! bao_token_reply=$(_curl -H 'Content-Type: application/json' \
	-d "{\"role_id\":\"$BAO_ROLE\",\"secret_id\":\"$BAO_SECRET\"}" \
	"$BAO_ADDR/v1/auth/$BAO_AUTH_PATH/login"); then
	err "Failed to login to '$BAO_ADDR'"
fi
bao_token=$(printf '%s' "$bao_token_reply" | jq -er '.auth.client_token') ||
	err "Failed to get AppRole login token from '$BAO_ADDR'"
unset bao_token_reply

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
debug -f "OPNsense login details from OpenBao ($BAO_PATH_OPNSENSE)\n%s" \
	"$(printf '%s' "$bao_opn_login" |
		jq '.data.data.secret = "[CENSORED]" | .data.data.key = "[CENSORED]"')"
opn_endpoint="${opn_endpoint%/}"

# Get OPNsense Wireguard config
opn_if_reply="$(opn_curl 'wireguard/server/searchServer' -d '{}' |
	jq ".rows[] | select(.name == \"$OPN_IF\")")"
piawg_uuid="$(printf '%s' "$opn_if_reply" | jq -r .uuid)"
piawg_pubkey="$(printf '%s' "$opn_if_reply" | jq -r .pubkey)"
piawg_tunaddr="$(printf '%s' "$opn_if_reply" | jq -r .tunneladdress)"
debug -f "Wireguard instance $OPN_IF from OPNsense API\n%s" \
	"$(printf '%s' "$opn_if_reply" | jq '.privkey = "[CENSORED]"')"
unset opn_if_reply

opn_peer_reply="$(opn_curl 'wireguard/client/searchClient' -d '{}' |
	jq ".rows[] | select(.name == \"$OPN_PEER\")")"
piawgsrv_uuid="$(printf '%s' "$opn_peer_reply" | jq -r .uuid)"
piawgsrv_pubkey="$(printf '%s' "$opn_peer_reply" | jq -r .pubkey)"
piawgsrv_srvaddr="$(printf '%s' "$opn_peer_reply" | jq -r .serveraddress)"
piawgsrv_srvport="$(printf '%s' "$opn_peer_reply" | jq -r .serverport)"
debug -f "Wireguard peer $OPN_PEER from OPNsense API\n%s" \
	"$(printf '%s' "$opn_peer_reply" | jq .)"
unset opn_peer_reply

# Get target server IP, common name, and OPNsense WG pubkey
wg_reply="$(bao_curl "$BAO_KV_MOUNT/data/$BAO_PATH_CONFIG")"
server_ip="$(printf '%s' "$wg_reply" | jq -r .data.data.server_ip)"
server_cn="$(printf '%s' "$wg_reply" | jq -r .data.data.server_cn)"
server_port="$(printf '%s' "$wg_reply" | jq -r .data.data.server_port)"
server_vip="$(printf '%s' "$wg_reply" | jq -r .data.data.server_vip)"
debug -f "Config from OpenBao ($BAO_PATH_CONFIG)\n%s" \
	"$(printf '%s' "$wg_reply" | jq .)"
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

# Optional: port forward
if conf_reply="$(bao_curl "$BAO_KV_MOUNT/data/$BAO_PATH_CONFIG")"; then
	debug -f "Check for port_forward value in OpenBao ($BAO_PATH_CONFIG)\n%s" \
		"$(printf '%s' "$conf_reply" | jq .)"
	port_forward="$(printf '%s' "$conf_reply" |
		jq -r '.data.data.port_forward')"
	[ "$port_forward" = "true" ] && pia_forward "$conf_reply"
fi
