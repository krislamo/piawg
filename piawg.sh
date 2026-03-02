#!/usr/bin/env sh
# SPDX-License-Identifier: 0BSD
# SPDX-FileCopyrightText: 2026 Kris Lamoureux <kris@lamoureux.io>

err() {
	printf '[ERROR]: %s\n' "$1" >&2
	exit 1
}

check_http() {
	case $1 in
	2[0-9][0-9]) return 0 ;;
	*) return 1 ;;
	esac
}

bao_curl() {
	curl -sS --connect-timeout 5 --max-time 20 --retry 5 --retry-delay 2 \
		-H 'Content-Type: application/json' \
		-H "X-Vault-Token: $bao_token" \
		-w '\n%{http_code}' \
		"$@"
}

# Fetch latest token in OpenBao
get_token() {
	if ! pia_token_reply=$(bao_curl \
		"$BAO_ADDR/v1/$BAO_KV_MOUNT/data/$BAO_PATH_TOKEN"); then
		err "Failed to fetch PIA token from '$BAO_ADDR'"
	fi
	printf '%s' "$pia_token_reply"
	unset pia_token_reply
}

# Get a new PIA token and store
renew_token() {
	login_response="$(bao_curl "$BAO_ADDR/v1/$BAO_KV_MOUNT/data/$BAO_PATH_LOGIN")"

	http_code="$(printf '%s' "$login_response" | tail -1)"
	if ! check_http "$http_code"; then
		err "Failed to get PIA login details (HTTP $http_code)"
	fi
	unset http_code

	login_response="$(printf '%s' "$login_response" | sed '$d')"
	pia_user="$(printf '%s' "$login_response" | jq -r '.data.data.username')"
	pia_pass="$(printf '%s' "$login_response" | jq -r '.data.data.password')"
	unset login_response
	if ! token_reply="$(curl -s -X POST "$PIA_API" \
		-F "username=$pia_user" \
		-F "password=$pia_pass")"; then
		err "Failed to get a new PIA token"
	fi
	unset pia_pass
	unset pia_user
	pia_token="$(echo "$token_reply" | jq -r .token)"
	unset token_reply
	if ! printf '%s' "$pia_token" | grep -Eq '^[0-9A-Fa-f]{128}$'; then
		err "Invalid token found during renewal attempt"
	fi
	if ! update_response="$(bao_curl -X POST -d "$(jq -n --arg t "$pia_token" '{data:{token:$t}}')" \
		"$BAO_ADDR/v1/$BAO_KV_MOUNT/data/$BAO_PATH_TOKEN")"; then
		err "Failed to save PIA token to '$BAO_ADDR'"
	fi
	unset pia_token
	http_code="$(printf '%s' "$update_response" | tail -1)"
	update_response="$(printf '%s' "$update_response" | sed '$d')"
	check_http "$http_code" ||
		err "Failed to write PIA token to OpenBao (HTTP $http_code)"
}

# Check for required external commands
for rbin in curl jq; do
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
fi

# Source config
if [ -r "$PIAWG_CONF" ]; then
	# shellcheck source=/dev/null
	. "$PIAWG_CONF"
else
	err "Can't find config at '$PIAWG_CONF'"
fi

# Overridable defaults
: "${PIA_API:=https://www.privateinternetaccess.com/api/client/v2/token}"
: "${BAO_AUTH_PATH:=approle}"
: "${BAO_KV_MOUNT:=kv}"
: "${BAO_PATH_LOGIN:=piawg/creds/login}"
: "${BAO_PATH_TOKEN:=piawg/session/token}"

# Must set these in PIAWG_CONF
: "${BAO_ADDR:?\[ERROR\]: BAO_ADDR is not set}"
: "${BAO_ROLE:?\[ERROR\]: BAO_ROLE is not set}"
: "${BAO_SECRET:?\[ERROR\]: BAO_SECRET is not set}"

# Get ephemeral session token from AppRole login
if ! bao_token_reply=$(curl -sS \
	--connect-timeout 5 \
	--max-time 20 \
	--retry 5 \
	--retry-delay 2 \
	-H 'Content-Type: application/json' \
	-d "{\"role_id\":\"$BAO_ROLE\",\"secret_id\":\"$BAO_SECRET\"}" \
	"$BAO_ADDR/v1/auth/$BAO_AUTH_PATH/login"); then
	err "Failed to login to '$BAO_ADDR'"
fi
bao_token=$(printf '%s' "$bao_token_reply" | jq -er '.auth.client_token')
unset bao_token_reply
[ -n "$bao_token" ] || err "Failed to get token from '$BAO_ADDR'"

# Get latest PIA token
get_token_reply="$(get_token)"
http_code="$(printf '%s' "$get_token_reply" | tail -1)"
get_token_reply="$(printf '%s' "$get_token_reply" | sed '$d')"

# Renew token if path doesn't exist yet
if [ "$http_code" -eq 404 ]; then
	renew_token
	get_token_reply="$(get_token)"
	http_code="$(printf '%s' "$get_token_reply" | tail -1)"
	get_token_reply="$(printf '%s' "$get_token_reply" | sed '$d')"
	if ! check_http "$http_code"; then
		err "Failed to get PIA token after renewal"
	fi
elif ! check_http "$http_code"; then
	err "Failed to get PIA token from '$BAO_ADDR' (HTTP $http_code)"
fi

printf '%s\n' "$get_token_reply"
exit 0
