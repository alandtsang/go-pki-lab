#!/usr/bin/env sh

# acme.sh DNS API hook for go-pki-lab.
#
# Install this file into acme.sh's dnsapi directory as dns_go_pki_lab.sh.
# Optional environment variable:
#   GO_PKI_LAB_API=http://127.0.0.1:8080

GO_PKI_LAB_API="${GO_PKI_LAB_API:-http://127.0.0.1:8080}"

# Usage: dns_go_pki_lab_add _acme-challenge.example.test "txt-value"
dns_go_pki_lab_add() {
  fulldomain="$1"
  txtvalue="$2"

  _info "go-pki-lab: adding TXT record for $fulldomain"
  _debug fulldomain "$fulldomain"
  _debug txtvalue "$txtvalue"

  data="{\"name\":\"$fulldomain\",\"values\":[\"$txtvalue\"]}"
  response="$(_post "$data" "$GO_PKI_LAB_API/dns/txt" "" "POST" "application/json")"
  if [ "$?" != "0" ]; then
    _err "go-pki-lab: failed to add TXT record"
    return 1
  fi

  if _contains "$response" "$txtvalue"; then
    _info "go-pki-lab: TXT record added"
    return 0
  fi

  _err "go-pki-lab: unexpected add response: $response"
  return 1
}

# Usage: dns_go_pki_lab_rm _acme-challenge.example.test "txt-value"
dns_go_pki_lab_rm() {
  fulldomain="$1"
  txtvalue="$2"

  _info "go-pki-lab: removing TXT record for $fulldomain"
  _debug fulldomain "$fulldomain"
  _debug txtvalue "$txtvalue"

  data="{\"name\":\"$fulldomain\"}"
  response="$(_post "$data" "$GO_PKI_LAB_API/dns/txt" "" "DELETE" "application/json")"
  if [ "$?" != "0" ]; then
    _err "go-pki-lab: failed to remove TXT record"
    return 1
  fi

  _info "go-pki-lab: TXT record removed"
  return 0
}
