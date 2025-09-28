#!/usr/bin/env bash
set -euo pipefail

# Simple diagnostic for Elasticsearch + Kibana reachability issues.
# Run from repo root: bash scripts/diagnose_stack.sh

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; NC="\e[0m"

section() { echo -e "\n==== $1 ====\n"; }
quick_http() {
  local name=$1 url=$2
  local code
  code=$(curl -m 4 -s -o /dev/null -w '%{http_code}' "$url" || true)
  if [[ $code == 200 || $code == 302 || $code == 401 ]]; then
    echo -e "$name: ${GREEN}$code${NC} $url"
  elif [[ -z $code || $code == 000 ]]; then
    echo -e "$name: ${RED}NO RESPONSE${NC} $url"
  else
    echo -e "$name: ${YELLOW}$code${NC} $url"
  fi
}

section "Environment"
uname -a || true
printf 'Date: '; date
printf 'User: %s\n' "${USER:-unknown}" || true

section "Host /etc/hosts localhost lines"
grep -i localhost /etc/hosts || true

section "Proxy variables"
(env | grep -i _proxy) || echo "(none)"

section "Docker ps (filtered)"
(docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E 'es|kibana') || echo "Containers not running"

section "Docker inspect port bindings"
for svc in es kibana; do
  if docker inspect "$svc" >/dev/null 2>&1; then
    echo "-- $svc --"
    docker inspect -f 'Name={{.Name}} HostPorts={{range $p, $conf := .NetworkSettings.Ports}}{{$p}} -> {{range $conf}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}' "$svc"
  else
    echo "$svc: not found"
  fi
done

section "Host socket listeners (9200/5601)"
(ss -ltnp 2>/dev/null | grep -E ':9200|:5601' ) || echo "No listeners detected (unexpected)"

section "Quick HTTP status codes (host)"
quick_http ES-root      http://localhost:9200/
quick_http ES-health    http://localhost:9200/_cluster/health
quick_http Kibana-root  http://localhost:5601/
quick_http Kibana-api   http://localhost:5601/api/status

section "Curl verbose samples"
set +e
curl -m 5 -v http://localhost:9200/ -o /dev/null 2>&1 | sed -n '1,25p'
echo
curl -m 8 -v http://localhost:5601/api/status -o /dev/null 2>&1 | sed -n '1,40p'
set -e

section "In-container checks"
if docker exec es true 2>/dev/null; then
  docker exec es curl -s -o /dev/null -w 'ES inside HTTP %{http_code}\n' http://localhost:9200/
  docker exec es curl -s http://localhost:9200/_cluster/health?pretty | head -20
else
  echo "es container not accessible"
fi
if docker exec kibana true 2>/dev/null; then
  docker exec kibana curl -s -o /dev/null -w 'Kibana inside HTTP %{http_code}\n' http://localhost:5601/api/status
  docker exec kibana curl -s http://localhost:5601/api/status | head -40
else
  echo "kibana container not accessible"
fi

section "Recent container logs (tail 40)"
for svc in es kibana; do
  echo "--- $svc logs ---"
  docker logs --tail=40 "$svc" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  echo
  done

section "Iptables rules referencing 9200/5601 (if any)"
(sudo iptables -S 2>/dev/null | grep -E '5601|9200') || echo "No explicit iptables rules for these ports"

section "Done"
echo "If ES/Kibana unreachable from browser but host curl OK: suspect browser cache, proxy, or cross-WSL boundary." 
