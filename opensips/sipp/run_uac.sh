#!/bin/bash
# =============================================================================
# Floki RTP Relay — SIPp UAC (cliente)
# =============================================================================
#
# Envia INVITEs com SDP para o OpenSIPS, que repassa ao UAS via Floki.
#
# Variáveis de ambiente:
#   OPENSIPS_IP   IP do OpenSIPS              (default: 127.0.0.1)
#   OPENSIPS_PORT Porta SIP do OpenSIPS       (default: 5060)
#   LOCAL_IP      IP local do SIPp            (default: auto-detectado)
#   CPS           Chamadas por segundo        (default: 10)
#   MAX_CALLS     Chamadas simultâneas        (default: 100)
#   CALL_DURATION Duração de cada chamada ms  (default: 5000)
#   TOTAL_CALLS   Total de chamadas a gerar   (default: 1000)
#   TRANSPORT     Transporte SIP              (default: u1 = UDP)
#
# Exemplos:
#   ./run_uac.sh
#   CPS=50 MAX_CALLS=500 CALL_DURATION=10000 ./run_uac.sh
#   OPENSIPS_IP=192.168.0.10 TOTAL_CALLS=5000 ./run_uac.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPENSIPS_IP="${OPENSIPS_IP:-127.0.0.1}"
OPENSIPS_PORT="${OPENSIPS_PORT:-5060}"
LOCAL_IP="${LOCAL_IP:-$(hostname -I | awk '{print $1}')}"
CPS="${CPS:-10}"
MAX_CALLS="${MAX_CALLS:-100}"
CALL_DURATION="${CALL_DURATION:-5000}"
TOTAL_CALLS="${TOTAL_CALLS:-1000}"
TRANSPORT="${TRANSPORT:-u1}"

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[UAC]${NC} $*"; }
err() { echo -e "${RED}[UAC]${NC} $*" >&2; }

if ! command -v sipp &>/dev/null; then
  err "sipp não encontrado. Instale com: apt install sipp"
  exit 1
fi

log "OpenSIPS  : ${OPENSIPS_IP}:${OPENSIPS_PORT}"
log "Local IP  : ${LOCAL_IP}"
log "CPS       : ${CPS}"
log "Max calls : ${MAX_CALLS}"
log "Duration  : ${CALL_DURATION}ms"
log "Total     : ${TOTAL_CALLS}"
log "Transport : ${TRANSPORT}"

exec sipp \
  "${OPENSIPS_IP}:${OPENSIPS_PORT}" \
  -sf "${SCRIPT_DIR}/uac.xml" \
  -i "${LOCAL_IP}" \
  -s "1000" \
  -r "${CPS}" \
  -rp 1000 \
  -l "${MAX_CALLS}" \
  -m "${TOTAL_CALLS}" \
  -d "${CALL_DURATION}" \
  -t "${TRANSPORT}" \
  -trace_err \
  -error_file "${SCRIPT_DIR}/uac_errors.log" \
  -message_file "${SCRIPT_DIR}/uac_messages.log" \
  -screen_file "${SCRIPT_DIR}/uac_screen.log"
