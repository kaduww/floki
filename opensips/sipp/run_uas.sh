#!/bin/bash
# =============================================================================
# Floki RTP Relay — SIPp UAS (servidor)
# =============================================================================
#
# Aguarda INVITEs, responde 100 → 183 → 200 OK com SDP.
# Deve ser iniciado antes do UAC.
#
# Variáveis de ambiente:
#   UAS_IP        IP de escuta do UAS         (default: 0.0.0.0)
#   UAS_PORT      Porta de escuta do UAS      (default: 5061)
#   MAX_CALLS     Chamadas simultâneas        (default: 100)
#   TRANSPORT     Transporte SIP              (default: u1 = UDP)
#
# Exemplos:
#   ./run_uas.sh
#   UAS_PORT=5080 MAX_CALLS=500 ./run_uas.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UAS_IP="${UAS_IP:-0.0.0.0}"
UAS_PORT="${UAS_PORT:-5061}"
MAX_CALLS="${MAX_CALLS:-100}"
TRANSPORT="${TRANSPORT:-u1}"

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[UAS]${NC} $*"; }
err() { echo -e "${RED}[UAS]${NC} $*" >&2; }

if ! command -v sipp &>/dev/null; then
  err "sipp não encontrado. Instale com: apt install sipp"
  exit 1
fi

log "Listen    : ${UAS_IP}:${UAS_PORT}"
log "Max calls : ${MAX_CALLS}"
log "Transport : ${TRANSPORT}"

exec sipp \
  -sf "${SCRIPT_DIR}/uas.xml" \
  -i "${UAS_IP}" \
  -p "${UAS_PORT}" \
  -l "${MAX_CALLS}" \
  -t "${TRANSPORT}" \
  -trace_err \
  -error_file "${SCRIPT_DIR}/uas_errors.log" \
  -message_file "${SCRIPT_DIR}/uas_messages.log" \
  -screen_file "${SCRIPT_DIR}/uas_screen.log" \
  -inf /dev/null
