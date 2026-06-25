#!/bin/bash
# ============================================
#  Coraza WAF Log Monitor v6
#  Usage: bash coraza-monitor.sh
# ============================================

CONTAINER="coraza-waf"
CUSTOM_CONF="/opt/coraza/custom-rules/custom.conf"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

check_deps() {
  MISSING=()
  for cmd in docker jq goaccess; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
  done
  if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "${RED}Dependency belum terinstall: ${MISSING[*]}${NC}"
    for dep in "${MISSING[@]}"; do
      [ "$dep" = "jq" ]       && echo "  apt install jq -y"
      [ "$dep" = "goaccess" ] && echo "  apt install goaccess -y"
    done
    exit 1
  fi
}

check_container() {
  if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo -e "${RED}Container '${CONTAINER}' tidak running.${NC}"
    exit 1
  fi
}

get_json_logs()   { docker logs "$CONTAINER" 2>/dev/null | grep '^{"transaction"'; }
get_attack_logs() { get_json_logs | grep -F '"messages":[{'; }

print_header() {
  clear
  # Mengambil versi OWASP CRS dari log JSON menggunakan grep dan sed
  CRS_VER=$(docker logs "$CONTAINER" 2>/dev/null | grep -o '"rulesets":\["OWASP_CRS/[0-9.]*"' | tail -1 | grep -o '[0-9.]*' | head -1)
  
  # Fallback: jika kosong, set ke "unknown"
  [ -z "$CRS_VER" ] && CRS_VER="unknown"
  
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════╗"
  printf "║         Coraza WAF Log Monitor               ║\n"
  printf "║         OWASP CRS %-27s║\n" "$CRS_VER"
  echo "╚══════════════════════════════════════════════╝"
  echo -e "${NC}"
}

# ============================================
# STATISTIK
# ============================================
quick_stats() {
  echo -e "${BOLD}Mengambil statistik...${NC}"
  echo ""

  TMP_ALL=$(mktemp /tmp/coraza-all-XXXX.log)
  TMP_ATK=$(mktemp /tmp/coraza-atk-XXXX.log)
  get_json_logs   > "$TMP_ALL"
  get_attack_logs > "$TMP_ATK"

  TOTAL_REQ=$(wc -l < "$TMP_ALL" | tr -d ' ')
  TOTAL_ATTACK=$(wc -l < "$TMP_ATK" | tr -d ' ')
  BLOCKED=$(grep -c '"is_interrupted":true' "$TMP_ATK" 2>/dev/null || true)
  [ -z "$BLOCKED" ] && BLOCKED=0

  SQLI=$(grep -c '"attack-sqli"'    "$TMP_ATK" 2>/dev/null || true); [ -z "$SQLI" ]  && SQLI=0
  XSS=$(grep -c '"attack-xss"'      "$TMP_ATK" 2>/dev/null || true); [ -z "$XSS" ]   && XSS=0
  RCE=$(grep -c '"attack-rce"'      "$TMP_ATK" 2>/dev/null || true); [ -z "$RCE" ]   && RCE=0
  LFI=$(grep -c '"attack-lfi\|attack-rfi"' "$TMP_ATK" 2>/dev/null || true); [ -z "$LFI" ] && LFI=0
  SCAN=$(grep -c '"detection-multiuse\|attack-reputation"' "$TMP_ATK" 2>/dev/null || true); [ -z "$SCAN" ] && SCAN=0

  # Hitung IP yang diblokir dari custom.conf
  BLOCKED_IPS=$(grep -c '^\# \[BL-' "$CUSTOM_CONF" 2>/dev/null || true)
  [ -z "$BLOCKED_IPS" ] && BLOCKED_IPS=0

  ENGINE=$(grep -o '"rule_engine":"[^"]*"' "$TMP_ALL" | tail -1 | cut -d'"' -f4)
  [ -z "$ENGINE" ] && ENGINE="Unknown"

  rm -f "$TMP_ALL" "$TMP_ATK"

  if [ "$ENGINE" = "On" ]; then
    ENGINE_DISP="${GREEN}${ENGINE} — Blocking aktif${NC}"
  else
    ENGINE_DISP="${YELLOW}${ENGINE} — Hanya deteksi${NC}"
  fi

  printf "  ${BOLD}Rule Engine        :${NC} "
  echo -e "$ENGINE_DISP"
  printf "  ${BOLD}IP Diblokir Manual : ${RED}%s IP${NC}\n" "$BLOCKED_IPS"
  echo ""
  printf "  ${BOLD}Total Request      : ${CYAN}%s${NC}\n" "$TOTAL_REQ"
  printf "  ${BOLD}Ancaman Terdeteksi : ${YELLOW}%s${NC}\n" "$TOTAL_ATTACK"
  printf "  ${BOLD}Request Diblokir   : ${RED}%s${NC}\n" "$BLOCKED"
  echo ""
  echo -e "  ${BOLD}─── Jenis Serangan ──────────────────${NC}"
  printf "  SQL Injection (SQLi)   : ${RED}%s${NC}\n"    "$SQLI"
  printf "  Cross-Site Script (XSS): ${RED}%s${NC}\n"    "$XSS"
  printf "  Remote Code Exec (RCE) : ${RED}%s${NC}\n"    "$RCE"
  printf "  LFI / RFI              : ${RED}%s${NC}\n"    "$LFI"
  printf "  Scanner / Bot          : ${YELLOW}%s${NC}\n" "$SCAN"
  echo ""
}

# ============================================
# LIVE ATTACK FEED
# ============================================
live_attacks() {
  echo -e "${BOLD}${RED}[LIVE] Monitor serangan — Ctrl+C untuk berhenti${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""

  docker logs "$CONTAINER" -f 2>/dev/null | while IFS= read -r line; do
    [[ "$line" != '{"transaction"'* ]] && continue
    echo "$line" | grep -qF '"messages":[{' || continue

    TS=$(echo "$line"   | jq -r '.transaction.timestamp // "-"' 2>/dev/null)
    IP=$(echo "$line"   | jq -r '.transaction.client_ip // "-"' 2>/dev/null)
    URI=$(echo "$line"  | jq -r '.transaction.request.uri // "-"' 2>/dev/null)
    HOST=$(echo "$line" | jq -r '(.transaction.request.headers.host // ["-"])[0]' 2>/dev/null)
    INTR=$(echo "$line" | jq -r '.transaction.is_interrupted // false' 2>/dev/null)
    ERRMSG=$(echo "$line" | jq -r '.messages[0].error_message // "-"' 2>/dev/null)
    MSG=$(echo "$ERRMSG" | grep -oP '(?<=\[msg ")[^"]+' | head -1)
    SEV=$(echo "$ERRMSG" | grep -oP '(?<=\[severity ")[^"]+' | head -1 | tr '[:upper:]' '[:lower:]')

    case "$SEV" in
      critical) COLOR="$RED" ;;
      warning)  COLOR="$YELLOW" ;;
      *)        COLOR="$NC" ;;
    esac

    [ "$INTR" = "true" ] \
      && STATUS="${RED}[BLOCKED]  ${NC}" \
      || STATUS="${YELLOW}[DETECTED] ${NC}"

    echo -e "${CYAN}[$TS]${NC} $(echo -e "$STATUS")"
    printf "  IP      : \033[1m%s\033[0m\n" "$IP"
    printf "  Host    : %s\n" "$HOST"
    printf "  URI     : %s\n" "$URI"
    echo -e "  Serangan: $(echo -e "${COLOR}")${MSG}${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────${NC}"
  done
}

# ============================================
# TOP ATTACKERS
# ============================================
top_attackers() {
  TMP=$(mktemp /tmp/coraza-top-XXXX.log)
  get_attack_logs > "$TMP"

  echo -e "${BOLD}Top 10 IP Penyerang:${NC}"
  echo ""
  if [ -s "$TMP" ]; then
    jq -r '.transaction.client_ip' "$TMP" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -10 \
      | while read -r count ip; do
          # Tandai IP yang sudah diblokir
          if grep -q "\[BL-" "$CUSTOM_CONF" 2>/dev/null && grep -q "$ip" "$CUSTOM_CONF" 2>/dev/null; then
            printf "  ${RED}%4d serangan  →  %s ${GREEN}[BLOCKED]${NC}\n" "$count" "$ip"
          else
            printf "  ${RED}%4d serangan  →  %s${NC}\n" "$count" "$ip"
          fi
        done
  else
    echo -e "  ${YELLOW}Belum ada data.${NC}"
  fi

  echo ""
  echo -e "${BOLD}Top 10 URI yang Diserang:${NC}"
  echo ""
  if [ -s "$TMP" ]; then
    jq -r '.transaction.request.uri' "$TMP" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -10 \
      | while read -r count uri; do
          printf "  ${YELLOW}%4d kali  →  %s${NC}\n" "$count" "$uri"
        done
  else
    echo -e "  ${YELLOW}Belum ada data.${NC}"
  fi

  echo ""
  echo -e "${BOLD}Top 10 Domain Diserang:${NC}"
  echo ""
  if [ -s "$TMP" ]; then
    jq -r '(.transaction.request.headers.host // ["-"])[0]' "$TMP" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -10 \
      | while read -r count host; do
          printf "  ${CYAN}%4d kali  →  %s${NC}\n" "$count" "$host"
        done
  else
    echo -e "  ${CYAN}Belum ada data.${NC}"
  fi

  rm -f "$TMP"
  echo ""
}

# ============================================
# GOACCESS
# ============================================
run_goaccess() {
  TMP_LOG=$(mktemp /tmp/coraza-access-XXXX.log)
  docker logs "$CONTAINER" 2>/dev/null \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ - -' \
    > "$TMP_LOG"

  LINE_COUNT=$(wc -l < "$TMP_LOG" | tr -d ' ')
  if [ "$LINE_COUNT" -eq 0 ]; then
    echo -e "${RED}Tidak ada access log.${NC}"
    rm -f "$TMP_LOG"
    read -rp "Tekan ENTER..."
    return
  fi

  printf "  Lines : ${CYAN}%s requests${NC}\n" "$LINE_COUNT"
  echo ""
  echo "  ↑↓ Scroll | 1-9 Panel | o Sort | q Keluar"
  echo ""
  read -rp "Tekan ENTER untuk mulai..."

  goaccess "$TMP_LOG" \
    --log-format='%h - - [%d:%t %^] "%r" %s %b "-" "%u"' \
    --date-format='%d/%b/%Y' \
    --time-format='%H:%M:%S'

  rm -f "$TMP_LOG"
}

# ============================================
# EXPORT
# ============================================
export_attacks() {
  OUTFILE="/opt/monitor/coraza-attacks-$(date +%Y%m%d-%H%M%S).log"
  get_attack_logs \
    | jq -r '[
        .transaction.timestamp,
        (.messages[0].error_message | capture("\\[severity \"(?P<s>[^\"]+)\"\\]").s // "unknown"),
        .transaction.client_ip,
        ((.transaction.request.headers.host // ["-"])[0]),
        .transaction.request.uri,
        (.messages[0].error_message | capture("\\[msg \"(?P<m>[^\"]+)\"\\]").m // "-")
      ] | "["+.[0]+"] ["+.[1]+"] IP:"+.[2]+" HOST:"+.[3]+" URI:"+.[4]+" MSG:"+.[5]
    ' 2>/dev/null > "$OUTFILE"

  COUNT=$(wc -l < "$OUTFILE" | tr -d ' ')
  printf "  ${GREEN}Export selesai!${NC}\n"
  printf "  File  : ${CYAN}%s${NC}\n" "$OUTFILE"
  printf "  Total : ${CYAN}%s entri${NC}\n" "$COUNT"
  echo ""
}

# ============================================
# HELPER - GENERATE ID
# ============================================
gen_id() {
  local PREFIX="$1"  # WL atau BL
  LAST_ID=$(grep -oP "(?<=${PREFIX}-)\d+" "$CUSTOM_CONF" 2>/dev/null | sort -n | tail -1)
  if [ -z "$LAST_ID" ]; then
    [ "$PREFIX" = "BL" ] && echo 8001 || echo 9001
  else
    echo $((LAST_ID + 1))
  fi
}

ensure_conf() {
  if [ ! -f "$CUSTOM_CONF" ]; then
    mkdir -p "$(dirname "$CUSTOM_CONF")"
    touch "$CUSTOM_CONF"
  fi
}

restart_coraza() {
  echo ""
  read -rp "Restart Coraza sekarang agar perubahan aktif? [y/N]: " RESTART
  if [[ "$RESTART" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Merestart Coraza...${NC}"
    cd /opt/coraza && docker compose restart coraza 2>&1 | tail -3
    sleep 2
    # Verifikasi container kembali running
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
      echo -e "${GREEN}✓ Coraza berhasil direstart!${NC}"
    else
      echo -e "${RED}✗ Coraza gagal restart, cek manual.${NC}"
    fi
  else
    echo -e "${YELLOW}Ingat restart manual:${NC}"
    echo "  cd /opt/coraza && docker compose restart coraza"
  fi
}

# ============================================
# BLOCK IP - TAMBAH
# ============================================
block_ip_add() {
  ensure_conf
  echo -e "${BOLD}${RED}⛔ Block IP — Mode DetectionOnly tetap aktif${NC}"
  echo -e "${DIM}IP yang diblokir akan dapat 403, traffic lain tetap DetectionOnly${NC}"
  echo ""

  # Tampilkan top attacker dari log sebagai referensi
  echo -e "${BOLD}Top IP Penyerang (dari log):${NC}"
  echo ""
  TMP_ATK=$(mktemp /tmp/coraza-bl-XXXX.log)
  get_attack_logs > "$TMP_ATK"

  ATTACKER_IPS=()
  if [ -s "$TMP_ATK" ]; then
    mapfile -t ATTACKER_IPS < <(
      jq -r '.transaction.client_ip' "$TMP_ATK" 2>/dev/null \
        | sort | uniq -c | sort -rn | head -10 \
        | awk '{print $2}'
    )
    IDX=0
    jq -r '.transaction.client_ip' "$TMP_ATK" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -10 \
      | while read -r count ip; do
          IDX=$((IDX+1))
          # Cek sudah diblokir atau belum
          if grep -q "\[BL-" "$CUSTOM_CONF" 2>/dev/null && grep -q "ipMatch $ip" "$CUSTOM_CONF" 2>/dev/null; then
            printf "  ${DIM}[%d] %s (%d serangan) — sudah diblokir${NC}\n" "$IDX" "$ip" "$count"
          else
            printf "  ${CYAN}[%d]${NC} ${RED}%s${NC} ${DIM}(%d serangan)${NC}\n" "$IDX" "$ip" "$count"
          fi
        done
  else
    echo -e "  ${YELLOW}Belum ada data serangan di log.${NC}"
  fi
  rm -f "$TMP_ATK"

  echo ""
  echo -e "${DIM}Pilih nomor dari daftar atau ketik IP manual${NC}"
  read -rp "  IP / CIDR [atau nomor 1-${#ATTACKER_IPS[@]}]: " IP_INPUT

  # Jika input angka, ambil dari daftar
  if [[ "$IP_INPUT" =~ ^[0-9]+$ ]] && [ "$IP_INPUT" -ge 1 ] && [ "$IP_INPUT" -le "${#ATTACKER_IPS[@]}" ]; then
    IP_ADDR="${ATTACKER_IPS[$((IP_INPUT-1))]}"
    echo -e "  → Dipilih: ${RED}${BOLD}$IP_ADDR${NC}"
  else
    IP_ADDR="$IP_INPUT"
  fi

  if [ -z "$IP_ADDR" ]; then
    echo -e "${RED}IP tidak boleh kosong.${NC}"
    return
  fi

  # Cek apakah sudah diblokir
  if grep -q "ipMatch $IP_ADDR" "$CUSTOM_CONF" 2>/dev/null; then
    echo -e "${YELLOW}IP ${IP_ADDR} sudah ada di daftar block.${NC}"
    return
  fi

  echo ""
  echo -e "  Pilih tipe block:"
  echo "  [1] Block semua request dari IP ini (403)"
  echo "  [2] Block hanya jika ada serangan terdeteksi (anomaly score ≥ 5)"
  read -rp "  Pilihan [1/2]: " BLOCK_TYPE

  echo ""
  read -rp "  Deskripsi (opsional): " DESC
  [ -z "$DESC" ] && DESC="Block IP: $IP_ADDR"

  RULE_ID=$(gen_id "BL")
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

  if [ "$BLOCK_TYPE" = "2" ]; then
    # Block hanya jika anomaly score tinggi
    cat >> "$CUSTOM_CONF" << EOF

# [BL-${RULE_ID}] ${DESC} | Tipe: Block-if-attack | Dibuat: ${TIMESTAMP}
SecRule REMOTE_ADDR "@ipMatch ${IP_ADDR}" \\
  "id:${RULE_ID},phase:2,deny,status:403,log,\\
  chain,\\
  msg:'Blocked attacker IP: ${IP_ADDR}'"
  SecRule TX:ANOMALY_SCORE "@ge 5" ""
EOF
    TYPE_LABEL="Block jika ada serangan (score ≥ 5)"
  else
    # Block semua request dari IP ini
    cat >> "$CUSTOM_CONF" << EOF

# [BL-${RULE_ID}] ${DESC} | Tipe: Block-all | Dibuat: ${TIMESTAMP}
SecRule REMOTE_ADDR "@ipMatch ${IP_ADDR}" \\
  "id:${RULE_ID},phase:1,deny,status:403,log,\\
  msg:'Blocked IP: ${IP_ADDR}'"
EOF
    TYPE_LABEL="Block semua request (403)"
  fi

  echo ""
  echo -e "  ${GREEN}✓ IP berhasil diblokir!${NC}"
  printf "  Rule ID : ${CYAN}%s${NC}\n" "$RULE_ID"
  printf "  IP      : ${RED}%s${NC}\n"  "$IP_ADDR"
  printf "  Tipe    : ${YELLOW}%s${NC}\n" "$TYPE_LABEL"
  echo ""
  echo -e "  ${DIM}Rule engine global tetap DetectionOnly.${NC}"
  echo -e "  ${DIM}Hanya IP ini yang akan mendapat 403.${NC}"
  restart_coraza
}

# ============================================
# BLOCK IP - LIHAT DAFTAR
# ============================================
block_ip_list() {
  ensure_conf
  echo -e "${BOLD}${RED}Daftar IP yang Diblokir:${NC}"
  echo ""

  COUNT=0
  while IFS= read -r line; do
    if echo "$line" | grep -qP '^\s*#\s*\[BL-'; then
      COUNT=$((COUNT+1))
      RID=$(echo "$line" | grep -oP '(?<=\[BL-)\d+')
      RDESC=$(echo "$line" | sed 's/.*\[BL-[0-9]*\] //' | cut -d'|' -f1 | xargs)
      RTYPE=$(echo "$line" | grep -oP '(?<=Tipe: )[^|]+' | xargs)
      RDATE=$(echo "$line" | grep -oP '(?<=Dibuat: ).+' | xargs)
      # Ambil IP dari baris SecRule berikutnya
      RIP=$(grep -A2 "\[BL-${RID}\]" "$CUSTOM_CONF" | grep -oP '(?<=ipMatch )[^ \\]+' | head -1)
      printf "  ${RED}[%d]${NC} ID:%-4s  IP: ${BOLD}%-20s${NC}\n" "$COUNT" "$RID" "$RIP"
      printf "       Tipe  : ${YELLOW}%s${NC}\n" "$RTYPE"
      printf "       Dibuat: ${DIM}%s${NC}\n" "$RDATE"
      printf "       Ket   : %s\n" "$RDESC"
      echo ""
    fi
  done < "$CUSTOM_CONF"

  if [ "$COUNT" -eq 0 ]; then
    echo -e "  ${YELLOW}Belum ada IP yang diblokir.${NC}"
    echo ""
  fi
}

# ============================================
# BLOCK IP - HAPUS
# ============================================
block_ip_delete() {
  ensure_conf
  echo -e "${BOLD}Hapus Block IP${NC}"
  echo ""

  RULE_IDS=()
  RULE_IPS=()
  RULE_DESCS=()

  while IFS= read -r line; do
    if echo "$line" | grep -qP '^\s*#\s*\[BL-'; then
      RID=$(echo "$line" | grep -oP '(?<=\[BL-)\d+')
      RDESC=$(echo "$line" | sed 's/.*\[BL-[0-9]*\] //' | cut -d'|' -f1 | xargs)
      RIP=$(grep -A2 "\[BL-${RID}\]" "$CUSTOM_CONF" | grep -oP '(?<=ipMatch )[^ \\]+' | head -1)
      RULE_IDS+=("$RID")
      RULE_IPS+=("$RIP")
      RULE_DESCS+=("$RDESC")
    fi
  done < "$CUSTOM_CONF"

  if [ ${#RULE_IDS[@]} -eq 0 ]; then
    echo -e "  ${YELLOW}Tidak ada block IP untuk dihapus.${NC}"
    echo ""
    return
  fi

  for i in "${!RULE_IDS[@]}"; do
    printf "  ${CYAN}[%d]${NC} ${RED}%-20s${NC} — %s\n" \
      "$((i+1))" "${RULE_IPS[$i]}" "${RULE_DESCS[$i]}"
  done

  echo ""
  read -rp "  Pilih nomor yang akan dihapus (atau 'q' batal): " DEL_CHOICE

  [[ "$DEL_CHOICE" =~ ^[qQ]$ ]] && return

  if ! [[ "$DEL_CHOICE" =~ ^[0-9]+$ ]] || \
     [ "$DEL_CHOICE" -lt 1 ] || \
     [ "$DEL_CHOICE" -gt ${#RULE_IDS[@]} ]; then
    echo -e "${RED}Pilihan tidak valid.${NC}"
    return
  fi

  TARGET_ID="${RULE_IDS[$((DEL_CHOICE-1))]}"
  TARGET_IP="${RULE_IPS[$((DEL_CHOICE-1))]}"

  echo ""
  echo -e "  ${YELLOW}Akan menghapus block: ${RED}${TARGET_IP}${NC}"
  read -rp "  Konfirmasi? [y/N]: " CONFIRM

  if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    TMP_CONF=$(mktemp /tmp/coraza-conf-XXXX.conf)
    awk -v id="$TARGET_ID" -v prefix="BL" '
      BEGIN { skip=0 }
      /^# \[BL-/ {
        if ($0 ~ "\\[BL-" id "\\]") { skip=1; next }
      }
      skip==1 && /^SecRule/ { skip=2; next }
      skip==2 && /\\$/ { next }
      skip==2 && /SecRule/ { next }
      skip==2 && !/\\$/ { skip=0; next }
      { print }
    ' "$CUSTOM_CONF" > "$TMP_CONF"
    mv "$TMP_CONF" "$CUSTOM_CONF"

    echo -e "  ${GREEN}✓ Block IP ${TARGET_IP} berhasil dihapus!${NC}"
    restart_coraza
  else
    echo -e "  ${YELLOW}Dibatalkan.${NC}"
  fi
  echo ""
}

# ============================================
# BLOCK IP MENU
# ============================================
block_ip_menu() {
  while true; do
    print_header
    echo -e "${BOLD}${RED}⛔ Block IP Manager${NC}"
    echo -e "${DIM}Rule engine global tetap DetectionOnly — hanya IP terdaftar yang diblokir${NC}"
    echo ""
    block_ip_list

    echo -e "${BOLD}Pilih Aksi:${NC}"
    echo ""
    echo "  [1] Block IP baru dari log / manual"
    echo "  [2] Hapus block IP"
    echo "  [b] Kembali"
    echo ""
    read -rp "Pilihan: " BL_CHOICE

    case "$BL_CHOICE" in
      1) clear; print_header; echo -e "${BOLD}${RED}⛔ Block IP Baru${NC}"; echo ""; block_ip_add; read -rp "Tekan ENTER untuk kembali..." ;;
      2) clear; print_header; echo -e "${BOLD}Hapus Block IP${NC}"; echo ""; block_ip_delete; read -rp "Tekan ENTER untuk kembali..." ;;
      b|B) return ;;
      *) echo -e "${RED}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

# ============================================
# WHITELIST HELPER
# ============================================
gen_wl_id() { gen_id "WL"; }

whitelist_list() {
  ensure_conf
  echo -e "${BOLD}Daftar Whitelist:${NC}"
  echo ""

  IDX=0
  while IFS= read -r line; do
    if echo "$line" | grep -qP '^\s*#\s*\[WL-'; then
      IDX=$((IDX+1))
      LABEL=$(echo "$line" | grep -oP '(?<=# ).*')
      printf "  ${CYAN}[%d]${NC} %s\n" "$IDX" "$LABEL"
    fi
  done < "$CUSTOM_CONF"

  if [ "$IDX" -eq 0 ]; then
    echo -e "  ${YELLOW}Belum ada whitelist.${NC}"
  fi
  echo ""
}

whitelist_add_uri() {
  ensure_conf
  echo -e "${BOLD}Tambah Whitelist URI Path${NC}"
  echo -e "${DIM}Contoh: /api/v1/webhook  atau  /admin/health${NC}"
  echo ""
  read -rp "  URI path (mulai /): " URI_PATH

  if [ -z "$URI_PATH" ] || [[ "$URI_PATH" != /* ]]; then
    echo -e "${RED}URI tidak valid.${NC}"
    return
  fi

  echo ""
  echo "  [1] DetectionOnly  — tetap dilog, tidak diblokir"
  echo "  [2] Off            — skip WAF sepenuhnya"
  read -rp "  Mode [1/2]: " MODE_CHOICE

  case "$MODE_CHOICE" in
    2) CTL_MODE="Off"; MODE_LABEL="Skip WAF" ;;
    *) CTL_MODE="DetectionOnly"; MODE_LABEL="DetectionOnly" ;;
  esac

  read -rp "  Deskripsi (opsional): " DESC
  [ -z "$DESC" ] && DESC="URI whitelist: $URI_PATH"

  RULE_ID=$(gen_id "WL")
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

  cat >> "$CUSTOM_CONF" << EOF

# [WL-${RULE_ID}] ${DESC} | Mode: ${MODE_LABEL} | Dibuat: ${TIMESTAMP}
SecRule REQUEST_URI "@beginsWith ${URI_PATH}" \\
  "id:${RULE_ID},phase:1,pass,nolog,\\
  ctl:ruleEngine=${CTL_MODE},\\
  msg:'Whitelist URI: ${URI_PATH}'"
EOF

  echo -e "  ${GREEN}✓ Whitelist URI ditambahkan! [ID:${RULE_ID}]${NC}"
  restart_coraza
}

whitelist_add_ip() {
  ensure_conf
  echo -e "${BOLD}Tambah Whitelist IP${NC}"
  echo -e "${DIM}Contoh: 10.0.0.1  atau  192.168.0.0/24${NC}"
  echo ""
  read -rp "  IP / CIDR: " IP_ADDR

  if [ -z "$IP_ADDR" ]; then
    echo -e "${RED}IP tidak boleh kosong.${NC}"
    return
  fi

  echo ""
  echo "  [1] DetectionOnly  — tetap dilog, tidak diblokir"
  echo "  [2] Off            — skip WAF sepenuhnya"
  read -rp "  Mode [1/2]: " MODE_CHOICE

  case "$MODE_CHOICE" in
    2) CTL_MODE="Off"; MODE_LABEL="Skip WAF" ;;
    *) CTL_MODE="DetectionOnly"; MODE_LABEL="DetectionOnly" ;;
  esac

  read -rp "  Deskripsi (opsional): " DESC
  [ -z "$DESC" ] && DESC="IP whitelist: $IP_ADDR"

  RULE_ID=$(gen_id "WL")
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

  cat >> "$CUSTOM_CONF" << EOF

# [WL-${RULE_ID}] ${DESC} | Mode: ${MODE_LABEL} | Dibuat: ${TIMESTAMP}
SecRule REMOTE_ADDR "@ipMatch ${IP_ADDR}" \\
  "id:${RULE_ID},phase:1,pass,nolog,\\
  ctl:ruleEngine=${CTL_MODE},\\
  msg:'Whitelist IP: ${IP_ADDR}'"
EOF

  echo -e "  ${GREEN}✓ Whitelist IP ditambahkan! [ID:${RULE_ID}]${NC}"
  restart_coraza
}

whitelist_add_combo() {
  ensure_conf
  echo -e "${BOLD}Tambah Whitelist Kombinasi IP + URI${NC}"
  echo ""
  read -rp "  IP / CIDR: " IP_ADDR
  read -rp "  URI path (mulai /): " URI_PATH

  if [ -z "$IP_ADDR" ] || [ -z "$URI_PATH" ] || [[ "$URI_PATH" != /* ]]; then
    echo -e "${RED}IP atau URI tidak valid.${NC}"
    return
  fi

  echo ""
  echo "  [1] DetectionOnly"
  echo "  [2] Off"
  read -rp "  Mode [1/2]: " MODE_CHOICE

  case "$MODE_CHOICE" in
    2) CTL_MODE="Off"; MODE_LABEL="Skip WAF" ;;
    *) CTL_MODE="DetectionOnly"; MODE_LABEL="DetectionOnly" ;;
  esac

  read -rp "  Deskripsi (opsional): " DESC
  [ -z "$DESC" ] && DESC="Combo IP $IP_ADDR + URI $URI_PATH"

  RULE_ID=$(gen_id "WL")
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

  cat >> "$CUSTOM_CONF" << EOF

# [WL-${RULE_ID}] ${DESC} | Mode: ${MODE_LABEL} | Dibuat: ${TIMESTAMP}
SecRule REMOTE_ADDR "@ipMatch ${IP_ADDR}" \\
  "id:${RULE_ID},phase:1,pass,nolog,chain"
  SecRule REQUEST_URI "@beginsWith ${URI_PATH}" \\
    "ctl:ruleEngine=${CTL_MODE}"
EOF

  echo -e "  ${GREEN}✓ Whitelist kombinasi ditambahkan! [ID:${RULE_ID}]${NC}"
  restart_coraza
}

whitelist_delete() {
  ensure_conf
  RULE_IDS=()
  RULE_DESCS=()

  while IFS= read -r line; do
    if echo "$line" | grep -qP '^\s*#\s*\[WL-'; then
      RID=$(echo "$line" | grep -oP '(?<=\[WL-)\d+')
      RDESC=$(echo "$line" | sed 's/.*\[WL-[0-9]*\] //' | cut -d'|' -f1 | xargs)
      RULE_IDS+=("$RID")
      RULE_DESCS+=("$RDESC")
    fi
  done < "$CUSTOM_CONF"

  if [ ${#RULE_IDS[@]} -eq 0 ]; then
    echo -e "  ${YELLOW}Tidak ada whitelist.${NC}"
    return
  fi

  for i in "${!RULE_IDS[@]}"; do
    printf "  ${CYAN}[%d]${NC} [ID:%s] %s\n" "$((i+1))" "${RULE_IDS[$i]}" "${RULE_DESCS[$i]}"
  done

  echo ""
  read -rp "  Pilih nomor (atau 'q' batal): " DEL_CHOICE
  [[ "$DEL_CHOICE" =~ ^[qQ]$ ]] && return

  if ! [[ "$DEL_CHOICE" =~ ^[0-9]+$ ]] || \
     [ "$DEL_CHOICE" -lt 1 ] || \
     [ "$DEL_CHOICE" -gt ${#RULE_IDS[@]} ]; then
    echo -e "${RED}Pilihan tidak valid.${NC}"
    return
  fi

  TARGET_ID="${RULE_IDS[$((DEL_CHOICE-1))]}"
  echo ""
  echo -e "  ${YELLOW}Hapus whitelist [WL-${TARGET_ID}]?${NC}"
  read -rp "  Konfirmasi? [y/N]: " CONFIRM

  if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    TMP_CONF=$(mktemp /tmp/coraza-conf-XXXX.conf)
    awk -v id="$TARGET_ID" '
      BEGIN { skip=0 }
      /^# \[WL-/ { if ($0 ~ "\\[WL-" id "\\]") { skip=1; next } }
      skip==1 && /^SecRule/ { skip=2; next }
      skip==2 && /\\$/ { next }
      skip==2 && !/\\$/ { skip=0; next }
      { print }
    ' "$CUSTOM_CONF" > "$TMP_CONF"
    mv "$TMP_CONF" "$CUSTOM_CONF"
    echo -e "  ${GREEN}✓ Whitelist [WL-${TARGET_ID}] dihapus!${NC}"
    restart_coraza
  else
    echo -e "  ${YELLOW}Dibatalkan.${NC}"
  fi
}

whitelist_view_raw() {
  ensure_conf
  echo -e "${BOLD}Isi file: $CUSTOM_CONF${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  [ -s "$CUSTOM_CONF" ] && cat "$CUSTOM_CONF" || echo -e "  ${YELLOW}File kosong.${NC}"
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ============================================
# WHITELIST MENU
# ============================================
whitelist_menu() {
  while true; do
    print_header
    echo -e "${BOLD}⚙  Whitelist Manager${NC}"
    echo -e "${DIM}File: $CUSTOM_CONF${NC}"
    echo ""
    whitelist_list

    echo -e "${BOLD}Pilih Aksi:${NC}"
    echo ""
    echo "  [1] Tambah whitelist URI path"
    echo "  [2] Tambah whitelist IP / CIDR"
    echo "  [3] Tambah whitelist kombinasi IP + URI"
    echo "  [4] Hapus whitelist"
    echo "  [5] Lihat isi file conf"
    echo "  [b] Kembali"
    echo ""
    read -rp "Pilihan: " WL_CHOICE

    case "$WL_CHOICE" in
      1) clear; print_header; whitelist_add_uri;   read -rp "Tekan ENTER..." ;;
      2) clear; print_header; whitelist_add_ip;    read -rp "Tekan ENTER..." ;;
      3) clear; print_header; whitelist_add_combo; read -rp "Tekan ENTER..." ;;
      4) clear; print_header; whitelist_delete;    read -rp "Tekan ENTER..." ;;
      5) clear; print_header; whitelist_view_raw;  read -rp "Tekan ENTER..." ;;
      b|B) return ;;
      *) echo -e "${RED}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

# ============================================
# MAIN MENU
# ============================================
main_menu() {
  while true; do
    print_header
    quick_stats

    echo -e "${BOLD}Pilih Menu:${NC}"
    echo ""
    echo "  [1] Live Attack Feed    - Monitor serangan realtime"
    echo "  [2] Top Attackers       - IP & URI paling sering diserang"
    echo "  [3] Traffic Analytics   - GoAccess full traffic"
    echo "  [4] Export Attack Log   - Simpan log serangan ke file"
    echo "  [5] Whitelist Manager   - Kelola whitelist URI / IP"
    echo "  [6] Block IP Manager    - Block IP penyerang (tetap DetectionOnly)"
    echo "  [7] Refresh Stats       - Update statistik"
    echo "  [q] Keluar"
    echo ""
    read -rp "Pilihan: " CHOICE

    case $CHOICE in
      1) clear; print_header; live_attacks ;;
      2) clear; print_header; top_attackers; read -rp "Tekan ENTER..." ;;
      3) clear; print_header; run_goaccess ;;
      4) clear; print_header; export_attacks; read -rp "Tekan ENTER..." ;;
      5) whitelist_menu ;;
      6) block_ip_menu ;;
      7) continue ;;
      q|Q) echo ""; echo -e "${GREEN}Sampai jumpa!${NC}"; echo ""; exit 0 ;;
      *) echo -e "${RED}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

check_deps
check_container
main_menu
