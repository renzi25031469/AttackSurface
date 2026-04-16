#!/usr/bin/env bash
# =============================================================================
#  attack_surface.sh — Attack Surface Mapper
#  DNS resolution (dnsx) + Port Scan (masscan/naabu) + Report
#  Use apenas em sistemas que você tem autorização para testar
#  Author: Renzi
#  Uso: sudo ./attack_surface.sh -i targets.txt [-m masscan|naabu|both] [-o DIR]
# =============================================================================

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     RESET='\033[0m'
BLUE='\033[0;34m'; MAGENTA='\033[0;35m'

# ── Defaults ──────────────────────────────────────────────────────────────────
INPUT_FILE=""
OUTPUT_DIR="./asm_$(date +%Y%m%d_%H%M%S)"
SCAN_MODE="both"          # masscan | naabu | both
MASSCAN_RATE=5000
NAABU_CONCURRENCY=100
TIMEOUT=10
THREADS=50
PROXY=""
EXCLUDE_FILE=""
RESUME="false"
LOG_FILE="/dev/null"
START_TS=$(date +%s)

# ── Serviços a monitorar (porta:nome:risco) ───────────────────────────────────
declare -A SVC_NAME
declare -A SVC_RISK   # critical | high | medium | low

# Acesso remoto
SVC_NAME[21]="FTP";          SVC_RISK[21]="critical"
SVC_NAME[22]="SSH";          SVC_RISK[22]="medium"
SVC_NAME[23]="Telnet";       SVC_RISK[23]="critical"
SVC_NAME[512]="rexec";       SVC_RISK[512]="critical"
SVC_NAME[513]="rlogin";      SVC_RISK[513]="critical"
SVC_NAME[514]="rsh";         SVC_RISK[514]="critical"
SVC_NAME[3389]="RDP";        SVC_RISK[3389]="critical"
SVC_NAME[5900]="VNC";        SVC_RISK[5900]="critical"
SVC_NAME[5901]="VNC-1";      SVC_RISK[5901]="critical"
SVC_NAME[5902]="VNC-2";      SVC_RISK[5902]="critical"

# E-mail
SVC_NAME[25]="SMTP";         SVC_RISK[25]="high"
SVC_NAME[110]="POP3";        SVC_RISK[110]="high"
SVC_NAME[143]="IMAP";        SVC_RISK[143]="high"
SVC_NAME[465]="SMTPS";       SVC_RISK[465]="medium"
SVC_NAME[587]="SMTP-Sub";    SVC_RISK[587]="medium"
SVC_NAME[993]="IMAPS";       SVC_RISK[993]="low"
SVC_NAME[995]="POP3S";       SVC_RISK[995]="low"

# Banco de dados
SVC_NAME[1433]="MSSQL";      SVC_RISK[1433]="critical"
SVC_NAME[1521]="Oracle";     SVC_RISK[1521]="critical"
SVC_NAME[3306]="MySQL";      SVC_RISK[3306]="critical"
SVC_NAME[5432]="PostgreSQL"; SVC_RISK[5432]="critical"
SVC_NAME[6379]="Redis";      SVC_RISK[6379]="critical"
SVC_NAME[27017]="MongoDB";   SVC_RISK[27017]="critical"
SVC_NAME[9200]="Elasticsearch"; SVC_RISK[9200]="critical"
SVC_NAME[5984]="CouchDB";    SVC_RISK[5984]="high"
SVC_NAME[11211]="Memcached"; SVC_RISK[11211]="critical"

# Web
SVC_NAME[80]="HTTP";         SVC_RISK[80]="low"
SVC_NAME[443]="HTTPS";       SVC_RISK[443]="low"
SVC_NAME[8080]="HTTP-Alt";   SVC_RISK[8080]="medium"
SVC_NAME[8443]="HTTPS-Alt";  SVC_RISK[8443]="medium"
SVC_NAME[8888]="HTTP-Dev";   SVC_RISK[8888]="medium"
SVC_NAME[9090]="HTTP-Admin"; SVC_RISK[9090]="high"
SVC_NAME[7070]="HTTP-Dev2";  SVC_RISK[7070]="medium"

# Diretório / Auth
SVC_NAME[389]="LDAP";        SVC_RISK[389]="high"
SVC_NAME[636]="LDAPS";       SVC_RISK[636]="medium"
SVC_NAME[88]="Kerberos";     SVC_RISK[88]="high"

# Rede / Infra
SVC_NAME[445]="SMB";         SVC_RISK[445]="critical"
SVC_NAME[139]="NetBIOS";     SVC_RISK[139]="high"
SVC_NAME[135]="MSRPC";       SVC_RISK[135]="high"
SVC_NAME[111]="RPCbind";     SVC_RISK[111]="high"
SVC_NAME[2049]="NFS";        SVC_RISK[2049]="critical"
SVC_NAME[161]="SNMP";        SVC_RISK[161]="high"
SVC_NAME[162]="SNMP-Trap";   SVC_RISK[162]="medium"
SVC_NAME[69]="TFTP";         SVC_RISK[69]="high"
SVC_NAME[53]="DNS";          SVC_RISK[53]="medium"
SVC_NAME[123]="NTP";         SVC_RISK[123]="medium"

# CI/CD / DevOps
SVC_NAME[2375]="Docker";     SVC_RISK[2375]="critical"
SVC_NAME[2376]="Docker-TLS"; SVC_RISK[2376]="high"
SVC_NAME[2379]="etcd";       SVC_RISK[2379]="critical"
SVC_NAME[2380]="etcd-peer";  SVC_RISK[2380]="critical"
SVC_NAME[6443]="K8s-API";    SVC_RISK[6443]="critical"
SVC_NAME[10250]="Kubelet";   SVC_RISK[10250]="critical"
SVC_NAME[8500]="Consul";     SVC_RISK[8500]="critical"
SVC_NAME[4848]="GlassFish";  SVC_RISK[4848]="high"
SVC_NAME[4444]="Metasploit"; SVC_RISK[4444]="critical"
SVC_NAME[9418]="Git";        SVC_RISK[9418]="medium"

# Mensageria
SVC_NAME[5672]="AMQP";       SVC_RISK[5672]="high"
SVC_NAME[5671]="AMQPS";      SVC_RISK[5671]="medium"
SVC_NAME[1883]="MQTT";       SVC_RISK[1883]="high"
SVC_NAME[9092]="Kafka";      SVC_RISK[9092]="high"
SVC_NAME[2181]="ZooKeeper";  SVC_RISK[2181]="critical"

# Monitoramento
SVC_NAME[9100]="Prometheus"; SVC_RISK[9100]="high"
SVC_NAME[3000]="Grafana";    SVC_RISK[3000]="high"
SVC_NAME[9090]="Prometheus-HTTP"; SVC_RISK[9090]="high"
SVC_NAME[8086]="InfluxDB";   SVC_RISK[8086]="high"

# Porta scan string
PORT_LIST=$(IFS=,; echo "${!SVC_NAME[*]}" | tr ' ' ',')

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
cat << 'EOF'
    _   _   _             _      ____              __                
   / \ | |_| |_ __ _  ___| | __ / ___| _   _ _ __ / _| __ _  ___ ___ 
  / _ \| __| __/ _` |/ __| |/ / \___ \| | | | '__| |_ / _` |/ __/ _ \
 / ___ \ |_| || (_| | (__|   <   ___) | |_| | |  |  _| (_| | (_|  __/
/_/   \_\__|\__\__,_|\___|_|\_\ |____/ \__,_|_|  |_|  \__,_|\___\___|
 	Attack Surface Mapper — DNS + Scan + Report
EOF
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    banner
    echo ""
    echo -e "${BOLD}Uso:${RESET}"
    echo "  $0 -i <arquivo> [opções]"
    echo ""
    echo -e "${BOLD}Opções:${RESET}"
    echo "  -i  FILE        Lista de domínios/IPs (um por linha)  [obrigatório]"
    echo "  -o  OUTPUT_DIR  Diretório de saída    (padrão: ./asm_DATE)"
    echo "  -m  MODE        Modo de scan: masscan | naabu | both  (padrão: ${SCAN_MODE})"
    echo "  -r  RATE        Taxa masscan pps                       (padrão: ${MASSCAN_RATE})"
    echo "  -c  CONC        Concorrência naabu                     (padrão: ${NAABU_CONCURRENCY})"
    echo "  -t  TIMEOUT     Timeout por host (s)                   (padrão: ${TIMEOUT})"
    echo "  -T  THREADS     Threads resolução DNS                  (padrão: ${THREADS})"
    echo "  -p  PROXY       Proxy HTTP (ex: http://127.0.0.1:8080)"
    echo "  -x  EXCLUDE     Arquivo de IPs/CIDRs a excluir"
    echo "  --resume        Reaproveita scans anteriores"
    echo "  -h              Exibe esta ajuda"
    echo ""
    echo -e "${BOLD}Variáveis de ambiente:${RESET}"
    echo "  MASSCAN_RATE, NAABU_CONCURRENCY, SCAN_MODE, TIMEOUT, THREADS"
    echo ""
    echo -e "${BOLD}Serviços monitorados (${#SVC_NAME[@]} portas):${RESET}"
    printf "  %-8s %-18s %s\n" "PORTA" "SERVIÇO" "RISCO"
    echo "  ──────────────────────────────────────"
    for port in $(echo "${!SVC_NAME[@]}" | tr ' ' '\n' | sort -n); do
        local risk="${SVC_RISK[$port]}"
        local color
        case "$risk" in
            critical) color="${RED}" ;;
            high)     color="${YELLOW}" ;;
            medium)   color="${CYAN}" ;;
            low)      color="${GREEN}" ;;
        esac
        printf "  %-8s %-18s %b%s%b\n" "${port}/tcp" "${SVC_NAME[$port]}" "$color" "$risk" "$RESET"
    done
    echo ""
    echo -e "${BOLD}Exemplos:${RESET}"
    echo "  sudo $0 -i targets.txt"
    echo "  sudo $0 -i targets.txt -m masscan -r 10000"
    echo "  sudo $0 -i targets.txt -m naabu -c 200"
    echo "  sudo $0 -i targets.txt -o /tmp/asm_report --resume"
    exit 0
}

# ── Logging ───────────────────────────────────────────────────────────────────
ts()      { date '+%H:%M:%S'; }
info()    { echo -e "[$(ts)] ${CYAN}[INFO]${RESET}   $*" | tee -a "$LOG_FILE"; }
success() { echo -e "[$(ts)] ${GREEN}[OK]${RESET}     $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "[$(ts)] ${YELLOW}[WARN]${RESET}   $*" | tee -a "$LOG_FILE"; }
error()   { echo -e "[$(ts)] ${RED}[ERROR]${RESET}  $*" | tee -a "$LOG_FILE" >&2; }
step()    { echo -e "\n[$(ts)] ${BOLD}${BLUE}[STEP]${RESET} $*" | tee -a "$LOG_FILE"; }
die()     { error "$*"; exit 1; }

# ── Dependências ──────────────────────────────────────────────────────────────
check_deps() {
    step "Verificando dependências..."
    local need=(dnsx jq)
    case "$SCAN_MODE" in
        masscan) need+=(masscan) ;;
        naabu)   need+=(naabu) ;;
        both)    need+=(masscan naabu) ;;
    esac
    local miss=()
    for t in "${need[@]}"; do
        command -v "$t" &>/dev/null || miss+=("$t")
    done
    if [[ ${#miss[@]} -gt 0 ]]; then
        warn "Ausentes: ${miss[*]}"
        for t in "${miss[@]}"; do
            case "$t" in
                dnsx)    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>>"$LOG_FILE" ;;
                masscan) apt-get install -y masscan 2>>"$LOG_FILE" || true ;;
                naabu)   go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>>"$LOG_FILE" ;;
                jq)      apt-get install -y jq 2>>"$LOG_FILE" || brew install jq 2>>"$LOG_FILE" || true ;;
            esac
        done
    fi
    success "Dependências OK."
}

# ── Separar domínios de IPs ───────────────────────────────────────────────────
split_input() {
    local raw_ips="${OUTPUT_DIR}/raw_ips.txt"
    local raw_domains="${OUTPUT_DIR}/raw_domains.txt"
    : > "$raw_ips"; : > "$raw_domains"

    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        # CIDR ou IP puro
        if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$ ]]; then
            echo "$line" >> "$raw_ips"
        else
            # Remove protocolo se houver
            local clean="${line#https://}"; clean="${clean#http://}"; clean="${clean%%/*}"
            echo "$clean" >> "$raw_domains"
        fi
    done < "$INPUT_FILE"

    local nip ndom
    nip=$(wc -l < "$raw_ips")
    ndom=$(wc -l < "$raw_domains")
    info "IPs/CIDRs diretos : ${nip}"
    info "Domínios          : ${ndom}"
}

# ── Resolução DNS com dnsx ────────────────────────────────────────────────────
resolve_dns() {
    local raw_domains="${OUTPUT_DIR}/raw_domains.txt"
    local dns_out="${OUTPUT_DIR}/dns_resolved.json"
    local resolved_ips="${OUTPUT_DIR}/resolved_ips.txt"

    [[ ! -s "$raw_domains" ]] && { info "Nenhum domínio para resolver."; return; }

    if [[ "$RESUME" == "true" && -s "$dns_out" ]]; then
        warn "--resume: reutilizando dns_resolved.json"
    else
        step "Resolvendo DNS com dnsx..."
        dnsx \
            -l "$raw_domains" \
            -a -aaaa -cname \
            -resp \
            -json \
            -t "$THREADS" \
            -silent \
            -o "$dns_out" \
            2>>"$LOG_FILE" || warn "dnsx encerrou com erros."
    fi

    # Extrai IPs do JSON do dnsx
    jq -r '
        .a[]?        // empty,
        .aaaa[]?     // empty
    ' "$dns_out" 2>/dev/null | sort -u > "$resolved_ips"

    # Também salva mapa domínio→IP para o relatório
    jq -r '
        . as $e |
        ([$e.a[]?] + [$e.aaaa[]?])[] |
        "\($e.host)|\(.)"
    ' "$dns_out" 2>/dev/null | sort -u > "${OUTPUT_DIR}/domain_ip_map.txt"

    local n
    n=$(wc -l < "$resolved_ips")
    success "IPs resolvidos: ${n}"
}

# ── Consolida todos os IPs para scan ─────────────────────────────────────────
build_ip_list() {
    local all_ips="${OUTPUT_DIR}/all_ips.txt"
    cat "${OUTPUT_DIR}/raw_ips.txt" \
        "${OUTPUT_DIR}/resolved_ips.txt" \
        2>/dev/null | sort -u > "$all_ips"
    local n
    n=$(wc -l < "$all_ips")
    info "Total de IPs para scan: ${BOLD}${n}${RESET}"
    [[ "$n" -eq 0 ]] && die "Nenhum IP para escanear. Verifique o arquivo de entrada."
}

# ── Masscan ───────────────────────────────────────────────────────────────────
run_masscan() {
    local all_ips="${OUTPUT_DIR}/all_ips.txt"
    local out="${OUTPUT_DIR}/masscan_raw.json"

    if [[ "$RESUME" == "true" && -s "$out" ]]; then
        warn "--resume: reutilizando masscan_raw.json"; return
    fi

    step "Masscan (rate=${MASSCAN_RATE} pps)..."
    [[ $EUID -ne 0 ]] && warn "masscan requer root."

    local cmd=(masscan -iL "$all_ips" -p "$PORT_LIST"
               --rate="$MASSCAN_RATE" --open-only
               -oJ "$out" --exclude 255.255.255.255)
    [[ -n "$EXCLUDE_FILE" ]] && cmd+=(--excludefile "$EXCLUDE_FILE")

    "${cmd[@]}" >>"$LOG_FILE" 2>&1 &
    local pid=$!
    while kill -0 $pid 2>/dev/null; do
        printf "\r  ${CYAN}⟳${RESET} masscan rodando..."
        sleep 2
    done
    wait $pid 2>/dev/null || true
    printf "\r  ${GREEN}✔${RESET} masscan concluído.        \n"
}

# ── Naabu ─────────────────────────────────────────────────────────────────────
run_naabu() {
    local all_ips="${OUTPUT_DIR}/all_ips.txt"
    local out="${OUTPUT_DIR}/naabu_raw.txt"

    if [[ "$RESUME" == "true" && -s "$out" ]]; then
        warn "--resume: reutilizando naabu_raw.txt"; return
    fi

    step "Naabu (concurrency=${NAABU_CONCURRENCY})..."

    naabu \
        -l "$all_ips" \
        -p "$PORT_LIST" \
        -c "$NAABU_CONCURRENCY" \
        -timeout "$TIMEOUT" \
        -silent \
        -o "$out" \
        2>>"$LOG_FILE" &
    local pid=$!
    while kill -0 $pid 2>/dev/null; do
        printf "\r  ${CYAN}⟳${RESET} naabu rodando..."
        sleep 2
    done
    wait $pid 2>/dev/null || true
    printf "\r  ${GREEN}✔${RESET} naabu concluído.        \n"
}

# ── Normaliza resultados → ip|port ────────────────────────────────────────────
normalize_results() {
    step "Normalizando resultados..."
    local final="${OUTPUT_DIR}/open_ports.txt"
    : > "$final"

    # masscan JSON: [{ip, ports:[{port,proto}]}]
    if [[ -s "${OUTPUT_DIR}/masscan_raw.json" ]]; then
        # Fix trailing commas do masscan
        python3 -c "
import json, sys, re
raw = open('${OUTPUT_DIR}/masscan_raw.json').read()
raw = re.sub(r',\s*]', ']', raw)
raw = re.sub(r',\s*}', '}', raw)
try:
    data = json.loads(raw)
    for h in data:
        for p in h.get('ports', []):
            print(f\"{h['ip']}|{p['port']}\")
except: pass
" 2>/dev/null >> "$final" || \
        grep '"ip"' "${OUTPUT_DIR}/masscan_raw.json" 2>/dev/null | \
            grep -oP '"ip":"[^"]+"|"port":\d+' | \
            paste - - | \
            sed 's/"ip":"//;s/"//g;s/"port"://;s/\t/|/' >> "$final" || true
    fi

    # naabu: ip:port
    if [[ -s "${OUTPUT_DIR}/naabu_raw.txt" ]]; then
        sed 's/:/|/' "${OUTPUT_DIR}/naabu_raw.txt" >> "$final"
    fi

    # Dedup
    sort -u -o "$final" "$final"
    local n
    n=$(wc -l < "$final")
    success "Portas abertas únicas: ${BOLD}${n}${RESET}"
}

# ── Gera relatório HTML ───────────────────────────────────────────────────────
generate_html_report() {
    step "Gerando relatório HTML..."

    local open_ports="${OUTPUT_DIR}/open_ports.txt"
    local dns_map="${OUTPUT_DIR}/domain_ip_map.txt"
    local report="${OUTPUT_DIR}/report.html"
    local end_ts elapsed
    end_ts=$(date +%s)
    elapsed=$(( end_ts - START_TS ))

    # Contadores por risco
    local cnt_critical=0 cnt_high=0 cnt_medium=0 cnt_low=0 cnt_total=0

    # Monta mapa ip→domínios
    declare -A IP_DOMAINS
    if [[ -f "$dns_map" ]]; then
        while IFS='|' read -r dom ip; do
            [[ -n "$ip" ]] && IP_DOMAINS[$ip]+="${dom} "
        done < "$dns_map"
    fi

    # Monta linhas da tabela e contadores
    local table_rows=""
    while IFS='|' read -r ip port; do
        [[ -z "$ip" || -z "$port" ]] && continue
        local svc="${SVC_NAME[$port]:-Unknown}"
        local risk="${SVC_RISK[$port]:-low}"
        local domains="${IP_DOMAINS[$ip]:-—}"
        local risk_badge risk_color

        case "$risk" in
            critical) risk_badge="CRÍTICO"; risk_color="#e74c3c"; ((cnt_critical++)) ;;
            high)     risk_badge="ALTO";    risk_color="#e67e22"; ((cnt_high++)) ;;
            medium)   risk_badge="MÉDIO";   risk_color="#f39c12"; ((cnt_medium++)) ;;
            low)      risk_badge="BAIXO";   risk_color="#27ae60"; ((cnt_low++)) ;;
        esac
        ((cnt_total++)) || true

        table_rows+="<tr class=\"row-${risk}\">
            <td><code>${ip}</code></td>
            <td><small>${domains}</small></td>
            <td><strong>${port}</strong></td>
            <td>${svc}</td>
            <td><span class=\"badge\" style=\"background:${risk_color}\">${risk_badge}</span></td>
        </tr>"
    done < "$open_ports"

    # Total de hosts únicos
    local total_hosts
    total_hosts=$(cut -d'|' -f1 "$open_ports" | sort -u | wc -l)
    local total_ips
    total_ips=$(wc -l < "${OUTPUT_DIR}/all_ips.txt" 2>/dev/null || echo 0)
    local scan_dur
    scan_dur=$(printf '%02dh:%02dm:%02ds' $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60)))

    cat > "$report" << HTMLEOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Surface Report — $(date +%Y-%m-%d)</title>
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --accent: #58a6ff; --critical: #e74c3c; --high: #e67e22;
    --medium: #f39c12; --low: #27ae60;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: linear-gradient(135deg, #0d1117 0%, #161b22 60%, #1a1f2e 100%); border-bottom: 1px solid var(--border); padding: 40px 48px 32px; }
  header h1 { font-size: 28px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
  header h1 span { color: var(--accent); }
  header p { color: var(--text2); margin-top: 6px; font-size: 13px; }
  .meta { display: flex; gap: 32px; margin-top: 20px; flex-wrap: wrap; }
  .meta-item { display: flex; flex-direction: column; }
  .meta-item label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text2); }
  .meta-item value { font-size: 15px; font-weight: 600; color: var(--text); margin-top: 2px; }
  main { max-width: 1400px; margin: 0 auto; padding: 32px 48px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 36px; }
  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 20px 24px; position: relative; overflow: hidden; }
  .card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--card-color, var(--accent)); }
  .card .num { font-size: 36px; font-weight: 700; line-height: 1; }
  .card .lbl { font-size: 12px; color: var(--text2); margin-top: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card.critical { --card-color: var(--critical); }
  .card.high     { --card-color: var(--high); }
  .card.medium   { --card-color: var(--medium); }
  .card.low      { --card-color: var(--low); }
  .card.total    { --card-color: var(--accent); }
  .card.hosts    { --card-color: #8b5cf6; }
  .section-title { font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }
  .section-title::before { content: ''; display: inline-block; width: 3px; height: 18px; background: var(--accent); border-radius: 2px; }
  .toolbar { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
  .filter-btn { background: var(--bg3); border: 1px solid var(--border); color: var(--text2); padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: 12px; transition: all .2s; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(88,166,255,.08); }
  .filter-btn.f-critical.active { border-color: var(--critical); color: var(--critical); background: rgba(231,76,60,.08); }
  .filter-btn.f-high.active     { border-color: var(--high);     color: var(--high);     background: rgba(230,126,34,.08); }
  .filter-btn.f-medium.active   { border-color: var(--medium);   color: var(--medium);   background: rgba(243,156,18,.08); }
  .filter-btn.f-low.active      { border-color: var(--low);      color: var(--low);      background: rgba(39,174,96,.08); }
  input[type=text] { background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: 6px 14px; border-radius: 6px; font-size: 13px; outline: none; width: 260px; }
  input[type=text]:focus { border-color: var(--accent); }
  .table-wrap { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; }
  thead th { background: var(--bg3); padding: 12px 16px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text2); font-weight: 600; border-bottom: 1px solid var(--border); }
  tbody tr { border-bottom: 1px solid var(--border); transition: background .15s; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg3); }
  tbody td { padding: 11px 16px; vertical-align: middle; }
  code { background: var(--bg3); padding: 2px 7px; border-radius: 4px; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 12px; color: var(--accent); border: 1px solid var(--border); }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; color: #fff; letter-spacing: 0.3px; }
  .hidden { display: none !important; }
  .chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 36px; }
  .chart-box { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 24px; }
  .bar-chart { display: flex; flex-direction: column; gap: 10px; margin-top: 16px; }
  .bar-item { display: flex; align-items: center; gap: 10px; }
  .bar-label { width: 110px; font-size: 12px; color: var(--text2); text-align: right; flex-shrink: 0; }
  .bar-track { flex: 1; background: var(--bg3); border-radius: 4px; height: 22px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 11px; font-weight: 700; color: #fff; min-width: 30px; transition: width 1s ease; }
  .donut-wrap { display: flex; align-items: center; justify-content: center; gap: 32px; margin-top: 16px; }
  .legend { display: flex; flex-direction: column; gap: 8px; }
  .legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .footer { text-align: center; color: var(--text2); font-size: 12px; padding: 32px; border-top: 1px solid var(--border); margin-top: 48px; }
  @media (max-width: 768px) {
    header { padding: 24px; } main { padding: 24px; }
    .chart-row { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<header>
  <h1>Attack <span>Surface</span> Report</h1>
  <p>Mapeamento de superfície de ataque — gerado automaticamente</p>
  <div class="meta">
    <div class="meta-item"><label>Data</label><value>$(date '+%d/%m/%Y %H:%M')</value></div>
    <div class="meta-item"><label>Arquivo de entrada</label><value>$(basename "$INPUT_FILE")</value></div>
    <div class="meta-item"><label>Modo de scan</label><value>${SCAN_MODE^^}</value></div>
    <div class="meta-item"><label>Duração</label><value>${scan_dur}</value></div>
    <div class="meta-item"><label>IPs escaneados</label><value>${total_ips}</value></div>
  </div>
</header>

<main>

<!-- Cards de resumo -->
<div class="cards">
  <div class="card total">
    <div class="num">${cnt_total}</div>
    <div class="lbl">Total de Achados</div>
  </div>
  <div class="card hosts">
    <div class="num">${total_hosts}</div>
    <div class="lbl">Hosts com Portas Abertas</div>
  </div>
  <div class="card critical">
    <div class="num">${cnt_critical}</div>
    <div class="lbl">Crítico</div>
  </div>
  <div class="card high">
    <div class="num">${cnt_high}</div>
    <div class="lbl">Alto</div>
  </div>
  <div class="card medium">
    <div class="num">${cnt_medium}</div>
    <div class="lbl">Médio</div>
  </div>
  <div class="card low">
    <div class="num">${cnt_low}</div>
    <div class="lbl">Baixo</div>
  </div>
</div>

<!-- Gráficos -->
<div class="chart-row">
  <div class="chart-box">
    <div class="section-title">Distribuição por Risco</div>
    <div class="donut-wrap">
      <canvas id="donutChart" width="160" height="160"></canvas>
      <div class="legend">
        <div class="legend-item"><div class="legend-dot" style="background:#e74c3c"></div> Crítico (${cnt_critical})</div>
        <div class="legend-item"><div class="legend-dot" style="background:#e67e22"></div> Alto (${cnt_high})</div>
        <div class="legend-item"><div class="legend-dot" style="background:#f39c12"></div> Médio (${cnt_medium})</div>
        <div class="legend-item"><div class="legend-dot" style="background:#27ae60"></div> Baixo (${cnt_low})</div>
      </div>
    </div>
  </div>
  <div class="chart-box">
    <div class="section-title">Top Serviços Expostos</div>
    <div class="bar-chart" id="barChart"></div>
  </div>
</div>

<!-- Tabela de resultados -->
<div class="section-title">Serviços Expostos</div>

<div class="toolbar">
  <input type="text" id="searchBox" placeholder="🔍 Buscar IP, domínio, serviço...">
  <button class="filter-btn active" data-filter="all">Todos (${cnt_total})</button>
  <button class="filter-btn f-critical" data-filter="critical">Crítico (${cnt_critical})</button>
  <button class="filter-btn f-high" data-filter="high">Alto (${cnt_high})</button>
  <button class="filter-btn f-medium" data-filter="medium">Médio (${cnt_medium})</button>
  <button class="filter-btn f-low" data-filter="low">Baixo (${cnt_low})</button>
</div>

<div class="table-wrap">
<table id="mainTable">
  <thead>
    <tr>
      <th>IP</th>
      <th>Domínio(s)</th>
      <th>Porta</th>
      <th>Serviço</th>
      <th>Risco</th>
    </tr>
  </thead>
  <tbody id="tableBody">
${table_rows}
  </tbody>
</table>
</div>

</main>

<div class="footer">
  Gerado por <strong>attack_surface.sh</strong> — $(date '+%Y-%m-%d %H:%M:%S') —
  Use este relatório apenas em sistemas com autorização de teste.
</div>

<script>
// ── Dados para gráficos ──────────────────────────────────────────────────────
const counts = { critical: ${cnt_critical}, high: ${cnt_high}, medium: ${cnt_medium}, low: ${cnt_low} };
const colors = { critical:'#e74c3c', high:'#e67e22', medium:'#f39c12', low:'#27ae60' };
const total  = ${cnt_total} || 1;

// Donut chart
(function() {
  const canvas = document.getElementById('donutChart');
  const ctx = canvas.getContext('2d');
  const cx = 80, cy = 80, r = 60, t = 18;
  let angle = -Math.PI / 2;
  const order = ['critical','high','medium','low'];
  order.forEach(k => {
    if (!counts[k]) return;
    const slice = (counts[k] / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, angle, angle + slice);
    ctx.closePath();
    ctx.fillStyle = colors[k];
    ctx.fill();
    angle += slice;
  });
  // Hole
  ctx.beginPath();
  ctx.arc(cx, cy, r - t, 0, 2 * Math.PI);
  ctx.fillStyle = '#161b22';
  ctx.fill();
  // Center text
  ctx.fillStyle = '#c9d1d9';
  ctx.font = 'bold 22px Segoe UI';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy - 8);
  ctx.font = '11px Segoe UI';
  ctx.fillStyle = '#8b949e';
  ctx.fillText('total', cx, cy + 12);
})();

// Bar chart — top serviços
(function() {
  const rows = document.querySelectorAll('#tableBody tr');
  const svcCount = {};
  const svcRisk  = {};
  rows.forEach(r => {
    const svc  = r.cells[3].textContent.trim();
    const port = r.cells[2].textContent.trim();
    const key  = svc + ' :' + port;
    const risk = r.className.replace('row-','');
    svcCount[key] = (svcCount[key] || 0) + 1;
    svcRisk[key]  = risk;
  });
  const sorted = Object.entries(svcCount).sort((a,b) => b[1]-a[1]).slice(0,8);
  const max    = sorted[0]?.[1] || 1;
  const bar    = document.getElementById('barChart');
  sorted.forEach(([svc, cnt]) => {
    const pct  = Math.max(8, Math.round((cnt/max)*100));
    const risk = svcRisk[svc] || 'low';
    bar.innerHTML += \`
      <div class="bar-item">
        <div class="bar-label">\${svc.split(' :')[0]}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:\${pct}%;background:\${colors[risk]}">\${cnt}</div>
        </div>
      </div>\`;
  });
})();

// ── Filtros e busca ──────────────────────────────────────────────────────────
const rows    = Array.from(document.querySelectorAll('#tableBody tr'));
const search  = document.getElementById('searchBox');
const buttons = document.querySelectorAll('.filter-btn');
let currentFilter = 'all';

function applyFilters() {
  const q = search.value.toLowerCase();
  rows.forEach(r => {
    const matchFilter = currentFilter === 'all' || r.classList.contains('row-' + currentFilter);
    const matchSearch = !q || r.textContent.toLowerCase().includes(q);
    r.classList.toggle('hidden', !(matchFilter && matchSearch));
  });
}

buttons.forEach(btn => {
  btn.addEventListener('click', () => {
    buttons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    applyFilters();
  });
});
search.addEventListener('input', applyFilters);
</script>
</body>
</html>
HTMLEOF

    success "Relatório HTML gerado: ${report}"
}

# ── Trap ──────────────────────────────────────────────────────────────────────
trap 'echo ""; warn "Interrompido. Resultados parciais em: ${OUTPUT_DIR}"; exit 130' INT TERM

# =============================================================================
# Main
# =============================================================================
main() {
    [[ $# -eq 0 ]] && usage

    [[ "$1" == "-h" || "$1" == "--help" ]] && usage

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i) INPUT_FILE="$2";          shift 2 ;;
            -o) OUTPUT_DIR="$2";          shift 2 ;;
            -m) SCAN_MODE="$2";           shift 2 ;;
            -r) MASSCAN_RATE="$2";        shift 2 ;;
            -c) NAABU_CONCURRENCY="$2";   shift 2 ;;
            -t) TIMEOUT="$2";             shift 2 ;;
            -T) THREADS="$2";             shift 2 ;;
            -p) PROXY="$2";               shift 2 ;;
            -x) EXCLUDE_FILE="$2";        shift 2 ;;
            --resume) RESUME="true";      shift   ;;
            -h|--help) usage ;;
            *) echo -e "${RED}Opção desconhecida: $1${RESET}"; exit 1 ;;
        esac
    done

    [[ -z "$INPUT_FILE" ]]          && die "Forneça -i <arquivo>."
    [[ ! -f "$INPUT_FILE" ]]        && die "Arquivo não encontrado: ${INPUT_FILE}"
    [[ ! -s "$INPUT_FILE" ]]        && die "Arquivo vazio: ${INPUT_FILE}"

    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/asm.log"
    touch "$LOG_FILE"

    banner; echo ""
    info "Input      : ${INPUT_FILE}"
    info "Output     : ${OUTPUT_DIR}"
    info "Scan mode  : ${SCAN_MODE}"
    info "Portas     : $(echo "$PORT_LIST" | tr ',' '\n' | wc -l) serviços monitorados"
    echo ""

    check_deps
    split_input
    resolve_dns
    build_ip_list

    case "$SCAN_MODE" in
        masscan) run_masscan ;;
        naabu)   run_naabu ;;
        both)    run_masscan; run_naabu ;;
        *) die "SCAN_MODE inválido: ${SCAN_MODE}" ;;
    esac

    normalize_results
    generate_html_report

    local end_ts elapsed
    end_ts=$(date +%s)
    elapsed=$(( end_ts - START_TS ))
    echo ""
    success "Concluído em $(printf '%02dh:%02dm:%02ds' $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60)))"
    success "Relatório: ${OUTPUT_DIR}/report.html"
    success "Log      : ${OUTPUT_DIR}/asm.log"
}

main "$@"

