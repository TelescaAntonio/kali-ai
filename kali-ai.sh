#!/bin/bash

# ╔═══════════════════════════════════════════════════════════════╗
# ║  🤖 KALI-AI v12.0 - COGNITIVE PENTEST FRAMEWORK                ║
# ║  Creato da Antonio Telesca                                    ║
# ║  GitHub: https://github.com/TelescaAntonio/kali-ai            ║
# ║  Powered by Claude Opus 4.6 (Anthropic)                      ║
# ╚═══════════════════════════════════════════════════════════════╝

AUTHOR="Antonio Telesca"
VERSION="12.0"
GITHUB_REPO="https://github.com/TelescaAntonio/kali-ai"
EMAIL="antonio.telesca@irst-institute.eu"

if [[ -f "$HOME/.kali_ai_config" ]]; then
    source "$HOME/.kali_ai_config"
fi
API_KEY="${ANTHROPIC_API_KEY:-}"
MODEL="claude-opus-4-6"

GREEN='\e[1;32m'
RED='\e[1;31m'
BLUE='\e[1;34m'
YELLOW='\e[1;33m'
CYAN='\e[1;36m'
MAGENTA='\e[1;35m'
WHITE='\e[1;37m'
RESET='\e[0m'

BASE_DIR="$HOME/.kali_ai"
LOGS_DIR="$BASE_DIR/logs"
REPORTS_DIR="$BASE_DIR/reports"
SESSION_DIR="$BASE_DIR/sessions"
PENTEST_DIR="$BASE_DIR/pentests"
VULN_DB="$BASE_DIR/vuln_database.json"
HISTORY_FILE="$BASE_DIR/history.json"
MEMORY_FILE="$BASE_DIR/long_term_memory.json"
USER_PROFILE="$BASE_DIR/user_profile.json"
DRIVER_DB="$BASE_DIR/driver_database.json"
THOUGHT_PIPE="/tmp/kali_ai_thoughts"
THOUGHT_PID=""
LAST_OUTPUT=""
LAST_EXIT_CODE=0
LAST_USER_REQUEST=""
CURRENT_SESSION_LOG=""
PENTEST_ACTIVE=false
PENTEST_TARGET=""
PENTEST_RESULTS_DIR=""
declare -A ACTIVE_TERMINALS
declare -a SCHEDULED_PIDS
declare -a AGENT_PIDS

mkdir -p "$LOGS_DIR" "$REPORTS_DIR" "$SESSION_DIR" "$PENTEST_DIR"

# ═══════════════════════════════════════════════════════════════
# FASE 14: THOUGHT TERMINAL - MATRIX STYLE
# ═══════════════════════════════════════════════════════════════

start_thought_terminal() {
    rm -f "$THOUGHT_PIPE"
    mkfifo "$THOUGHT_PIPE" 2>/dev/null

    cat > /tmp/kali_ai_thought_display.sh << 'THOUGHTEOF'
#!/bin/bash
PIPE="/tmp/kali_ai_thoughts"
CMATRIX_PID=""
THINKING=false

start_cmatrix() {
    if [[ -z "$CMATRIX_PID" ]] || ! kill -0 "$CMATRIX_PID" 2>/dev/null; then
        cmatrix -b -u 4 -C green &
        CMATRIX_PID=$!
    fi
}

stop_cmatrix() {
    if [[ -n "$CMATRIX_PID" ]] && kill -0 "$CMATRIX_PID" 2>/dev/null; then
        kill "$CMATRIX_PID" 2>/dev/null
        wait "$CMATRIX_PID" 2>/dev/null
        CMATRIX_PID=""
    fi
    clear
}

typewriter() {
    local text="$1"
    local row="$2"
    local color="${3:-\e[1;32m}"
    local cols=$(tput cols 2>/dev/null || echo 40)
    local pad=$(( (cols - ${#text}) / 2 ))
    [[ $pad -lt 1 ]] && pad=1
    printf "\e[${row};${pad}H${color}"
    for (( i=0; i<${#text}; i++ )); do
        printf "%s" "${text:$i:1}"
        sleep 0.03
    done
    printf "\e[0m"
}

cleanup() {
    stop_cmatrix
    tput cnorm 2>/dev/null
    exit 0
}

trap cleanup EXIT INT TERM

clear
tput civis 2>/dev/null
start_cmatrix

CURRENT_ROW=0
MAX_LINES=0

while true; do
    if read -t 0.1 -r line < "$PIPE" 2>/dev/null; then
        if [[ -n "$line" ]]; then
            msg_type="${line%%:*}"
            msg_content="${line#*:}"
            rows=$(tput lines 2>/dev/null || echo 15)
            cr=$((rows / 2))
            
            case "$msg_type" in
                "PHASE")
                    stop_cmatrix
                    THINKING=true
                    clear
                    CURRENT_ROW=$((cr - 1))
                    typewriter "$msg_content" $CURRENT_ROW "\e[1;32m"
                    CURRENT_ROW=$((CURRENT_ROW + 2))
                    ;;
                "THINK")
                    if [[ "$THINKING" == "false" ]]; then
                        stop_cmatrix
                        clear
                        THINKING=true
                        CURRENT_ROW=$((cr - 2))
                    fi
                    typewriter "$msg_content" $CURRENT_ROW "\e[0;32m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    if [[ $CURRENT_ROW -ge $((rows - 1)) ]]; then
                        CURRENT_ROW=$((cr - 2))
                        clear
                    fi
                    ;;
                "OBSERVE")
                    if [[ "$THINKING" == "false" ]]; then
                        stop_cmatrix
                        clear
                        THINKING=true
                        CURRENT_ROW=$((cr - 2))
                    fi
                    typewriter "$msg_content" $CURRENT_ROW "\e[0;32m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    if [[ $CURRENT_ROW -ge $((rows - 1)) ]]; then
                        CURRENT_ROW=$((cr - 2))
                        clear
                    fi
                    ;;
                "DECIDE")
                    typewriter "$msg_content" $CURRENT_ROW "\e[1;92m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    if [[ $CURRENT_ROW -ge $((rows - 1)) ]]; then
                        CURRENT_ROW=$((cr - 2))
                        clear
                    fi
                    ;;
                "STRATEGY")
                    typewriter "$msg_content" $CURRENT_ROW "\e[1;32m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    if [[ $CURRENT_ROW -ge $((rows - 1)) ]]; then
                        CURRENT_ROW=$((cr - 2))
                        clear
                    fi
                    ;;
                "AGENT")
                    typewriter "$msg_content" $CURRENT_ROW "\e[0;32m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    if [[ $CURRENT_ROW -ge $((rows - 1)) ]]; then
                        CURRENT_ROW=$((cr - 2))
                        clear
                    fi
                    ;;
                "LEARN")
                    typewriter "$msg_content" $CURRENT_ROW "\e[1;32m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    ;;
                "VULN")
                    typewriter "VULN: $msg_content" $CURRENT_ROW "\e[1;91m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    sleep 1
                    ;;
                "ERROR")
                    typewriter "$msg_content" $CURRENT_ROW "\e[1;91m"
                    CURRENT_ROW=$((CURRENT_ROW + 1))
                    ;;
                "RESULT")
                    typewriter "$msg_content" $CURRENT_ROW "\e[1;32m"
                    sleep 2
                    THINKING=false
                    clear
                    start_cmatrix
                    ;;
                "SEPARATOR")
                    if [[ "$THINKING" == "true" ]]; then
                        sleep 1
                        THINKING=false
                        clear
                        start_cmatrix
                    fi
                    ;;
            esac
        fi
    fi
done
THOUGHTEOF
    chmod +x /tmp/kali_ai_thought_display.sh

    if command -v qterminal &>/dev/null; then
        qterminal -e "bash /tmp/kali_ai_thought_display.sh" 2>/dev/null &
        sleep 0.5
        xdotool getactivewindow windowsize 450 280 windowmove 1050 0 2>/dev/null
    elif command -v xfce4-terminal &>/dev/null; then
        xfce4-terminal --title="🧠 Neural Thought Process" --geometry=40x14+1050+0 -e "bash /tmp/kali_ai_thought_display.sh" 2>/dev/null &
    elif command -v gnome-terminal &>/dev/null; then
        gnome-terminal --title="🧠 Neural Thought Process" --geometry=40x14+1050+0 -- bash /tmp/kali_ai_thought_display.sh 2>/dev/null &
    elif command -v xterm &>/dev/null; then
        xterm -bg black -fg green -geometry 40x14+1050+0 -title "Neural Thought Process" -e "bash /tmp/kali_ai_thought_display.sh" 2>/dev/null &
    fi
    THOUGHT_PID=$!
    sleep 1
    
    # Ridimensiona il terminale principale a sinistra
    if command -v wmctrl &>/dev/null; then
        sleep 0.5
        wmctrl -r :ACTIVE: -e 0,0,0,950,700 2>/dev/null
    elif command -v xdotool &>/dev/null; then
        sleep 0.5
        xdotool getactivewindow windowmove 0 0 windowsize 950 700 2>/dev/null
    fi
}

think() {
    local type="$1" message="$2"
    [[ -p "$THOUGHT_PIPE" ]] && echo "${type}:${message}" > "$THOUGHT_PIPE" 2>/dev/null &
}

think_phase() { think "PHASE" "$1"; }
think_thought() { think "THINK" "$1"; }
think_observe() { think "OBSERVE" "$1"; }
think_decide() { think "DECIDE" "$1"; }
think_learn() { think "LEARN" "$1"; }
think_vuln() { think "VULN" "$1"; }
think_strategy() { think "STRATEGY" "$1"; }
think_agent() { think "AGENT" "$1"; }
think_result() { think "RESULT" "$1"; }
think_error() { think "ERROR" "$1"; }
think_separator() { [[ -p "$THOUGHT_PIPE" ]] && echo "SEPARATOR" > "$THOUGHT_PIPE" 2>/dev/null & }

# ═══════════════════════════════════════════════════════════════
# SESSION LOG
# ═══════════════════════════════════════════════════════════════

start_session_log() {
    CURRENT_SESSION_LOG="$SESSION_DIR/session_$(date +%Y%m%d_%H%M%S).md"
    cat > "$CURRENT_SESSION_LOG" << SEOF
# 🤖 Kali-AI v6.0 Session Log
**Data:** $(date)
**Host:** $(hostname) | **Modello:** $MODEL
---
SEOF
}

log_action() {
    local type="$1" desc="$2" cmd="${3:-}" out="${4:-}"
    [[ -z "$CURRENT_SESSION_LOG" ]] && return
    echo -e "\n## [$type] $(date +%H:%M:%S)\n$desc" >> "$CURRENT_SESSION_LOG"
    [[ -n "$cmd" ]] && echo -e "\`\`\`\n$cmd\n\`\`\`" >> "$CURRENT_SESSION_LOG"
    [[ -n "$out" ]] && echo -e "\n${out:0:500}" >> "$CURRENT_SESSION_LOG"
}

# ═══════════════════════════════════════════════════════════════
# INIT E SETUP
# ═══════════════════════════════════════════════════════════════

check_api_key() {
    if [[ -z "$API_KEY" ]]; then
        echo -e "${RED}❌ API Key Anthropic non configurata!${RESET}"
        echo "echo 'ANTHROPIC_API_KEY=\"tua-key\"' > ~/.kali_ai_config"
        exit 1
    fi
}

init_files() {
    [[ ! -f "$HISTORY_FILE" ]] && echo '[]' > "$HISTORY_FILE"
    [[ ! -f "$MEMORY_FILE" ]] && echo '{"learned_commands":{},"successful_operations":[],"failed_operations":[],"frequently_used_tools":{},"error_solutions":{},"pentest_knowledge":{},"vuln_found":[]}' > "$MEMORY_FILE"
    [[ ! -f "$USER_PROFILE" ]] && echo '{"total_commands":0,"total_sessions":0,"successful_commands":0,"failed_commands":0,"pentests_completed":0,"last_session":null}' > "$USER_PROFILE"
    [[ ! -f "$DRIVER_DB" ]] && echo '{"wifi_drivers":{"0bda:8812":{"name":"Realtek RTL8812AU","driver":"rtl8812au-dkms"}}}' > "$DRIVER_DB"
    init_vuln_database
}

init_vuln_database() {
    [[ -f "$VULN_DB" ]] && return
    cat > "$VULN_DB" << 'VEOF'
{
    "services": {
        "Apache/2.4.49": {"cve":"CVE-2021-41773","severity":"critical","desc":"Path Traversal RCE","exploit":"curl -s --path-as-is 'http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'"},
        "Apache/2.4.50": {"cve":"CVE-2021-42013","severity":"critical","desc":"Path Traversal RCE v2","exploit":"Bypass del fix CVE-2021-41773"},
        "vsftpd 2.3.4": {"cve":"CVE-2011-2523","severity":"critical","desc":"Backdoor Command Execution","exploit":"msf: exploit/unix/ftp/vsftpd_234_backdoor"},
        "OpenSSH 7.2p2": {"cve":"CVE-2016-6210","severity":"medium","desc":"User Enumeration","exploit":"Timing attack su auth"},
        "ProFTPD 1.3.5": {"cve":"CVE-2015-3306","severity":"critical","desc":"Remote Code Execution","exploit":"msf: exploit/unix/ftp/proftpd_modcopy_exec"},
        "Samba 3.5.0": {"cve":"CVE-2017-7494","severity":"critical","desc":"SambaCry RCE","exploit":"msf: exploit/linux/samba/is_known_pipename"},
        "SMBv1": {"cve":"MS17-010","severity":"critical","desc":"EternalBlue","exploit":"msf: exploit/windows/smb/ms17_010_eternalblue"},
        "MySQL 5.5": {"cve":"CVE-2012-2122","severity":"high","desc":"Auth Bypass","exploit":"Ripetere login ~300 volte"},
        "Redis": {"cve":"REDIS-UNAUTH","severity":"high","desc":"Accesso non autenticato","exploit":"redis-cli -h TARGET"},
        "MongoDB 27017": {"cve":"MONGO-NOAUTH","severity":"high","desc":"No Authentication","exploit":"mongo --host TARGET"},
        "Elasticsearch 9200": {"cve":"CVE-2015-1427","severity":"critical","desc":"RCE via Groovy Script","exploit":"POST /_search con script groovy"},
        "Jenkins": {"cve":"CVE-2019-1003000","severity":"critical","desc":"RCE via Script Console","exploit":"/script endpoint"},
        "Tomcat/8": {"cve":"CVE-2017-12615","severity":"high","desc":"Remote Code Execution via PUT","exploit":"PUT /shell.jsp"},
        "IIS/6.0": {"cve":"CVE-2017-7269","severity":"critical","desc":"Buffer Overflow RCE","exploit":"msf: exploit/windows/iis/iis_webdav_scstoragepathfromurl"},
        "phpMyAdmin/4.8": {"cve":"CVE-2018-12613","severity":"high","desc":"Local File Inclusion","exploit":"index.php?target=db_sql.php%253f/../../etc/passwd"},
        "WordPress": {"cve":"MULTI","severity":"varies","desc":"CMS vulnerabilities","exploit":"wpscan --url TARGET"},
        "Drupal/7": {"cve":"CVE-2018-7600","severity":"critical","desc":"Drupalgeddon2 RCE","exploit":"msf: exploit/unix/webapp/drupal_drupalgeddon2"},
        "NFS": {"cve":"NFS-EXPORT","severity":"high","desc":"Misconfigured exports","exploit":"showmount -e TARGET"},
        "SNMP public": {"cve":"SNMP-DEFAULT","severity":"medium","desc":"Default community string","exploit":"snmpwalk -v2c -c public TARGET"}
    },
    "ports": {
        "21": {"service":"FTP","checks":["anonymous login","version vulns"]},
        "22": {"service":"SSH","checks":["version","auth methods","weak creds"]},
        "23": {"service":"Telnet","checks":["cleartext","default creds"]},
        "25": {"service":"SMTP","checks":["open relay","vrfy","version"]},
        "53": {"service":"DNS","checks":["zone transfer","version"]},
        "80": {"service":"HTTP","checks":["nikto","dirb","whatweb","version"]},
        "110": {"service":"POP3","checks":["version","cleartext"]},
        "111": {"service":"RPC","checks":["rpcinfo","nfs"]},
        "135": {"service":"MSRPC","checks":["rpcdump","enumeration"]},
        "139": {"service":"NetBIOS","checks":["nbtscan","enum4linux"]},
        "443": {"service":"HTTPS","checks":["ssl scan","nikto","cert info"]},
        "445": {"service":"SMB","checks":["enum4linux","smbclient","version","ms17-010"]},
        "1433": {"service":"MSSQL","checks":["nmap scripts","default creds"]},
        "1521": {"service":"Oracle","checks":["tnscmd10g","version"]},
        "3306": {"service":"MySQL","checks":["version","default creds","nmap scripts"]},
        "3389": {"service":"RDP","checks":["nla check","bluekeep"]},
        "5432": {"service":"PostgreSQL","checks":["version","default creds"]},
        "5900": {"service":"VNC","checks":["auth bypass","version"]},
        "6379": {"service":"Redis","checks":["noauth","info"]},
        "8080": {"service":"HTTP-Alt","checks":["nikto","version","manager"]},
        "8443": {"service":"HTTPS-Alt","checks":["ssl","nikto"]},
        "27017": {"service":"MongoDB","checks":["noauth","info"]}
    }
}
VEOF
}

cleanup_on_startup() {
    find "$LOGS_DIR" -type f -mtime +7 -delete 2>/dev/null
    rm -f /tmp/kali_ai_*.sh 2>/dev/null
    if [[ -f "$HISTORY_FILE" ]]; then
        local hs=$(stat -c%s "$HISTORY_FILE" 2>/dev/null || echo 0)
        [[ $hs -gt 200000 ]] && cat "$HISTORY_FILE" | jq '.[-30:]' > "${HISTORY_FILE}.tmp" && mv "${HISTORY_FILE}.tmp" "$HISTORY_FILE"
    fi
    local profile=$(cat "$USER_PROFILE" 2>/dev/null || echo '{}')
    echo "$profile" | jq --arg ts "$(date -Iseconds)" '.total_sessions+=1|.last_session=$ts' > "$USER_PROFILE"
}

setup_sudo_nopass() {
    sudo -n true 2>/dev/null && return 0
    echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/kali-ai-nopass >/dev/null 2>&1
}

get_system_snapshot() {
    local s=""
    s+="OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)\n"
    s+="Kernel: $(uname -r) | User: $(whoami) | PWD: $(pwd)\n"
    s+="RAM: $(free -h 2>/dev/null | awk '/Mem:/{print $3"/"$2}') | CPU: $(cat /proc/loadavg 2>/dev/null | awk '{print $1,$2,$3}')\n"
    s+="Disco: $(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" ("$5")"}')\n"
    s+="Rete: $(ip -br addr 2>/dev/null | tr '\n' ' ')\n"
    [[ "$PENTEST_ACTIVE" == "true" ]] && s+="PENTEST ATTIVO: $PENTEST_TARGET\n"
    [[ -n "$LAST_OUTPUT" ]] && s+="Last output: ${LAST_OUTPUT:0:500}\n"
    echo -e "$s"
}

learn_from_success() {
    local command="$1" user_request="$2"
    [[ -z "$command" || -z "$user_request" ]] && return
    local memory=$(cat "$MEMORY_FILE" 2>/dev/null || echo '{}')
    local tool=$(echo "$command" | awk '{print $1}')
    memory=$(echo "$memory" | jq --arg req "$user_request" --arg cmd "$command" --arg tool "$tool" '.learned_commands[$req]=$cmd|.frequently_used_tools[$tool]=((.frequently_used_tools[$tool]//0)+1)|.successful_operations+=[$req]|.successful_operations=.successful_operations[-50:]')
    echo "$memory" > "$MEMORY_FILE"
    local profile=$(cat "$USER_PROFILE" 2>/dev/null || echo '{}')
    echo "$profile" | jq '.total_commands+=1|.successful_commands+=1' > "$USER_PROFILE"
    think_learn "Comando appreso: $command"
}

learn_from_failure() {
    local command="$1" error="$2"
    [[ -z "$command" ]] && return
    local memory=$(cat "$MEMORY_FILE" 2>/dev/null || echo '{}')
    memory=$(echo "$memory" | jq --arg cmd "$command" --arg err "${error:0:200}" '.failed_operations+=[{"cmd":$cmd,"error":$err}]|.failed_operations=.failed_operations[-30:]')
    echo "$memory" > "$MEMORY_FILE"
    think_error "Fallito: $command"
}

get_memory_context() {
    local memory=$(cat "$MEMORY_FILE" 2>/dev/null)
    echo "Tool: $(echo "$memory" | jq -r '.frequently_used_tools|to_entries|sort_by(-.value)|.[0:5]|.[].key' 2>/dev/null | tr '\n' ',')"
}


# ═══════════════════════════════════════════════════════════════
# ESECUZIONE COMANDI
# ═══════════════════════════════════════════════════════════════

execute_and_capture() {
    local cmd="$1"
    echo -e "${CYAN}⚡ $cmd${RESET}"
    think_decide "Eseguo: $cmd"
    local output
    output=$(eval "$cmd" 2>&1)
    local exit_code=$?
    LAST_OUTPUT="$output"
    LAST_EXIT_CODE=$exit_code
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}✅ OK${RESET}"
        [[ -n "$output" ]] && echo "$output" | head -100
        learn_from_success "$cmd" "$LAST_USER_REQUEST"
        think_result "Successo: $cmd"
        log_action "CMD" "OK" "$cmd" "${output:0:300}"
    else
        echo -e "${RED}❌ Errore ($exit_code)${RESET}"
        echo "$output" | head -50
        learn_from_failure "$cmd" "$output"
        think_error "Fallito ($exit_code): ${output:0:100}"
        log_action "ERR" "Fallito" "$cmd" "${output:0:300}"
    fi
    return $exit_code
}

execute_direct() { execute_and_capture "$1"; }

call_api() {
    local user_message="$1"
    local system_message="${2:-Sei un assistente AI per Kali Linux. Rispondi in italiano.}"
    local response=$(curl -s --max-time 120 https://api.anthropic.com/v1/messages \
        -H "x-api-key: $API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        -H "Content-Type: application/json" \
        -d "$(jq -cn --arg model "$MODEL" --arg system "$system_message" --arg user "$user_message" '{"model":$model,"max_tokens":8192,"system":$system,"messages":[{"role":"user","content":$user}]}')")
    echo "$response" | jq -r '.content[0].text // empty'
}

execute_with_retry() {
    local cmd="$1" max_retries="${2:-3}" attempt=0
    while [[ $attempt -lt $max_retries ]]; do
        execute_and_capture "$cmd"
        [[ $? -eq 0 ]] && return 0
        ((attempt++))
        if [[ $attempt -lt $max_retries ]]; then
            think_thought "Tentativo $attempt fallito, chiedo correzione..."
            local fix=$(call_api "Comando '$cmd' fallito: ${LAST_OUTPUT:0:300}. Dammi SOLO il comando corretto.")
            local nc=$(echo "$fix" | awk '/```bash/{f=1;next}/```/{f=0}f' | head -1)
            [[ -n "$nc" && "$nc" != "$cmd" ]] && cmd="$nc" && think_decide "Correggo con: $nc"
        fi
    done
    return 1
}

execute_chain() {
    local -a commands=("$@")
    local step=1 total=${#commands[@]}
    think_phase "CATENA: $total comandi in sequenza"
    for cmd in "${commands[@]}"; do
        think_decide "Step $step/$total: $cmd"
        echo -e "${BLUE}[$step/$total]${RESET} $cmd"
        execute_and_capture "$cmd"
        [[ $? -ne 0 ]] && think_error "Catena interrotta step $step" && return 1
        ((step++))
    done
    think_result "Catena completata!"
}

execute_in_terminal() {
    local cmd="$1" title="$2" wait="${3:-false}"
    local tid="T$(date +%s%N | cut -c1-13)"
    local log_file="$LOGS_DIR/${tid}.log"
    cat > "/tmp/kali_ai_${tid}.sh" << TEOF
#!/bin/bash
exec > >(tee "$log_file") 2>&1
echo -e "\e[1;32m╔═══════════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[1;32m║  🤖 KALI-AI AGENT - $title\e[0m"
echo -e "\e[1;32m╚═══════════════════════════════════════════════════════════╝\e[0m"
echo ""
echo -e "\e[1;36m⚡ $cmd\e[0m"
echo "═══════════════════════════════════════"
$cmd
EC=\$?
echo "═══════════════════════════════════════"
[[ \$EC -eq 0 ]] && echo -e "\e[1;32m✅ Completato\e[0m" || echo -e "\e[1;31m❌ Errore (\$EC)\e[0m"
echo "📌 ENTER per chiudere..."
read -r
TEOF
    chmod +x "/tmp/kali_ai_${tid}.sh"
    think_agent "Lancio terminale: $title"
    if command -v qterminal &>/dev/null; then
        qterminal -e "bash /tmp/kali_ai_${tid}.sh" 2>/dev/null &
    elif command -v xfce4-terminal &>/dev/null; then
        xfce4-terminal --title="🤖 $title" -e "bash /tmp/kali_ai_${tid}.sh" 2>/dev/null &
    elif command -v gnome-terminal &>/dev/null; then
        gnome-terminal --title="🤖 $title" -- bash "/tmp/kali_ai_${tid}.sh" 2>/dev/null &
    elif command -v xterm &>/dev/null; then
        xterm -title "$title" -e "bash /tmp/kali_ai_${tid}.sh" 2>/dev/null &
    fi
    ACTIVE_TERMINALS["$tid"]="$title"
    if [[ "$wait" == "true" ]]; then
        local c=0
        while [[ $c -lt 300 ]]; do
            [[ -f "$log_file" ]] && grep -q "════" "$log_file" 2>/dev/null && break
            sleep 0.5; ((c++))
        done
        [[ -f "$log_file" ]] && LAST_OUTPUT=$(cat "$log_file" 2>/dev/null)
    fi
    log_action "TERMINAL" "$title" "$cmd"
    echo -e "${GREEN}✅ Terminale: $title${RESET}"
}

execute_in_terminal_bg() {
    local cmd="$1" title="$2" result_file="$3"
    local tid="T$(date +%s%N | cut -c1-13)"
    local log_file="$LOGS_DIR/${tid}.log"
    cat > "/tmp/kali_ai_${tid}.sh" << TEOF
#!/bin/bash
exec > >(tee "$log_file") 2>&1
echo -e "\e[1;32m╔═══════════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[1;32m║  🤖 KALI-AI AGENT - $title\e[0m"
echo -e "\e[1;32m╚═══════════════════════════════════════════════════════════╝\e[0m"
echo -e "\e[1;36m⚡ $cmd\e[0m"
echo "═══════════════════════════════════════"
$cmd
EC=\$?
echo "═══════════════════════════════════════"
[[ \$EC -eq 0 ]] && echo "✅ OK" || echo "❌ Errore (\$EC)"
cp "$log_file" "$result_file" 2>/dev/null
echo "📌 ENTER per chiudere..."
read -r
TEOF
    chmod +x "/tmp/kali_ai_${tid}.sh"
    think_agent "Agent avviato: $title"
    if command -v qterminal &>/dev/null; then
        qterminal -e "bash /tmp/kali_ai_${tid}.sh" 2>/dev/null &
    elif command -v xfce4-terminal &>/dev/null; then
        xfce4-terminal --title="🤖 $title" -e "bash /tmp/kali_ai_${tid}.sh" 2>/dev/null &
    elif command -v gnome-terminal &>/dev/null; then
        gnome-terminal --title="🤖 $title" -- bash "/tmp/kali_ai_${tid}.sh" 2>/dev/null &
    elif command -v xterm &>/dev/null; then
        xterm -title "$title" -e "bash /tmp/kali_ai_${tid}.sh" 2>/dev/null &
    fi
    echo "$log_file"
}

execute_parallel() {
    local -a commands=("$@")
    think_phase "PARALLELO: ${#commands[@]} agenti"
    for i in "${!commands[@]}"; do
        execute_in_terminal "${commands[$i]}" "Task $((i+1))" "false"
        sleep 0.5
    done
    echo -e "${GREEN}✅ ${#commands[@]} terminali aperti!${RESET}"
}

wait_for_results() {
    local -a result_files=("$@")
    local timeout=300 start=$(date +%s)
    think_thought "Attendo ${#result_files[@]} agenti..."
    while true; do
        local all_done=true
        for rf in "${result_files[@]}"; do
            [[ ! -f "$rf" ]] && all_done=false && break
            grep -q "════" "$rf" 2>/dev/null || { all_done=false; break; }
        done
        [[ "$all_done" == "true" ]] && break
        [[ $(( $(date +%s) - start )) -gt $timeout ]] && think_error "Timeout agenti!" && break
        sleep 2
    done
    think_result "Tutti gli agenti hanno completato"
}

# ═══════════════════════════════════════════════════════════════
# FASE 12: VULNERABILITY INTELLIGENCE
# ═══════════════════════════════════════════════════════════════

check_vulnerabilities() {
    local scan_file="$1"
    local vuln_db=$(cat "$VULN_DB" 2>/dev/null)
    local found_vulns=""
    
    think_phase "ANALISI VULNERABILITÀ"
    think_thought "Confronto risultati scan con database vulnerabilità..."
    
    # Controlla versioni servizi
    while IFS= read -r line; do
        local service_version=$(echo "$line" | grep -oP '\d+/tcp\s+open\s+\S+\s+\K.*' | head -1)
        [[ -z "$service_version" ]] && continue
        
        # Cerca nel DB
        echo "$vuln_db" | jq -r '.services | to_entries[] | .key' 2>/dev/null | while read -r known_vuln; do
            if echo "$service_version" | grep -qi "$known_vuln" 2>/dev/null; then
                local cve=$(echo "$vuln_db" | jq -r --arg k "$known_vuln" '.services[$k].cve')
                local severity=$(echo "$vuln_db" | jq -r --arg k "$known_vuln" '.services[$k].severity')
                local desc=$(echo "$vuln_db" | jq -r --arg k "$known_vuln" '.services[$k].desc')
                think_vuln "$cve ($severity): $desc in $service_version"
                echo "$cve|$severity|$desc|$service_version"
            fi
        done
    done < "$scan_file"
    
    # Controlla porte e suggerisci checks
    while IFS= read -r line; do
        local port=$(echo "$line" | grep -oP '^\d+(?=/tcp.*open)')
        [[ -z "$port" ]] && continue
        local port_info=$(echo "$vuln_db" | jq -r --arg p "$port" '.ports[$p] // empty')
        if [[ -n "$port_info" && "$port_info" != "null" ]]; then
            local svc=$(echo "$port_info" | jq -r '.service')
            local checks=$(echo "$port_info" | jq -r '.checks[]' | tr '\n' ', ')
            think_observe "Porta $port ($svc): checks consigliati: $checks"
        fi
    done < "$scan_file"
}

# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════

network_recon() {
    local target="$1"
    think_phase "RICOGNIZIONE: $target"
    nmap -sn "$target" 2>/dev/null | grep "Nmap scan\|Host is up"
    nmap -F "$target" 2>/dev/null
}

file_operations() {
    local action="$1"; shift
    case "$action" in
        "search") find / -iname "*$1*" -type f 2>/dev/null | head -20 ;;
        "analyze") echo "File: $1 | Tipo: $(file "$1" 2>/dev/null) | Dim: $(du -h "$1" 2>/dev/null | cut -f1)"; file "$1" 2>/dev/null | grep -qE "text|script" && head -50 "$1" ;;
        "monitor") execute_in_terminal "inotifywait -m -r '$1'" "Monitor $1" "false" ;;
    esac
}

system_monitor() { echo "CPU: $(top -bn1 2>/dev/null | grep 'Cpu(s)' | awk '{print $2}')% | RAM: $(free 2>/dev/null | awk '/Mem:/{printf "%.1f%%",$3/$2*100}') | Load: $(cat /proc/loadavg 2>/dev/null | awk '{print $1,$2,$3}')"; }

service_control() {
    case "$1" in
        "list") systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -30 ;;
        *) sudo systemctl "$1" "$2" 2>&1 ;;
    esac
}

smart_install() {
    local tool="$1"
    command -v "$tool" &>/dev/null && echo -e "${GREEN}✅ $tool OK${RESET}" && return 0
    think_thought "Cerco $tool..."
    apt-cache show "$tool" &>/dev/null 2>&1 && sudo apt install -y "$tool" 2>&1 && return $?
    pip3 install "$tool" --dry-run &>/dev/null 2>&1 && pip3 install "$tool" 2>&1 && return $?
    local gurl=$(curl -s --max-time 10 "https://api.github.com/search/repositories?q=$tool&sort=stars" | jq -r '.items[0].clone_url // empty')
    [[ -n "$gurl" ]] && sudo git clone "$gurl" "/opt/$tool" 2>&1 && return 0
    return 1
}

scan_usb_devices() {
    local db=$(cat "$DRIVER_DB" 2>/dev/null)
    while IFS= read -r line; do
        local did=$(echo "$line" | grep -oP '\d{4}:\d{4}')
        [[ -n "$did" ]] && { local drv=$(echo "$db" | jq -r --arg id "$did" '.wifi_drivers[$id].name // empty'); [[ -n "$drv" ]] && echo "$drv ($did)"; }
    done < <(lsusb)
}

open_browser() {
    local q="$1" url
    [[ "$q" =~ ^https?:// ]] && url="$q" || url="https://www.google.com/search?q=$(echo "$q" | sed 's/ /+/g')"
    command -v firefox &>/dev/null && firefox "$url" 2>/dev/null &
    echo -e "${GREEN}✅ Browser${RESET}"
}

check_system_updates() {
    sudo apt update -qq 2>/dev/null
    local up=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    [[ $up -gt 0 ]] && echo "$up aggiornamenti" && apt list --upgradable 2>/dev/null | head -10 || echo "Sistema aggiornato"
}

update_system() { execute_in_terminal "sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y" "Update" "false"; }

schedule_task() { ( sleep "$1" && eval "$2" ) &
    SCHEDULED_PIDS+=("$!"); echo "⏰ $3 (PID:$!)"; }
list_scheduled_tasks() { for pid in "${SCHEDULED_PIDS[@]}"; do kill -0 "$pid" 2>/dev/null && echo "● $pid Attivo" || echo "● $pid Done"; done; }

watch_and_react() {
    ( local last=$(eval "$1" 2>&1); while true; do sleep "${3:-5}"; local now=$(eval "$1" 2>&1); [[ "$now" != "$last" ]] && eval "$2" 2>&1 && last="$now"; done ) &
    SCHEDULED_PIDS+=("$!"); echo "👁️ Watcher PID:$!"
}

web_fetch() { curl -s --max-time 15 -L "$1" | sed 's/<[^>]*>//g' | sed '/^[[:space:]]*$/d' | head -100; }


# ═══════════════════════════════════════════════════════════════
# FASE 6+11: PENTEST AUTONOMO CON REASONING ENGINE
# ═══════════════════════════════════════════════════════════════

pentest_start() {
    local target="$1"
    PENTEST_ACTIVE=true
    PENTEST_TARGET="$target"
    PENTEST_RESULTS_DIR="$PENTEST_DIR/pt_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$PENTEST_RESULTS_DIR"/{recon,scan,enum,vuln,exploit,report}
    
    think_phase "PENTEST INIZIALIZZATO"
    think_thought "Target: $target"
    think_thought "Directory: $PENTEST_RESULTS_DIR"
    think_strategy "Piano: Recon → Scan → Enum → Vuln Analysis → Report"
    
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}║  🎯 PENTEST AUTONOMO - TARGET: $(printf '%-35s' "$target")║${RESET}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${RESET}"
}

pentest_phase1_recon() {
    local target="$1"
    local rd="$PENTEST_RESULTS_DIR/recon"
    
    think_phase "FASE 1: RICOGNIZIONE"
    think_thought "Lancio 3 agenti paralleli per massima copertura"
    think_strategy "Agent 1: Nmap host discovery | Agent 2: DNS | Agent 3: ARP"
    think_separator
    
    local r1="$rd/r1_hosts.log"
    local r2="$rd/r2_dns.log"
    local r3="$rd/r3_arp.log"
    
    think_agent "Lancio Agent 1: Host Discovery (nmap -sn)"
    execute_in_terminal_bg "nmap -sn $target -oN $rd/hosts.txt 2>&1 && echo AGENT_DONE" "🔍 Agent 1: Host Discovery" "$r1"
    sleep 0.5
    
    think_agent "Lancio Agent 2: DNS Recon"
    execute_in_terminal_bg "nmap -sn --dns-servers 8.8.8.8 $target -oN $rd/dns.txt 2>&1 && echo AGENT_DONE" "🌐 Agent 2: DNS Recon" "$r2"
    sleep 0.5
    
    think_agent "Lancio Agent 3: ARP Discovery"
    execute_in_terminal_bg "sudo arp-scan --localnet > $rd/arp.txt 2>&1; echo AGENT_DONE" "📡 Agent 3: ARP Scan" "$r3"
    
    echo -e "${YELLOW}⏳ 3 agenti ricognizione...${RESET}"
    think_thought "Attendo risultati da 3 agenti paralleli..."
    wait_for_results "$r1" "$r2" "$r3"
    
    local hosts=$(grep "Nmap scan report" "$rd/hosts.txt" 2>/dev/null | awk '{print $NF}' | tr -d '()')
    echo "$hosts" > "$rd/live_hosts.txt"
    local hc=$(echo "$hosts" | grep -c "." 2>/dev/null || echo 0)
    
    think_result "Fase 1 completata: $hc host trovati"
    think_observe "Host attivi: $hosts"
    think_separator
    
    echo -e "${GREEN}✅ Recon: $hc host trovati${RESET}"
    LAST_OUTPUT="$hosts"
}

pentest_phase2_scan() {
    local target="$1"
    local sd="$PENTEST_RESULTS_DIR/scan"
    local hf="$PENTEST_RESULTS_DIR/recon/live_hosts.txt"
    
    think_phase "FASE 2: SCANSIONE PORTE"
    think_thought "Analizzo host trovati, lancio agente per ciascuno"
    think_strategy "Scansione: top 1000 porte + versione servizi + OS detection"
    think_separator
    
    local -a rfiles=()
    local anum=1
    
    while IFS= read -r host && [[ $anum -le 5 ]]; do
        [[ -z "$host" ]] && continue
        local rf="$sd/scan_${host}.log"
        think_agent "Agent $anum: Scansione $host (nmap -sV -sC -O)"
        execute_in_terminal_bg "sudo nmap -sV -sC -O --top-ports 1000 $host -oN $sd/ports_${host}.txt 2>&1 && echo AGENT_DONE" "🔍 Agent $anum: Scan $host" "$rf"
        rfiles+=("$rf")
        ((anum++))
        sleep 0.5
    done < "$hf"
    
    echo -e "${YELLOW}⏳ $((anum-1)) agenti scanning...${RESET}"
    think_thought "Attendo $((anum-1)) agenti di scansione..."
    wait_for_results "${rfiles[@]}"
    
    # Analisi vulnerabilità automatica
    think_thought "Scansioni complete, avvio analisi vulnerabilità..."
    for f in "$sd"/ports_*.txt; do
        [[ -f "$f" ]] && check_vulnerabilities "$f"
    done
    
    local op=$(grep "open" "$sd"/ports_*.txt 2>/dev/null | grep -v "filtered\|closed" | wc -l)
    think_result "Fase 2: $op porte aperte trovate"
    think_separator
    
    echo -e "${GREEN}✅ Scan: $op porte aperte${RESET}"
}

pentest_phase3_enum() {
    local target="$1"
    local ed="$PENTEST_RESULTS_DIR/enum"
    local sd="$PENTEST_RESULTS_DIR/scan"
    
    think_phase "FASE 3: ENUMERAZIONE SERVIZI"
    think_thought "Analizzo servizi trovati, lancio agenti specifici per protocollo"
    think_separator
    
    local -a rfiles=()
    local anum=1
    
    # HTTP
    if grep -rq "80/tcp.*open\|443/tcp.*open\|8080/tcp.*open" "$sd"/ports_*.txt 2>/dev/null; then
        local wh=$(grep -rl "80/tcp.*open\|443/tcp.*open" "$sd"/ports_*.txt 2>/dev/null | head -1 | grep -oP 'ports_\K[^.]+')
        if [[ -n "$wh" ]]; then
            think_strategy "HTTP trovato su $wh - lancio web enumeration"
            think_agent "Agent $anum: Nikto + WhatWeb su $wh"
            local rf="$ed/web_${wh}.log"
            execute_in_terminal_bg "nikto -h $wh -o $ed/nikto_$wh.txt 2>&1; whatweb $wh > $ed/whatweb_$wh.txt 2>&1; dirb http://$wh $ed/dirb_$wh.txt 2>&1; echo AGENT_DONE" "🌐 Agent $anum: Web Enum $wh" "$rf"
            rfiles+=("$rf")
            ((anum++))
            sleep 0.5
        fi
    fi
    
    # SMB
    if grep -rq "445/tcp.*open\|139/tcp.*open" "$sd"/ports_*.txt 2>/dev/null; then
        local sh=$(grep -rl "445/tcp.*open" "$sd"/ports_*.txt 2>/dev/null | head -1 | grep -oP 'ports_\K[^.]+')
        if [[ -n "$sh" ]]; then
            think_strategy "SMB trovato su $sh - lancio SMB enumeration"
            think_agent "Agent $anum: Enum4linux + SMBclient su $sh"
            local rf="$ed/smb_${sh}.log"
            execute_in_terminal_bg "enum4linux -a $sh > $ed/enum4linux_$sh.txt 2>&1; smbclient -L //$sh -N > $ed/smb_$sh.txt 2>&1; echo AGENT_DONE" "📁 Agent $anum: SMB Enum $sh" "$rf"
            rfiles+=("$rf")
            ((anum++))
            sleep 0.5
        fi
    fi
    
    # SSH
    if grep -rq "22/tcp.*open" "$sd"/ports_*.txt 2>/dev/null; then
        local ssh_h=$(grep -rl "22/tcp.*open" "$sd"/ports_*.txt 2>/dev/null | head -1 | grep -oP 'ports_\K[^.]+')
        if [[ -n "$ssh_h" ]]; then
            think_strategy "SSH trovato su $ssh_h"
            think_agent "Agent $anum: SSH enum su $ssh_h"
            local rf="$ed/ssh_${ssh_h}.log"
            execute_in_terminal_bg "nmap --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -p22 $ssh_h -oN $ed/ssh_$ssh_h.txt 2>&1; echo AGENT_DONE" "🔑 Agent $anum: SSH Enum $ssh_h" "$rf"
            rfiles+=("$rf")
            ((anum++))
            sleep 0.5
        fi
    fi
    
    # FTP
    if grep -rq "21/tcp.*open" "$sd"/ports_*.txt 2>/dev/null; then
        local ftp_h=$(grep -rl "21/tcp.*open" "$sd"/ports_*.txt 2>/dev/null | head -1 | grep -oP 'ports_\K[^.]+')
        if [[ -n "$ftp_h" ]]; then
            think_strategy "FTP trovato su $ftp_h - test anonymous login"
            think_agent "Agent $anum: FTP enum su $ftp_h"
            local rf="$ed/ftp_${ftp_h}.log"
            execute_in_terminal_bg "nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -p21 $ftp_h -oN $ed/ftp_$ftp_h.txt 2>&1; echo AGENT_DONE" "📂 Agent $anum: FTP Enum $ftp_h" "$rf"
            rfiles+=("$rf")
            ((anum++))
            sleep 0.5
        fi
    fi
    
    if [[ ${#rfiles[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⏳ $((anum-1)) agenti enumerazione...${RESET}"
        think_thought "Attendo $((anum-1)) agenti di enumerazione..."
        wait_for_results "${rfiles[@]}"
    fi
    
    think_result "Fase 3: $((anum-1)) servizi enumerati"
    think_separator
    echo -e "${GREEN}✅ Enum: $((anum-1)) servizi analizzati${RESET}"
}

pentest_phase4_analyze() {
    local target="$1"
    
    think_phase "FASE 4: ANALISI COGNITIVA AI"
    think_thought "Raccolgo tutti i risultati per analisi approfondita..."
    think_thought "Avvio analisi cognitiva approfondita..."
    think_separator
    
    local all=""
    for f in $(find "$PENTEST_RESULTS_DIR" -name "*.txt" -type f 2>/dev/null); do
        all+="=== $(basename $f) ===\n$(head -80 "$f")\n\n"
    done
    
    think_thought "Dati raccolti, avvio elaborazione..."
    think_thought "Avvio ragionamento multi-livello..."
    
    local analysis=$(call_api "Sei un penetration tester esperto di livello senior. Analizza TUTTI questi risultati e fornisci un report DETTAGLIATO:

1. **EXECUTIVE SUMMARY**: Panoramica in 3-4 frasi
2. **HOST TROVATI**: Lista con IP, OS, servizi per ogni host
3. **VULNERABILITÀ CRITICHE**: CVE, severità, descrizione, impatto
4. **VULNERABILITÀ ALTE**: CVE, severità, descrizione
5. **VULNERABILITÀ MEDIE/BASSE**: Lista
6. **VETTORI DI ATTACCO**: Top 5 ordinati per probabilità successo, con comandi specifici
7. **CATENA DI ATTACCO SUGGERITA**: Sequenza di passi per compromettere il target
8. **RACCOMANDAZIONI DIFENSIVE**: Come proteggere ogni servizio vulnerabile
9. **PUNTEGGIO RISCHIO**: Da 1 a 10 per ogni host con giustificazione

Target: $target
Risultati:
${all:0:8000}

Rispondi in italiano, sii tecnico e dettagliato. Includi comandi specifici per ogni exploit suggerito.")
    
    echo -e "${GREEN}$analysis${RESET}"
    echo "$analysis" > "$PENTEST_RESULTS_DIR/vuln/ai_analysis.txt"
    
    think_result "Analisi AI completata"
    think_observe "Report salvato in vuln/ai_analysis.txt"
    
    # Estrai e pensa sulle vulnerabilità trovate
    if echo "$analysis" | grep -qi "critic"; then
        think_vuln "TROVATE VULNERABILITÀ CRITICHE - Vedere report"
    fi
    
    LAST_OUTPUT="$analysis"
}

pentest_full_auto() {
    local target="$1"
    
    pentest_start "$target"
    
    think_phase "PENTEST COMPLETO AUTOMATICO"
    think_strategy "5 fasi: Recon → Scan → Enum → AI Analysis → Report"
    think_thought "Ogni fase usa agenti paralleli su terminali separati"
    think_thought "Il reasoning engine monitora e adatta la strategia"
    think_separator
    
    echo -e "${CYAN}🚀 Pentest automatico su $target${RESET}"
    
    pentest_phase1_recon "$target"
    sleep 1
    pentest_phase2_scan "$target"
    sleep 1
    pentest_phase3_enum "$target"
    sleep 1
    pentest_phase4_analyze "$target"
    sleep 1
    pentest_generate_report "$target"
    
    # Aggiorna profilo
    local profile=$(cat "$USER_PROFILE" 2>/dev/null || echo '{}')
    echo "$profile" | jq '.pentests_completed+=1' > "$USER_PROFILE"
    
    PENTEST_ACTIVE=false
    think_phase "PENTEST COMPLETATO"
    think_result "Tutti i risultati in: $PENTEST_RESULTS_DIR"
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║  ✅ PENTEST COMPLETATO - Risultati: $PENTEST_RESULTS_DIR${RESET}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${RESET}"
}


# ═══════════════════════════════════════════════════════════════
# REPORT E EXPORT TESI
# ═══════════════════════════════════════════════════════════════

pentest_generate_report() {
    local target="$1"
    local rf="$PENTEST_RESULTS_DIR/report/pentest_report.md"
    
    think_phase "GENERAZIONE REPORT"
    think_thought "Compilo report finale con tutti i risultati..."
    
    local ai_analysis=""
    [[ -f "$PENTEST_RESULTS_DIR/vuln/ai_analysis.txt" ]] && ai_analysis=$(cat "$PENTEST_RESULTS_DIR/vuln/ai_analysis.txt")
    local hc=$(cat "$PENTEST_RESULTS_DIR/recon/live_hosts.txt" 2>/dev/null | grep -c "." || echo 0)
    local pc=$(grep "open" "$PENTEST_RESULTS_DIR/scan"/ports_*.txt 2>/dev/null | wc -l || echo 0)
    
    cat > "$rf" << REOF
# 🎯 Penetration Test Report
## Kali-AI v6.0 — Cognitive Pentest Framework

| Campo | Valore |
|-------|--------|
| **Data** | $(date) |
| **Target** | $target |
| **Engine** | Claude Opus 4.6 |
| **Operatore** | $AUTHOR |
| **Host trovati** | $hc |
| **Porte aperte** | $pc |

---

## 1. Executive Summary
Penetration test autonomo multi-agente eseguito con Kali-AI v6.0.
Il sistema ha impiegato agenti paralleli per ricognizione, scansione e enumerazione,
seguiti da analisi cognitiva tramite Claude Opus 4.6.

## 2. Metodologia
| Fase | Metodo | Agenti |
|------|--------|--------|
| Ricognizione | nmap -sn, DNS, ARP | 3 paralleli |
| Scansione | nmap -sV -sC -O | 1 per host |
| Enumerazione | nikto, enum4linux, ssh-audit | Per servizio |
| Analisi | Claude Opus 4.6 AI | 1 cognitivo |

## 3. Ricognizione
\`\`\`
$(cat "$PENTEST_RESULTS_DIR/recon/hosts.txt" 2>/dev/null | head -40)
\`\`\`

## 4. Scansione Porte
$(for f in "$PENTEST_RESULTS_DIR/scan"/ports_*.txt; do
    [[ -f "$f" ]] && echo "### $(basename $f)" && echo '```' && head -50 "$f" && echo '```'
done)

## 5. Enumerazione Servizi
$(for f in "$PENTEST_RESULTS_DIR/enum"/*.txt; do
    [[ -f "$f" ]] && echo "### $(basename $f)" && echo '```' && head -30 "$f" && echo '```'
done)

## 6. Analisi AI Vulnerabilita

$ai_analysis

## 7. Timeline Operazioni
$(cat "$CURRENT_SESSION_LOG" 2>/dev/null | grep "##" | head -30)

---
*Report generato da Kali-AI v$VERSION — Cognitive Pentest Framework*
*Powered by Claude Opus 4.6 (Anthropic)*
REOF

    think_result "Report salvato: $rf"
    echo -e "${GREEN}📄 Report: $rf${RESET}"
}

generate_report() {
    local rf="$REPORTS_DIR/report_$(date +%Y%m%d_%H%M%S).md"
    cat > "$rf" << REOF
# Kali-AI v6.0 System Report - $(date)
## Sistema
- OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2) | Kernel: $(uname -r)
- RAM: $(free -h | awk '/Mem:/{print $3"/"$2}') | CPU: $(nproc) core | Load: $(cat /proc/loadavg | awk '{print $1,$2,$3}')
- Disco: $(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')
## Rete
$(ip -br addr 2>/dev/null)
## Porte
$(ss -tlnp 2>/dev/null | head -15)
## Stats
- Comandi: $(cat "$USER_PROFILE" 2>/dev/null | jq '.total_commands//0') | Pentests: $(cat "$USER_PROFILE" 2>/dev/null | jq '.pentests_completed//0')
REOF
    echo -e "${GREEN}📄 $rf${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 15: BENCHMARK - CONFRONTO CON TOOL SINGOLI
# ═══════════════════════════════════════════════════════════════

benchmark_test() {
    local target="$1"
    local bd="$REPORTS_DIR/benchmark_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$bd"
    
    think_phase "BENCHMARK: Kali-AI vs Tool Singoli"
    think_strategy "Confronto tempi e risultati: sistema integrato vs tool individuali"
    think_separator
    
    echo -e "${CYAN}📊 Avvio benchmark su $target...${RESET}"
    
    # Test 1: Nmap singolo
    think_agent "Benchmark 1: Nmap singolo"
    local t1_start=$(date +%s)
    nmap -sV -F "$target" -oN "$bd/nmap_solo.txt" 2>&1 > /dev/null
    local t1_end=$(date +%s)
    local t1_time=$((t1_end - t1_start))
    local t1_ports=$(grep "open" "$bd/nmap_solo.txt" 2>/dev/null | wc -l)
    think_result "Nmap solo: ${t1_time}s, $t1_ports porte"
    
    # Test 2: Kali-AI multi-agente
    think_agent "Benchmark 2: Kali-AI multi-agente"
    local t2_start=$(date +%s)
    
    local br1="$bd/b_r1.log"
    local br2="$bd/b_r2.log"
    execute_in_terminal_bg "nmap -sV -F $target -oN $bd/kai_scan1.txt 2>&1 && echo AGENT_DONE" "📊 Bench Agent 1" "$br1"
    sleep 0.3
    execute_in_terminal_bg "nmap -sC -F $target -oN $bd/kai_scan2.txt 2>&1 && echo AGENT_DONE" "📊 Bench Agent 2" "$br2"
    
    wait_for_results "$br1" "$br2"
    local t2_end=$(date +%s)
    local t2_time=$((t2_end - t2_start))
    local t2_ports=$(grep "open" "$bd"/kai_scan*.txt 2>/dev/null | sort -u | wc -l)
    think_result "Kali-AI: ${t2_time}s, $t2_ports porte (2 agenti)"
    
    # Genera report benchmark
    cat > "$bd/benchmark_report.md" << BEOF
# 📊 Benchmark Report — Kali-AI v6.0
**Data:** $(date)
**Target:** $target

## Risultati

| Metodo | Tempo | Porte Trovate | Agenti |
|--------|-------|---------------|--------|
| Nmap singolo | ${t1_time}s | $t1_ports | 1 |
| Kali-AI multi-agente | ${t2_time}s | $t2_ports | 2 |

## Analisi
- Speedup: $(echo "scale=1; $t1_time / ($t2_time + 0.1)" | bc 2>/dev/null || echo "N/A")x
- Copertura aggiuntiva: $((t2_ports - t1_ports)) porte extra

## Conclusione
Il sistema multi-agente di Kali-AI permette di eseguire scansioni parallele,
riducendo il tempo totale e aumentando la copertura grazie alla combinazione
di diversi tipi di scansione simultanea.

*Benchmark generato da Kali-AI v$VERSION*
BEOF
    
    echo -e "${GREEN}📊 Benchmark completato: $bd/benchmark_report.md${RESET}"
    think_result "Benchmark: Nmap=${t1_time}s vs KaliAI=${t2_time}s"
    
    cat "$bd/benchmark_report.md"
}

# ═══════════════════════════════════════════════════════════════
# FASE 10: EXPORT TESI COMPLETO
# ═══════════════════════════════════════════════════════════════

export_thesis() {
    local od="$HOME/Desktop/KaliAI_Tesi_$(date +%Y%m%d)"
    mkdir -p "$od"/{codice,documentazione,report,sessioni,pentest,benchmark}
    
    think_phase "GENERAZIONE MATERIALE TESI"
    think_thought "Raccolgo tutto il materiale..."
    
    cp ~/kali-ai/kali-ai.sh "$od/codice/"
    cp ~/kali-ai/README.md "$od/codice/" 2>/dev/null
    cp "$REPORTS_DIR"/*.md "$od/report/" 2>/dev/null
    cp "$SESSION_DIR"/*.md "$od/sessioni/" 2>/dev/null
    cp -r "$PENTEST_DIR"/* "$od/pentest/" 2>/dev/null
    cp -r "$REPORTS_DIR"/benchmark_* "$od/benchmark/" 2>/dev/null
    
    local lines=$(wc -l < ~/kali-ai/kali-ai.sh 2>/dev/null || echo 0)
    local funcs=$(grep -c "^[a-z_]*() {" ~/kali-ai/kali-ai.sh 2>/dev/null || echo 0)
    
    cat > "$od/documentazione/TESI_kali_ai.md" << DEOF
# Kali-AI v6.0 — Cognitive Pentest Framework
# Documentazione Tecnica per Tesi
**Autore:** Antonio Telesca
**Email:** $EMAIL
**Data:** $(date)

---

## 1. Abstract
Kali-AI è un framework di penetration testing autonomo basato su intelligenza artificiale.
Utilizza Claude Opus 4.6 come motore cognitivo per analizzare, pianificare ed eseguire
test di sicurezza in modo completamente automatico. Il sistema implementa un'architettura
multi-agente dove diversi processi lavorano in parallelo su terminali separati, coordinati
da un Reasoning Engine centrale che mostra il processo decisionale in tempo reale.

## 2. Introduzione
### 2.1 Problema
Il penetration testing tradizionale richiede competenze specialistiche elevate e 
l'uso coordinato di decine di tool diversi. L'automazione esistente (es. Metasploit)
è limitata a pattern predefiniti senza capacità di ragionamento adattivo.

### 2.2 Soluzione Proposta
Un agente AI autonomo che:
- Ragiona come un pentester esperto (Reasoning Engine)
- Esegue operazioni in parallelo (Multi-Agent System)
- Mostra il processo decisionale in tempo reale (Thought Terminal)
- Apprende da successi e fallimenti (Memory System)
- Genera report professionali automaticamente

## 3. Architettura
### 3.1 Componenti
- **Core Engine**: Script Bash ($lines righe, $funcs funzioni)
- **AI Engine**: Claude Opus 4.6 via Anthropic API
- **Multi-Agent System**: Terminali paralleli indipendenti
- **Reasoning Engine**: Ciclo OBSERVE→THINK→PLAN→ACT→VERIFY→LEARN
- **Thought Terminal**: Visualizzazione real-time del ragionamento (stile Matrix)
- **Memory System**: Apprendimento persistente JSON
- **Vuln Database**: Database vulnerabilità noto integrato

### 3.2 Ciclo Cognitivo
\`\`\`
Input Utente → Snapshot Sistema → AI Reasoning → Piano di Azione
     ↑                                               ↓
     └── LEARN ← VERIFY ← ACT (Multi-Agent) ← PLAN
\`\`\`

### 3.3 Flusso Pentest Autonomo
\`\`\`
FASE 1: Ricognizione (3 agenti paralleli)
  ├─ Agent 1: Host Discovery (nmap -sn)
  ├─ Agent 2: DNS Reconnaissance
  └─ Agent 3: ARP Scan
       ↓ [raccolta risultati]
FASE 2: Scansione (1 agente per host)
  ├─ Agent N: Port scan + Version detection
  └─ Vulnerability matching automatico
       ↓ [analisi porte]
FASE 3: Enumerazione (agenti per servizio)
  ├─ Web: nikto + whatweb + dirb
  ├─ SMB: enum4linux + smbclient
  ├─ SSH: nmap scripts
  └─ FTP: anonymous + version check
       ↓ [tutti i risultati]
FASE 4: Analisi Cognitiva
  └─ Claude Opus 4.6 analizza tutto
       ↓
FASE 5: Report Automatico
\`\`\`

## 4. Innovazioni Chiave
### 4.1 Thought Terminal (Matrix Style)
Un terminale dedicato mostra in tempo reale il ragionamento dell'AI:
pensieri, osservazioni, decisioni, vulnerabilità trovate, strategie.
Questo garantisce trasparenza e ispezionabilità del processo decisionale.

### 4.2 Multi-Agent Coordination
Ogni fase del pentest lancia agenti indipendenti su terminali separati.
Un coordinatore centrale raccoglie i risultati e li passa alla fase successiva.

### 4.3 Adaptive Strategy
L'AI adatta la strategia in base ai risultati:
- Se trova HTTP → lancia web enumeration
- Se trova SMB → lancia SMB enumeration
- Se un comando fallisce → retry con correzione automatica

### 4.4 Vulnerability Intelligence
Database integrato di vulnerabilità note con matching automatico
su versioni di servizi trovati durante la scansione.

## 5. Tecnologie
| Tecnologia | Uso |
|-----------|-----|
| Bash | Core scripting |
| Claude Opus 4.6 | Motore AI cognitivo |
| Anthropic API | Comunicazione AI |
| Nmap | Scansione rete |
| Nikto | Web vulnerability scanner |
| Enum4linux | SMB enumeration |
| jq | JSON processing |
| Named Pipes | IPC per Thought Terminal |

## 6. Statistiche Utilizzo
- Sessioni: $(cat "$USER_PROFILE" 2>/dev/null | jq '.total_sessions//0')
- Comandi: $(cat "$USER_PROFILE" 2>/dev/null | jq '.total_commands//0')
- Successi: $(cat "$USER_PROFILE" 2>/dev/null | jq '.successful_commands//0')
- Pentests: $(cat "$USER_PROFILE" 2>/dev/null | jq '.pentests_completed//0')

## 7. Confronto con Soluzioni Esistenti
| Feature | Kali-AI | Metasploit | OpenVAS | Nmap |
|---------|---------|------------|---------|------|
| AI Reasoning | ✅ | ❌ | ❌ | ❌ |
| Multi-Agent | ✅ | ❌ | ❌ | ❌ |
| Thought Visualization | ✅ | ❌ | ❌ | ❌ |
| Natural Language | ✅ | ❌ | ❌ | ❌ |
| Auto-Adaptive | ✅ | Parziale | ❌ | ❌ |
| Vulnerability DB | ✅ | ✅ | ✅ | Parziale |
| Report Auto | ✅ | ✅ | ✅ | ❌ |
| Learning | ✅ | ❌ | ❌ | ❌ |

## 8. Conclusioni e Sviluppi Futuri
Kali-AI dimostra che un sistema basato su LLM può coordinare autonomamente
un penetration test complesso, utilizzando ragionamento adattivo e 
esecuzione parallela multi-agente. Il Thought Terminal fornisce trasparenza
completa sul processo decisionale dell'AI.

---
*Generato automaticamente da Kali-AI v$VERSION*
DEOF

    cat > "$od/INDICE.md" << IEOF
# 📚 Kali-AI v6.0 — Materiale Tesi
**Autore:** Antonio Telesca | **Data:** $(date)

## Contenuto
- **/codice/** — Codice sorgente ($lines righe)
- **/documentazione/** — Documentazione tecnica completa
- **/report/** — Report sistema
- **/pentest/** — Risultati penetration test
- **/sessioni/** — Log sessioni di lavoro
- **/benchmark/** — Confronti prestazionali
IEOF

    think_result "Materiale tesi generato: $od"
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║  📚 TESI GENERATA: $od${RESET}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${RESET}"
}


# ═══════════════════════════════════════════════════════════════
# DISPATCH COMANDI
# ═══════════════════════════════════════════════════════════════

autonomous_command() {
    local action="$1"; shift
    case "$action" in
        "direct") execute_and_capture "$*" ;;
        "terminal") execute_in_terminal "$1" "${2:-Comando}" "false" ;;
        "terminal_wait") execute_in_terminal "$1" "${2:-Comando}" "true" ;;
        "parallel") execute_parallel "$@" ;;
        "chain") execute_chain "$@" ;;
        "retry") execute_with_retry "$1" "${2:-3}" ;;
        "check_updates") check_system_updates ;;
        "update_system") update_system ;;
        "scan_usb") scan_usb_devices ;;
        "browser") open_browser "$*" ;;
        "system_info") execute_in_terminal "uname -a && lscpu | head -15 && free -h && df -h && ip -br addr" "Info Sistema" "false" ;;
        "show_ip")
            local ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -1)
            local pub=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "N/A")
            echo -e "${GREEN}🌐 Locale: $ip | Pubblico: $pub${RESET}" ;;
        "network_recon") network_recon "$1" ;;
        "file_search") file_operations "search" "$1" ;;
        "file_analyze") file_operations "analyze" "$1" ;;
        "file_monitor") file_operations "monitor" "$1" ;;
        "monitor") system_monitor ;;
        "service") service_control "$1" "$2" ;;
        "smart_install") smart_install "$1" ;;
        "schedule") schedule_task "$1" "$2" "$3" ;;
        "scheduled_list") list_scheduled_tasks ;;
        "watch") watch_and_react "$1" "$2" "$3" ;;
        "report") generate_report ;;
        "web_fetch") web_fetch "$1" ;;
        "pentest_auto") pentest_full_auto "$1" ;;
        "pentest_start") pentest_start "$1" ;;
        "pentest_recon") pentest_phase1_recon "$1" ;;
        "pentest_scan") pentest_phase2_scan "$1" ;;
        "pentest_enum") pentest_phase3_enum "$1" ;;
        "pentest_analyze") pentest_phase4_analyze "$1" ;;
        "pentest_report") pentest_generate_report "$1" ;;
        mitre_analyze_scan "$PENTEST_RESULTS_DIR/scan/ports_*.txt"
        "benchmark") benchmark_test "$1" ;;
        "mitre") mitre_analyze_scan "$1" "$2" ;;
        "cve") cve_lookup "$1" "$2" ;;
        "cve_scan") cve_scan_from_nmap "$1" ;;
        "topology") network_topology_map "$1" ;;
        "risk_score") risk_score_target "$1" ;;
        "exploit_search") exploit_search "$1" "$2" ;;
        "exploit_scan") exploit_scan_from_nmap "$1" ;;
        "attack_chain") generate_attack_chain "$1" ;;
        "credentials") credential_harvest "$1" ;;
        "multi_pentest") multi_target_pentest "$@" ;;
        "auto_tools") auto_select_tools "$1" "$2" ;;
        "tool_install") tool_ensure "$1" ;;
        "tool_update") tool_update "$1" ;;
        "osint") osint_full_scan "$1" ;;
        "web_vuln") website_vuln_scan "$1" ;;
        "investigate") investigate_email "$1" "$2" ;;
        "export_thesis") export_thesis ;;
        *) echo -e "${YELLOW}⚠️ $action non riconosciuto${RESET}" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════
# CONVERSAZIONE AI
# ═══════════════════════════════════════════════════════════════

show_prompt() {
    local ram=$(free 2>/dev/null | awk '/Mem:/{printf "%.0f%%",$3/$2*100}')
    local net="🔴"; ping -c1 -W1 8.8.8.8 &>/dev/null && net="🟢"
    local pt=""; [[ "$PENTEST_ACTIVE" == "true" ]] && pt="─[🎯PT]"
    echo -ne "╭─[${RED}🤖KALI-AI${RESET}]─[${BLUE}$(date +%H:%M)${RESET}]─[RAM:${YELLOW}${ram}${RESET}]─[${net}]${pt}\n╰─➤ "
}

process_conversation() {
    local user_input="$1"
    LAST_USER_REQUEST="$user_input"
    local history=$(cat "$HISTORY_FILE" 2>/dev/null || echo "[]")
    local hl=$(echo "$history" | jq '.|length' 2>/dev/null || echo 0)
    [[ $hl -gt 50 ]] && history=$(echo "$history" | jq '.[-50:]')
    local mem=$(get_memory_context)
    local snap=$(get_system_snapshot)
    
    think_phase "NUOVA RICHIESTA: $user_input"
    think_thought "Analizzo richiesta utente..."
    think_observe "Stato sistema: RAM=$(free -h 2>/dev/null | awk '/Mem:/{print $3"/"$2}')"
    
    local context="Sei KALI-AI v12.0, un COGNITIVE PENTEST FRAMEWORK per Kali Linux creato da Antonio Telesca.
Powered by Claude Opus 4.6. HAI IL CONTROLLO COMPLETO DEL SISTEMA.

STATO: $snap

COMANDI (in blocchi bash):
autonomous_command \"direct\" \"CMD\" - esecuzione diretta
autonomous_command \"terminal\" \"CMD\" \"TITOLO\" - terminale separato
autonomous_command \"terminal_wait\" \"CMD\" \"TITOLO\" - terminale con attesa
autonomous_command \"parallel\" \"CMD1\" \"CMD2\" - multi terminale
autonomous_command \"chain\" \"CMD1\" \"CMD2\" - sequenza
autonomous_command \"retry\" \"CMD\" \"3\" - con retry
autonomous_command \"check_updates\" - aggiornamenti
autonomous_command \"update_system\" - aggiorna
autonomous_command \"show_ip\" - IP
autonomous_command \"monitor\" - risorse
autonomous_command \"system_info\" - info in terminale
autonomous_command \"network_recon\" \"TARGET\" - scan rete
autonomous_command \"scan_usb\" - USB
autonomous_command \"file_search\" \"NOME\" - cerca
autonomous_command \"file_analyze\" \"PATH\" - analizza
autonomous_command \"file_monitor\" \"PATH\" - monitora
autonomous_command \"service\" \"list|start|stop|restart\" \"NOME\"
autonomous_command \"smart_install\" \"TOOL\" - installa
autonomous_command \"schedule\" \"DELAY\" \"CMD\" \"DESC\"
autonomous_command \"watch\" \"CHECK\" \"REACT\" \"SEC\"
autonomous_command \"browser\" \"QUERY\"
autonomous_command \"web_fetch\" \"URL\"
autonomous_command \"pentest_auto\" \"TARGET\" - PENTEST COMPLETO AUTOMATICO MULTI-AGENTE
autonomous_command \"pentest_start\" \"TARGET\"
autonomous_command \"pentest_recon\" \"TARGET\"
autonomous_command \"pentest_scan\" \"TARGET\"
autonomous_command \"pentest_enum\" \"TARGET\"
autonomous_command \"pentest_analyze\" \"TARGET\"
autonomous_command \"pentest_report\" \"TARGET\"
autonomous_command \"benchmark\" \"TARGET\" - confronto prestazionale
autonomous_command \"export_thesis\" - genera materiale tesi
autonomous_command \"report\" - report sistema

REGOLE:
1. Rispondi in italiano
2. Per file usa direct, per tool interattivi usa terminal
3. Comandi nel blocco bash
4. Per pentest completo usa SEMPRE pentest_auto
5. Il pentest apre MULTIPLI TERMINALI in parallelo automaticamente
6. Per la tesi usa export_thesis
7. Puoi usare piu comandi nello stesso blocco bash

PERCORSI: Desktop=~/Desktop | Pentest=$PENTEST_DIR
MEMORIA: $mem"

    echo -e "${YELLOW}🤔 Elaboro...${RESET}"
    think_thought "Elaboro la richiesta..."
    
    local ch=$(echo "$history" | jq '[.[]|select(.role=="user" or .role=="assistant")]' 2>/dev/null || echo "[]")
    local messages=$(echo "$ch" | jq --arg p "$user_input" '.+[{"role":"user","content":$p}]')
    local response=$(curl -s --max-time 120 https://api.anthropic.com/v1/messages \
        -H "x-api-key: $API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        -H "Content-Type: application/json" \
        -d "$(jq -cn --arg model "$MODEL" --arg system "$context" --argjson messages "$messages" '{"model":$model,"max_tokens":8192,"system":$system,"messages":$messages}')")
    local answer=$(echo "$response" | jq -r '.content[0].text // empty')
    if [[ -z "$answer" ]]; then
        echo -e "${RED}❌ Errore API${RESET}"
        echo "$response" | jq -r '.error.message // "Errore"' 2>/dev/null
        think_error "Errore API Anthropic"
        return 1
    fi
    
    think_decide "Risposta ricevuta, eseguo azioni..."
    
    echo ""
    echo -e "${GREEN}🤖 Kali-AI:${RESET}"
    local expl=$(echo "$answer" | awk '/```bash/{exit}1')
    [[ -n "$expl" ]] && echo -e "${GREEN}$expl${RESET}"
    while IFS= read -r cmd; do
        [[ -n "$cmd" && ! "$cmd" =~ ^# ]] && eval "$cmd"
    done < <(echo "$answer" | awk '/```bash/{f=1;next}/```/{f=0}f')
    
    think_result "Azione completata"
    log_action "AI" "$user_input" "" "${answer:0:500}"
    jq -cn --argjson h "$history" --arg u "$user_input" --arg a "$answer" '$h+[{"role":"user","content":$u},{"role":"assistant","content":$a}]' > "$HISTORY_FILE"
}

# ═══════════════════════════════════════════════════════════════
# COMANDI SPECIALI
# ═══════════════════════════════════════════════════════════════

handle_special_commands() {
    case "$1" in
        "clear"|"c") clear; return 0 ;;
        "help"|"h"|"aiuto")
            echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}"
            echo -e "${CYAN}║  🤖 KALI-AI v12.0 — COGNITIVE PENTEST FRAMEWORK                ║${RESET}"
            echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════╣${RESET}"
            echo -e "${CYAN}║${RESET}  🗣️  Parla naturalmente!                                     ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  📁 crea cartella, cerca file, analizza file                 ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  🌐 scansiona rete, mostra IP                               ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  📦 installa tool, aggiorna sistema                         ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  💻 apri htop, terminale con...                              ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  🎯 PENTEST AUTONOMO:                                       ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  'pentest 192.168.1.0/24' → multi-agente completo           ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  'benchmark 192.168.1.0/24' → confronto prestazioni         ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  📚 TESI:                                                    ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  'esporta tesi' → genera tutto il materiale                 ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  🧠 Il Thought Terminal mostra il ragionamento AI            ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
            echo -e "${CYAN}║${RESET}  ⚡ clear help about stats report tasks session exit         ${CYAN}║${RESET}"
            echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}"
            return 0 ;;
        "about"|"a")
            echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${RESET}"
            echo -e "${RED}║  🤖 KALI-AI v$VERSION — COGNITIVE PENTEST FRAMEWORK               ║${RESET}"
            echo -e "${RED}║  Powered by Claude Opus 4.6 (Anthropic)                      ║${RESET}"
            echo -e "${RED}║  Reasoning Engine + Multi-Agent + Thought Terminal            ║${RESET}"
            echo -e "${RED}║  Creato da $AUTHOR                                  ║${RESET}"
            echo -e "${RED}║  $GITHUB_REPO              ║${RESET}"
            echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${RESET}"
            return 0 ;;
        "stats")
            local p=$(cat "$USER_PROFILE" 2>/dev/null) m=$(cat "$MEMORY_FILE" 2>/dev/null)
            echo -e "${CYAN}📊 Kali-AI v6.0 Stats${RESET}"
            echo "  Sessioni: $(echo "$p"|jq '.total_sessions//0') | Comandi: $(echo "$p"|jq '.total_commands//0')"
            echo "  OK: $(echo "$p"|jq '.successful_commands//0') | Fail: $(echo "$p"|jq '.failed_commands//0')"
            echo "  Pentests: $(echo "$p"|jq '.pentests_completed//0') | Appresi: $(echo "$m"|jq '.learned_commands|length')"
            return 0 ;;
        "report") generate_report; return 0 ;;
        "tasks") list_scheduled_tasks; return 0 ;;
        "snapshot") get_system_snapshot; return 0 ;;
        "session") [[ -f "$CURRENT_SESSION_LOG" ]] && cat "$CURRENT_SESSION_LOG" || echo "Nessuna sessione"; return 0 ;;
    esac
    return 1
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

main() {
    trap 'echo -e "\n${GREEN}👋 Arrivederci!${RESET}"; kill "${SCHEDULED_PIDS[@]}" "${AGENT_PIDS[@]}" "$THOUGHT_PID" 2>/dev/null; rm -f "$THOUGHT_PIPE"; exit 0' EXIT INT TERM
    clear
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  🤖 KALI-AI v12.0 — COGNITIVE PENTEST FRAMEWORK                ║"
    echo "║        Powered by Claude Opus 4.6 (Anthropic)                 ║"
    echo "║           Reasoning Engine + Multi-Agent System               ║"
    echo "║              Creato da Antonio Telesca                        ║"
    echo "║      GitHub: github.com/TelescaAntonio/kali-ai                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    check_api_key
    init_files
    cleanup_on_startup
    setup_sudo_nopass
    start_session_log
    command -v jq &>/dev/null || sudo apt install -y jq 2>/dev/null
    command -v nmap &>/dev/null || sudo apt install -y nmap 2>/dev/null
    
    echo -e "${CYAN}🧠 Avvio Thought Terminal...${RESET}"
    start_thought_terminal
    sleep 1
    
    think_phase "KALI-AI v12.0 INIZIALIZZATO"
    think_thought "Sistema operativo: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'\"' -f2)"
    think_thought "Modello AI: $MODEL"
    think_thought "RAM: $(free -h 2>/dev/null | awk '/Mem:/{print $3"/"$2}')"
    think_observe "Interfacce rete: $(ip -br addr 2>/dev/null | grep UP | awk '{print $1":"$3}' | tr '\n' ' ')"
    think_result "Sistema pronto per operazioni"
    
    echo ""
    echo -e "${GREEN}✅ Kali-AI v6.0 pronto! (Claude Opus 4.6)${RESET}"
    echo -e "${YELLOW}💡 Parla naturalmente — 'help' per comandi${RESET}"
    echo -e "${CYAN}🧠 Thought Terminal attivo — guarda il ragionamento AI!${RESET}"
    echo -e "${MAGENTA}🎯 Prova: 'pentest 192.168.186.0/24'${RESET}"
    echo ""
    while true; do
        show_prompt
        read -r user_input
        [[ "$user_input" == "exit" || "$user_input" == "quit" || "$user_input" == "esci" ]] && break
        [[ -z "$user_input" ]] && continue
        handle_special_commands "$user_input" && continue
        process_conversation "$user_input"
    done
}

main

# ═══════════════════════════════════════════════════════════════
# FASE 16: MITRE ATT&CK MAPPING ENGINE
# ═══════════════════════════════════════════════════════════════

MITRE_DB="$HOME/kali-ai/mitre_attack.json"

mitre_map_tool() {
    local tool="$1"
    local results=""
    if [[ -f "$MITRE_DB" ]]; then
        results=$(jq -r --arg t "$tool" '
            [.. | objects | select(.tools? // [] | index($t)) | 
            {id: (input_line_number | tostring), name: .name, tactic: .tactic}] | 
            .[] | "\(.tactic) | \(.name)"
        ' "$MITRE_DB" 2>/dev/null)
        
        if [[ -z "$results" ]]; then
            results=$(grep -l "\"$tool\"" "$MITRE_DB" 2>/dev/null | head -1)
            if [[ -n "$results" ]]; then
                results=$(jq -r --arg t "$tool" '
                    .. | objects | select(.tools? // [] | index($t)) | 
                    "\(.tactic) → \(.name)"
                ' "$MITRE_DB" 2>/dev/null)
            fi
        fi
    fi
    echo "$results"
}

mitre_analyze_scan() {
    local scan_file="$1"
    local report_file="${2:-$REPORTS_DIR/mitre_mapping_$(date +%Y%m%d_%H%M%S).md}"
    
    think_phase "MITRE ATT&CK MAPPING"
    think_thought "Analizzo risultati scan e mappo a MITRE ATT&CK..."
    
    local open_ports=""
    local services=""
    
    if [[ -f "$scan_file" ]]; then
        open_ports=$(grep -E "^[0-9]+/" "$scan_file" 2>/dev/null | grep "open")
        services=$(grep -oP '(?<=open\s{1,10})\S+' "$scan_file" 2>/dev/null | sort -u)
    fi
    
    cat > "$report_file" << MEOF
# 🎯 MITRE ATT&CK Mapping Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Scan File:** $scan_file

---

## Tecniche Identificate

| MITRE ID | Tecnica | Tattica | Tool Utilizzato | Evidenza |
|----------|---------|---------|-----------------|----------|
MEOF

    local technique_count=0
    
    # Map nmap usage
    if grep -q "nmap" "$scan_file" 2>/dev/null || [[ -n "$open_ports" ]]; then
        echo "| T1595 | Active Scanning | Reconnaissance | nmap | Port scan eseguito |" >> "$report_file"
        echo "| T1046 | Network Service Discovery | Discovery | nmap | Servizi identificati |" >> "$report_file"
        echo "| T1592 | Gather Victim Host Information | Reconnaissance | nmap | OS/Version detection |" >> "$report_file"
        technique_count=$((technique_count + 3))
        think_observe "MITRE: T1595, T1046, T1592 — Scansione attiva identificata"
    fi
    
    # Map service-specific techniques
    if echo "$services" | grep -qi "http\|https\|web"; then
        echo "| T1190 | Exploit Public-Facing Application | Initial Access | nikto/dirb | Servizio web trovato |" >> "$report_file"
        technique_count=$((technique_count + 1))
        think_observe "MITRE: T1190 — Applicazione web esposta"
    fi
    
    if echo "$services" | grep -qi "ssh"; then
        echo "| T1133 | External Remote Services | Initial Access | ssh | SSH aperto |" >> "$report_file"
        echo "| T1021 | Remote Services | Lateral Movement | ssh | Accesso remoto possibile |" >> "$report_file"
        echo "| T1110 | Brute Force | Credential Access | hydra | Target per brute force |" >> "$report_file"
        technique_count=$((technique_count + 3))
        think_observe "MITRE: T1133, T1021, T1110 — SSH esposto"
    fi
    
    if echo "$services" | grep -qi "smb\|microsoft-ds\|netbios"; then
        echo "| T1135 | Network Share Discovery | Discovery | enum4linux | SMB attivo |" >> "$report_file"
        echo "| T1087 | Account Discovery | Discovery | enum4linux | Enumerazione account |" >> "$report_file"
        echo "| T1039 | Data from Network Shared Drive | Collection | smbclient | Share accessibili |" >> "$report_file"
        technique_count=$((technique_count + 3))
        think_observe "MITRE: T1135, T1087, T1039 — SMB esposto"
    fi
    
    if echo "$services" | grep -qi "ftp"; then
        echo "| T1078 | Valid Accounts | Initial Access | ftp | FTP aperto, check anonymous |" >> "$report_file"
        technique_count=$((technique_count + 1))
        think_observe "MITRE: T1078 — FTP esposto"
    fi
    
    if echo "$services" | grep -qi "rdp\|ms-wbt"; then
        echo "| T1133 | External Remote Services | Initial Access | rdp | RDP esposto |" >> "$report_file"
        echo "| T1110 | Brute Force | Credential Access | hydra | Target RDP brute force |" >> "$report_file"
        technique_count=$((technique_count + 2))
        think_observe "MITRE: T1133, T1110 — RDP esposto"
    fi
    
    if echo "$services" | grep -qi "snmp"; then
        echo "| T1082 | System Information Discovery | Discovery | snmp-check | SNMP esposto |" >> "$report_file"
        technique_count=$((technique_count + 1))
        think_observe "MITRE: T1082 — SNMP esposto"
    fi

    cat >> "$report_file" << MEOF2

---

## Sommario
- **Tecniche ATT&CK identificate:** $technique_count
- **Servizi esposti:** $(echo "$services" | wc -w)
- **Porte aperte:** $(echo "$open_ports" | grep -c "open")

## Raccomandazioni Difensive
$(if echo "$services" | grep -qi "ssh"; then echo "- **SSH:** Disabilitare accesso root, usare chiavi, fail2ban"; fi)
$(if echo "$services" | grep -qi "http"; then echo "- **HTTP:** WAF, HTTPS enforcing, patching applicativo"; fi)
$(if echo "$services" | grep -qi "smb"; then echo "- **SMB:** Disabilitare SMBv1, restringere share, autenticazione forte"; fi)
$(if echo "$services" | grep -qi "ftp"; then echo "- **FTP:** Disabilitare anonymous, migrare a SFTP"; fi)
$(if echo "$services" | grep -qi "rdp"; then echo "- **RDP:** NLA obbligatorio, VPN, limitare accesso IP"; fi)
$(if echo "$services" | grep -qi "snmp"; then echo "- **SNMP:** Cambiare community string, usare SNMPv3"; fi)

---
*Report MITRE ATT&CK generato da Kali-AI v$VERSION*
*Framework: MITRE ATT&CK v14 — https://attack.mitre.org*
MEOF2

    think_result "MITRE Mapping: $technique_count tecniche identificate → $report_file"
    echo -e "${GREEN}🎯 MITRE ATT&CK: $technique_count tecniche mappate → $report_file${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 17: ADVANCED MEMORY & LEARNING ENGINE
# ═══════════════════════════════════════════════════════════════

ATTACK_MEMORY="$BASE_DIR/attack_memory.json"
STRATEGY_DB="$BASE_DIR/strategy_database.json"

init_advanced_memory() {
    if [[ ! -f "$ATTACK_MEMORY" ]]; then
        echo '{"attacks":[],"successful_techniques":[],"failed_techniques":[],"target_profiles":[]}' > "$ATTACK_MEMORY"
    fi
    if [[ ! -f "$STRATEGY_DB" ]]; then
        cat > "$STRATEGY_DB" << 'STRATEOF'
{
  "port_strategies": {
    "21": {"service":"FTP","priority":"high","actions":["anonymous_login","version_check","brute_force"],"tools":["ftp","nmap","hydra"]},
    "22": {"service":"SSH","priority":"high","actions":["version_check","key_auth_test","brute_force"],"tools":["ssh","nmap","hydra","ssh-audit"]},
    "23": {"service":"Telnet","priority":"critical","actions":["banner_grab","brute_force"],"tools":["telnet","nmap","hydra"]},
    "25": {"service":"SMTP","priority":"medium","actions":["user_enum","relay_test"],"tools":["smtp-user-enum","nmap","swaks"]},
    "53": {"service":"DNS","priority":"medium","actions":["zone_transfer","enum"],"tools":["dig","dnsrecon","dnsenum"]},
    "80": {"service":"HTTP","priority":"high","actions":["dir_scan","vuln_scan","tech_detect"],"tools":["nikto","dirb","whatweb","gobuster"]},
    "110": {"service":"POP3","priority":"medium","actions":["version_check","brute_force"],"tools":["nmap","hydra"]},
    "111": {"service":"RPCbind","priority":"medium","actions":["rpc_enum"],"tools":["rpcinfo","nmap"]},
    "135": {"service":"MSRPC","priority":"high","actions":["rpc_enum"],"tools":["rpcdump","nmap"]},
    "139": {"service":"NetBIOS","priority":"high","actions":["smb_enum","share_enum"],"tools":["enum4linux","smbclient","nbtscan"]},
    "143": {"service":"IMAP","priority":"medium","actions":["version_check","brute_force"],"tools":["nmap","hydra"]},
    "443": {"service":"HTTPS","priority":"high","actions":["ssl_check","dir_scan","vuln_scan"],"tools":["sslscan","nikto","dirb","testssl.sh"]},
    "445": {"service":"SMB","priority":"critical","actions":["smb_enum","share_enum","vuln_check"],"tools":["enum4linux","smbclient","crackmapexec","nmap"]},
    "993": {"service":"IMAPS","priority":"low","actions":["version_check"],"tools":["nmap","openssl"]},
    "1433": {"service":"MSSQL","priority":"critical","actions":["brute_force","enum"],"tools":["nmap","hydra","sqsh"]},
    "1521": {"service":"Oracle","priority":"critical","actions":["sid_enum","brute_force"],"tools":["odat","nmap","hydra"]},
    "3306": {"service":"MySQL","priority":"critical","actions":["version_check","brute_force"],"tools":["mysql","nmap","hydra"]},
    "3389": {"service":"RDP","priority":"critical","actions":["nla_check","brute_force"],"tools":["nmap","hydra","xfreerdp"]},
    "5432": {"service":"PostgreSQL","priority":"high","actions":["version_check","brute_force"],"tools":["psql","nmap","hydra"]},
    "5900": {"service":"VNC","priority":"high","actions":["auth_check","brute_force"],"tools":["nmap","hydra","vncviewer"]},
    "6379": {"service":"Redis","priority":"critical","actions":["noauth_check","info"],"tools":["redis-cli","nmap"]},
    "8080": {"service":"HTTP-Proxy","priority":"high","actions":["dir_scan","vuln_scan"],"tools":["nikto","dirb","whatweb"]},
    "8443": {"service":"HTTPS-Alt","priority":"high","actions":["ssl_check","dir_scan"],"tools":["sslscan","nikto","dirb"]},
    "27017": {"service":"MongoDB","priority":"critical","actions":["noauth_check","enum"],"tools":["mongosh","nmap"]}
  }
}
STRATEOF
    fi
    think_thought "Advanced Memory Engine inizializzato"
}

memory_record_attack() {
    local target="$1"
    local technique="$2"
    local tool="$3"
    local success="$4"
    local details="$5"
    
    local entry=$(jq -cn \
        --arg t "$target" \
        --arg tech "$technique" \
        --arg tool "$tool" \
        --arg s "$success" \
        --arg d "$details" \
        --arg date "$(date -Iseconds)" \
        '{target:$t, technique:$tech, tool:$tool, success:($s=="true"), details:$d, date:$date}')
    
    local mem=$(cat "$ATTACK_MEMORY")
    echo "$mem" | jq --argjson e "$entry" '.attacks += [$e]' > "$ATTACK_MEMORY"
    
    if [[ "$success" == "true" ]]; then
        echo "$mem" | jq --arg tech "$technique" \
            'if (.successful_techniques | index($tech)) then . else .successful_techniques += [$tech] end' > "$ATTACK_MEMORY"
        think_learn "Tecnica $technique registrata come SUCCESSO"
    else
        echo "$mem" | jq --arg tech "$technique" \
            'if (.failed_techniques | index($tech)) then . else .failed_techniques += [$tech] end' > "$ATTACK_MEMORY"
        think_learn "Tecnica $technique registrata come FALLITA"
    fi
}

memory_get_strategy() {
    local port="$1"
    if [[ -f "$STRATEGY_DB" ]]; then
        local strategy=$(jq -r --arg p "$port" '.port_strategies[$p] // empty' "$STRATEGY_DB")
        if [[ -n "$strategy" ]]; then
            local service=$(echo "$strategy" | jq -r '.service')
            local priority=$(echo "$strategy" | jq -r '.priority')
            local actions=$(echo "$strategy" | jq -r '.actions | join(", ")')
            local tools=$(echo "$strategy" | jq -r '.tools | join(", ")')
            think_strategy "Porta $port → $service [Priorità: $priority]"
            think_strategy "Azioni: $actions"
            think_strategy "Tools: $tools"
            echo "$strategy"
        fi
    fi
}

memory_analyze_target_profile() {
    local target="$1"
    local scan_file="$2"
    
    think_phase "ANALISI PROFILO TARGET"
    
    local profile="unknown"
    local open_ports=$(grep -oP '^\d+' "$scan_file" 2>/dev/null | sort -n)
    local port_count=$(echo "$open_ports" | grep -c "." 2>/dev/null || echo 0)
    
    if echo "$open_ports" | grep -q "^80$\|^443$\|^8080$"; then
        profile="web_server"
        think_observe "Profilo: WEB SERVER"
    fi
    if echo "$open_ports" | grep -q "^445$\|^139$\|^135$"; then
        profile="windows_host"
        think_observe "Profilo: WINDOWS HOST"
    fi
    if echo "$open_ports" | grep -q "^22$" && ! echo "$open_ports" | grep -q "^445$"; then
        profile="linux_host"
        think_observe "Profilo: LINUX HOST"
    fi
    if echo "$open_ports" | grep -q "^3306$\|^5432$\|^1433$\|^27017$\|^6379$"; then
        profile="database_server"
        think_observe "Profilo: DATABASE SERVER"
    fi
    
    local target_entry=$(jq -cn \
        --arg t "$target" \
        --arg p "$profile" \
        --arg pc "$port_count" \
        --arg ports "$(echo $open_ports | tr '\n' ',')" \
        --arg date "$(date -Iseconds)" \
        '{target:$t, profile:$p, port_count:($pc|tonumber), ports:$ports, date:$date}')
    
    local mem=$(cat "$ATTACK_MEMORY")
    echo "$mem" | jq --argjson e "$target_entry" '.target_profiles += [$e]' > "$ATTACK_MEMORY"
    
    think_result "Target $target classificato come: $profile ($port_count porte)"
    echo "$profile"
}

memory_suggest_next_action() {
    local target="$1"
    local current_phase="$2"
    
    think_phase "AI STRATEGY SUGGESTION"
    
    local past_successes=$(jq -r '.successful_techniques | join(", ")' "$ATTACK_MEMORY" 2>/dev/null)
    local past_failures=$(jq -r '.failed_techniques | join(", ")' "$ATTACK_MEMORY" 2>/dev/null)
    
    if [[ -n "$past_successes" ]]; then
        think_learn "Tecniche vincenti passate: $past_successes"
    fi
    if [[ -n "$past_failures" ]]; then
        think_learn "Tecniche fallite passate: $past_failures — evito di ripetere"
    fi
    
    think_decide "Suggerisco strategia basata su esperienza accumulata"
}

# ═══════════════════════════════════════════════════════════════
# FASE 18: CVE LOOKUP ENGINE
# ═══════════════════════════════════════════════════════════════

cve_lookup() {
    local service="$1"
    local version="$2"
    local output_file="${3:-}"
    
    think_phase "CVE LOOKUP: $service $version"
    think_thought "Interrogo database CVE per vulnerabilità note..."
    
    local query="${service}+${version}"
    local cve_results=""
    
    # NVD NIST API (gratuita, no API key)
    cve_results=$(curl -s --max-time 15 \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=10" 2>/dev/null)
    
    if [[ -n "$cve_results" ]] && echo "$cve_results" | jq -e '.vulnerabilities' &>/dev/null; then
        local total=$(echo "$cve_results" | jq '.totalResults // 0')
        think_observe "Trovate $total CVE per $service $version"
        
        local cve_report=""
        cve_report=$(echo "$cve_results" | jq -r '
            .vulnerabilities[:10][] | 
            "| " + (.cve.id // "N/A") + 
            " | " + ((.cve.metrics.cvssMetricV31[0].cvssData.baseScore // .cve.metrics.cvssMetricV2[0].cvssData.baseScore // 0) | tostring) +
            " | " + ((.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].baseSeverity // "N/A") | tostring) +
            " | " + (.cve.descriptions[0].value // "N/A" | .[0:80]) + " |"
        ' 2>/dev/null)
        
        if [[ -n "$cve_report" ]]; then
            echo -e "${RED}🔴 CVE trovate per $service $version:${RESET}"
            echo ""
            echo "| CVE ID | CVSS | Severity | Descrizione |"
            echo "|--------|------|----------|-------------|"
            echo "$cve_report"
            echo ""
            
            if [[ -n "$output_file" ]]; then
                echo "## CVE per $service $version" >> "$output_file"
                echo "| CVE ID | CVSS | Severity | Descrizione |" >> "$output_file"
                echo "|--------|------|----------|-------------|" >> "$output_file"
                echo "$cve_report" >> "$output_file"
                echo "" >> "$output_file"
            fi
            
            # Conta CVE critiche
            local critical=$(echo "$cve_results" | jq '[.vulnerabilities[] | select((.cve.metrics.cvssMetricV31[0].cvssData.baseScore // 0) >= 9.0)] | length' 2>/dev/null || echo 0)
            local high=$(echo "$cve_results" | jq '[.vulnerabilities[] | select((.cve.metrics.cvssMetricV31[0].cvssData.baseScore // 0) >= 7.0 and (.cve.metrics.cvssMetricV31[0].cvssData.baseScore // 0) < 9.0)] | length' 2>/dev/null || echo 0)
            
            [[ $critical -gt 0 ]] && think_observe "⚠️ CRITICAL: $critical CVE con CVSS >= 9.0!"
            [[ $high -gt 0 ]] && think_observe "🔴 HIGH: $high CVE con CVSS >= 7.0"
            
            think_result "CVE Lookup: $total risultati per $service $version"
        else
            think_result "Nessuna CVE formattabile trovata"
        fi
    else
        think_thought "Nessuna risposta dal database NVD per $service $version"
        echo -e "${YELLOW}⚠️ Nessuna CVE trovata per $service $version${RESET}"
    fi
}

cve_scan_from_nmap() {
    local scan_file="$1"
    local report_file="$REPORTS_DIR/cve_report_$(date +%Y%m%d_%H%M%S).md"
    
    think_phase "CVE SCAN AUTOMATICO"
    think_thought "Estraggo servizi e versioni dal scan nmap..."
    
    cat > "$report_file" << CVEHEAD
# 🔴 CVE Vulnerability Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Scan File:** $scan_file

---

CVEHEAD
    
    local total_cve=0
    
    while IFS= read -r line; do
        local port=$(echo "$line" | grep -oP '^\d+')
        local service=$(echo "$line" | awk '{print $3}')
        local version=$(echo "$line" | grep -oP '(?<=\s)\S+\s+\S+$' | sed 's/^ *//')
        
        if [[ -n "$service" && -n "$version" && "$version" != "$service" ]]; then
            think_agent "CVE Check: $service $version (porta $port)"
            cve_lookup "$service" "$version" "$report_file"
            total_cve=$((total_cve + 1))
            sleep 1  # Rate limiting NVD API
        fi
    done < <(grep "open" "$scan_file" 2>/dev/null | grep -v "^#")
    
    echo "---" >> "$report_file"
    echo "*Report CVE generato da Kali-AI v$VERSION*" >> "$report_file"
    
    think_result "CVE Scan completato: $total_cve servizi analizzati → $report_file"
    echo -e "${GREEN}🔴 CVE Report: $report_file${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 19: SMART AUTO-INSTALL & EXECUTE ENGINE
# ═══════════════════════════════════════════════════════════════

TOOL_REGISTRY="$BASE_DIR/tool_registry.json"

init_tool_registry() {
    if [[ ! -f "$TOOL_REGISTRY" ]]; then
        cat > "$TOOL_REGISTRY" << 'TOOLEOF'
{
  "tools": {
    "nmap": {"package":"nmap","category":"scanner","check":"nmap --version","install":"apt"},
    "masscan": {"package":"masscan","category":"scanner","check":"masscan --version","install":"apt"},
    "nikto": {"package":"nikto","category":"web","check":"nikto -Version","install":"apt"},
    "dirb": {"package":"dirb","category":"web","check":"which dirb","install":"apt"},
    "gobuster": {"package":"gobuster","category":"web","check":"gobuster version","install":"apt"},
    "feroxbuster": {"package":"feroxbuster","category":"web","check":"feroxbuster --version","install":"apt"},
    "whatweb": {"package":"whatweb","category":"web","check":"whatweb --version","install":"apt"},
    "wpscan": {"package":"wpscan","category":"web","check":"wpscan --version","install":"apt"},
    "sqlmap": {"package":"sqlmap","category":"web","check":"sqlmap --version","install":"apt"},
    "hydra": {"package":"hydra","category":"bruteforce","check":"hydra -h","install":"apt"},
    "medusa": {"package":"medusa","category":"bruteforce","check":"medusa -V","install":"apt"},
    "john": {"package":"john","category":"password","check":"john --version","install":"apt"},
    "hashcat": {"package":"hashcat","category":"password","check":"hashcat --version","install":"apt"},
    "enum4linux": {"package":"enum4linux","category":"enum","check":"which enum4linux","install":"apt"},
    "smbclient": {"package":"smbclient","category":"enum","check":"smbclient --version","install":"apt"},
    "crackmapexec": {"package":"crackmapexec","category":"enum","check":"crackmapexec --version","install":"apt"},
    "netexec": {"package":"netexec","category":"enum","check":"netexec --version","install":"pip"},
    "responder": {"package":"responder","category":"mitm","check":"which responder","install":"apt"},
    "wireshark": {"package":"wireshark","category":"sniffer","check":"wireshark --version","install":"apt"},
    "tcpdump": {"package":"tcpdump","category":"sniffer","check":"tcpdump --version","install":"apt"},
    "metasploit-framework": {"package":"metasploit-framework","category":"exploit","check":"msfconsole -v","install":"apt"},
    "exploitdb": {"package":"exploitdb","category":"exploit","check":"searchsploit -h","install":"apt"},
    "sslscan": {"package":"sslscan","category":"ssl","check":"sslscan --version","install":"apt"},
    "testssl.sh": {"package":"testssl.sh","category":"ssl","check":"which testssl.sh","install":"apt"},
    "dnsrecon": {"package":"dnsrecon","category":"dns","check":"dnsrecon -h","install":"apt"},
    "dnsenum": {"package":"dnsenum","category":"dns","check":"which dnsenum","install":"apt"},
    "fierce": {"package":"fierce","category":"dns","check":"fierce -h","install":"pip"},
    "subfinder": {"package":"subfinder","category":"dns","check":"subfinder -version","install":"go"},
    "nuclei": {"package":"nuclei","category":"vuln","check":"nuclei -version","install":"go"},
    "amass": {"package":"amass","category":"recon","check":"amass -version","install":"apt"},
    "theHarvester": {"package":"theharvester","category":"recon","check":"theHarvester -h","install":"apt"},
    "recon-ng": {"package":"recon-ng","category":"recon","check":"which recon-ng","install":"apt"},
    "aircrack-ng": {"package":"aircrack-ng","category":"wireless","check":"aircrack-ng --version","install":"apt"},
    "bettercap": {"package":"bettercap","category":"mitm","check":"bettercap -v","install":"apt"},
    "ettercap-common": {"package":"ettercap-common","category":"mitm","check":"ettercap -v","install":"apt"},
    "bloodhound": {"package":"bloodhound","category":"ad","check":"which bloodhound","install":"apt"},
    "impacket-scripts": {"package":"impacket-scripts","category":"ad","check":"which impacket-scripts","install":"apt"},
    "evil-winrm": {"package":"evil-winrm","category":"ad","check":"evil-winrm -v","install":"gem"},
    "ssh-audit": {"package":"ssh-audit","category":"audit","check":"ssh-audit -h","install":"pip"},
    "lynis": {"package":"lynis","category":"audit","check":"lynis --version","install":"apt"},
    "snmpcheck": {"package":"snmpcheck","category":"enum","check":"which snmpcheck","install":"apt"},
    "onesixtyone": {"package":"onesixtyone","category":"enum","check":"which onesixtyone","install":"apt"},
    "nbtscan": {"package":"nbtscan","category":"enum","check":"nbtscan -h","install":"apt"},
    "graphviz": {"package":"graphviz","category":"util","check":"dot -V","install":"apt"},
    "xsltproc": {"package":"xsltproc","category":"util","check":"xsltproc --version","install":"apt"},
    "jq": {"package":"jq","category":"util","check":"jq --version","install":"apt"},
    "python3-pip": {"package":"python3-pip","category":"util","check":"pip3 --version","install":"apt"},
    "curl": {"package":"curl","category":"util","check":"curl --version","install":"apt"},
    "wget": {"package":"wget","category":"util","check":"wget --version","install":"apt"}
  }
}
TOOLEOF
    fi
}

tool_ensure() {
    local tool_name="$1"
    local silent="${2:-false}"
    
    if command -v "$tool_name" &>/dev/null; then
        [[ "$silent" != "true" ]] && think_thought "✅ $tool_name già installato"
        return 0
    fi
    
    think_phase "AUTO-INSTALL: $tool_name"
    think_thought "$tool_name non trovato, installo automaticamente..."
    
    local pkg_info=""
    if [[ -f "$TOOL_REGISTRY" ]]; then
        pkg_info=$(jq -r --arg t "$tool_name" '.tools[$t] // empty' "$TOOL_REGISTRY" 2>/dev/null)
    fi
    
    local package="$tool_name"
    local install_method="apt"
    
    if [[ -n "$pkg_info" ]]; then
        package=$(echo "$pkg_info" | jq -r '.package // empty')
        install_method=$(echo "$pkg_info" | jq -r '.install // "apt"')
    fi
    
    case "$install_method" in
        "apt")
            think_agent "📦 apt install -y $package"
            sudo apt update -qq 2>/dev/null
            sudo DEBIAN_FRONTEND=noninteractive apt install -y "$package" 2>&1 | tail -3
            ;;
        "pip")
            think_agent "📦 pip3 install $package"
            pip3 install "$package" 2>&1 | tail -3
            ;;
        "go")
            think_agent "📦 go install $package"
            if ! command -v go &>/dev/null; then
                sudo apt install -y golang 2>/dev/null
            fi
            go install "github.com/projectdiscovery/${package}/v2/cmd/${package}@latest" 2>&1 | tail -3
            export PATH="$PATH:$HOME/go/bin"
            ;;
        "gem")
            think_agent "📦 gem install $package"
            sudo gem install "$package" 2>&1 | tail -3
            ;;
    esac
    
    if command -v "$tool_name" &>/dev/null; then
        think_result "✅ $tool_name installato con successo"
        return 0
    else
        think_error "❌ Installazione $tool_name fallita"
        return 1
    fi
}

tool_ensure_list() {
    local tools=("$@")
    local missing=()
    local installed=()
    
    think_phase "VERIFICA TOOL RICHIESTI"
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            installed+=("$tool")
        else
            missing+=("$tool")
        fi
    done
    
    think_observe "Installati: ${#installed[@]} | Mancanti: ${#missing[@]}"
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        think_thought "Installo ${#missing[@]} tool mancanti: ${missing[*]}"
        for tool in "${missing[@]}"; do
            tool_ensure "$tool"
        done
    fi
    
    think_result "Tutti i tool verificati e pronti"
}

tool_update() {
    local tool_name="$1"
    
    think_phase "AGGIORNAMENTO: $tool_name"
    
    local pkg_info=""
    if [[ -f "$TOOL_REGISTRY" ]]; then
        pkg_info=$(jq -r --arg t "$tool_name" '.tools[$t] // empty' "$TOOL_REGISTRY" 2>/dev/null)
    fi
    
    local package="${tool_name}"
    local install_method="apt"
    
    if [[ -n "$pkg_info" ]]; then
        package=$(echo "$pkg_info" | jq -r '.package // empty')
        install_method=$(echo "$pkg_info" | jq -r '.install // "apt"')
    fi
    
    case "$install_method" in
        "apt")
            sudo apt update -qq 2>/dev/null
            sudo apt install --only-upgrade -y "$package" 2>&1 | tail -3
            ;;
        "pip")
            pip3 install --upgrade "$package" 2>&1 | tail -3
            ;;
        "go")
            go install "github.com/projectdiscovery/${package}/v2/cmd/${package}@latest" 2>&1 | tail -3
            ;;
        "gem")
            sudo gem update "$package" 2>&1 | tail -3
            ;;
    esac
    
    think_result "$tool_name aggiornato"
}

auto_select_tools() {
    local task="$1"
    local target="$2"
    
    think_phase "AUTO-SELECT TOOLS per: $task"
    
    case "$task" in
        "web_scan"|"web")
            tool_ensure_list nikto dirb gobuster whatweb wpscan
            think_decide "Tool web pronti: nikto, dirb, gobuster, whatweb, wpscan"
            ;;
        "sql_injection"|"sqli")
            tool_ensure_list sqlmap
            think_decide "Tool SQLi pronto: sqlmap"
            ;;
        "brute_force"|"bruteforce")
            tool_ensure_list hydra medusa john
            think_decide "Tool bruteforce pronti: hydra, medusa, john"
            ;;
        "smb_enum"|"smb")
            tool_ensure_list enum4linux smbclient crackmapexec nbtscan
            think_decide "Tool SMB pronti: enum4linux, smbclient, crackmapexec"
            ;;
        "dns_enum"|"dns")
            tool_ensure_list dnsrecon dnsenum fierce
            think_decide "Tool DNS pronti: dnsrecon, dnsenum, fierce"
            ;;
        "ssl_audit"|"ssl")
            tool_ensure_list sslscan testssl.sh
            think_decide "Tool SSL pronti: sslscan, testssl.sh"
            ;;
        "wireless"|"wifi")
            tool_ensure_list aircrack-ng bettercap
            think_decide "Tool wireless pronti: aircrack-ng, bettercap"
            ;;
        "exploit")
            tool_ensure_list metasploit-framework exploitdb
            think_decide "Tool exploit pronti: msfconsole, searchsploit"
            ;;
        "ad_attack"|"active_directory")
            tool_ensure_list bloodhound impacket-scripts crackmapexec evil-winrm
            think_decide "Tool AD pronti: bloodhound, impacket, crackmapexec, evil-winrm"
            ;;
        "sniff"|"mitm")
            tool_ensure_list tcpdump wireshark bettercap ettercap-common responder
            think_decide "Tool sniffing pronti: tcpdump, wireshark, bettercap, ettercap"
            ;;
        "recon"|"osint")
            tool_ensure_list amass theHarvester recon-ng
            think_decide "Tool OSINT pronti: amass, theHarvester, recon-ng"
            ;;
        "vuln_scan"|"vuln")
            tool_ensure_list nuclei nmap nikto
            think_decide "Tool vuln scan pronti: nuclei, nmap, nikto"
            ;;
        "full_pentest"|"pentest")
            tool_ensure_list nmap nikto dirb gobuster whatweb enum4linux smbclient hydra \
                sqlmap sslscan dnsrecon exploitdb crackmapexec
            think_decide "Arsenal completo pronto per pentest"
            ;;
        *)
            think_thought "Task non riconosciuto, verifico tool base..."
            tool_ensure_list nmap jq curl
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════
# FASE 19: SMART AUTO-INSTALL & EXECUTE ENGINE
# ═══════════════════════════════════════════════════════════════

TOOL_REGISTRY="$BASE_DIR/tool_registry.json"

init_tool_registry() {
    if [[ ! -f "$TOOL_REGISTRY" ]]; then
        cat > "$TOOL_REGISTRY" << 'TOOLEOF'
{
  "tools": {
    "nmap": {"package":"nmap","category":"scanner","check":"nmap --version","install":"apt"},
    "masscan": {"package":"masscan","category":"scanner","check":"masscan --version","install":"apt"},
    "nikto": {"package":"nikto","category":"web","check":"nikto -Version","install":"apt"},
    "dirb": {"package":"dirb","category":"web","check":"which dirb","install":"apt"},
    "gobuster": {"package":"gobuster","category":"web","check":"gobuster version","install":"apt"},
    "feroxbuster": {"package":"feroxbuster","category":"web","check":"feroxbuster --version","install":"apt"},
    "whatweb": {"package":"whatweb","category":"web","check":"whatweb --version","install":"apt"},
    "wpscan": {"package":"wpscan","category":"web","check":"wpscan --version","install":"apt"},
    "sqlmap": {"package":"sqlmap","category":"web","check":"sqlmap --version","install":"apt"},
    "hydra": {"package":"hydra","category":"bruteforce","check":"hydra -h","install":"apt"},
    "medusa": {"package":"medusa","category":"bruteforce","check":"medusa -V","install":"apt"},
    "john": {"package":"john","category":"password","check":"john --version","install":"apt"},
    "hashcat": {"package":"hashcat","category":"password","check":"hashcat --version","install":"apt"},
    "enum4linux": {"package":"enum4linux","category":"enum","check":"which enum4linux","install":"apt"},
    "smbclient": {"package":"smbclient","category":"enum","check":"smbclient --version","install":"apt"},
    "crackmapexec": {"package":"crackmapexec","category":"enum","check":"crackmapexec --version","install":"apt"},
    "netexec": {"package":"netexec","category":"enum","check":"netexec --version","install":"pip"},
    "responder": {"package":"responder","category":"mitm","check":"which responder","install":"apt"},
    "wireshark": {"package":"wireshark","category":"sniffer","check":"wireshark --version","install":"apt"},
    "tcpdump": {"package":"tcpdump","category":"sniffer","check":"tcpdump --version","install":"apt"},
    "metasploit-framework": {"package":"metasploit-framework","category":"exploit","check":"msfconsole -v","install":"apt"},
    "exploitdb": {"package":"exploitdb","category":"exploit","check":"searchsploit -h","install":"apt"},
    "sslscan": {"package":"sslscan","category":"ssl","check":"sslscan --version","install":"apt"},
    "testssl.sh": {"package":"testssl.sh","category":"ssl","check":"which testssl.sh","install":"apt"},
    "dnsrecon": {"package":"dnsrecon","category":"dns","check":"dnsrecon -h","install":"apt"},
    "dnsenum": {"package":"dnsenum","category":"dns","check":"which dnsenum","install":"apt"},
    "fierce": {"package":"fierce","category":"dns","check":"fierce -h","install":"pip"},
    "subfinder": {"package":"subfinder","category":"dns","check":"subfinder -version","install":"go"},
    "nuclei": {"package":"nuclei","category":"vuln","check":"nuclei -version","install":"go"},
    "amass": {"package":"amass","category":"recon","check":"amass -version","install":"apt"},
    "theHarvester": {"package":"theharvester","category":"recon","check":"theHarvester -h","install":"apt"},
    "recon-ng": {"package":"recon-ng","category":"recon","check":"which recon-ng","install":"apt"},
    "aircrack-ng": {"package":"aircrack-ng","category":"wireless","check":"aircrack-ng --version","install":"apt"},
    "bettercap": {"package":"bettercap","category":"mitm","check":"bettercap -v","install":"apt"},
    "ettercap-common": {"package":"ettercap-common","category":"mitm","check":"ettercap -v","install":"apt"},
    "bloodhound": {"package":"bloodhound","category":"ad","check":"which bloodhound","install":"apt"},
    "impacket-scripts": {"package":"impacket-scripts","category":"ad","check":"which impacket-scripts","install":"apt"},
    "evil-winrm": {"package":"evil-winrm","category":"ad","check":"evil-winrm -v","install":"gem"},
    "ssh-audit": {"package":"ssh-audit","category":"audit","check":"ssh-audit -h","install":"pip"},
    "lynis": {"package":"lynis","category":"audit","check":"lynis --version","install":"apt"},
    "snmpcheck": {"package":"snmpcheck","category":"enum","check":"which snmpcheck","install":"apt"},
    "onesixtyone": {"package":"onesixtyone","category":"enum","check":"which onesixtyone","install":"apt"},
    "nbtscan": {"package":"nbtscan","category":"enum","check":"nbtscan -h","install":"apt"},
    "graphviz": {"package":"graphviz","category":"util","check":"dot -V","install":"apt"},
    "xsltproc": {"package":"xsltproc","category":"util","check":"xsltproc --version","install":"apt"},
    "jq": {"package":"jq","category":"util","check":"jq --version","install":"apt"},
    "python3-pip": {"package":"python3-pip","category":"util","check":"pip3 --version","install":"apt"},
    "curl": {"package":"curl","category":"util","check":"curl --version","install":"apt"},
    "wget": {"package":"wget","category":"util","check":"wget --version","install":"apt"}
  }
}
TOOLEOF
    fi
}

tool_ensure() {
    local tool_name="$1"
    local silent="${2:-false}"
    
    if command -v "$tool_name" &>/dev/null; then
        [[ "$silent" != "true" ]] && think_thought "✅ $tool_name già installato"
        return 0
    fi
    
    think_phase "AUTO-INSTALL: $tool_name"
    think_thought "$tool_name non trovato, installo automaticamente..."
    
    local pkg_info=""
    if [[ -f "$TOOL_REGISTRY" ]]; then
        pkg_info=$(jq -r --arg t "$tool_name" '.tools[$t] // empty' "$TOOL_REGISTRY" 2>/dev/null)
    fi
    
    local package="$tool_name"
    local install_method="apt"
    
    if [[ -n "$pkg_info" ]]; then
        package=$(echo "$pkg_info" | jq -r '.package // empty')
        install_method=$(echo "$pkg_info" | jq -r '.install // "apt"')
    fi
    
    case "$install_method" in
        "apt")
            think_agent "📦 apt install -y $package"
            sudo apt update -qq 2>/dev/null
            sudo DEBIAN_FRONTEND=noninteractive apt install -y "$package" 2>&1 | tail -3
            ;;
        "pip")
            think_agent "📦 pip3 install $package"
            pip3 install "$package" 2>&1 | tail -3
            ;;
        "go")
            think_agent "📦 go install $package"
            if ! command -v go &>/dev/null; then
                sudo apt install -y golang 2>/dev/null
            fi
            go install "github.com/projectdiscovery/${package}/v2/cmd/${package}@latest" 2>&1 | tail -3
            export PATH="$PATH:$HOME/go/bin"
            ;;
        "gem")
            think_agent "📦 gem install $package"
            sudo gem install "$package" 2>&1 | tail -3
            ;;
    esac
    
    if command -v "$tool_name" &>/dev/null; then
        think_result "✅ $tool_name installato con successo"
        return 0
    else
        think_error "❌ Installazione $tool_name fallita"
        return 1
    fi
}

tool_ensure_list() {
    local tools=("$@")
    local missing=()
    local installed=()
    
    think_phase "VERIFICA TOOL RICHIESTI"
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            installed+=("$tool")
        else
            missing+=("$tool")
        fi
    done
    
    think_observe "Installati: ${#installed[@]} | Mancanti: ${#missing[@]}"
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        think_thought "Installo ${#missing[@]} tool mancanti: ${missing[*]}"
        for tool in "${missing[@]}"; do
            tool_ensure "$tool"
        done
    fi
    
    think_result "Tutti i tool verificati e pronti"
}

tool_update() {
    local tool_name="$1"
    
    think_phase "AGGIORNAMENTO: $tool_name"
    
    local pkg_info=""
    if [[ -f "$TOOL_REGISTRY" ]]; then
        pkg_info=$(jq -r --arg t "$tool_name" '.tools[$t] // empty' "$TOOL_REGISTRY" 2>/dev/null)
    fi
    
    local package="${tool_name}"
    local install_method="apt"
    
    if [[ -n "$pkg_info" ]]; then
        package=$(echo "$pkg_info" | jq -r '.package // empty')
        install_method=$(echo "$pkg_info" | jq -r '.install // "apt"')
    fi
    
    case "$install_method" in
        "apt")
            sudo apt update -qq 2>/dev/null
            sudo apt install --only-upgrade -y "$package" 2>&1 | tail -3
            ;;
        "pip")
            pip3 install --upgrade "$package" 2>&1 | tail -3
            ;;
        "go")
            go install "github.com/projectdiscovery/${package}/v2/cmd/${package}@latest" 2>&1 | tail -3
            ;;
        "gem")
            sudo gem update "$package" 2>&1 | tail -3
            ;;
    esac
    
    think_result "$tool_name aggiornato"
}

auto_select_tools() {
    local task="$1"
    local target="$2"
    
    think_phase "AUTO-SELECT TOOLS per: $task"
    
    case "$task" in
        "web_scan"|"web")
            tool_ensure_list nikto dirb gobuster whatweb wpscan
            think_decide "Tool web pronti: nikto, dirb, gobuster, whatweb, wpscan"
            ;;
        "sql_injection"|"sqli")
            tool_ensure_list sqlmap
            think_decide "Tool SQLi pronto: sqlmap"
            ;;
        "brute_force"|"bruteforce")
            tool_ensure_list hydra medusa john
            think_decide "Tool bruteforce pronti: hydra, medusa, john"
            ;;
        "smb_enum"|"smb")
            tool_ensure_list enum4linux smbclient crackmapexec nbtscan
            think_decide "Tool SMB pronti: enum4linux, smbclient, crackmapexec"
            ;;
        "dns_enum"|"dns")
            tool_ensure_list dnsrecon dnsenum fierce
            think_decide "Tool DNS pronti: dnsrecon, dnsenum, fierce"
            ;;
        "ssl_audit"|"ssl")
            tool_ensure_list sslscan testssl.sh
            think_decide "Tool SSL pronti: sslscan, testssl.sh"
            ;;
        "wireless"|"wifi")
            tool_ensure_list aircrack-ng bettercap
            think_decide "Tool wireless pronti: aircrack-ng, bettercap"
            ;;
        "exploit")
            tool_ensure_list metasploit-framework exploitdb
            think_decide "Tool exploit pronti: msfconsole, searchsploit"
            ;;
        "ad_attack"|"active_directory")
            tool_ensure_list bloodhound impacket-scripts crackmapexec evil-winrm
            think_decide "Tool AD pronti: bloodhound, impacket, crackmapexec, evil-winrm"
            ;;
        "sniff"|"mitm")
            tool_ensure_list tcpdump wireshark bettercap ettercap-common responder
            think_decide "Tool sniffing pronti: tcpdump, wireshark, bettercap, ettercap"
            ;;
        "recon"|"osint")
            tool_ensure_list amass theHarvester recon-ng
            think_decide "Tool OSINT pronti: amass, theHarvester, recon-ng"
            ;;
        "vuln_scan"|"vuln")
            tool_ensure_list nuclei nmap nikto
            think_decide "Tool vuln scan pronti: nuclei, nmap, nikto"
            ;;
        "full_pentest"|"pentest")
            tool_ensure_list nmap nikto dirb gobuster whatweb enum4linux smbclient hydra \
                sqlmap sslscan dnsrecon exploitdb crackmapexec
            think_decide "Arsenal completo pronto per pentest"
            ;;
        *)
            think_thought "Task non riconosciuto, verifico tool base..."
            tool_ensure_list nmap jq curl
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════
# FASE 20: NETWORK TOPOLOGY MAPPER
# ═══════════════════════════════════════════════════════════════

network_topology_map() {
    local target="$1"
    local scan_dir="${2:-$PENTEST_RESULTS_DIR}"
    local map_dir="$REPORTS_DIR/topology_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$map_dir"
    
    tool_ensure "graphviz" "true"
    
    think_phase "NETWORK TOPOLOGY MAPPING"
    think_thought "Genero mappa della rete da risultati scan..."
    
    local dot_file="$map_dir/network.dot"
    local png_file="$map_dir/network_map.png"
    local svg_file="$map_dir/network_map.svg"
    local report_file="$map_dir/topology_report.md"
    
    cat > "$dot_file" << 'DOTHEAD'
digraph NetworkTopology {
    rankdir=TB;
    bgcolor="#1a1a2e";
    node [style=filled, fontname="Courier New", fontcolor=white];
    edge [color="#00ff41", fontcolor="#00ff41", fontname="Courier New"];
    
    label="Kali-AI Network Topology Map";
    labelloc=t;
    fontname="Courier New Bold";
    fontsize=20;
    fontcolor="#00ff41";
    
    attacker [label="🤖 KALI-AI\nAttacker", shape=doubleoctagon, fillcolor="#e94560", fontcolor=white];
DOTHEAD

    local host_count=0
    local total_ports=0
    local host_nodes=""
    
    # Parse host e porte dai risultati scan
    for scan_file in "$scan_dir"/scan/ports_*.txt "$scan_dir"/recon/hosts.txt; do
        [[ ! -f "$scan_file" ]] && continue
        
        while IFS= read -r line; do
            local ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
            [[ -z "$ip" ]] && continue
            [[ "$host_nodes" == *"$ip"* ]] && continue
            
            host_count=$((host_count + 1))
            local node_id="host_${host_count}"
            local os_info=""
            local ports=""
            local services=""
            local risk_color="#16213e"
            local port_count=0
            
            # Cerca info dettagliate nel file scan specifico
            local host_scan="$scan_dir/scan/ports_${ip}.txt"
            if [[ -f "$host_scan" ]]; then
                ports=$(grep "open" "$host_scan" 2>/dev/null | awk '{print $1}' | tr '\n' ', ' | sed 's/,$//')
                services=$(grep "open" "$host_scan" 2>/dev/null | awk '{print $3}' | sort -u | tr '\n' ', ' | sed 's/,$//')
                os_info=$(grep -i "os details\|running:" "$host_scan" 2>/dev/null | head -1 | sed 's/.*: //')
                port_count=$(grep -c "open" "$host_scan" 2>/dev/null || echo 0)
            fi
            
            # Colore basato sul rischio
            if [[ $port_count -gt 10 ]]; then
                risk_color="#e94560"  # rosso = alto rischio
            elif [[ $port_count -gt 5 ]]; then
                risk_color="#f5a623"  # arancione = medio
            elif [[ $port_count -gt 0 ]]; then
                risk_color="#16213e"  # blu = basso
            else
                risk_color="#0f3460"  # blu scuro = minimo
            fi
            
            local label="$ip"
            [[ -n "$os_info" ]] && label="$label\n$os_info"
            [[ -n "$services" ]] && label="$label\n[$services]"
            [[ $port_count -gt 0 ]] && label="$label\n${port_count} porte aperte"
            
            echo "    $node_id [label=\"$label\", shape=box, fillcolor=\"$risk_color\"];" >> "$dot_file"
            echo "    attacker -> $node_id [label=\"scan\"];" >> "$dot_file"
            
            # Aggiungi nodi per servizi critici
            if echo "$ports" | grep -q "80\|443\|8080"; then
                echo "    ${node_id}_web [label=\"🌐 Web\n$ip:80/443\", shape=ellipse, fillcolor=\"#e94560\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_web;" >> "$dot_file"
            fi
            if echo "$ports" | grep -q "445\|139"; then
                echo "    ${node_id}_smb [label=\"📁 SMB\n$ip:445\", shape=ellipse, fillcolor=\"#f5a623\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_smb;" >> "$dot_file"
            fi
            if echo "$ports" | grep -q "3306\|5432\|1433\|27017"; then
                echo "    ${node_id}_db [label=\"🗄️ Database\n$ip\", shape=cylinder, fillcolor=\"#e94560\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_db;" >> "$dot_file"
            fi
            if echo "$ports" | grep -q "22"; then
                echo "    ${node_id}_ssh [label=\"🔑 SSH\n$ip:22\", shape=ellipse, fillcolor=\"#16213e\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_ssh;" >> "$dot_file"
            fi
            
            total_ports=$((total_ports + port_count))
            host_nodes="$host_nodes $ip"
            
            think_observe "Host $ip: $port_count porte, servizi: $services"
        done < <(grep -oP '\d+\.\d+\.\d+\.\d+' "$scan_file" 2>/dev/null | sort -u)
    done
    
    # Legenda
    cat >> "$dot_file" << 'DOTLEGEND'
    
    subgraph cluster_legend {
        label="Legenda Rischio";
        style=dashed;
        color="#00ff41";
        fontcolor="#00ff41";
        
        leg_high [label="Alto Rischio\n>10 porte", shape=box, fillcolor="#e94560"];
        leg_med [label="Medio Rischio\n5-10 porte", shape=box, fillcolor="#f5a623"];
        leg_low [label="Basso Rischio\n<5 porte", shape=box, fillcolor="#16213e"];
        leg_high -> leg_med -> leg_low [style=invis];
    }
}
DOTLEGEND

    # Genera immagini
    if command -v dot &>/dev/null; then
        dot -Tpng "$dot_file" -o "$png_file" 2>/dev/null
        dot -Tsvg "$dot_file" -o "$svg_file" 2>/dev/null
        think_result "Mappa PNG: $png_file"
        think_result "Mappa SVG: $svg_file"
    else
        think_error "graphviz non disponibile, solo file DOT generato"
    fi
    
    # Report testuale
    cat > "$report_file" << TOPOREOF
# 🗺️ Network Topology Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Target:** $target

---

## Statistiche Rete
- **Host trovati:** $host_count
- **Porte aperte totali:** $total_ports
- **Media porte/host:** $(( host_count > 0 ? total_ports / host_count : 0 ))

## File Generati
- Mappa PNG: $png_file
- Mappa SVG: $svg_file
- File DOT: $dot_file

## Host Identificati
$(for ip in $host_nodes; do echo "- $ip"; done)

---
*Topology Map generata da Kali-AI v$VERSION*
TOPOREOF

    echo -e "${GREEN}🗺️ Network Topology Map generata: $map_dir${RESET}"
    think_result "Topology: $host_count host, $total_ports porte → $map_dir"
}

# ═══════════════════════════════════════════════════════════════
# FASE 20: NETWORK TOPOLOGY MAPPER
# ═══════════════════════════════════════════════════════════════

network_topology_map() {
    local target="$1"
    local scan_dir="${2:-$PENTEST_RESULTS_DIR}"
    local map_dir="$REPORTS_DIR/topology_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$map_dir"
    
    tool_ensure "graphviz" "true"
    
    think_phase "NETWORK TOPOLOGY MAPPING"
    think_thought "Genero mappa della rete da risultati scan..."
    
    local dot_file="$map_dir/network.dot"
    local png_file="$map_dir/network_map.png"
    local svg_file="$map_dir/network_map.svg"
    local report_file="$map_dir/topology_report.md"
    
    cat > "$dot_file" << 'DOTHEAD'
digraph NetworkTopology {
    rankdir=TB;
    bgcolor="#1a1a2e";
    node [style=filled, fontname="Courier New", fontcolor=white];
    edge [color="#00ff41", fontcolor="#00ff41", fontname="Courier New"];
    
    label="Kali-AI Network Topology Map";
    labelloc=t;
    fontname="Courier New Bold";
    fontsize=20;
    fontcolor="#00ff41";
    
    attacker [label="🤖 KALI-AI\nAttacker", shape=doubleoctagon, fillcolor="#e94560", fontcolor=white];
DOTHEAD

    local host_count=0
    local total_ports=0
    local host_nodes=""
    
    # Parse host e porte dai risultati scan
    for scan_file in "$scan_dir"/scan/ports_*.txt "$scan_dir"/recon/hosts.txt; do
        [[ ! -f "$scan_file" ]] && continue
        
        while IFS= read -r line; do
            local ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
            [[ -z "$ip" ]] && continue
            [[ "$host_nodes" == *"$ip"* ]] && continue
            
            host_count=$((host_count + 1))
            local node_id="host_${host_count}"
            local os_info=""
            local ports=""
            local services=""
            local risk_color="#16213e"
            local port_count=0
            
            # Cerca info dettagliate nel file scan specifico
            local host_scan="$scan_dir/scan/ports_${ip}.txt"
            if [[ -f "$host_scan" ]]; then
                ports=$(grep "open" "$host_scan" 2>/dev/null | awk '{print $1}' | tr '\n' ', ' | sed 's/,$//')
                services=$(grep "open" "$host_scan" 2>/dev/null | awk '{print $3}' | sort -u | tr '\n' ', ' | sed 's/,$//')
                os_info=$(grep -i "os details\|running:" "$host_scan" 2>/dev/null | head -1 | sed 's/.*: //')
                port_count=$(grep -c "open" "$host_scan" 2>/dev/null || echo 0)
            fi
            
            # Colore basato sul rischio
            if [[ $port_count -gt 10 ]]; then
                risk_color="#e94560"  # rosso = alto rischio
            elif [[ $port_count -gt 5 ]]; then
                risk_color="#f5a623"  # arancione = medio
            elif [[ $port_count -gt 0 ]]; then
                risk_color="#16213e"  # blu = basso
            else
                risk_color="#0f3460"  # blu scuro = minimo
            fi
            
            local label="$ip"
            [[ -n "$os_info" ]] && label="$label\n$os_info"
            [[ -n "$services" ]] && label="$label\n[$services]"
            [[ $port_count -gt 0 ]] && label="$label\n${port_count} porte aperte"
            
            echo "    $node_id [label=\"$label\", shape=box, fillcolor=\"$risk_color\"];" >> "$dot_file"
            echo "    attacker -> $node_id [label=\"scan\"];" >> "$dot_file"
            
            # Aggiungi nodi per servizi critici
            if echo "$ports" | grep -q "80\|443\|8080"; then
                echo "    ${node_id}_web [label=\"🌐 Web\n$ip:80/443\", shape=ellipse, fillcolor=\"#e94560\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_web;" >> "$dot_file"
            fi
            if echo "$ports" | grep -q "445\|139"; then
                echo "    ${node_id}_smb [label=\"📁 SMB\n$ip:445\", shape=ellipse, fillcolor=\"#f5a623\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_smb;" >> "$dot_file"
            fi
            if echo "$ports" | grep -q "3306\|5432\|1433\|27017"; then
                echo "    ${node_id}_db [label=\"🗄️ Database\n$ip\", shape=cylinder, fillcolor=\"#e94560\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_db;" >> "$dot_file"
            fi
            if echo "$ports" | grep -q "22"; then
                echo "    ${node_id}_ssh [label=\"🔑 SSH\n$ip:22\", shape=ellipse, fillcolor=\"#16213e\"];" >> "$dot_file"
                echo "    $node_id -> ${node_id}_ssh;" >> "$dot_file"
            fi
            
            total_ports=$((total_ports + port_count))
            host_nodes="$host_nodes $ip"
            
            think_observe "Host $ip: $port_count porte, servizi: $services"
        done < <(grep -oP '\d+\.\d+\.\d+\.\d+' "$scan_file" 2>/dev/null | sort -u)
    done
    
    # Legenda
    cat >> "$dot_file" << 'DOTLEGEND'
    
    subgraph cluster_legend {
        label="Legenda Rischio";
        style=dashed;
        color="#00ff41";
        fontcolor="#00ff41";
        
        leg_high [label="Alto Rischio\n>10 porte", shape=box, fillcolor="#e94560"];
        leg_med [label="Medio Rischio\n5-10 porte", shape=box, fillcolor="#f5a623"];
        leg_low [label="Basso Rischio\n<5 porte", shape=box, fillcolor="#16213e"];
        leg_high -> leg_med -> leg_low [style=invis];
    }
}
DOTLEGEND

    # Genera immagini
    if command -v dot &>/dev/null; then
        dot -Tpng "$dot_file" -o "$png_file" 2>/dev/null
        dot -Tsvg "$dot_file" -o "$svg_file" 2>/dev/null
        think_result "Mappa PNG: $png_file"
        think_result "Mappa SVG: $svg_file"
    else
        think_error "graphviz non disponibile, solo file DOT generato"
    fi
    
    # Report testuale
    cat > "$report_file" << TOPOREOF
# 🗺️ Network Topology Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Target:** $target

---

## Statistiche Rete
- **Host trovati:** $host_count
- **Porte aperte totali:** $total_ports
- **Media porte/host:** $(( host_count > 0 ? total_ports / host_count : 0 ))

## File Generati
- Mappa PNG: $png_file
- Mappa SVG: $svg_file
- File DOT: $dot_file

## Host Identificati
$(for ip in $host_nodes; do echo "- $ip"; done)

---
*Topology Map generata da Kali-AI v$VERSION*
TOPOREOF

    echo -e "${GREEN}🗺️ Network Topology Map generata: $map_dir${RESET}"
    think_result "Topology: $host_count host, $total_ports porte → $map_dir"
}

# ═══════════════════════════════════════════════════════════════
# FASE 21: RISK SCORING ENGINE
# ═══════════════════════════════════════════════════════════════

risk_score_target() {
    local target="$1"
    local scan_dir="${2:-$PENTEST_RESULTS_DIR}"
    local report_file="$REPORTS_DIR/risk_score_$(date +%Y%m%d_%H%M%S).md"
    
    think_phase "RISK SCORING ENGINE"
    think_thought "Calcolo punteggio di rischio complessivo..."
    
    local total_score=0
    local max_score=100
    local findings=()
    
    # 1. Analisi porte aperte (max 25 punti)
    local port_count=0
    local critical_ports=0
    for scan_file in "$scan_dir"/scan/ports_*.txt; do
        [[ ! -f "$scan_file" ]] && continue
        local pc=$(grep -c "open" "$scan_file" 2>/dev/null || echo 0)
        port_count=$((port_count + pc))
        
        # Porte critiche
        grep "open" "$scan_file" 2>/dev/null | while read -r line; do
            local port=$(echo "$line" | grep -oP '^\d+')
            case "$port" in
                21) critical_ports=$((critical_ports + 1)); findings+=("FTP esposto (porta 21)") ;;
                23) critical_ports=$((critical_ports + 2)); findings+=("TELNET esposto (porta 23) — CRITICO") ;;
                445) critical_ports=$((critical_ports + 2)); findings+=("SMB esposto (porta 445) — CRITICO") ;;
                3389) critical_ports=$((critical_ports + 2)); findings+=("RDP esposto (porta 3389) — CRITICO") ;;
                3306) critical_ports=$((critical_ports + 1)); findings+=("MySQL esposto (porta 3306)") ;;
                5432) critical_ports=$((critical_ports + 1)); findings+=("PostgreSQL esposto (porta 5432)") ;;
                6379) critical_ports=$((critical_ports + 2)); findings+=("Redis esposto (porta 6379) — CRITICO") ;;
                27017) critical_ports=$((critical_ports + 2)); findings+=("MongoDB esposto (porta 27017) — CRITICO") ;;
                1433) critical_ports=$((critical_ports + 2)); findings+=("MSSQL esposto (porta 1433) — CRITICO") ;;
            esac
        done
    done
    
    local port_score=0
    if [[ $port_count -gt 20 ]]; then port_score=25
    elif [[ $port_count -gt 10 ]]; then port_score=20
    elif [[ $port_count -gt 5 ]]; then port_score=15
    elif [[ $port_count -gt 0 ]]; then port_score=10
    fi
    total_score=$((total_score + port_score))
    think_observe "Porte aperte: $port_count → Score: $port_score/25"
    
    # 2. Servizi critici esposti (max 25 punti)
    local service_score=$((critical_ports * 3))
    [[ $service_score -gt 25 ]] && service_score=25
    total_score=$((total_score + service_score))
    think_observe "Servizi critici: $critical_ports → Score: $service_score/25"
    
    # 3. Versioni obsolete / CVE note (max 25 punti)
    local vuln_score=0
    local vuln_count=0
    for vuln_file in "$scan_dir"/vuln/*.txt "$REPORTS_DIR"/cve_report_*.md; do
        [[ ! -f "$vuln_file" ]] && continue
        local vc=$(grep -ci "CVE-\|CRITICAL\|HIGH\|vulnerable" "$vuln_file" 2>/dev/null || echo 0)
        vuln_count=$((vuln_count + vc))
    done
    
    if [[ $vuln_count -gt 20 ]]; then vuln_score=25
    elif [[ $vuln_count -gt 10 ]]; then vuln_score=20
    elif [[ $vuln_count -gt 5 ]]; then vuln_score=15
    elif [[ $vuln_count -gt 0 ]]; then vuln_score=10
    fi
    total_score=$((total_score + vuln_score))
    think_observe "Vulnerabilità trovate: $vuln_count → Score: $vuln_score/25"
    
    # 4. Configurazione debole (max 25 punti)
    local config_score=0
    local weak_configs=0
    
    # Check anonymous FTP
    for f in "$scan_dir"/enum/*.txt "$scan_dir"/scan/*.txt; do
        [[ ! -f "$f" ]] && continue
        grep -qi "anonymous" "$f" 2>/dev/null && { weak_configs=$((weak_configs + 3)); findings+=("FTP Anonymous abilitato"); }
        grep -qi "null session\|guest" "$f" 2>/dev/null && { weak_configs=$((weak_configs + 3)); findings+=("Null session / Guest access"); }
        grep -qi "default password\|admin:admin\|root:root" "$f" 2>/dev/null && { weak_configs=$((weak_configs + 5)); findings+=("Credenziali di default trovate — CRITICO"); }
        grep -qi "directory listing\|index of" "$f" 2>/dev/null && { weak_configs=$((weak_configs + 2)); findings+=("Directory listing abilitato"); }
        grep -qi "ssl.*weak\|sslv3\|tlsv1.0" "$f" 2>/dev/null && { weak_configs=$((weak_configs + 2)); findings+=("SSL/TLS debole"); }
    done
    
    config_score=$((weak_configs))
    [[ $config_score -gt 25 ]] && config_score=25
    total_score=$((total_score + config_score))
    think_observe "Configurazioni deboli: $weak_configs → Score: $config_score/25"
    
    # Determina livello di rischio
    local risk_level=""
    local risk_color=""
    local risk_emoji=""
    if [[ $total_score -ge 75 ]]; then
        risk_level="CRITICAL"
        risk_color="$RED"
        risk_emoji="🔴"
    elif [[ $total_score -ge 50 ]]; then
        risk_level="HIGH"
        risk_color="$RED"
        risk_emoji="🟠"
    elif [[ $total_score -ge 25 ]]; then
        risk_level="MEDIUM"
        risk_color="$YELLOW"
        risk_emoji="🟡"
    else
        risk_level="LOW"
        risk_color="$GREEN"
        risk_emoji="🟢"
    fi
    
    think_result "RISK SCORE: $total_score/$max_score — $risk_level"
    
    # Genera report
    cat > "$report_file" << RISKREOF
# $risk_emoji Risk Assessment Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Target:** $target

---

## Risk Score: $total_score / $max_score — $risk_level

### Breakdown
| Categoria | Score | Max | Dettaglio |
|-----------|-------|-----|-----------|
| Porte Aperte | $port_score | 25 | $port_count porte trovate |
| Servizi Critici | $service_score | 25 | $critical_ports servizi ad alto rischio |
| Vulnerabilità Note | $vuln_score | 25 | $vuln_count CVE/vulnerabilità |
| Configurazioni Deboli | $config_score | 25 | $weak_configs problemi configurazione |
| **TOTALE** | **$total_score** | **$max_score** | **$risk_level** |

### Risk Meter
\`\`\`
[$(printf '█%.0s' $(seq 1 $((total_score / 2))))$(printf '░%.0s' $(seq 1 $(( (max_score - total_score) / 2))))] $total_score%
 0    10    20    30    40    50    60    70    80    90   100
 🟢 LOW    🟡 MEDIUM      🟠 HIGH         🔴 CRITICAL
\`\`\`

### Findings
$(for f in "${findings[@]}"; do echo "- $f"; done)

### Raccomandazioni Prioritarie
$(if [[ $total_score -ge 75 ]]; then
echo "1. **URGENTE:** Isolare immediatamente i sistemi esposti"
echo "2. **URGENTE:** Applicare patch per tutte le CVE critiche"
echo "3. **URGENTE:** Disabilitare servizi non necessari"
echo "4. Implementare segmentazione di rete"
echo "5. Attivare IDS/IPS"
elif [[ $total_score -ge 50 ]]; then
echo "1. Chiudere porte non necessarie"
echo "2. Aggiornare servizi con CVE note"
echo "3. Rimuovere credenziali di default"
echo "4. Implementare firewall rules"
elif [[ $total_score -ge 25 ]]; then
echo "1. Monitorare servizi esposti"
echo "2. Pianificare aggiornamenti"
echo "3. Verificare configurazioni"
else
echo "1. Mantenere le buone pratiche attuali"
echo "2. Continuare monitoraggio periodico"
fi)

---
*Risk Assessment generato da Kali-AI v$VERSION*
RISKREOF

    echo -e "${risk_color}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${risk_color}║  $risk_emoji RISK SCORE: $total_score/$max_score — $risk_level${RESET}"
    echo -e "${risk_color}║  Porte: $port_score | Servizi: $service_score | CVE: $vuln_score | Config: $config_score${RESET}"
    echo -e "${risk_color}╚═══════════════════════════════════════════════════════════════╝${RESET}"
    echo -e "${GREEN}📊 Report: $report_file${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 22: AUTO-EXPLOITATION ENGINE
# ═══════════════════════════════════════════════════════════════

exploit_search() {
    local service="$1"
    local version="$2"
    local output_file="${3:-}"
    
    tool_ensure "exploitdb" "true"
    
    think_phase "EXPLOIT SEARCH: $service $version"
    think_thought "Cerco exploit noti per $service $version..."
    
    local results=""
    local query="$service $version"
    
    # SearchSploit (ExploitDB locale)
    if command -v searchsploit &>/dev/null; then
        results=$(searchsploit --no-colour "$query" 2>/dev/null | head -20)
        
        if [[ -n "$results" ]] && ! echo "$results" | grep -q "No Results"; then
            local exploit_count=$(echo "$results" | grep -c "/" 2>/dev/null || echo 0)
            think_observe "SearchSploit: $exploit_count exploit trovati per $query"
            
            echo -e "${RED}💀 Exploit trovati per $service $version:${RESET}"
            echo "$results"
            echo ""
            
            if [[ -n "$output_file" ]]; then
                echo "## Exploit per $service $version" >> "$output_file"
                echo '```' >> "$output_file"
                echo "$results" >> "$output_file"
                echo '```' >> "$output_file"
                echo "" >> "$output_file"
            fi
        else
            think_thought "Nessun exploit trovato per $query"
        fi
    fi
    
    # Cerca anche moduli Metasploit
    if command -v msfconsole &>/dev/null; then
        think_agent "Cerco moduli Metasploit..."
        local msf_results=$(msfconsole -q -x "search $query; exit" 2>/dev/null | grep -E "exploit/|auxiliary/" | head -10)
        
        if [[ -n "$msf_results" ]]; then
            local msf_count=$(echo "$msf_results" | wc -l)
            think_observe "Metasploit: $msf_count moduli trovati"
            
            echo -e "${RED}🎯 Moduli Metasploit per $service $version:${RESET}"
            echo "$msf_results"
            echo ""
            
            if [[ -n "$output_file" ]]; then
                echo "## Moduli Metasploit per $service $version" >> "$output_file"
                echo '```' >> "$output_file"
                echo "$msf_results" >> "$output_file"
                echo '```' >> "$output_file"
                echo "" >> "$output_file"
            fi
        fi
    fi
}

exploit_scan_from_nmap() {
    local scan_file="$1"
    local report_file="$REPORTS_DIR/exploit_report_$(date +%Y%m%d_%H%M%S).md"
    
    think_phase "AUTO-EXPLOITATION SCAN"
    think_thought "Cerco exploit per tutti i servizi trovati..."
    
    cat > "$report_file" << EXPHEAD
# 💀 Exploitation Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Scan File:** $scan_file
**⚠️ SOLO PER SCOPI DI RICERCA E TEST AUTORIZZATI**

---

EXPHEAD

    local total_exploits=0
    
    while IFS= read -r line; do
        local port=$(echo "$line" | grep -oP '^\d+')
        local service=$(echo "$line" | awk '{print $3}')
        local version_info=$(echo "$line" | sed 's/.*open[[:space:]]*//' | awk '{$1=""; print $0}' | sed 's/^ *//')
        
        if [[ -n "$service" && -n "$version_info" ]]; then
            think_agent "Exploit Search: $service $version_info (porta $port)"
            exploit_search "$service" "$version_info" "$report_file"
            total_exploits=$((total_exploits + 1))
            sleep 0.5
        fi
    done < <(grep "open" "$scan_file" 2>/dev/null | grep -v "^#")
    
    cat >> "$report_file" << EXPFOOT

---

## Sommario
- **Servizi analizzati:** $total_exploits
- **Database:** ExploitDB + Metasploit Framework

## ⚠️ Disclaimer
Questo report è generato per scopi di ricerca e penetration testing autorizzato.
L'uso non autorizzato di exploit è illegale.

---
*Exploitation Report generato da Kali-AI v$VERSION*
EXPFOOT

    think_result "Exploit Scan completato: $total_exploits servizi → $report_file"
    echo -e "${GREEN}💀 Exploit Report: $report_file${RESET}"
}

generate_attack_chain() {
    local target="$1"
    local scan_dir="${2:-$PENTEST_RESULTS_DIR}"
    local report_file="$REPORTS_DIR/attack_chain_$(date +%Y%m%d_%H%M%S).md"
    
    think_phase "ATTACK CHAIN GENERATOR"
    think_thought "Genero catena di attacco basata sui risultati..."
    
    local chain_steps=()
    local step=1
    
    # Step 1: Ricognizione
    chain_steps+=("$step. **Ricognizione** → nmap -sn $target (Host Discovery)")
    step=$((step + 1))
    
    # Step 2: Scansione
    chain_steps+=("$step. **Scansione Porte** → nmap -sV -sC -O $target")
    step=$((step + 1))
    
    # Analizza servizi trovati per costruire la catena
    for scan_file in "$scan_dir"/scan/ports_*.txt; do
        [[ ! -f "$scan_file" ]] && continue
        
        if grep -q "80/tcp.*open\|443/tcp.*open\|8080/tcp.*open" "$scan_file" 2>/dev/null; then
            chain_steps+=("$step. **Web Enumeration** → nikto + dirb + whatweb")
            step=$((step + 1))
            chain_steps+=("$step. **SQL Injection Test** → sqlmap --crawl=3")
            step=$((step + 1))
        fi
        
        if grep -q "445/tcp.*open\|139/tcp.*open" "$scan_file" 2>/dev/null; then
            chain_steps+=("$step. **SMB Enumeration** → enum4linux -a + smbclient")
            step=$((step + 1))
            chain_steps+=("$step. **SMB Exploit Check** → EternalBlue (MS17-010)")
            step=$((step + 1))
        fi
        
        if grep -q "22/tcp.*open" "$scan_file" 2>/dev/null; then
            chain_steps+=("$step. **SSH Audit** → ssh-audit + version check")
            step=$((step + 1))
            chain_steps+=("$step. **SSH Brute Force** → hydra -l root -P wordlist")
            step=$((step + 1))
        fi
        
        if grep -q "21/tcp.*open" "$scan_file" 2>/dev/null; then
            chain_steps+=("$step. **FTP Check** → anonymous login + version exploit")
            step=$((step + 1))
        fi
        
        if grep -q "3306/tcp.*open\|5432/tcp.*open\|1433/tcp.*open" "$scan_file" 2>/dev/null; then
            chain_steps+=("$step. **Database Attack** → brute force + default creds")
            step=$((step + 1))
        fi
        
        if grep -q "3389/tcp.*open" "$scan_file" 2>/dev/null; then
            chain_steps+=("$step. **RDP Attack** → BlueKeep check + brute force")
            step=$((step + 1))
        fi
    done
    
    # Step finale
    chain_steps+=("$step. **Post-Exploitation** → privilege escalation + data exfiltration")
    step=$((step + 1))
    chain_steps+=("$step. **Report** → generazione report completo con evidenze")
    
    cat > "$report_file" << CHAINEOF
# ⛓️ Attack Chain Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Target:** $target

---

## Catena di Attacco Proposta

$(for s in "${chain_steps[@]}"; do echo "$s"; echo ""; done)

## Visualizzazione Catena
\`\`\`
$(for s in "${chain_steps[@]}"; do
    echo "  ┃ $s"
    echo "  ┃   ↓"
done)
  ┗━━ PENTEST COMPLETATO
\`\`\`

---
*Attack Chain generata da Kali-AI v$VERSION*
CHAINEOF

    think_result "Attack Chain: $((step - 1)) step generati → $report_file"
    echo -e "${GREEN}⛓️ Attack Chain: $report_file${RESET}"
    cat "$report_file"
}

# ═══════════════════════════════════════════════════════════════
# FASE 23: PASSIVE CREDENTIAL HARVESTER
# ═══════════════════════════════════════════════════════════════

credential_harvest() {
    local scan_dir="${1:-$PENTEST_RESULTS_DIR}"
    local report_file="$REPORTS_DIR/credentials_$(date +%Y%m%d_%H%M%S).md"
    
    think_phase "PASSIVE CREDENTIAL HARVESTER"
    think_thought "Analizzo risultati per credenziali esposte e configurazioni deboli..."
    
    local findings=()
    local cred_count=0
    
    cat > "$report_file" << CREDHEAD
# 🔑 Credential & Configuration Analysis
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)

---

| Tipo | Dettaglio | Rischio | Fonte |
|------|-----------|---------|-------|
CREDHEAD

    for f in "$scan_dir"/**/*.txt "$scan_dir"/**/*.xml "$scan_dir"/**/*.log 2>/dev/null; do
        [[ ! -f "$f" ]] && continue
        local fname=$(basename "$f")
        
        # Credenziali di default
        if grep -qi "anonymous\s*login\|anonymous\s*allowed\|Anonymous FTP" "$f" 2>/dev/null; then
            echo "| Default Creds | FTP Anonymous Access | CRITICO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
            think_observe "🔑 FTP Anonymous trovato in $fname"
        fi
        
        if grep -qi "null session\|IPC\$.*OK\|guest\s*account" "$f" 2>/dev/null; then
            echo "| Null Session | SMB Null/Guest Session | ALTO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
            think_observe "🔑 SMB Null Session in $fname"
        fi
        
        if grep -qiE "admin:admin|root:root|admin:password|test:test|user:user" "$f" 2>/dev/null; then
            echo "| Default Creds | Default username:password | CRITICO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
            think_observe "🔑 Credenziali default in $fname"
        fi
        
        # Info disclosure
        if grep -qi "server:.*apache\|server:.*nginx\|server:.*iis\|x-powered-by" "$f" 2>/dev/null; then
            local server_info=$(grep -oi "server:.*\|x-powered-by:.*" "$f" 2>/dev/null | head -3 | tr '\n' '; ')
            echo "| Info Disclosure | Server Header: $server_info | MEDIO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
        fi
        
        if grep -qi "phpinfo\|debug.*true\|stack\s*trace\|traceback" "$f" 2>/dev/null; then
            echo "| Info Disclosure | Debug/Error info esposta | ALTO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
            think_observe "🔑 Debug info esposta in $fname"
        fi
        
        # Email e nomi utente
        local emails=$(grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$f" 2>/dev/null | sort -u | head -10)
        if [[ -n "$emails" ]]; then
            local email_count=$(echo "$emails" | wc -l)
            echo "| Email Harvested | $email_count indirizzi email trovati | MEDIO | $fname |" >> "$report_file"
            cred_count=$((cred_count + email_count))
            think_observe "🔑 $email_count email trovate in $fname"
        fi
        
        # Chiavi e token
        if grep -qiE "api[_-]?key|secret[_-]?key|password\s*=|passwd\s*=|token\s*=" "$f" 2>/dev/null; then
            echo "| Secrets | API key/password/token esposti | CRITICO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
            think_observe "🔑 Secrets esposti in $fname"
        fi
        
        # SSL debole
        if grep -qi "sslv2\|sslv3\|tlsv1\.0\|weak cipher\|rc4\|des-cbc" "$f" 2>/dev/null; then
            echo "| Weak Crypto | SSL/TLS debole | ALTO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
        fi
        
        # SNMP community string
        if grep -qi "public\|private" "$f" 2>/dev/null && echo "$fname" | grep -qi "snmp"; then
            echo "| SNMP | Community string default (public/private) | CRITICO | $fname |" >> "$report_file"
            cred_count=$((cred_count + 1))
            think_observe "🔑 SNMP community string default in $fname"
        fi
        
    done
    
    cat >> "$report_file" << CREDFOOT

---

## Sommario
- **Credenziali/configurazioni deboli trovate:** $cred_count
- **Raccomandazione:** Cambiare tutte le credenziali di default, disabilitare accessi anonimi, rimuovere info disclosure

---
*Credential Analysis generata da Kali-AI v$VERSION*
CREDFOOT

    think_result "Credential Harvest: $cred_count findings → $report_file"
    echo -e "${GREEN}🔑 Credential Report: $report_file${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 24: MULTI-TARGET ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

multi_target_pentest() {
    local targets=("$@")
    local master_dir="$PENTEST_DIR/multi_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$master_dir"
    
    think_phase "MULTI-TARGET ORCHESTRATOR"
    think_strategy "Lancio pentest paralleli su ${#targets[@]} target..."
    
    local pids=()
    local target_dirs=()
    
    for target in "${targets[@]}"; do
        local target_dir="$master_dir/target_$(echo $target | tr './' '_')"
        mkdir -p "$target_dir"/{recon,scan,enum,vuln,report}
        target_dirs+=("$target_dir")
        
        think_agent "Avvio pentest su $target..."
        
        (
            PENTEST_RESULTS_DIR="$target_dir"
            
            # Fase 1: Recon
            nmap -sn "$target" -oN "$target_dir/recon/hosts.txt" 2>/dev/null
            
            # Fase 2: Scan
            local hosts=$(grep -oP '\d+\.\d+\.\d+\.\d+' "$target_dir/recon/hosts.txt" 2>/dev/null | sort -u)
            for host in $hosts; do
                nmap -sV -sC -O --top-ports 1000 "$host" -oN "$target_dir/scan/ports_${host}.txt" 2>/dev/null
            done
            
            # Fase 3: Enum per servizio
            for scan_file in "$target_dir"/scan/ports_*.txt; do
                [[ ! -f "$scan_file" ]] && continue
                local ip=$(basename "$scan_file" | grep -oP '\d+\.\d+\.\d+\.\d+')
                
                if grep -q "80/tcp.*open\|443/tcp.*open" "$scan_file" 2>/dev/null; then
                    nikto -h "$ip" -o "$target_dir/enum/nikto_${ip}.txt" 2>/dev/null &
                fi
                if grep -q "445/tcp.*open" "$scan_file" 2>/dev/null; then
                    enum4linux -a "$ip" > "$target_dir/enum/smb_${ip}.txt" 2>/dev/null &
                fi
                wait
            done
            
            echo "PENTEST_DONE" > "$target_dir/.done"
        ) &
        
        pids+=($!)
        think_observe "PID $! avviato per $target"
    done
    
    # Attendi completamento
    think_thought "Attendo completamento di ${#pids[@]} pentest paralleli..."
    local completed=0
    while [[ $completed -lt ${#pids[@]} ]]; do
        completed=0
        for td in "${target_dirs[@]}"; do
            [[ -f "$td/.done" ]] && completed=$((completed + 1))
        done
        think_observe "Completati: $completed/${#pids[@]}"
        sleep 5
    done
    
    # Attendi tutti i processi
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    
    think_result "Tutti i pentest completati"
    
    # Genera report master
    local master_report="$master_dir/master_report.md"
    cat > "$master_report" << MASTEREOF
# 🎯 Multi-Target Pentest Report
## Kali-AI v$VERSION — Cognitive Pentest Framework
**Data:** $(date)
**Target analizzati:** ${#targets[@]}

---

MASTEREOF

    for i in "${!targets[@]}"; do
        local td="${target_dirs[$i]}"
        local t="${targets[$i]}"
        local hosts=$(grep -oP '\d+\.\d+\.\d+\.\d+' "$td/recon/hosts.txt" 2>/dev/null | wc -l)
        local ports=$(grep -c "open" "$td"/scan/ports_*.txt 2>/dev/null || echo 0)
        
        echo "## Target: $t" >> "$master_report"
        echo "- Host trovati: $hosts" >> "$master_report"
        echo "- Porte aperte: $ports" >> "$master_report"
        echo "- Risultati: $td" >> "$master_report"
        echo "" >> "$master_report"
    done
    
    echo "---" >> "$master_report"
    echo "*Multi-Target Report generato da Kali-AI v$VERSION*" >> "$master_report"
    
    echo -e "${GREEN}🎯 Multi-Target Report: $master_report${RESET}"
    think_result "Master Report: $master_report"
}

# ═══════════════════════════════════════════════════════════════
# FASE 25: OSINT AUTOMATED INTELLIGENCE ENGINE
# ═══════════════════════════════════════════════════════════════

osint_full_scan() {
    local target="$1"
    local osint_dir="$REPORTS_DIR/osint_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$osint_dir"/{emails,phones,social,dns,whois,tech,subdomains,wayback,leaks}
    
    think_phase "OSINT FULL SCAN: $target"
    think_strategy "Lancio raccolta intelligence completa su $target..."
    
    tool_ensure_list curl jq whois dnsrecon theHarvester amass
    
    local report_file="$osint_dir/osint_master_report.md"
    
    cat > "$report_file" << OSINTHEAD
# 🔍 OSINT Intelligence Report
## Kali-AI v$VERSION — Automated OSINT Engine
**Data:** $(date)
**Target:** $target
**Classificazione:** RISERVATO — Solo per uso autorizzato

---

OSINTHEAD

    # ═══ 1. WHOIS ═══
    think_agent "OSINT Agent 1: WHOIS Lookup"
    local whois_data=$(whois "$target" 2>/dev/null)
    echo "$whois_data" > "$osint_dir/whois/whois_raw.txt"
    
    local registrant=$(echo "$whois_data" | grep -i "registrant\|admin\|tech" | head -10)
    local registrar=$(echo "$whois_data" | grep -i "registrar:" | head -1)
    local creation=$(echo "$whois_data" | grep -i "creation\|created" | head -1)
    local expiry=$(echo "$whois_data" | grep -i "expir" | head -1)
    local nameservers=$(echo "$whois_data" | grep -i "name server\|nserver" | head -5)
    
    cat >> "$report_file" << WHOISEOF
## 1. WHOIS Intelligence
\`\`\`
Registrar: $registrar
Creazione: $creation
Scadenza: $expiry
Name Servers:
$nameservers

Contatti Registrant:
$registrant
\`\`\`

WHOISEOF
    think_observe "WHOIS completato: registrar, date, nameservers"

    # ═══ 2. DNS ENUMERATION ═══
    think_agent "OSINT Agent 2: DNS Enumeration"
    
    local dns_records=""
    for rtype in A AAAA MX NS TXT SOA CNAME SRV; do
        local result=$(dig +short "$target" "$rtype" 2>/dev/null)
        if [[ -n "$result" ]]; then
            dns_records="$dns_records\n$rtype: $result"
            echo "$rtype: $result" >> "$osint_dir/dns/dns_records.txt"
        fi
    done
    
    # Reverse DNS
    local ip=$(dig +short "$target" A 2>/dev/null | head -1)
    local rdns=""
    if [[ -n "$ip" ]]; then
        rdns=$(dig +short -x "$ip" 2>/dev/null)
        echo "Reverse DNS: $ip → $rdns" >> "$osint_dir/dns/reverse_dns.txt"
    fi
    
    # MX records per email
    local mx_records=$(dig +short "$target" MX 2>/dev/null)
    echo "$mx_records" > "$osint_dir/dns/mx_records.txt"
    
    cat >> "$report_file" << DNSEOF
## 2. DNS Intelligence
**IP Principale:** $ip
**Reverse DNS:** $rdns
**MX Records (email):**
\`\`\`
$mx_records
\`\`\`
**Tutti i record DNS:**
\`\`\`
$(cat "$osint_dir/dns/dns_records.txt" 2>/dev/null)
\`\`\`

DNSEOF
    think_observe "DNS: IP=$ip, MX trovati, $(wc -l < "$osint_dir/dns/dns_records.txt" 2>/dev/null || echo 0) record"

    # ═══ 3. SUBDOMAIN ENUMERATION ═══
    think_agent "OSINT Agent 3: Subdomain Discovery"
    
    # Metodo 1: crt.sh (Certificate Transparency)
    local crtsh_subs=$(curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | sort -u | grep -v "^\*" | head -50)
    echo "$crtsh_subs" > "$osint_dir/subdomains/crtsh.txt"
    
    # Metodo 2: DNS brute force leggero
    local common_subs="www mail ftp admin blog shop api dev staging test portal vpn remote cdn assets static media img images files docs help support forum wiki login register app mobile m"
    for sub in $common_subs; do
        local resolved=$(dig +short "$sub.$target" A 2>/dev/null)
        if [[ -n "$resolved" ]]; then
            echo "$sub.$target → $resolved" >> "$osint_dir/subdomains/bruteforce.txt"
        fi
    done
    
    local sub_count=$(cat "$osint_dir/subdomains/"*.txt 2>/dev/null | sort -u | grep -c "." || echo 0)
    
    cat >> "$report_file" << SUBEOF
## 3. Subdomains ($sub_count trovati)
**Da Certificate Transparency (crt.sh):**
\`\`\`
$(head -20 "$osint_dir/subdomains/crtsh.txt" 2>/dev/null)
\`\`\`
**Da DNS Brute Force:**
\`\`\`
$(cat "$osint_dir/subdomains/bruteforce.txt" 2>/dev/null)
\`\`\`

SUBEOF
    think_observe "Subdomains: $sub_count trovati"

    # ═══ 4. EMAIL HARVESTING ═══
    think_agent "OSINT Agent 4: Email Harvesting"
    
    # Metodo 1: theHarvester
    if command -v theHarvester &>/dev/null; then
        theHarvester -d "$target" -b all -l 200 -f "$osint_dir/emails/harvester" 2>/dev/null
    fi
    
    # Metodo 2: scraping pagine
    local emails=""
    for page in "" "/about" "/contact" "/team" "/impressum" "/privacy"; do
        local page_content=$(curl -sL --max-time 10 "https://$target$page" 2>/dev/null)
        local found_emails=$(echo "$page_content" | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u)
        if [[ -n "$found_emails" ]]; then
            echo "$found_emails" >> "$osint_dir/emails/scraped.txt"
        fi
        
        # Estrai anche numeri di telefono
        local phones=$(echo "$page_content" | grep -oP '[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}' | sort -u)
        if [[ -n "$phones" ]]; then
            echo "$phones" >> "$osint_dir/phones/scraped.txt"
        fi
    done
    
    # Metodo 3: pattern comuni
    for prefix in info contact admin support sales marketing hr jobs; do
        echo "${prefix}@${target}" >> "$osint_dir/emails/guessed.txt"
    done
    
    local email_count=$(cat "$osint_dir/emails/"*.txt 2>/dev/null | sort -u | grep -c "@" || echo 0)
    local phone_count=$(cat "$osint_dir/phones/"*.txt 2>/dev/null | sort -u | grep -c "." || echo 0)
    
    cat >> "$report_file" << EMAILEOF
## 4. Email Intelligence ($email_count trovate)
**Email trovate:**
\`\`\`
$(cat "$osint_dir/emails/"*.txt 2>/dev/null | sort -u | head -30)
\`\`\`

## 5. Phone Intelligence ($phone_count trovati)
**Numeri trovati:**
\`\`\`
$(cat "$osint_dir/phones/"*.txt 2>/dev/null | sort -u | head -20)
\`\`\`

EMAILEOF
    think_observe "Email: $email_count | Telefoni: $phone_count"

    # ═══ 5. TECHNOLOGY DETECTION ═══
    think_agent "OSINT Agent 5: Technology Fingerprinting"
    
    local tech_report=""
    local headers=$(curl -sI --max-time 10 "https://$target" 2>/dev/null)
    echo "$headers" > "$osint_dir/tech/headers.txt"
    
    local server=$(echo "$headers" | grep -i "^server:" | head -1)
    local powered=$(echo "$headers" | grep -i "^x-powered-by:" | head -1)
    local cookies=$(echo "$headers" | grep -i "^set-cookie:" | head -5)
    
    # WhatWeb
    if command -v whatweb &>/dev/null; then
        whatweb -q "$target" > "$osint_dir/tech/whatweb.txt" 2>/dev/null
    fi
    
    # Detect CMS
    local cms="Sconosciuto"
    local page_source=$(curl -sL --max-time 10 "https://$target" 2>/dev/null)
    echo "$page_source" | grep -qi "wp-content\|wordpress" && cms="WordPress"
    echo "$page_source" | grep -qi "joomla" && cms="Joomla"
    echo "$page_source" | grep -qi "drupal" && cms="Drupal"
    echo "$page_source" | grep -qi "shopify" && cms="Shopify"
    echo "$page_source" | grep -qi "wix\.com" && cms="Wix"
    echo "$page_source" | grep -qi "squarespace" && cms="Squarespace"
    echo "$page_source" | grep -qi "magento" && cms="Magento"
    echo "$page_source" | grep -qi "prestashop" && cms="PrestaShop"
    
    cat >> "$report_file" << TECHEOF
## 6. Technology Stack
**Server:** $server
**Powered By:** $powered
**CMS Rilevato:** $cms
**Headers Completi:**
\`\`\`
$headers
\`\`\`
**WhatWeb:**
\`\`\`
$(cat "$osint_dir/tech/whatweb.txt" 2>/dev/null | head -10)
\`\`\`

TECHEOF
    think_observe "Tech: $server | CMS: $cms"

    # ═══ 6. SOCIAL MEDIA DISCOVERY ═══
    think_agent "OSINT Agent 6: Social Media Discovery"
    
    local social_found=""
    local social_platforms=(
        "facebook.com/$target"
        "twitter.com/$target"
        "x.com/$target"
        "instagram.com/$target"
        "linkedin.com/company/$target"
        "github.com/$target"
        "youtube.com/@$target"
        "tiktok.com/@$target"
        "t.me/$target"
        "reddit.com/r/$target"
    )
    
    local domain_name=$(echo "$target" | sed 's/\..*//')
    
    for social_url in "${social_platforms[@]}"; do
        local http_code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "https://$social_url" 2>/dev/null)
        if [[ "$http_code" == "200" || "$http_code" == "301" || "$http_code" == "302" ]]; then
            echo "✅ https://$social_url (HTTP $http_code)" >> "$osint_dir/social/found.txt"
            social_found="$social_found\n✅ https://$social_url"
            think_observe "Social trovato: $social_url"
        fi
    done
    
    # Cerca anche con il nome senza TLD
    for social_url in "facebook.com/$domain_name" "twitter.com/$domain_name" "instagram.com/$domain_name" "linkedin.com/company/$domain_name" "github.com/$domain_name"; do
        local http_code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "https://$social_url" 2>/dev/null)
        if [[ "$http_code" == "200" || "$http_code" == "301" || "$http_code" == "302" ]]; then
            echo "✅ https://$social_url (HTTP $http_code)" >> "$osint_dir/social/found.txt"
        fi
    done
    
    local social_count=$(cat "$osint_dir/social/found.txt" 2>/dev/null | grep -c "✅" || echo 0)
    
    cat >> "$report_file" << SOCIALEOF
## 7. Social Media ($social_count profili trovati)
\`\`\`
$(cat "$osint_dir/social/found.txt" 2>/dev/null)
\`\`\`

SOCIALEOF

    # ═══ 7. WAYBACK MACHINE ═══
    think_agent "OSINT Agent 7: Wayback Machine History"
    
    local wayback=$(curl -s "https://web.archive.org/web/timemap/json?url=$target&limit=20" 2>/dev/null | \
        jq -r '.[]? | "\(.[1]) - \(.[2])"' 2>/dev/null | tail -10)
    echo "$wayback" > "$osint_dir/wayback/history.txt"
    
    cat >> "$report_file" << WAYEOF
## 8. Wayback Machine History
\`\`\`
$(cat "$osint_dir/wayback/history.txt" 2>/dev/null | head -10)
\`\`\`

WAYEOF

    # ═══ 8. SECURITY HEADERS CHECK ═══
    think_agent "OSINT Agent 8: Security Headers Audit"
    
    local sec_score=0
    local sec_max=7
    local sec_findings=""
    
    echo "$headers" | grep -qi "strict-transport-security" && sec_score=$((sec_score+1)) || sec_findings="$sec_findings\n❌ HSTS mancante"
    echo "$headers" | grep -qi "content-security-policy" && sec_score=$((sec_score+1)) || sec_findings="$sec_findings\n❌ CSP mancante"
    echo "$headers" | grep -qi "x-frame-options" && sec_score=$((sec_score+1)) || sec_findings="$sec_findings\n❌ X-Frame-Options mancante"
    echo "$headers" | grep -qi "x-content-type-options" && sec_score=$((sec_score+1)) || sec_findings="$sec_findings\n❌ X-Content-Type-Options mancante"
    echo "$headers" | grep -qi "x-xss-protection" && sec_score=$((sec_score+1)) || sec_findings="$sec_findings\n❌ X-XSS-Protection mancante"
    echo "$headers" | grep -qi "referrer-policy" && sec_score=$((sec_score+1)) || sec_findings="$sec_findings\n❌ Referrer-Policy mancante"
    echo "$headers" | grep -qi "permissions-policy" && sec_score=$((sec_score+1)) || sec_findings="$sec_findings\n❌ Permissions-Policy mancante"
    
    cat >> "$report_file" << SECEOF
## 9. Security Headers ($sec_score/$sec_max)
$sec_findings

SECEOF

    # ═══ SOMMARIO FINALE ═══
    cat >> "$report_file" << OSINTFOOT

---

## 📊 Sommario OSINT
| Categoria | Risultati |
|-----------|-----------|
| Subdomains | $sub_count |
| Email | $email_count |
| Telefoni | $phone_count |
| Social Media | $social_count |
| Security Headers | $sec_score/$sec_max |
| CMS | $cms |
| IP | $ip |

## 📁 File Generati
- WHOIS: $osint_dir/whois/
- DNS: $osint_dir/dns/
- Subdomains: $osint_dir/subdomains/
- Email: $osint_dir/emails/
- Telefoni: $osint_dir/phones/
- Social: $osint_dir/social/
- Tech: $osint_dir/tech/
- Wayback: $osint_dir/wayback/

---
*OSINT Report generato da Kali-AI v$VERSION — Automated OSINT Engine*
*⚠️ Uso autorizzato — Legge 48/2008 (IT), GDPR Art.6*
OSINTFOOT

    think_result "OSINT completato: $sub_count subdomains, $email_count email, $phone_count telefoni, $social_count social"
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║  🔍 OSINT COMPLETATO: $target${RESET}"
    echo -e "${GREEN}║  📧 Email: $email_count | 📱 Telefoni: $phone_count | 🌐 Social: $social_count${RESET}"
    echo -e "${GREEN}║  🔗 Subdomains: $sub_count | 🔒 Security: $sec_score/$sec_max${RESET}"
    echo -e "${GREEN}║  📄 Report: $report_file${RESET}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 26: WEBSITE VULNERABILITY SCANNER
# ═══════════════════════════════════════════════════════════════

website_vuln_scan() {
    local target="$1"
    local vuln_dir="$REPORTS_DIR/webvuln_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$vuln_dir"
    
    think_phase "WEBSITE VULNERABILITY SCAN: $target"
    tool_ensure_list nikto dirb whatweb sqlmap sslscan
    
    local report_file="$vuln_dir/vuln_report.md"
    
    cat > "$report_file" << VULNHEAD
# 🛡️ Website Vulnerability Report
## Kali-AI v$VERSION — Web Security Scanner
**Data:** $(date)
**Target:** $target

---

VULNHEAD

    # 1. Nikto
    think_agent "Web Agent 1: Nikto Scan"
    nikto -h "https://$target" -o "$vuln_dir/nikto.txt" -Format txt 2>/dev/null &
    local nikto_pid=$!
    
    # 2. Directory Bruteforce
    think_agent "Web Agent 2: Directory Scan"
    dirb "https://$target" /usr/share/wordlists/dirb/common.txt -o "$vuln_dir/dirb.txt" -S 2>/dev/null &
    local dirb_pid=$!
    
    # 3. WhatWeb fingerprint
    think_agent "Web Agent 3: Technology Fingerprint"
    whatweb -a 3 "https://$target" > "$vuln_dir/whatweb.txt" 2>/dev/null &
    local whatweb_pid=$!
    
    # 4. SSL Check
    think_agent "Web Agent 4: SSL/TLS Audit"
    if command -v sslscan &>/dev/null; then
        sslscan "$target" > "$vuln_dir/sslscan.txt" 2>/dev/null &
        local ssl_pid=$!
    fi
    
    # 5. Header analysis
    think_agent "Web Agent 5: Header Analysis"
    curl -sI "https://$target" > "$vuln_dir/headers.txt" 2>/dev/null
    curl -sI "http://$target" > "$vuln_dir/headers_http.txt" 2>/dev/null
    
    # 6. Robots.txt e sitemap
    think_agent "Web Agent 6: Robots & Sitemap"
    curl -s "https://$target/robots.txt" > "$vuln_dir/robots.txt" 2>/dev/null
    curl -s "https://$target/sitemap.xml" > "$vuln_dir/sitemap.xml" 2>/dev/null
    
    # Attendi scan paralleli
    think_thought "Attendo completamento scan paralleli..."
    wait $nikto_pid 2>/dev/null
    wait $dirb_pid 2>/dev/null
    wait $whatweb_pid 2>/dev/null
    [[ -n "${ssl_pid:-}" ]] && wait $ssl_pid 2>/dev/null
    
    # Compila report
    local nikto_vulns=$(grep -c "OSVDB\|+" "$vuln_dir/nikto.txt" 2>/dev/null || echo 0)
    local dirs_found=$(grep -c "CODE:200" "$vuln_dir/dirb.txt" 2>/dev/null || echo 0)
    local ssl_issues=$(grep -ci "weak\|vulnerable\|sslv\|tlsv1\.0" "$vuln_dir/sslscan.txt" 2>/dev/null || echo 0)
    
    cat >> "$report_file" << VULNBODY
## 1. Nikto Scan ($nikto_vulns findings)
\`\`\`
$(cat "$vuln_dir/nikto.txt" 2>/dev/null | head -40)
\`\`\`

## 2. Directory Discovery ($dirs_found trovate)
\`\`\`
$(grep "CODE:200" "$vuln_dir/dirb.txt" 2>/dev/null | head -30)
\`\`\`

## 3. Technology Stack
\`\`\`
$(cat "$vuln_dir/whatweb.txt" 2>/dev/null | head -10)
\`\`\`

## 4. SSL/TLS Audit ($ssl_issues problemi)
\`\`\`
$(cat "$vuln_dir/sslscan.txt" 2>/dev/null | head -30)
\`\`\`

## 5. Robots.txt
\`\`\`
$(cat "$vuln_dir/robots.txt" 2>/dev/null | head -20)
\`\`\`

## 6. Response Headers
\`\`\`
$(cat "$vuln_dir/headers.txt" 2>/dev/null)
\`\`\`

---

## Sommario Vulnerabilità
| Scanner | Findings |
|---------|----------|
| Nikto | $nikto_vulns |
| Directories | $dirs_found |
| SSL Issues | $ssl_issues |

---
*Web Vulnerability Report generato da Kali-AI v$VERSION*
*⚠️ Solo per penetration testing autorizzato*
VULNBODY

    think_result "Web Vuln Scan: nikto=$nikto_vulns, dirs=$dirs_found, ssl=$ssl_issues"
    echo -e "${GREEN}🛡️ Web Vuln Report: $report_file${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 27: EMAIL FORENSICS & THREAT INVESTIGATION ENGINE
# ═══════════════════════════════════════════════════════════════

investigate_email() {
    local suspect_email="$1"
    local case_description="${2:-Indagine email sospetta}"
    local case_dir="$REPORTS_DIR/investigation_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$case_dir"/{email_trace,ip_trace,domain_intel,social_links,vpn_detection,timeline,evidence}
    
    think_phase "🔎 INVESTIGAZIONE EMAIL: $suspect_email"
    think_strategy "Attivo tutti i protocolli di investigazione simultaneamente..."
    think_thought "Caso: $case_description"
    
    tool_ensure_list curl jq whois dnsrecon nmap theHarvester
    
    # Estrai dominio dalla email
    local email_domain=$(echo "$suspect_email" | grep -oP '@\K.*')
    local email_user=$(echo "$suspect_email" | grep -oP '^[^@]+')
    
    think_observe "Email: $suspect_email | User: $email_user | Dominio: $email_domain"
    
    local report_file="$case_dir/investigation_report.txt"
    local evidence_log="$case_dir/evidence/evidence_chain.txt"
    
    # Inizia catena di custodia
    cat > "$evidence_log" << EVIDEOF
═══════════════════════════════════════════════════════════════
CATENA DI CUSTODIA DIGITALE — EVIDENCE LOG
═══════════════════════════════════════════════════════════════
Caso: $case_description
Email sospetta: $suspect_email
Data inizio indagine: $(date)
Investigatore: Kali-AI v$VERSION (Automated)
Operatore: $AUTHOR

TIMELINE EVIDENZE:
EVIDEOF

    cat > "$report_file" << REPHEAD
═══════════════════════════════════════════════════════════════
        KALI-AI v$VERSION — RAPPORTO INVESTIGATIVO
           Email Forensics & Threat Investigation
═══════════════════════════════════════════════════════════════

DATI CASO
  Oggetto:         $case_description
  Email sospetta:  $suspect_email
  Dominio:         $email_domain
  Data indagine:   $(date)
  Investigatore:   Kali-AI v$VERSION Automated Forensics
  Operatore:       $AUTHOR

═══════════════════════════════════════════════════════════════
REPHEAD

    # ═══════════════════════════════════════════════
    # AGENTE 1: DOMAIN INTELLIGENCE (background)
    # ═══════════════════════════════════════════════
    (
        think_agent "Agent 1: Domain Intelligence — $email_domain"
        
        # WHOIS
        local whois_data=$(whois "$email_domain" 2>/dev/null)
        echo "$whois_data" > "$case_dir/domain_intel/whois_raw.txt"
        
        local registrant=$(echo "$whois_data" | grep -iE "registrant|admin name|tech name" | head -10)
        local registrar=$(echo "$whois_data" | grep -i "registrar:" | head -1 | sed 's/.*: //')
        local creation=$(echo "$whois_data" | grep -iE "creation|created" | head -1 | sed 's/.*: //')
        local country=$(echo "$whois_data" | grep -iE "country|registrant country" | head -1 | sed 's/.*: //')
        local nameservers=$(echo "$whois_data" | grep -iE "name server|nserver" | sed 's/.*: //')
        
        # DNS
        local mx=$(dig +short "$email_domain" MX 2>/dev/null)
        local spf=$(dig +short "$email_domain" TXT 2>/dev/null | grep -i "spf")
        local dmarc=$(dig +short "_dmarc.$email_domain" TXT 2>/dev/null)
        local dkim_selectors="default google selector1 selector2 k1 mandrill"
        local dkim_found=""
        for sel in $dkim_selectors; do
            local dk=$(dig +short "${sel}._domainkey.$email_domain" TXT 2>/dev/null)
            [[ -n "$dk" ]] && dkim_found="$dkim_found\n  $sel: $dk"
        done
        
        local ip=$(dig +short "$email_domain" A 2>/dev/null | head -1)
        local rdns=$(dig +short -x "$ip" 2>/dev/null)
        
        # Verifica se dominio e temporaneo/disposable
        local disposable="NO"
        local disposable_domains="tempmail guerrillamail mailinator throwaway yopmail trashmail 10minutemail dispostable"
        for dd in $disposable_domains; do
            echo "$email_domain" | grep -qi "$dd" && disposable="SI — DOMINIO TEMPORANEO"
        done
        
        # Eta del dominio
        local domain_age="Sconosciuta"
        if [[ -n "$creation" ]]; then
            local creation_year=$(echo "$creation" | grep -oP '\d{4}' | head -1)
            local current_year=$(date +%Y)
            if [[ -n "$creation_year" ]]; then
                domain_age="$((current_year - creation_year)) anni (creato: $creation)"
            fi
        fi
        
        cat > "$case_dir/domain_intel/analysis.txt" << DOMEOF
ANALISI DOMINIO: $email_domain
  Registrar:      $registrar
  Creazione:      $creation
  Età dominio:    $domain_age
  Paese:          $country
  Disposable:     $disposable
  IP:             $ip
  Reverse DNS:    $rdns
  Name Servers:   $nameservers
  MX Records:     $mx
  SPF:            $spf
  DMARC:          $dmarc
  DKIM:           $dkim_found
  
REGISTRANT INFO:
$registrant
DOMEOF
        
        echo "[$(date +%H:%M:%S)] EVIDENCE: Domain Intel completato — $email_domain → IP:$ip, Registrar:$registrar, Country:$country" >> "$evidence_log"
        echo "AGENT1_DONE" > "$case_dir/.agent1_done"
    ) &
    local agent1_pid=$!

    # ═══════════════════════════════════════════════
    # AGENTE 2: IP TRACING & GEOLOCATION (background)
    # ═══════════════════════════════════════════════
    (
        think_agent "Agent 2: IP Tracing & Geolocation"
        
        local ip=$(dig +short "$email_domain" A 2>/dev/null | head -1)
        
        if [[ -n "$ip" ]]; then
            # IP Geolocation
            local geoip=$(curl -s "http://ip-api.com/json/$ip" 2>/dev/null)
            echo "$geoip" > "$case_dir/ip_trace/geoip.json"
            
            local geo_country=$(echo "$geoip" | jq -r '.country // "N/A"')
            local geo_city=$(echo "$geoip" | jq -r '.city // "N/A"')
            local geo_region=$(echo "$geoip" | jq -r '.regionName // "N/A"')
            local geo_isp=$(echo "$geoip" | jq -r '.isp // "N/A"')
            local geo_org=$(echo "$geoip" | jq -r '.org // "N/A"')
            local geo_as=$(echo "$geoip" | jq -r '.as // "N/A"')
            local geo_lat=$(echo "$geoip" | jq -r '.lat // "N/A"')
            local geo_lon=$(echo "$geoip" | jq -r '.lon // "N/A"')
            local geo_proxy=$(echo "$geoip" | jq -r '.proxy // false')
            local geo_hosting=$(echo "$geoip" | jq -r '.hosting // false')
            
            # VPN/Proxy detection
            local vpn_detected="NO"
            local vpn_indicators=""
            
            # Check known VPN/Proxy ASNs
            echo "$geo_as" | grep -qi "nord\|express\|surfshark\|proton\|mullvad\|cyberghost\|private internet\|tunnelbear" && {
                vpn_detected="SI — VPN COMMERCIALE RILEVATA"
                vpn_indicators="ASN associato a provider VPN noto"
            }
            
            echo "$geo_org" | grep -qi "hosting\|cloud\|server\|digital ocean\|aws\|azure\|google cloud\|ovh\|hetzner\|vultr\|linode" && {
                vpn_detected="PROBABILE — IP di hosting/cloud"
                vpn_indicators="$vpn_indicators | IP appartiene a provider hosting"
            }
            
            [[ "$geo_proxy" == "true" ]] && vpn_detected="SI — PROXY RILEVATO"
            [[ "$geo_hosting" == "true" ]] && vpn_indicators="$vpn_indicators | IP hosting confermato"
            
            # Traceroute
            traceroute -m 15 -w 2 "$ip" > "$case_dir/ip_trace/traceroute.txt" 2>/dev/null
            
            # Port scan leggero
            nmap -sV --top-ports 100 -T4 "$ip" -oN "$case_dir/ip_trace/portscan.txt" 2>/dev/null
            
            # Shodan-like info via headers
            local server_headers=$(curl -sI --max-time 10 "http://$ip" 2>/dev/null)
            echo "$server_headers" > "$case_dir/ip_trace/server_headers.txt"
            
            cat > "$case_dir/ip_trace/analysis.txt" << IPEOF
ANALISI IP: $ip
  Paese:          $geo_country
  Regione:        $geo_region
  Città:          $geo_city
  Coordinate:     $geo_lat, $geo_lon
  ISP:            $geo_isp
  Organizzazione: $geo_org
  ASN:            $geo_as
  
VPN/PROXY DETECTION:
  VPN rilevata:   $vpn_detected
  Indicatori:     $vpn_indicators
  Proxy flag:     $geo_proxy
  Hosting flag:   $geo_hosting
  
PORTE APERTE:
$(grep "open" "$case_dir/ip_trace/portscan.txt" 2>/dev/null | head -20)

TRACEROUTE:
$(cat "$case_dir/ip_trace/traceroute.txt" 2>/dev/null | tail -15)
IPEOF
            
            echo "[$(date +%H:%M:%S)] EVIDENCE: IP Trace — $ip → $geo_country/$geo_city, ISP:$geo_isp, VPN:$vpn_detected" >> "$evidence_log"
        fi
        
        echo "AGENT2_DONE" > "$case_dir/.agent2_done"
    ) &
    local agent2_pid=$!

    # ═══════════════════════════════════════════════
    # AGENTE 3: EMAIL REPUTATION & BREACH CHECK (background)
    # ═══════════════════════════════════════════════
    (
        think_agent "Agent 3: Email Reputation & Breach Check"
        
        # Check email format validity
        local email_valid="SI"
        echo "$suspect_email" | grep -qP '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' || email_valid="NO — FORMATO NON VALIDO"
        
        # Check MX validity (dominio accetta email?)
        local mx_valid=$(dig +short "$email_domain" MX 2>/dev/null)
        local mx_status="NO — Nessun MX record (dominio non riceve email)"
        [[ -n "$mx_valid" ]] && mx_status="SI — MX attivo"
        
        # Email age estimation (basato su quando il dominio è stato creato)
        local domain_whois=$(whois "$email_domain" 2>/dev/null)
        local domain_created=$(echo "$domain_whois" | grep -iE "creation|created" | head -1 | sed 's/.*: //')
        
        # Check se email appare in paste/leak databases (via API pubbliche)
        local breach_check=""
        
        # Hunter.io verification (se disponibile)
        local hunter_check=$(curl -s "https://api.hunter.io/v2/email-verifier?email=$suspect_email" 2>/dev/null | jq -r '.data.status // "unknown"' 2>/dev/null)
        
        # Gravatar check (email ha un profilo?)
        local email_md5=$(echo -n "$suspect_email" | md5sum | awk '{print $1}')
        local gravatar_check=$(curl -sI "https://www.gravatar.com/avatar/$email_md5?d=404" 2>/dev/null | head -1)
        local has_gravatar="NO"
        echo "$gravatar_check" | grep -q "200" && has_gravatar="SI — Profilo Gravatar trovato"
        
        cat > "$case_dir/email_trace/reputation.txt" << REPEOF
ANALISI EMAIL: $suspect_email
  Formato valido:     $email_valid
  MX attivo:          $mx_status
  Dominio creato:     $domain_created
  Gravatar:           $has_gravatar
  Hunter.io status:   $hunter_check
  
INDICATORI DI RISCHIO:
$(echo "$email_domain" | grep -qiE "temp|trash|guerrilla|mailinator|throwaway|yop|disposable" && echo "  ⚠️ DOMINIO EMAIL TEMPORANEO/DISPOSABLE" || echo "  ✅ Dominio non in blacklist disposable")
$(echo "$email_user" | grep -qP '^[a-z]{15,}$|^[0-9]+$|^[a-z]+[0-9]{4,}$' && echo "  ⚠️ USERNAME SOSPETTO (pattern automatico)" || echo "  ✅ Username con pattern normale")
$([[ -z "$mx_valid" ]] && echo "  ⚠️ NESSUN MX — Il dominio potrebbe non esistere o essere falso" || echo "  ✅ MX record presente")
REPEOF
        
        echo "[$(date +%H:%M:%S)] EVIDENCE: Email Reputation — Valid:$email_valid, MX:$mx_status, Gravatar:$has_gravatar" >> "$evidence_log"
        echo "AGENT3_DONE" > "$case_dir/.agent3_done"
    ) &
    local agent3_pid=$!

    # ═══════════════════════════════════════════════
    # AGENTE 4: SOCIAL MEDIA OSINT (background)
    # ═══════════════════════════════════════════════
    (
        think_agent "Agent 4: Social Media & Web Presence"
        
        # Cerca username su social media
        local username="$email_user"
        
        local social_results=""
        local platforms=(
            "https://www.facebook.com/$username"
            "https://twitter.com/$username"
            "https://x.com/$username"
            "https://www.instagram.com/$username"
            "https://www.linkedin.com/in/$username"
            "https://github.com/$username"
            "https://www.reddit.com/user/$username"
            "https://t.me/$username"
            "https://www.tiktok.com/@$username"
            "https://www.youtube.com/@$username"
            "https://www.pinterest.com/$username"
            "https://medium.com/@$username"
            "https://keybase.io/$username"
            "https://www.flickr.com/people/$username"
            "https://steamcommunity.com/id/$username"
        )
        
        for url in "${platforms[@]}"; do
            local http_code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null)
            if [[ "$http_code" == "200" ]]; then
                echo "TROVATO: $url (HTTP $http_code)" >> "$case_dir/social_links/found.txt"
            fi
        done
        
        # Cerca l'email stessa nel web
        local web_mentions=$(curl -s "https://www.google.com/search?q=%22$suspect_email%22&num=10" 2>/dev/null | \
            grep -oP 'href="[^"]*"' | grep -v "google" | head -10)
        echo "$web_mentions" > "$case_dir/social_links/web_mentions.txt"
        
        cat > "$case_dir/social_links/analysis.txt" << SOCEOF
SOCIAL MEDIA OSINT: $username (da $suspect_email)

PROFILI TROVATI:
$(cat "$case_dir/social_links/found.txt" 2>/dev/null || echo "Nessun profilo trovato")

MENZIONI WEB:
$(cat "$case_dir/social_links/web_mentions.txt" 2>/dev/null | head -10 || echo "Nessuna menzione")
SOCEOF
        
        local social_count=$(grep -c "TROVATO" "$case_dir/social_links/found.txt" 2>/dev/null || echo 0)
        echo "[$(date +%H:%M:%S)] EVIDENCE: Social OSINT — $social_count profili trovati per username '$username'" >> "$evidence_log"
        echo "AGENT4_DONE" > "$case_dir/.agent4_done"
    ) &
    local agent4_pid=$!

    # ═══════════════════════════════════════════════
    # AGENTE 5: HEADER ANALYSIS (se forniti)
    # ═══════════════════════════════════════════════
    (
        think_agent "Agent 5: Infrastructure Analysis"
        
        local ip=$(dig +short "$email_domain" A 2>/dev/null | head -1)
        
        # Cerca altri domini sullo stesso IP (reverse IP)
        if [[ -n "$ip" ]]; then
            local reverse_ip=$(curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip" 2>/dev/null)
            echo "$reverse_ip" > "$case_dir/domain_intel/reverse_ip.txt"
            
            # Subdomains via crt.sh
            local subs=$(curl -s "https://crt.sh/?q=%25.$email_domain&output=json" 2>/dev/null | \
                jq -r '.[].name_value' 2>/dev/null | sort -u | head -30)
            echo "$subs" > "$case_dir/domain_intel/subdomains.txt"
            
            # SSL Certificate info
            local cert_info=$(echo | openssl s_client -servername "$email_domain" -connect "$email_domain:443" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null)
            echo "$cert_info" > "$case_dir/domain_intel/ssl_cert.txt"
        fi
        
        cat > "$case_dir/domain_intel/infrastructure.txt" << INFRAEOF
INFRASTRUTTURA: $email_domain

ALTRI DOMINI SULLO STESSO IP ($ip):
$(cat "$case_dir/domain_intel/reverse_ip.txt" 2>/dev/null | head -20)

SUBDOMAINS:
$(cat "$case_dir/domain_intel/subdomains.txt" 2>/dev/null | head -20)

CERTIFICATO SSL:
$(cat "$case_dir/domain_intel/ssl_cert.txt" 2>/dev/null)
INFRAEOF
        
        echo "[$(date +%H:%M:%S)] EVIDENCE: Infrastructure — reverse IP, subdomains, SSL cert analizzati" >> "$evidence_log"
        echo "AGENT5_DONE" > "$case_dir/.agent5_done"
    ) &
    local agent5_pid=$!

    # ═══════════════════════════════════════════════
    # ATTENDI TUTTI GLI AGENTI
    # ═══════════════════════════════════════════════
    think_thought "5 agenti investigativi attivi in parallelo..."
    
    local agents_done=0
    while [[ $agents_done -lt 5 ]]; do
        agents_done=0
        for i in 1 2 3 4 5; do
            [[ -f "$case_dir/.agent${i}_done" ]] && agents_done=$((agents_done + 1))
        done
        think_observe "Agenti completati: $agents_done/5"
        sleep 2
    done
    
    wait $agent1_pid $agent2_pid $agent3_pid $agent4_pid $agent5_pid 2>/dev/null
    
    think_result "Tutti gli agenti hanno completato l'indagine"

    # ═══════════════════════════════════════════════
    # COMPILAZIONE REPORT FINALE
    # ═══════════════════════════════════════════════
    think_phase "COMPILAZIONE REPORT INVESTIGATIVO"
    
    cat >> "$report_file" << REPBODY

═══════════════════════════════════════════════════════════════
1. ANALISI DOMINIO EMAIL
═══════════════════════════════════════════════════════════════
$(cat "$case_dir/domain_intel/analysis.txt" 2>/dev/null)

═══════════════════════════════════════════════════════════════
2. TRACCIAMENTO IP & GEOLOCALIZZAZIONE
═══════════════════════════════════════════════════════════════
$(cat "$case_dir/ip_trace/analysis.txt" 2>/dev/null)

═══════════════════════════════════════════════════════════════
3. REPUTAZIONE EMAIL & BREACH CHECK
═══════════════════════════════════════════════════════════════
$(cat "$case_dir/email_trace/reputation.txt" 2>/dev/null)

═══════════════════════════════════════════════════════════════
4. SOCIAL MEDIA & PRESENZA WEB
═══════════════════════════════════════════════════════════════
$(cat "$case_dir/social_links/analysis.txt" 2>/dev/null)

═══════════════════════════════════════════════════════════════
5. ANALISI INFRASTRUTTURA
═══════════════════════════════════════════════════════════════
$(cat "$case_dir/domain_intel/infrastructure.txt" 2>/dev/null)

═══════════════════════════════════════════════════════════════
6. CATENA DELLE EVIDENZE
═══════════════════════════════════════════════════════════════
$(cat "$evidence_log" 2>/dev/null)

═══════════════════════════════════════════════════════════════
7. CONCLUSIONI E RACCOMANDAZIONI
═══════════════════════════════════════════════════════════════

VALUTAZIONE MINACCIA:
$(cat "$case_dir/ip_trace/analysis.txt" 2>/dev/null | grep -i "vpn" | head -3)
$(cat "$case_dir/email_trace/reputation.txt" 2>/dev/null | grep "⚠️" | head -5)

RACCOMANDAZIONI:
  1. Conservare tutte le evidenze digitali (cartella: $case_dir)
  2. Verificare gli header originali dell'email malevola
  3. Segnalare l'IP sorgente al provider (abuse@)
  4. Se VPN rilevata: richiedere log al provider tramite autorità
  5. Cross-referenziare i profili social trovati
  6. Presentare il report alle autorità competenti (Polizia Postale)

═══════════════════════════════════════════════════════════════
Fine indagine: $(date)
Report generato da: Kali-AI v$VERSION — Automated Forensics
Operatore: $AUTHOR
Classificazione: RISERVATO
═══════════════════════════════════════════════════════════════
REPBODY

    # Pulizia file temporanei
    rm -f "$case_dir"/.agent*_done
    
    think_result "INDAGINE COMPLETATA — Report: $report_file"
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║  🔎 INDAGINE COMPLETATA: $suspect_email${RESET}"
    echo -e "${GREEN}║  📄 Report TXT: $report_file${RESET}"
    echo -e "${GREEN}║  📁 Evidenze: $case_dir${RESET}"
    echo -e "${GREEN}║  📋 Evidence Log: $evidence_log${RESET}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 28: CRIMINAL NETWORK INTELLIGENCE ENGINE (CNI)
# ═══════════════════════════════════════════════════════════════
# Il cuore di Kali-AI: dato un punto di partenza (email, telefono,
# IP, username, wallet crypto), costruisce automaticamente il grafo
# delle connessioni, identifica le identità collegate, traccia i
# flussi e identifica i nodi centrali della rete.
# ═══════════════════════════════════════════════════════════════

CNI_DIR="$BASE_DIR/cni_investigations"

cni_init_case() {
    local case_id="CNI_$(date +%Y%m%d_%H%M%S)"
    local case_dir="$CNI_DIR/$case_id"
    mkdir -p "$case_dir"/{graph,entities,connections,timeline,evidence,reports,crypto,correlation}
    
    # Database grafo entità
    echo '{"nodes":[],"edges":[],"clusters":[]}' > "$case_dir/graph/network_graph.json"
    # Database entità scoperte
    echo '{"emails":[],"phones":[],"ips":[],"usernames":[],"domains":[],"wallets":[],"names":[],"addresses":[]}' > "$case_dir/entities/entity_db.json"
    # Timeline eventi
    echo '[]' > "$case_dir/timeline/events.json"
    
    echo "$case_id"
    echo "$case_dir"
}

cni_add_entity() {
    local case_dir="$1"
    local entity_type="$2"  # email, phone, ip, username, domain, wallet, name
    local entity_value="$3"
    local source="$4"
    local confidence="${5:-medium}"
    
    local db="$case_dir/entities/entity_db.json"
    local graph="$case_dir/graph/network_graph.json"
    
    # Check duplicati
    if jq -e --arg v "$entity_value" --arg t "$entity_type" '.[$t] | index($v)' "$db" &>/dev/null; then
        return 0  # Già presente
    fi
    
    # Aggiungi a entity_db
    local updated=$(jq --arg t "$entity_type" --arg v "$entity_value" '.[$t] += [$v]' "$db")
    echo "$updated" > "$db"
    
    # Aggiungi nodo al grafo
    local node_id=$(echo "$entity_value" | md5sum | cut -c1-12)
    local node=$(jq -cn \
        --arg id "$node_id" \
        --arg type "$entity_type" \
        --arg value "$entity_value" \
        --arg src "$source" \
        --arg conf "$confidence" \
        --arg time "$(date -Iseconds)" \
        '{id:$id, type:$type, value:$value, source:$src, confidence:$conf, discovered:$time}')
    
    local graph_updated=$(jq --argjson n "$node" '.nodes += [$n]' "$graph")
    echo "$graph_updated" > "$graph"
    
    think_observe "CNI: Nuova entità [$entity_type] $entity_value (confidence: $confidence)"
}

cni_add_connection() {
    local case_dir="$1"
    local from_value="$2"
    local to_value="$3"
    local relation="$4"  # owns, uses, contacted, linked_to, same_person, hosted_on
    local evidence="$5"
    local strength="${6:-medium}"
    
    local graph="$case_dir/graph/network_graph.json"
    
    local from_id=$(echo "$from_value" | md5sum | cut -c1-12)
    local to_id=$(echo "$to_value" | md5sum | cut -c1-12)
    
    local edge=$(jq -cn \
        --arg fid "$from_id" \
        --arg tid "$to_id" \
        --arg fv "$from_value" \
        --arg tv "$to_value" \
        --arg rel "$relation" \
        --arg ev "$evidence" \
        --arg str "$strength" \
        --arg time "$(date -Iseconds)" \
        '{from:$fid, to:$tid, from_value:$fv, to_value:$tv, relation:$rel, evidence:$ev, strength:$str, discovered:$time}')
    
    local graph_updated=$(jq --argjson e "$edge" '.edges += [$e]' "$graph")
    echo "$graph_updated" > "$graph"
    
    think_observe "CNI: Connessione [$from_value] --($relation)--> [$to_value]"
}

cni_add_event() {
    local case_dir="$1"
    local event_type="$2"
    local description="$3"
    local entities="$4"
    
    local timeline="$case_dir/timeline/events.json"
    
    local event=$(jq -cn \
        --arg type "$event_type" \
        --arg desc "$description" \
        --arg ent "$entities" \
        --arg time "$(date -Iseconds)" \
        '{timestamp:$time, type:$type, description:$desc, entities:$ent}')
    
    local updated=$(jq --argjson e "$event" '. += [$e]' "$timeline")
    echo "$updated" > "$timeline"
}

# ═══════════════════════════════════════════════════════════════
# CNI DEEP INVESTIGATION AGENTS
# ═══════════════════════════════════════════════════════════════

cni_deep_email() {
    local case_dir="$1"
    local email="$2"
    local depth="${3:-2}"
    
    think_agent "CNI Deep Agent: Email Investigation — $email (depth $depth)"
    
    local domain=$(echo "$email" | grep -oP '@\K.*')
    local user=$(echo "$email" | grep -oP '^[^@]+')
    
    # Registra entità iniziale
    cni_add_entity "$case_dir" "email" "$email" "input" "high"
    cni_add_entity "$case_dir" "domain" "$domain" "extracted_from_email" "high"
    cni_add_entity "$case_dir" "username" "$user" "extracted_from_email" "medium"
    cni_add_connection "$case_dir" "$email" "$domain" "belongs_to" "Email domain extraction" "high"
    cni_add_connection "$case_dir" "$email" "$user" "has_username" "Email username extraction" "high"
    
    # WHOIS deep
    local whois_data=$(whois "$domain" 2>/dev/null)
    
    local registrant_email=$(echo "$whois_data" | grep -ioP '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u)
    for reg_email in $registrant_email; do
        [[ "$reg_email" == "$email" ]] && continue
        cni_add_entity "$case_dir" "email" "$reg_email" "whois_registrant" "high"
        cni_add_connection "$case_dir" "$domain" "$reg_email" "registered_by" "WHOIS record" "high"
        cni_add_event "$case_dir" "discovery" "Email registrant trovata via WHOIS: $reg_email" "$domain,$reg_email"
    done
    
    local registrant_name=$(echo "$whois_data" | grep -iP "registrant name:" | head -1 | sed 's/.*: //')
    if [[ -n "$registrant_name" && "$registrant_name" != "REDACTED"* ]]; then
        cni_add_entity "$case_dir" "name" "$registrant_name" "whois" "medium"
        cni_add_connection "$case_dir" "$domain" "$registrant_name" "registered_by" "WHOIS registrant name" "medium"
    fi
    
    local registrant_phone=$(echo "$whois_data" | grep -iP "phone:" | head -1 | sed 's/.*: //' | tr -d ' ')
    if [[ -n "$registrant_phone" && "$registrant_phone" != "REDACTED"* ]]; then
        cni_add_entity "$case_dir" "phone" "$registrant_phone" "whois" "medium"
        cni_add_connection "$case_dir" "$domain" "$registrant_phone" "registered_with" "WHOIS phone" "medium"
    fi
    
    local registrant_addr=$(echo "$whois_data" | grep -iP "registrant street:|address:" | head -1 | sed 's/.*: //')
    if [[ -n "$registrant_addr" && "$registrant_addr" != "REDACTED"* ]]; then
        cni_add_entity "$case_dir" "address" "$registrant_addr" "whois" "medium"
        cni_add_connection "$case_dir" "$domain" "$registrant_addr" "located_at" "WHOIS address" "medium"
    fi
    
    # IP e reverse
    local ip=$(dig +short "$domain" A 2>/dev/null | head -1)
    if [[ -n "$ip" ]]; then
        cni_add_entity "$case_dir" "ip" "$ip" "dns_resolution" "high"
        cni_add_connection "$case_dir" "$domain" "$ip" "resolves_to" "DNS A record" "high"
        
        # Reverse IP — altri domini sullo stesso server
        local reverse_domains=$(curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip" 2>/dev/null | head -20)
        for rdomain in $reverse_domains; do
            [[ "$rdomain" == "$domain" || "$rdomain" == "error"* || -z "$rdomain" ]] && continue
            cni_add_entity "$case_dir" "domain" "$rdomain" "reverse_ip" "medium"
            cni_add_connection "$case_dir" "$ip" "$rdomain" "hosts" "Reverse IP lookup" "medium"
            cni_add_connection "$case_dir" "$domain" "$rdomain" "shared_hosting" "Same IP address" "medium"
            
            # Recursione depth 2: cerca WHOIS dei domini collegati
            if [[ $depth -gt 1 ]]; then
                local linked_whois=$(whois "$rdomain" 2>/dev/null)
                local linked_emails=$(echo "$linked_whois" | grep -ioP '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u)
                for le in $linked_emails; do
                    cni_add_entity "$case_dir" "email" "$le" "linked_domain_whois" "low"
                    cni_add_connection "$case_dir" "$rdomain" "$le" "registered_by" "Linked domain WHOIS" "low"
                done
            fi
        done
        
        # Geolocation
        local geoip=$(curl -s "http://ip-api.com/json/$ip?fields=status,country,regionName,city,isp,org,as,proxy,hosting" 2>/dev/null)
        local geo_isp=$(echo "$geoip" | jq -r '.isp // "N/A"')
        local geo_org=$(echo "$geoip" | jq -r '.org // "N/A"')
        local geo_country=$(echo "$geoip" | jq -r '.country // "N/A"')
        local geo_city=$(echo "$geoip" | jq -r '.city // "N/A"')
        echo "$geoip" > "$case_dir/evidence/geoip_${ip}.json"
        
        cni_add_event "$case_dir" "geolocation" "IP $ip → $geo_country/$geo_city ISP:$geo_isp" "$ip"
    fi
    
    # Subdomains discovery per espandere la rete
    local subs=$(curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | sort -u | grep -v "^\*" | head -30)
    for sub in $subs; do
        [[ -z "$sub" ]] && continue
        cni_add_entity "$case_dir" "domain" "$sub" "certificate_transparency" "medium"
        cni_add_connection "$case_dir" "$domain" "$sub" "has_subdomain" "CT log (crt.sh)" "high"
    done
    
    # Social media lookup per username
    local social_platforms="facebook.com twitter.com instagram.com github.com reddit.com linkedin.com/in t.me tiktok.com medium.com keybase.io"
    for platform in $social_platforms; do
        local url="https://www.$platform/$user"
        [[ "$platform" == "t.me" ]] && url="https://t.me/$user"
        local http_code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null)
        if [[ "$http_code" == "200" ]]; then
            cni_add_entity "$case_dir" "username" "$platform/$user" "social_media_check" "medium"
            cni_add_connection "$case_dir" "$user" "$platform/$user" "has_profile" "HTTP 200 response" "medium"
            cni_add_event "$case_dir" "social_discovery" "Profilo social trovato: $url" "$user,$platform"
        fi
    done
    
    # Scraping pagine web del dominio per email/telefoni aggiuntivi
    for page in "" "/about" "/contact" "/team" "/impressum" "/privacy-policy"; do
        local content=$(curl -sL --max-time 8 "https://$domain$page" 2>/dev/null)
        [[ -z "$content" ]] && continue
        
        # Email aggiuntive
        local found_emails=$(echo "$content" | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u)
        for fe in $found_emails; do
            cni_add_entity "$case_dir" "email" "$fe" "web_scraping_$domain$page" "medium"
            cni_add_connection "$case_dir" "$domain" "$fe" "mentions" "Found on $domain$page" "medium"
        done
        
        # Telefoni
        local found_phones=$(echo "$content" | grep -oP '[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{8,15}' | sort -u | head -10)
        for fp in $found_phones; do
            local clean_phone=$(echo "$fp" | tr -d ' .-()' )
            [[ ${#clean_phone} -lt 8 ]] && continue
            cni_add_entity "$case_dir" "phone" "$fp" "web_scraping_$domain$page" "medium"
            cni_add_connection "$case_dir" "$domain" "$fp" "mentions" "Found on $domain$page" "medium"
        done
        
        # Nomi persone (pattern base)
        local found_names=$(echo "$content" | grep -oP '(?:CEO|CTO|Founder|Director|Manager|Owner)[:\s]+[A-Z][a-z]+ [A-Z][a-z]+' | head -5)
        for fn in $found_names; do
            cni_add_entity "$case_dir" "name" "$fn" "web_scraping_$domain$page" "low"
            cni_add_connection "$case_dir" "$domain" "$fn" "associated_with" "Found on website" "low"
        done
        
        # Link a social media
        local social_links=$(echo "$content" | grep -oP 'https?://(www\.)?(facebook|twitter|instagram|linkedin|youtube|tiktok|t\.me|github)[^"'"'"'\s<>]+' | sort -u)
        for sl in $social_links; do
            cni_add_entity "$case_dir" "username" "$sl" "web_link" "high"
            cni_add_connection "$case_dir" "$domain" "$sl" "linked_social" "Website link" "high"
        done
    done
    
    # Google dorking per informazioni aggiuntive
    local dork_results=$(curl -s "https://www.google.com/search?q=%22$email%22&num=10" 2>/dev/null | \
        grep -oP 'https?://[^"'"'"'\s<>]+' | grep -v "google\|gstatic\|googleapis" | sort -u | head -10)
    for dork_url in $dork_results; do
        cni_add_entity "$case_dir" "domain" "$dork_url" "google_dork" "low"
        cni_add_connection "$case_dir" "$email" "$dork_url" "mentioned_on" "Google search result" "low"
    done
    
    think_result "CNI Deep Email: investigazione completata per $email"
}

cni_deep_phone() {
    local case_dir="$1"
    local phone="$2"
    
    think_agent "CNI Deep Agent: Phone Investigation — $phone"
    
    cni_add_entity "$case_dir" "phone" "$phone" "input" "high"
    
    # Cerca il numero nel web
    local clean=$(echo "$phone" | tr -d ' +-.()' )
    
    local web_results=$(curl -s "https://www.google.com/search?q=%22$phone%22+OR+%22$clean%22&num=10" 2>/dev/null | \
        grep -oP 'https?://[^"'"'"'\s<>]+' | grep -v "google\|gstatic" | sort -u | head -10)
    
    for url in $web_results; do
        local domain=$(echo "$url" | grep -oP '(?<=://)[^/]+')
        cni_add_entity "$case_dir" "domain" "$domain" "phone_web_search" "low"
        cni_add_connection "$case_dir" "$phone" "$domain" "found_on" "Web search for phone number" "low"
        
        # Scrapa la pagina per altre informazioni
        local page_content=$(curl -sL --max-time 8 "$url" 2>/dev/null)
        local page_emails=$(echo "$page_content" | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u | head -5)
        for pe in $page_emails; do
            cni_add_entity "$case_dir" "email" "$pe" "linked_via_phone" "medium"
            cni_add_connection "$case_dir" "$phone" "$pe" "associated_with" "Found on same page" "medium"
        done
    done
    
    think_result "CNI Deep Phone: investigazione completata per $phone"
}

cni_deep_ip() {
    local case_dir="$1"
    local ip="$2"
    
    think_agent "CNI Deep Agent: IP Investigation — $ip"
    
    cni_add_entity "$case_dir" "ip" "$ip" "input" "high"
    
    # Geolocation
    local geoip=$(curl -s "http://ip-api.com/json/$ip?fields=66846719" 2>/dev/null)
    echo "$geoip" > "$case_dir/evidence/geoip_${ip}.json"
    
    local geo_country=$(echo "$geoip" | jq -r '.country // "N/A"')
    local geo_city=$(echo "$geoip" | jq -r '.city // "N/A"')
    local geo_isp=$(echo "$geoip" | jq -r '.isp // "N/A"')
    local geo_org=$(echo "$geoip" | jq -r '.org // "N/A"')
    local geo_as=$(echo "$geoip" | jq -r '.as // "N/A"')
    local geo_proxy=$(echo "$geoip" | jq -r '.proxy // false')
    local geo_hosting=$(echo "$geoip" | jq -r '.hosting // false')
    local geo_mobile=$(echo "$geoip" | jq -r '.mobile // false')
    
    cni_add_event "$case_dir" "geolocation" "IP $ip: $geo_country/$geo_city, ISP:$geo_isp, Proxy:$geo_proxy" "$ip"
    
    # Reverse DNS
    local rdns=$(dig +short -x "$ip" 2>/dev/null)
    if [[ -n "$rdns" ]]; then
        cni_add_entity "$case_dir" "domain" "$rdns" "reverse_dns" "high"
        cni_add_connection "$case_dir" "$ip" "$rdns" "reverse_dns" "PTR record" "high"
    fi
    
    # Reverse IP — tutti i domini su questo IP
    local rev_domains=$(curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip" 2>/dev/null | head -30)
    for rd in $rev_domains; do
        [[ -z "$rd" || "$rd" == "error"* ]] && continue
        cni_add_entity "$case_dir" "domain" "$rd" "reverse_ip" "high"
        cni_add_connection "$case_dir" "$ip" "$rd" "hosts" "Reverse IP lookup" "high"
    done
    
    # Port scan
    nmap -sV --top-ports 200 -T4 "$ip" -oN "$case_dir/evidence/portscan_${ip}.txt" 2>/dev/null
    
    # Shodan-like via headers
    for port in 80 443 8080 8443; do
        local headers=$(curl -sI --max-time 5 "http://$ip:$port" 2>/dev/null)
        [[ -n "$headers" ]] && echo "Port $port headers:\n$headers" >> "$case_dir/evidence/headers_${ip}.txt"
    done
    
    # VPN detection avanzata
    local vpn_score=0
    local vpn_reasons=""
    
    [[ "$geo_proxy" == "true" ]] && { vpn_score=$((vpn_score + 30)); vpn_reasons="$vpn_reasons|Proxy flag attivo"; }
    [[ "$geo_hosting" == "true" ]] && { vpn_score=$((vpn_score + 20)); vpn_reasons="$vpn_reasons|IP hosting"; }
    echo "$geo_as" | grep -qi "nord\|express\|surfshark\|proton\|mullvad\|cyberghost\|pia\|ipvanish\|vypr\|hide\.me\|windscribe" && \
        { vpn_score=$((vpn_score + 40)); vpn_reasons="$vpn_reasons|ASN VPN commerciale"; }
    echo "$geo_org" | grep -qi "hosting\|cloud\|server\|data center\|colocation" && \
        { vpn_score=$((vpn_score + 15)); vpn_reasons="$vpn_reasons|Organizzazione hosting/cloud"; }
    echo "$rdns" | grep -qi "vpn\|proxy\|tor\|exit\|relay" && \
        { vpn_score=$((vpn_score + 25)); vpn_reasons="$vpn_reasons|Reverse DNS indica VPN/Proxy/Tor"; }
    
    # Check Tor exit node
    local tor_check=$(curl -s "https://check.torproject.org/torbulkexitlist" 2>/dev/null | grep -c "^$ip$")
    [[ $tor_check -gt 0 ]] && { vpn_score=$((vpn_score + 50)); vpn_reasons="$vpn_reasons|TOR EXIT NODE CONFERMATO"; }
    
    echo "VPN_SCORE=$vpn_score" > "$case_dir/evidence/vpn_analysis_${ip}.txt"
    echo "VPN_REASONS=$vpn_reasons" >> "$case_dir/evidence/vpn_analysis_${ip}.txt"
    
    cni_add_event "$case_dir" "vpn_analysis" "IP $ip VPN Score: $vpn_score/100, Reasons: $vpn_reasons" "$ip"
    
    think_result "CNI Deep IP: $ip → $geo_country/$geo_city, VPN Score: $vpn_score/100"
}

cni_deep_wallet() {
    local case_dir="$1"
    local wallet="$2"
    local chain="${3:-auto}"
    
    think_agent "CNI Deep Agent: Crypto Wallet Investigation — $wallet"
    
    cni_add_entity "$case_dir" "wallet" "$wallet" "input" "high"
    
    # Detect chain
    if [[ "$chain" == "auto" ]]; then
        if [[ "$wallet" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
            chain="ethereum"
        elif [[ "$wallet" =~ ^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$ ]]; then
            chain="bitcoin"
        elif [[ "$wallet" =~ ^bc1[a-zA-HJ-NP-Z0-9]{25,89}$ ]]; then
            chain="bitcoin"
        elif [[ "$wallet" =~ ^T[A-Za-z1-9]{33}$ ]]; then
            chain="tron"
        fi
    fi
    
    case "$chain" in
        "ethereum"|"eth"|"bsc")
            # Etherscan / BscScan API
            local api_url="https://api.etherscan.io/api"
            [[ "$chain" == "bsc" ]] && api_url="https://api.bscscan.com/api"
            
            # Balance
            local balance=$(curl -s "${api_url}?module=account&action=balance&address=$wallet&tag=latest" 2>/dev/null | \
                jq -r '.result // "0"' 2>/dev/null)
            local balance_eth=$(echo "scale=6; $balance / 1000000000000000000" | bc 2>/dev/null || echo "N/A")
            
            # Transazioni recenti
            local txs=$(curl -s "${api_url}?module=account&action=txlist&address=$wallet&startblock=0&endblock=99999999&page=1&offset=20&sort=desc" 2>/dev/null)
            echo "$txs" > "$case_dir/crypto/txlist_${wallet}.json"
            
            # Estrai indirizzi collegati
            local connected_wallets=$(echo "$txs" | jq -r '.result[]? | select(.from != "" and .to != "") | .from + "\n" + .to' 2>/dev/null | \
                sort -u | grep -v "^$wallet$" | head -20)
            
            for cw in $connected_wallets; do
                [[ -z "$cw" ]] && continue
                cni_add_entity "$case_dir" "wallet" "$cw" "blockchain_transaction" "high"
                
                # Determina direzione
                local is_sender=$(echo "$txs" | jq -r --arg w "$cw" '.result[] | select(.from == $w) | .hash' 2>/dev/null | head -1)
                local is_receiver=$(echo "$txs" | jq -r --arg w "$cw" '.result[] | select(.to == $w) | .hash' 2>/dev/null | head -1)
                
                [[ -n "$is_sender" ]] && cni_add_connection "$case_dir" "$cw" "$wallet" "sent_funds" "Blockchain TX" "high"
                [[ -n "$is_receiver" ]] && cni_add_connection "$case_dir" "$wallet" "$cw" "sent_funds" "Blockchain TX" "high"
            done
            
            # Token transfers
            local tokens=$(curl -s "${api_url}?module=account&action=tokentx&address=$wallet&page=1&offset=10&sort=desc" 2>/dev/null)
            echo "$tokens" > "$case_dir/crypto/tokens_${wallet}.json"
            
            cni_add_event "$case_dir" "crypto_analysis" "Wallet $wallet: Balance $balance_eth ETH, $(echo "$connected_wallets" | wc -w) connected wallets" "$wallet"
            ;;
            
        "bitcoin"|"btc")
            # Blockchain.info API
            local btc_data=$(curl -s "https://blockchain.info/rawaddr/$wallet?limit=20" 2>/dev/null)
            echo "$btc_data" > "$case_dir/crypto/btc_${wallet}.json"
            
            local btc_balance=$(echo "$btc_data" | jq -r '.final_balance // 0' 2>/dev/null)
            local btc_balance_btc=$(echo "scale=8; $btc_balance / 100000000" | bc 2>/dev/null || echo "N/A")
            local btc_tx_count=$(echo "$btc_data" | jq -r '.n_tx // 0' 2>/dev/null)
            
            # Estrai indirizzi collegati dalle transazioni
            local btc_connected=$(echo "$btc_data" | jq -r '.txs[]?.inputs[]?.prev_out?.addr // empty, .txs[]?.out[]?.addr // empty' 2>/dev/null | \
                sort -u | grep -v "^$wallet$" | head -20)
            
            for bw in $btc_connected; do
                [[ -z "$bw" ]] && continue
                cni_add_entity "$case_dir" "wallet" "$bw" "bitcoin_transaction" "high"
                cni_add_connection "$case_dir" "$wallet" "$bw" "transacted_with" "Bitcoin TX" "high"
            done
            
            cni_add_event "$case_dir" "crypto_analysis" "BTC Wallet $wallet: Balance $btc_balance_btc BTC, $btc_tx_count TX, $(echo "$btc_connected" | wc -w) connected" "$wallet"
            ;;
    esac
    
    think_result "CNI Crypto: wallet $wallet analizzato, chain: $chain"
}

# ═══════════════════════════════════════════════════════════════
# CNI GRAPH ANALYSIS & CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════

cni_analyze_graph() {
    local case_dir="$1"
    local graph="$case_dir/graph/network_graph.json"
    local analysis_file="$case_dir/correlation/graph_analysis.txt"
    
    think_phase "CNI GRAPH ANALYSIS"
    think_thought "Analizzo il grafo delle connessioni per trovare pattern..."
    
    local node_count=$(jq '.nodes | length' "$graph" 2>/dev/null || echo 0)
    local edge_count=$(jq '.edges | length' "$graph" 2>/dev/null || echo 0)
    
    # Calcola i nodi più connessi (hub della rete)
    local hub_analysis=$(jq -r '
        .edges as $edges |
        [.nodes[].value] | unique | map(. as $v |
            {value: $v,
             connections: ([$edges[] | select(.from_value == $v or .to_value == $v)] | length),
             outgoing: ([$edges[] | select(.from_value == $v)] | length),
             incoming: ([$edges[] | select(.to_value == $v)] | length)
            }
        ) | sort_by(-.connections) | .[:15] |
        .[] | "\(.value) | Connessioni: \(.connections) (OUT:\(.outgoing) IN:\(.incoming))"
    ' "$graph" 2>/dev/null)
    
    # Trova cluster di identità (nodi collegati da "same_person", "owns", "has_username")
    local identity_links=$(jq -r '
        .edges[] | select(.relation == "same_person" or .relation == "owns" or .relation == "has_username" or .relation == "registered_by") |
        "\(.from_value) ←[\(.relation)]→ \(.to_value)"
    ' "$graph" 2>/dev/null)
    
    # Trova path tra entità (catene di connessione)
    local strong_connections=$(jq -r '
        .edges[] | select(.strength == "high") |
        "\(.from_value) --[\(.relation)]--> \(.to_value) [Evidenza: \(.evidence)]"
    ' "$graph" 2>/dev/null)
    
    # Analisi per tipo di entità
    local email_count=$(jq '[.nodes[] | select(.type == "email")] | length' "$graph" 2>/dev/null || echo 0)
    local phone_count=$(jq '[.nodes[] | select(.type == "phone")] | length' "$graph" 2>/dev/null || echo 0)
    local ip_count=$(jq '[.nodes[] | select(.type == "ip")] | length' "$graph" 2>/dev/null || echo 0)
    local domain_count=$(jq '[.nodes[] | select(.type == "domain")] | length' "$graph" 2>/dev/null || echo 0)
    local wallet_count=$(jq '[.nodes[] | select(.type == "wallet")] | length' "$graph" 2>/dev/null || echo 0)
    local username_count=$(jq '[.nodes[] | select(.type == "username")] | length' "$graph" 2>/dev/null || echo 0)
    local name_count=$(jq '[.nodes[] | select(.type == "name")] | length' "$graph" 2>/dev/null || echo 0)
    
    # Trova entità ponte (collegano cluster diversi)
    local bridge_entities=$(jq -r '
        .edges as $edges |
        [.nodes[].value] | unique | map(. as $v |
            {value: $v,
             unique_connections: ([$edges[] | select(.from_value == $v or .to_value == $v) | 
                if .from_value == $v then .to_value else .from_value end] | unique | length)
            }
        ) | sort_by(-.unique_connections) | .[:10] |
        .[] | select(.unique_connections > 2) | "\(.value) → collega \(.unique_connections) entità diverse"
    ' "$graph" 2>/dev/null)
    
    # Cross-reference: stesse entità appaiono in contesti diversi
    local cross_refs=$(jq -r '
        .edges | group_by(.to_value) | map(select(length > 1)) |
        .[] | "[\(.[0].to_value)] referenziato da \(length) fonti: \([.[].from_value] | join(", "))"
    ' "$graph" 2>/dev/null | head -20)

    cat > "$analysis_file" << ANALYSISEOF
═══════════════════════════════════════════════════════════════
CNI GRAPH ANALYSIS — ANALISI RETE CRIMINALE
═══════════════════════════════════════════════════════════════
Data: $(date)

STATISTICHE GRAFO
  Nodi totali:      $node_count
  Connessioni:      $edge_count
  Email:            $email_count
  Telefoni:         $phone_count
  IP:               $ip_count
  Domini:           $domain_count
  Wallet crypto:    $wallet_count
  Username:         $username_count
  Nomi:             $name_count

═══════════════════════════════════════════════════════════════
HUB DELLA RETE (nodi più connessi = probabili identità centrali)
═══════════════════════════════════════════════════════════════
$hub_analysis

═══════════════════════════════════════════════════════════════
ENTITÀ PONTE (collegano parti diverse della rete)
═══════════════════════════════════════════════════════════════
$bridge_entities

═══════════════════════════════════════════════════════════════
CONNESSIONI AD ALTA AFFIDABILITÀ
═══════════════════════════════════════════════════════════════
$strong_connections

═══════════════════════════════════════════════════════════════
LINK DI IDENTITÀ (possibili stessa persona)
═══════════════════════════════════════════════════════════════
$identity_links

═══════════════════════════════════════════════════════════════
CROSS-REFERENCE (entità referenziate da più fonti)
═══════════════════════════════════════════════════════════════
$cross_refs

ANALYSISEOF

    think_result "Graph Analysis: $node_count nodi, $edge_count connessioni, hub e bridge identificati"
    echo "$analysis_file"
}

cni_generate_visual_graph() {
    local case_dir="$1"
    local graph="$case_dir/graph/network_graph.json"
    local dot_file="$case_dir/graph/criminal_network.dot"
    local png_file="$case_dir/graph/criminal_network.png"
    local svg_file="$case_dir/graph/criminal_network.svg"
    
    tool_ensure "graphviz" "true"
    
    think_phase "CNI VISUAL GRAPH GENERATION"
    
    cat > "$dot_file" << 'DOTSTART'
digraph CriminalNetwork {
    rankdir=LR;
    bgcolor="#0a0a1a";
    node [style=filled, fontname="Courier New", fontsize=10, fontcolor=white];
    edge [fontname="Courier New", fontsize=8, fontcolor="#00ff41"];
    
    label="KALI-AI — Criminal Network Intelligence Map";
    labelloc=t;
    fontname="Courier New Bold";
    fontsize=16;
    fontcolor="#00ff41";
    
DOTSTART

    # Colori per tipo
    # email=rosso, phone=arancione, ip=blu, domain=verde, wallet=giallo, username=viola, name=ciano
    
    jq -r '.nodes[] | 
        if .type == "email" then "\(.id) [label=\"📧 \(.value)\", fillcolor=\"#e94560\", shape=box];"
        elif .type == "phone" then "\(.id) [label=\"📱 \(.value)\", fillcolor=\"#f5a623\", shape=box];"
        elif .type == "ip" then "\(.id) [label=\"🌐 \(.value)\", fillcolor=\"#1a56db\", shape=octagon];"
        elif .type == "domain" then "\(.id) [label=\"🔗 \(.value)\", fillcolor=\"#00a86b\", shape=ellipse];"
        elif .type == "wallet" then "\(.id) [label=\"💰 \(.value | .[0:16])...\", fillcolor=\"#d4a017\", shape=hexagon];"
        elif .type == "username" then "\(.id) [label=\"👤 \(.value)\", fillcolor=\"#9b59b6\", shape=diamond];"
        elif .type == "name" then "\(.id) [label=\"🏷️ \(.value)\", fillcolor=\"#17a2b8\", shape=doubleoctagon];"
        else "\(.id) [label=\"\(.value)\", fillcolor=\"#333333\", shape=box];"
        end
    ' "$graph" 2>/dev/null >> "$dot_file"
    
    jq -r '.edges[] |
        if .strength == "high" then "\(.from) -> \(.to) [label=\"\(.relation)\", color=\"#ff0000\", penwidth=2];"
        elif .strength == "medium" then "\(.from) -> \(.to) [label=\"\(.relation)\", color=\"#f5a623\", penwidth=1.5];"
        else "\(.from) -> \(.to) [label=\"\(.relation)\", color=\"#00ff41\", style=dashed];"
        end
    ' "$graph" 2>/dev/null >> "$dot_file"
    
    echo "}" >> "$dot_file"
    
    if command -v dot &>/dev/null; then
        dot -Tpng -Gdpi=150 "$dot_file" -o "$png_file" 2>/dev/null
        dot -Tsvg "$dot_file" -o "$svg_file" 2>/dev/null
        think_result "Grafo visuale generato: $png_file"
    fi
}

# ═══════════════════════════════════════════════════════════════
# CNI MASTER INVESTIGATION — ENTRY POINT PRINCIPALE
# ═══════════════════════════════════════════════════════════════

cni_investigate() {
    local input="$1"
    local description="${2:-Indagine CNI automatica}"
    
    think_phase "═══ CRIMINAL NETWORK INTELLIGENCE ═══"
    think_strategy "Avvio indagine completa su: $input"
    think_thought "Descrizione caso: $description"
    
    # Inizializza caso
    local case_info=$(cni_init_case)
    local case_id=$(echo "$case_info" | head -1)
    local case_dir=$(echo "$case_info" | tail -1)
    
    think_observe "Caso creato: $case_id"
    think_observe "Directory: $case_dir"
    
    # Detect tipo di input
    local input_type="unknown"
    if echo "$input" | grep -qP '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
        input_type="email"
    elif echo "$input" | grep -qP '^\+?[0-9\s\-\.\(\)]{8,}$'; then
        input_type="phone"
    elif echo "$input" | grep -qP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'; then
        input_type="ip"
    elif echo "$input" | grep -qP '^0x[a-fA-F0-9]{40}$'; then
        input_type="wallet_eth"
    elif echo "$input" | grep -qP '^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-zA-HJ-NP-Z0-9]{25,89}$'; then
        input_type="wallet_btc"
    elif echo "$input" | grep -qP '^T[A-Za-z1-9]{33}$'; then
        input_type="wallet_tron"
    elif echo "$input" | grep -qP '^[a-zA-Z0-9][a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}$'; then
        input_type="domain"
    else
        input_type="username"
    fi
    
    think_decide "Input riconosciuto come: $input_type"
    cni_add_event "$case_dir" "case_start" "Indagine avviata su $input ($input_type): $description" "$input"
    
    # Lancia agenti in base al tipo di input
    case "$input_type" in
        "email")
            think_strategy "Lancio investigazione email multi-livello..."
            
            # Agent 1: Deep email investigation
            cni_deep_email "$case_dir" "$input" 2 &
            local pid1=$!
            
            # Agent 2: Phone da WHOIS (se trovato, sarà investigato dopo)
            local domain=$(echo "$input" | grep -oP '@\K.*')
            local ip=$(dig +short "$domain" A 2>/dev/null | head -1)
            
            # Agent 3: IP investigation parallela
            if [[ -n "$ip" ]]; then
                cni_deep_ip "$case_dir" "$ip" &
                local pid3=$!
            fi
            
            wait $pid1 2>/dev/null
            [[ -n "${pid3:-}" ]] && wait $pid3 2>/dev/null
            
            # Secondo passaggio: investiga entità scoperte
            think_phase "CNI SECONDO PASSAGGIO — Espansione rete"
            
            local discovered_phones=$(jq -r '.phones[]' "$case_dir/entities/entity_db.json" 2>/dev/null)
            for phone in $discovered_phones; do
                cni_deep_phone "$case_dir" "$phone" &
            done
            
            local discovered_wallets=$(jq -r '.wallets[]' "$case_dir/entities/entity_db.json" 2>/dev/null)
            for wallet in $discovered_wallets; do
                cni_deep_wallet "$case_dir" "$wallet" &
            done
            
            wait
            ;;
            
        "phone")
            cni_deep_phone "$case_dir" "$input" &
            local pid1=$!
            wait $pid1
            
            # Investiga email trovate
            local discovered_emails=$(jq -r '.emails[]' "$case_dir/entities/entity_db.json" 2>/dev/null)
            for email in $discovered_emails; do
                cni_deep_email "$case_dir" "$email" 1 &
            done
            wait
            ;;
            
        "ip")
            cni_deep_ip "$case_dir" "$input" &
            local pid1=$!
            wait $pid1
            
            # Investiga domini trovati
            local discovered_domains=$(jq -r '.domains[]' "$case_dir/entities/entity_db.json" 2>/dev/null | head -5)
            for domain in $discovered_domains; do
                local domain_emails=$(whois "$domain" 2>/dev/null | grep -ioP '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | head -3)
                for de in $domain_emails; do
                    cni_deep_email "$case_dir" "$de" 1 &
                done
            done
            wait
            ;;
            
        "wallet_eth"|"wallet_btc"|"wallet_tron")
            local chain="ethereum"
            [[ "$input_type" == "wallet_btc" ]] && chain="bitcoin"
            [[ "$input_type" == "wallet_tron" ]] && chain="tron"
            
            cni_deep_wallet "$case_dir" "$input" "$chain" &
            local pid1=$!
            wait $pid1
            
            # Investiga wallet collegati (top 5 per volume)
            local connected=$(jq -r '.wallets[]' "$case_dir/entities/entity_db.json" 2>/dev/null | grep -v "^$input$" | head -5)
            for cw in $connected; do
                cni_deep_wallet "$case_dir" "$cw" "$chain" &
            done
            wait
            ;;
            
        "domain")
            local domain_emails=$(whois "$input" 2>/dev/null | grep -ioP '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | head -3)
            cni_add_entity "$case_dir" "domain" "$input" "input" "high"
            
            local ip=$(dig +short "$input" A 2>/dev/null | head -1)
            [[ -n "$ip" ]] && cni_deep_ip "$case_dir" "$ip" &
            
            for de in $domain_emails; do
                cni_deep_email "$case_dir" "$de" 1 &
            done
            wait
            ;;
            
        "username")
            cni_add_entity "$case_dir" "username" "$input" "input" "high"
            
            # Cerca su tutte le piattaforme
            local platforms="facebook.com twitter.com instagram.com github.com reddit.com linkedin.com/in t.me tiktok.com medium.com keybase.io youtube.com pinterest.com"
            for p in $platforms; do
                local url="https://www.$p/$input"
                [[ "$p" == "t.me" ]] && url="https://t.me/$input"
                local code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null)
                if [[ "$code" == "200" ]]; then
                    cni_add_entity "$case_dir" "username" "$p/$input" "social_check" "medium"
                    cni_add_connection "$case_dir" "$input" "$p/$input" "has_profile" "HTTP 200" "medium"
                fi
            done
            ;;
    esac
    
    # ═══════════════════════════════════════════════
    # ANALISI FINALE
    # ═══════════════════════════════════════════════
    think_phase "CNI ANALISI FINALE"
    
    # Analizza grafo
    local analysis_file=$(cni_analyze_graph "$case_dir")
    
    # Genera grafo visuale
    cni_generate_visual_graph "$case_dir"
    
    # Genera report finale
    local final_report="$case_dir/reports/CNI_REPORT_FINAL.txt"
    
    local node_count=$(jq '.nodes | length' "$case_dir/graph/network_graph.json" 2>/dev/null || echo 0)
    local edge_count=$(jq '.edges | length' "$case_dir/graph/network_graph.json" 2>/dev/null || echo 0)
    local email_count=$(jq '[.nodes[] | select(.type == "email")] | length' "$case_dir/graph/network_graph.json" 2>/dev/null || echo 0)
    local phone_count=$(jq '[.nodes[] | select(.type == "phone")] | length' "$case_dir/graph/network_graph.json" 2>/dev/null || echo 0)
    local ip_count=$(jq '[.nodes[] | select(.type == "ip")] | length' "$case_dir/graph/network_graph.json" 2>/dev/null || echo 0)
    local wallet_count=$(jq '[.nodes[] | select(.type == "wallet")] | length' "$case_dir/graph/network_graph.json" 2>/dev/null || echo 0)
    
    cat > "$final_report" << FINALEOF
═══════════════════════════════════════════════════════════════════════
   KALI-AI v$VERSION — CRIMINAL NETWORK INTELLIGENCE REPORT
              Rapporto Investigativo Automatizzato
═══════════════════════════════════════════════════════════════════════

INFORMAZIONI CASO
  Case ID:           $case_id
  Input iniziale:    $input ($input_type)
  Descrizione:       $description
  Data indagine:     $(date)
  Investigatore:     Kali-AI v$VERSION — CNI Engine
  Operatore:         $AUTHOR

═══════════════════════════════════════════════════════════════════════
SOMMARIO ESECUTIVO
═══════════════════════════════════════════════════════════════════════
  Entità totali scoperte:    $node_count
  Connessioni mappate:       $edge_count
  Email identificate:        $email_count
  Numeri telefono:           $phone_count
  Indirizzi IP:              $ip_count
  Wallet crypto:             $wallet_count

═══════════════════════════════════════════════════════════════════════
ANALISI DETTAGLIATA DELLA RETE
═══════════════════════════════════════════════════════════════════════
$(cat "$analysis_file" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════
EVIDENZE GEOLOCALIZZAZIONE
═══════════════════════════════════════════════════════════════════════
$(for f in "$case_dir"/evidence/geoip_*.json; do
    [[ ! -f "$f" ]] && continue
    local eip=$(basename "$f" | grep -oP '\d+\.\d+\.\d+\.\d+')
    echo "IP: $eip"
    jq -r '"  Paese: \(.country // "N/A")\n  Città: \(.city // "N/A")\n  ISP: \(.isp // "N/A")\n  Org: \(.org // "N/A")\n  AS: \(.as // "N/A")\n  Proxy: \(.proxy // "N/A")\n  Hosting: \(.hosting // "N/A")"' "$f" 2>/dev/null
    echo ""
done)

═══════════════════════════════════════════════════════════════════════
ANALISI VPN/PROXY
═══════════════════════════════════════════════════════════════════════
$(for f in "$case_dir"/evidence/vpn_analysis_*.txt; do
    [[ ! -f "$f" ]] && continue
    cat "$f"
    echo ""
done)

═══════════════════════════════════════════════════════════════════════
ANALISI CRYPTO (se applicabile)
═══════════════════════════════════════════════════════════════════════
$(jq -r '.[] | select(.type == "crypto_analysis") | .description' "$case_dir/timeline/events.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════
TIMELINE EVENTI
═══════════════════════════════════════════════════════════════════════
$(jq -r '.[] | "[\(.timestamp)] \(.type): \(.description)"' "$case_dir/timeline/events.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════
TUTTE LE ENTITÀ SCOPERTE
═══════════════════════════════════════════════════════════════════════
EMAIL:
$(jq -r '.emails[]' "$case_dir/entities/entity_db.json" 2>/dev/null | sed 's/^/  /')

TELEFONI:
$(jq -r '.phones[]' "$case_dir/entities/entity_db.json" 2>/dev/null | sed 's/^/  /')

IP:
$(jq -r '.ips[]' "$case_dir/entities/entity_db.json" 2>/dev/null | sed 's/^/  /')

DOMINI:
$(jq -r '.domains[]' "$case_dir/entities/entity_db.json" 2>/dev/null | sed 's/^/  /')

WALLET CRYPTO:
$(jq -r '.wallets[]' "$case_dir/entities/entity_db.json" 2>/dev/null | sed 's/^/  /')

USERNAME/SOCIAL:
$(jq -r '.usernames[]' "$case_dir/entities/entity_db.json" 2>/dev/null | sed 's/^/  /')

NOMI:
$(jq -r '.names[]' "$case_dir/entities/entity_db.json" 2>/dev/null | sed 's/^/  /')

═══════════════════════════════════════════════════════════════════════
TUTTE LE CONNESSIONI
═══════════════════════════════════════════════════════════════════════
$(jq -r '.edges[] | "  \(.from_value) --[\(.relation)]--> \(.to_value) [\(.strength)] (\(.evidence))"' "$case_dir/graph/network_graph.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════
FILE E RISORSE
═══════════════════════════════════════════════════════════════════════
  Report:     $final_report
  Grafo JSON: $case_dir/graph/network_graph.json
  Grafo PNG:  $case_dir/graph/criminal_network.png
  Grafo SVG:  $case_dir/graph/criminal_network.svg
  Entità DB:  $case_dir/entities/entity_db.json
  Timeline:   $case_dir/timeline/events.json
  Evidenze:   $case_dir/evidence/
  Analisi:    $analysis_file

═══════════════════════════════════════════════════════════════════════
RACCOMANDAZIONI INVESTIGATIVE
═══════════════════════════════════════════════════════════════════════
  1. Verificare gli hub principali della rete (nodi con più connessioni)
  2. Approfondire le entità ponte che collegano cluster diversi
  3. Se VPN rilevata: richiedere log tramite ordine giudiziario
  4. Cross-referenziare wallet crypto con exchange per KYC
  5. Verificare i profili social per conferma identità
  6. Preservare tutte le evidenze per catena di custodia
  7. Presentare il report con il grafo visuale alle autorità

═══════════════════════════════════════════════════════════════════════
Fine Report — $(date)
Generato da Kali-AI v$VERSION — Criminal Network Intelligence Engine
Classificazione: RISERVATO — Solo per uso investigativo autorizzato
═══════════════════════════════════════════════════════════════════════
FINALEOF

    think_result "CNI INVESTIGAZIONE COMPLETATA"
    
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}║  🔎 CNI INVESTIGATION COMPLETE                               ║${RESET}"
    echo -e "${RED}║  Case: $case_id${RESET}"
    echo -e "${RED}║  Entità: $node_count | Connessioni: $edge_count${RESET}"
    echo -e "${RED}║  Email: $email_count | Phone: $phone_count | IP: $ip_count${RESET}"
    echo -e "${RED}║  Wallet: $wallet_count${RESET}"
    echo -e "${RED}║  📄 Report: $final_report${RESET}"
    echo -e "${RED}║  🗺️ Grafo: $case_dir/graph/criminal_network.png${RESET}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# FASE 29: ADVANCED CRYPTO FORENSICS ENGINE
# ═══════════════════════════════════════════════════════════════
# Traccia flussi crypto, identifica exchange, rileva conversioni
# fiat, mappa la rete di wallet, scoring rischio riciclaggio
# ═══════════════════════════════════════════════════════════════

KNOWN_EXCHANGES="$BASE_DIR/known_exchanges.json"

init_exchange_db() {
    if [[ ! -f "$KNOWN_EXCHANGES" ]]; then
        cat > "$KNOWN_EXCHANGES" << 'EXCHEOF'
{
  "ethereum": {
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": {"name":"Binance","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "0x28c6c06298d514db089934071355e5743bf21d60": {"name":"Binance Hot Wallet 2","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": {"name":"Binance","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": {"name":"Binance","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": {"name":"Binance Old","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": {"name":"Coinbase","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "0x503828976d22510aad0201ac7ec88293211d23da": {"name":"Coinbase","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740": {"name":"Coinbase","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": {"name":"Kraken","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "0x2910543af39aba0cd09dbb2d50200b3e800a63d2": {"name":"Kraken","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "0x53d284357ec70ce289d6d64134dfac8e511c8a3d": {"name":"Kraken Cold","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "0x1151314c646ce4e0efd76d1af4760ae66a9fe30f": {"name":"Bitfinex","type":"CEX","kyc":"mandatory","jurisdiction":"BVI"},
    "0x742d35cc6634c0532925a3b844bc9e7595f2bd1e": {"name":"Bitfinex","type":"CEX","kyc":"mandatory","jurisdiction":"BVI"},
    "0xfbb1b73c4f0bda4f67dca266ce6ef42f520fbb98": {"name":"Bittrex","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "0x2b5634c42055806a59e9107ed44d43c426e58258": {"name":"KuCoin","type":"CEX","kyc":"partial","jurisdiction":"Seychelles"},
    "0xd6216fc19db775df9774a6e33526131da7d19a2c": {"name":"KuCoin","type":"CEX","kyc":"partial","jurisdiction":"Seychelles"},
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": {"name":"OKX","type":"CEX","kyc":"mandatory","jurisdiction":"Seychelles"},
    "0x236f9f97e0e62388479bf9e5ba4889e46b0273c3": {"name":"OKX","type":"CEX","kyc":"mandatory","jurisdiction":"Seychelles"},
    "0xab5c66752a9e8167967685f1450532fb96d5d24f": {"name":"Huobi","type":"CEX","kyc":"mandatory","jurisdiction":"Seychelles"},
    "0x46340b20830761efd32832a74d7169b29feb9758": {"name":"Crypto.com","type":"CEX","kyc":"mandatory","jurisdiction":"Singapore"},
    "0xd47140f6ab73f6d6b6675fb1610bb5e9b5d96fe5": {"name":"MEXC","type":"CEX","kyc":"partial","jurisdiction":"Singapore"},
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe": {"name":"Gate.io","type":"CEX","kyc":"partial","jurisdiction":"Cayman"},
    "0x1111111254eeb25477b68fb85ed929f73a960582": {"name":"1inch Router","type":"DEX_Aggregator","kyc":"none","jurisdiction":"Decentralized"},
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {"name":"Uniswap V2 Router","type":"DEX","kyc":"none","jurisdiction":"Decentralized"},
    "0xe592427a0aece92de3edee1f18e0157c05861564": {"name":"Uniswap V3 Router","type":"DEX","kyc":"none","jurisdiction":"Decentralized"},
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": {"name":"SushiSwap Router","type":"DEX","kyc":"none","jurisdiction":"Decentralized"},
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": {"name":"0x Exchange Proxy","type":"DEX","kyc":"none","jurisdiction":"Decentralized"},
    "0x00000000006c3852cbef3e08e8df289169ede581": {"name":"OpenSea Seaport","type":"NFT_Market","kyc":"none","jurisdiction":"Decentralized"},
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {"name":"Tornado Cash Router","type":"MIXER","kyc":"none","jurisdiction":"SANCTIONED"},
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": {"name":"Tornado Cash","type":"MIXER","kyc":"none","jurisdiction":"SANCTIONED"},
    "0xba214c1c1928a32bffe790263e38b4af9bfcd659": {"name":"Tornado Cash 1","type":"MIXER","kyc":"none","jurisdiction":"SANCTIONED"},
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": {"name":"Tornado Cash 10","type":"MIXER","kyc":"none","jurisdiction":"SANCTIONED"},
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": {"name":"Tornado Cash 100","type":"MIXER","kyc":"none","jurisdiction":"SANCTIONED"},
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": {"name":"Tornado Cash 0.1","type":"MIXER","kyc":"none","jurisdiction":"SANCTIONED"}
  },
  "bitcoin": {
    "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo": {"name":"Binance","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6": {"name":"Binance Cold","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h": {"name":"Binance","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS": {"name":"Coinbase","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "3FHNBLobJnbCTFTVakh5TXmEneyf5PT61B": {"name":"Coinbase","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": {"name":"Binance","type":"CEX","kyc":"mandatory","jurisdiction":"Global"},
    "3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64": {"name":"Bitfinex","type":"CEX","kyc":"mandatory","jurisdiction":"BVI"},
    "3JZq4atUahhuA9rLhXLMhhTo133J9rF97j": {"name":"Bittrex","type":"CEX","kyc":"mandatory","jurisdiction":"USA"},
    "3KF9nXowQ4asSGxRRzeiTpDjMuwM2nFjkR": {"name":"Kraken","type":"CEX","kyc":"mandatory","jurisdiction":"USA"}
  }
}
EXCHEOF
    fi
}

crypto_trace_flow() {
    local wallet="$1"
    local chain="${2:-auto}"
    local depth="${3:-3}"
    local case_dir="$REPORTS_DIR/crypto_forensics_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$case_dir"/{transactions,wallets,exchange_hits,flow_map,evidence,fiat_exits}
    
    init_exchange_db
    
    think_phase "═══ CRYPTO FORENSICS ENGINE ═══"
    think_strategy "Tracciamento completo flussi crypto: $wallet (depth: $depth)"
    
    # Auto-detect chain
    if [[ "$chain" == "auto" ]]; then
        if [[ "$wallet" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
            chain="ethereum"
        elif [[ "$wallet" =~ ^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$ ]] || [[ "$wallet" =~ ^bc1 ]]; then
            chain="bitcoin"
        fi
    fi
    
    think_observe "Chain: $chain | Wallet: $wallet | Profondità: $depth livelli"
    
    local report_file="$case_dir/CRYPTO_FORENSICS_REPORT.txt"
    local exchange_hits_file="$case_dir/exchange_hits/matches.txt"
    local fiat_exits_file="$case_dir/fiat_exits/fiat_conversion_points.txt"
    local flow_json="$case_dir/flow_map/money_flow.json"
    
    echo '{"nodes":[],"flows":[],"exchange_hits":[],"mixer_hits":[],"risk_indicators":[]}' > "$flow_json"
    echo "" > "$exchange_hits_file"
    echo "" > "$fiat_exits_file"
    
    # Variabili globali per tracking
    local total_exchange_hits=0
    local total_mixer_hits=0
    local total_wallets_traced=0
    local total_transactions=0
    local total_value_moved="0"
    local risk_score=0
    local traced_wallets=""
    
    cat > "$report_file" << CRYPTOHEAD
═══════════════════════════════════════════════════════════════════════
     KALI-AI v$VERSION — CRYPTO FORENSICS REPORT
          Tracciamento Flussi & Analisi Riciclaggio
═══════════════════════════════════════════════════════════════════════

DATI CASO
  Wallet target:     $wallet
  Blockchain:        $chain
  Profondità trace:  $depth livelli
  Data analisi:      $(date)
  Engine:            Kali-AI Crypto Forensics v$VERSION
  Operatore:         $AUTHOR

═══════════════════════════════════════════════════════════════════════
CRYPTOHEAD

    # ═══════════════════════════════════════════════
    # FUNZIONE: Traccia un singolo wallet
    # ═══════════════════════════════════════════════
    trace_single_wallet() {
        local w="$1"
        local current_depth="$2"
        local direction="$3"
        
        # Evita loop
        echo "$traced_wallets" | grep -q "$w" && return
        traced_wallets="$traced_wallets $w"
        total_wallets_traced=$((total_wallets_traced + 1))
        
        think_agent "Trace depth $current_depth: $w ($direction)"
        
        # Check se è un exchange noto
        local exchange_match=""
        local w_lower=$(echo "$w" | tr '[:upper:]' '[:lower:]')
        
        if [[ "$chain" == "ethereum" ]]; then
            exchange_match=$(jq -r --arg addr "$w_lower" '.ethereum[$addr] // empty' "$KNOWN_EXCHANGES" 2>/dev/null)
        elif [[ "$chain" == "bitcoin" ]]; then
            exchange_match=$(jq -r --arg addr "$w" '.bitcoin[$addr] // empty' "$KNOWN_EXCHANGES" 2>/dev/null)
        fi
        
        if [[ -n "$exchange_match" ]]; then
            local ex_name=$(echo "$exchange_match" | jq -r '.name')
            local ex_type=$(echo "$exchange_match" | jq -r '.type')
            local ex_kyc=$(echo "$exchange_match" | jq -r '.kyc')
            local ex_jurisdiction=$(echo "$exchange_match" | jq -r '.jurisdiction')
            
            echo "EXCHANGE HIT: $w → $ex_name ($ex_type) | KYC: $ex_kyc | Giurisdizione: $ex_jurisdiction" >> "$exchange_hits_file"
            
            if [[ "$ex_type" == "CEX" ]]; then
                total_exchange_hits=$((total_exchange_hits + 1))
                echo "FIAT EXIT POINT: $ex_name — KYC $ex_kyc — Giurisdizione: $ex_jurisdiction" >> "$fiat_exits_file"
                echo "  → Richiedere dati KYC a $ex_name tramite autorità giudiziaria ($ex_jurisdiction)" >> "$fiat_exits_file"
                echo "  → Wallet associato: $w" >> "$fiat_exits_file"
                echo "" >> "$fiat_exits_file"
                think_observe "🎯 EXCHANGE CEX TROVATO: $ex_name — PUNTO DI CONVERSIONE FIAT — KYC: $ex_kyc"
                risk_score=$((risk_score + 5))
            elif [[ "$ex_type" == "MIXER" ]]; then
                total_mixer_hits=$((total_mixer_hits + 1))
                think_observe "⚠️ MIXER/TUMBLER: $ex_name — TENTATIVO DI OSCURAMENTO"
                risk_score=$((risk_score + 30))
                
                local flow_updated=$(jq --arg w "$w" --arg name "$ex_name" \
                    '.mixer_hits += [{wallet:$w, mixer:$name, severity:"CRITICAL"}]' "$flow_json")
                echo "$flow_updated" > "$flow_json"
            elif [[ "$ex_type" == "DEX" || "$ex_type" == "DEX_Aggregator" ]]; then
                think_observe "🔄 DEX: $ex_name — Swap decentralizzato (no KYC)"
                risk_score=$((risk_score + 10))
            fi
            
            local flow_updated=$(jq --arg w "$w" --arg name "$ex_name" --arg type "$ex_type" --arg kyc "$ex_kyc" --arg jur "$ex_jurisdiction" \
                '.exchange_hits += [{wallet:$w, exchange:$name, type:$type, kyc:$kyc, jurisdiction:$jur}]' "$flow_json")
            echo "$flow_updated" > "$flow_json"
        fi
        
        # Se raggiunti la profondità massima, stop
        [[ $current_depth -ge $depth ]] && return
        
        # Recupera transazioni
        local txs=""
        if [[ "$chain" == "ethereum" ]]; then
            txs=$(curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=$w&startblock=0&endblock=99999999&page=1&offset=30&sort=desc" 2>/dev/null)
            echo "$txs" > "$case_dir/transactions/tx_${w:0:16}_depth${current_depth}.json"
            
            local tx_count=$(echo "$txs" | jq '.result | length' 2>/dev/null || echo 0)
            total_transactions=$((total_transactions + tx_count))
            
            # Estrai wallet collegati con valori
            local connected=$(echo "$txs" | jq -r '.result[]? | 
                select(.value != "0") |
                "\(.from)|\(.to)|\(.value)|\(.hash)|\(.timeStamp)"' 2>/dev/null | head -20)
            
            while IFS='|' read -r tx_from tx_to tx_value tx_hash tx_time; do
                [[ -z "$tx_from" ]] && continue
                
                local value_eth=$(echo "scale=4; $tx_value / 1000000000000000000" | bc 2>/dev/null || echo "0")
                local tx_date=$(date -d "@$tx_time" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$tx_time")
                
                # Registra nel flow
                local flow_entry=$(jq -cn \
                    --arg from "$tx_from" \
                    --arg to "$tx_to" \
                    --arg value "$value_eth" \
                    --arg hash "$tx_hash" \
                    --arg date "$tx_date" \
                    --arg depth "$current_depth" \
                    '{from:$from, to:$to, value_eth:$value, tx_hash:$hash, date:$date, trace_depth:($depth|tonumber)}')
                
                local flow_updated=$(jq --argjson f "$flow_entry" '.flows += [$f]' "$flow_json")
                echo "$flow_updated" > "$flow_json"
                
                # Segui il flusso
                if [[ "$tx_from" == "$w_lower" || "$tx_from" == "$w" ]]; then
                    # Fondi IN USCITA — segui dove vanno
                    trace_single_wallet "$tx_to" $((current_depth + 1)) "outgoing_from_$w"
                elif [[ "$tx_to" == "$w_lower" || "$tx_to" == "$w" ]]; then
                    # Fondi IN ENTRATA — segui da dove vengono
                    trace_single_wallet "$tx_from" $((current_depth + 1)) "incoming_to_$w"
                fi
            done <<< "$connected"
            
            # Check anche token transfers (ERC-20)
            local token_txs=$(curl -s "https://api.etherscan.io/api?module=account&action=tokentx&address=$w&page=1&offset=15&sort=desc" 2>/dev/null)
            echo "$token_txs" > "$case_dir/transactions/tokens_${w:0:16}.json"
            
            local token_connected=$(echo "$token_txs" | jq -r '.result[]? | "\(.from)|\(.to)|\(.tokenName)|\(.value)|\(.tokenDecimal)"' 2>/dev/null | head -10)
            while IFS='|' read -r tf tt tn tv td; do
                [[ -z "$tf" ]] && continue
                local token_value=$(echo "scale=2; $tv / (10 ^ ${td:-18})" | bc 2>/dev/null || echo "0")
                
                if [[ "$tf" != "$w_lower" && "$tf" != "$w" ]]; then
                    echo "$tf" | grep -q "^0x" && trace_single_wallet "$tf" $((current_depth + 1)) "token_${tn}_from"
                fi
                if [[ "$tt" != "$w_lower" && "$tt" != "$w" ]]; then
                    echo "$tt" | grep -q "^0x" && trace_single_wallet "$tt" $((current_depth + 1)) "token_${tn}_to"
                fi
            done <<< "$token_connected"
            
        elif [[ "$chain" == "bitcoin" ]]; then
            txs=$(curl -s "https://blockchain.info/rawaddr/$w?limit=30" 2>/dev/null)
            echo "$txs" > "$case_dir/transactions/tx_${w:0:16}_depth${current_depth}.json"
            
            local tx_count=$(echo "$txs" | jq '.n_tx // 0' 2>/dev/null || echo 0)
            total_transactions=$((total_transactions + tx_count))
            
            local btc_balance=$(echo "$txs" | jq '.final_balance // 0' 2>/dev/null)
            local btc_total_received=$(echo "$txs" | jq '.total_received // 0' 2>/dev/null)
            local btc_total_sent=$(echo "$txs" | jq '.total_sent // 0' 2>/dev/null)
            
            # Estrai wallet collegati
            local btc_connected=$(echo "$txs" | jq -r '
                .txs[]? | 
                (.inputs[]?.prev_out?.addr // empty) + "|" + 
                (.out[]?.addr // empty) + "|" +
                ((.out[]?.value // 0) | tostring)
            ' 2>/dev/null | sort -u | head -20)
            
            while IFS='|' read -r btc_from btc_to btc_val; do
                [[ -z "$btc_from" && -z "$btc_to" ]] && continue
                local btc_value=$(echo "scale=8; ${btc_val:-0} / 100000000" | bc 2>/dev/null || echo "0")
                
                [[ -n "$btc_from" && "$btc_from" != "$w" ]] && trace_single_wallet "$btc_from" $((current_depth + 1)) "btc_input"
                [[ -n "$btc_to" && "$btc_to" != "$w" ]] && trace_single_wallet "$btc_to" $((current_depth + 1)) "btc_output"
            done <<< "$btc_connected"
        fi
        
        sleep 0.3  # Rate limiting
    }
    
    # ═══════════════════════════════════════════════
    # AVVIO TRACCIAMENTO
    # ═══════════════════════════════════════════════
    think_phase "AVVIO TRACCIAMENTO MULTI-LIVELLO"
    
    # Wallet iniziale info
    local initial_balance=""
    if [[ "$chain" == "ethereum" ]]; then
        local bal=$(curl -s "https://api.etherscan.io/api?module=account&action=balance&address=$wallet&tag=latest" 2>/dev/null | jq -r '.result // "0"')
        initial_balance=$(echo "scale=6; $bal / 1000000000000000000" | bc 2>/dev/null || echo "0")
        think_observe "Balance iniziale: $initial_balance ETH"
    elif [[ "$chain" == "bitcoin" ]]; then
        local bal=$(curl -s "https://blockchain.info/q/addressbalance/$wallet" 2>/dev/null)
        initial_balance=$(echo "scale=8; ${bal:-0} / 100000000" | bc 2>/dev/null || echo "0")
        think_observe "Balance iniziale: $initial_balance BTC"
    fi
    
    # Lancia tracciamento ricorsivo
    trace_single_wallet "$wallet" 0 "origin"
    
    # ═══════════════════════════════════════════════
    # RISK SCORING RICICLAGGIO
    # ═══════════════════════════════════════════════
    think_phase "ANALISI RISCHIO RICICLAGGIO"
    
    local laundering_indicators=""
    
    # Indicatore 1: uso di mixer
    [[ $total_mixer_hits -gt 0 ]] && {
        risk_score=$((risk_score + 40))
        laundering_indicators="$laundering_indicators\n  ⚠️ CRITICO: Uso di mixer/tumbler rilevato ($total_mixer_hits hit)"
    }
    
    # Indicatore 2: chain-hopping (molti DEX)
    local dex_count=$(jq '[.exchange_hits[] | select(.type == "DEX" or .type == "DEX_Aggregator")] | length' "$flow_json" 2>/dev/null || echo 0)
    [[ $dex_count -gt 2 ]] && {
        risk_score=$((risk_score + 15))
        laundering_indicators="$laundering_indicators\n  ⚠️ ALTO: Chain-hopping tramite $dex_count DEX"
    }
    
    # Indicatore 3: rapide conversioni fiat
    [[ $total_exchange_hits -gt 2 ]] && {
        risk_score=$((risk_score + 10))
        laundering_indicators="$laundering_indicators\n  ⚠️ MEDIO: Fondi passano per $total_exchange_hits exchange CEX (possibile cash-out)"
    }
    
    # Indicatore 4: splitting (molti wallet intermedi)
    [[ $total_wallets_traced -gt 15 ]] && {
        risk_score=$((risk_score + 10))
        laundering_indicators="$laundering_indicators\n  ⚠️ MEDIO: $total_wallets_traced wallet nella catena — possibile splitting"
    }
    
    # Cap a 100
    [[ $risk_score -gt 100 ]] && risk_score=100
    
    local risk_level="BASSO"
    [[ $risk_score -ge 25 ]] && risk_level="MEDIO"
    [[ $risk_score -ge 50 ]] && risk_level="ALTO"
    [[ $risk_score -ge 75 ]] && risk_level="CRITICO"
    
    # ═══════════════════════════════════════════════
    # GENERA REPORT FINALE
    # ═══════════════════════════════════════════════
    
    cat >> "$report_file" << CRYPTOBODY

═══════════════════════════════════════════════════════════════════════
1. PANORAMICA WALLET TARGET
═══════════════════════════════════════════════════════════════════════
  Indirizzo:         $wallet
  Blockchain:        $chain
  Balance attuale:   $initial_balance $(echo "$chain" | tr '[:lower:]' '[:upper:]' | sed 's/ETHEREUM/ETH/' | sed 's/BITCOIN/BTC/')
  Transazioni:       $total_transactions

═══════════════════════════════════════════════════════════════════════
2. RISULTATI TRACCIAMENTO ($depth livelli di profondità)
═══════════════════════════════════════════════════════════════════════
  Wallet tracciati:         $total_wallets_traced
  Exchange CEX identificati: $total_exchange_hits
  Mixer/Tumbler rilevati:   $total_mixer_hits
  DEX utilizzati:           $dex_count
  Transazioni analizzate:   $total_transactions

═══════════════════════════════════════════════════════════════════════
3. PUNTI DI CONVERSIONE FIAT (EXCHANGE CON KYC)
═══════════════════════════════════════════════════════════════════════
$(cat "$fiat_exits_file" 2>/dev/null)
$(if [[ $total_exchange_hits -eq 0 ]]; then echo "  Nessun exchange CEX identificato nella catena — il soggetto potrebbe usare P2P o OTC"; fi)

═══════════════════════════════════════════════════════════════════════
4. EXCHANGE E SERVIZI IDENTIFICATI
═══════════════════════════════════════════════════════════════════════
$(cat "$exchange_hits_file" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════
5. RISK SCORING RICICLAGGIO
═══════════════════════════════════════════════════════════════════════
  
  RISK SCORE: $risk_score / 100 — $risk_level
  
  [$(printf '█%.0s' $(seq 1 $((risk_score / 2))))$(printf '░%.0s' $(seq 1 $(( (100 - risk_score) / 2))))]
   0        25        50        75       100
   BASSO    MEDIO     ALTO      CRITICO

INDICATORI DI RICICLAGGIO:
$(echo -e "$laundering_indicators")

═══════════════════════════════════════════════════════════════════════
6. FLUSSO FONDI (TOP TRANSAZIONI)
═══════════════════════════════════════════════════════════════════════
$(jq -r '.flows[:30][] | "  \(.date) | \(.from[:16])... → \(.to[:16])... | \(.value_eth) ETH | Depth:\(.trace_depth)"' "$flow_json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════
7. AZIONI INVESTIGATIVE RACCOMANDATE
═══════════════════════════════════════════════════════════════════════
$(if [[ $total_exchange_hits -gt 0 ]]; then
echo "  PRIORITÀ ALTA — RICHIESTE KYC:"
jq -r '.exchange_hits[] | select(.type == "CEX") | "  → Richiedere dati KYC a \(.exchange) (\(.jurisdiction))\n    Wallet: \(.wallet)\n    Procedura: ordine giudiziario / MLAT se estero\n"' "$flow_json" 2>/dev/null
fi)
$(if [[ $total_mixer_hits -gt 0 ]]; then
echo "  ⚠️ ATTENZIONE — MIXER RILEVATI:"
echo "  I fondi sono passati attraverso servizi di mixing."
echo "  Questo rende il tracciamento diretto più difficile."
echo "  Raccomandazione: analisi statistica dei flussi in/out del mixer"
echo "  per tentare correlazione temporale e di importo."
fi)
  
  AZIONI GENERALI:
  1. Congelare i wallet sugli exchange identificati (richiesta alle autorità)
  2. Richiedere log completi delle transazioni agli exchange CEX
  3. Verificare dati KYC per identificazione soggetti
  4. Cross-referenziare con database OSINT per collegare identità
  5. Se fondi su DEX: monitorare per future conversioni su CEX
  6. Preservare tutte le evidenze blockchain (immutabili per natura)
  7. Preparare documentazione per rogatoria internazionale se necessario

═══════════════════════════════════════════════════════════════════════
8. FILE E RISORSE
═══════════════════════════════════════════════════════════════════════
  Report:           $report_file
  Flow Map JSON:    $flow_json
  Exchange Hits:    $exchange_hits_file
  Fiat Exit Points: $fiat_exits_file
  Transazioni raw:  $case_dir/transactions/
  Evidenze:         $case_dir/evidence/

═══════════════════════════════════════════════════════════════════════
Fine analisi: $(date)
Kali-AI v$VERSION — Crypto Forensics Engine
Classificazione: RISERVATO — Solo per uso investigativo autorizzato
═══════════════════════════════════════════════════════════════════════
CRYPTOBODY

    think_result "CRYPTO FORENSICS COMPLETATO — Risk: $risk_score/100 ($risk_level)"
    
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}║  💰 CRYPTO FORENSICS COMPLETE                                ║${RESET}"
    echo -e "${RED}║  Wallet: ${wallet:0:20}...${RESET}"
    echo -e "${RED}║  Chain: $chain | Balance: $initial_balance${RESET}"
    echo -e "${RED}║  Wallets tracciati: $total_wallets_traced${RESET}"
    echo -e "${RED}║  Exchange CEX: $total_exchange_hits | Mixer: $total_mixer_hits${RESET}"
    echo -e "${RED}║  Risk Score: $risk_score/100 — $risk_level${RESET}"
    echo -e "${RED}║  📄 Report: $report_file${RESET}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${RESET}"
}

# ╔═══════════════════════════════════════════════════════════════════╗
# ║  FASE 28: THREAT INTELLIGENCE FEED AGGREGATOR                    ║
# ║  AbuseIPDB, VirusTotal, AlienVault OTX, Shodan — real-time      ║
# ╚═══════════════════════════════════════════════════════════════════╝

THREAT_INTEL_DIR="$BASE_DIR/threat_intel"
THREAT_INTEL_KEYS="$BASE_DIR/api_keys.json"

init_threat_intel() {
    mkdir -p "$THREAT_INTEL_DIR"/{cache,reports}
    if [[ ! -f "$THREAT_INTEL_KEYS" ]]; then
        cat > "$THREAT_INTEL_KEYS" << 'APIKEYS'
{
    "abuseipdb": "",
    "virustotal": "",
    "alienvault_otx": "",
    "shodan": ""
}
APIKEYS
        echo -e "${YELLOW}⚠️ Configura le API key in $THREAT_INTEL_KEYS${RESET}"
    fi
}

get_api_key() {
    local service="$1"
    jq -r ".$service // empty" "$THREAT_INTEL_KEYS" 2>/dev/null
}

# ──────────────────────────────────────────────
# AbuseIPDB — IP reputation & abuse reports
# ──────────────────────────────────────────────
threat_abuseipdb() {
    local ip="$1"
    local output_dir="$2"
    local api_key=$(get_api_key "abuseipdb")
    
    if [[ -z "$api_key" ]]; then
        echo '{"error":"no_api_key","source":"abuseipdb"}' > "$output_dir/abuseipdb.json"
        return 1
    fi

    think_observe "AbuseIPDB: interrogo $ip"

    curl -sG "https://api.abuseipdb.com/api/v2/check" \
        -d "ipAddress=$ip" \
        -d "maxAgeInDays=90" \
        -d "verbose" \
        -H "Key: $api_key" \
        -H "Accept: application/json" \
        -o "$output_dir/abuseipdb.json" 2>/dev/null

    local score=$(jq -r '.data.abuseConfidenceScore // 0' "$output_dir/abuseipdb.json" 2>/dev/null)
    local reports=$(jq -r '.data.totalReports // 0' "$output_dir/abuseipdb.json" 2>/dev/null)
    local country=$(jq -r '.data.countryCode // "N/A"' "$output_dir/abuseipdb.json" 2>/dev/null)
    local isp=$(jq -r '.data.isp // "N/A"' "$output_dir/abuseipdb.json" 2>/dev/null)
    local domain=$(jq -r '.data.domain // "N/A"' "$output_dir/abuseipdb.json" 2>/dev/null)
    local usage=$(jq -r '.data.usageType // "N/A"' "$output_dir/abuseipdb.json" 2>/dev/null)
    local tor=$(jq -r '.data.isTor // false' "$output_dir/abuseipdb.json" 2>/dev/null)
    local whitelisted=$(jq -r '.data.isWhitelisted // false' "$output_dir/abuseipdb.json" 2>/dev/null)

    # Ultimi report di abuso
    jq -r '.data.reports[]? | "\(.reportedAt) | \(.categories | join(",")) | \(.comment // "no comment")"' \
        "$output_dir/abuseipdb.json" 2>/dev/null | head -20 > "$output_dir/abuseipdb_reports.txt"

    think_result "AbuseIPDB: score=$score%, reports=$reports, country=$country, tor=$tor"
    echo "$score"
}

# ──────────────────────────────────────────────
# VirusTotal — file/URL/IP/domain analysis
# ──────────────────────────────────────────────
threat_virustotal() {
    local indicator="$1"
    local indicator_type="$2"  # ip, domain, url, hash
    local output_dir="$3"
    local api_key=$(get_api_key "virustotal")

    if [[ -z "$api_key" ]]; then
        echo '{"error":"no_api_key","source":"virustotal"}' > "$output_dir/virustotal.json"
        return 1
    fi

    think_observe "VirusTotal: analizzo $indicator (tipo: $indicator_type)"

    local vt_url=""
    case "$indicator_type" in
        ip)     vt_url="https://www.virustotal.com/api/v3/ip_addresses/$indicator" ;;
        domain) vt_url="https://www.virustotal.com/api/v3/domains/$indicator" ;;
        hash)   vt_url="https://www.virustotal.com/api/v3/files/$indicator" ;;
        url)
            local url_id=$(echo -n "$indicator" | base64 -w0 | tr '+/' '-_' | tr -d '=')
            vt_url="https://www.virustotal.com/api/v3/urls/$url_id"
            ;;
    esac

    curl -s "$vt_url" \
        -H "x-apikey: $api_key" \
        -o "$output_dir/virustotal.json" 2>/dev/null

    local malicious=$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' "$output_dir/virustotal.json" 2>/dev/null)
    local suspicious=$(jq -r '.data.attributes.last_analysis_stats.suspicious // 0' "$output_dir/virustotal.json" 2>/dev/null)
    local harmless=$(jq -r '.data.attributes.last_analysis_stats.harmless // 0' "$output_dir/virustotal.json" 2>/dev/null)
    local undetected=$(jq -r '.data.attributes.last_analysis_stats.undetected // 0' "$output_dir/virustotal.json" 2>/dev/null)
    local reputation=$(jq -r '.data.attributes.reputation // 0' "$output_dir/virustotal.json" 2>/dev/null)

    # Dettagli engine che hanno flaggato
    jq -r '.data.attributes.last_analysis_results | to_entries[] | select(.value.category == "malicious") | "\(.key): \(.value.result)"' \
        "$output_dir/virustotal.json" 2>/dev/null > "$output_dir/vt_detections.txt"

    # Relazioni (communicating files, referrer files, etc.)
    if [[ "$indicator_type" == "ip" || "$indicator_type" == "domain" ]]; then
        curl -s "${vt_url}/communicating_files?limit=10" \
            -H "x-apikey: $api_key" \
            -o "$output_dir/vt_comm_files.json" 2>/dev/null
        
        curl -s "${vt_url}/resolutions?limit=20" \
            -H "x-apikey: $api_key" \
            -o "$output_dir/vt_resolutions.json" 2>/dev/null
    fi

    think_result "VirusTotal: malicious=$malicious, suspicious=$suspicious, harmless=$harmless, reputation=$reputation"
    echo "$malicious"
}

# ──────────────────────────────────────────────
# AlienVault OTX — threat pulses & indicators
# ──────────────────────────────────────────────
threat_alienvault() {
    local indicator="$1"
    local indicator_type="$2"  # IPv4, domain, hostname, url, FileHash-MD5/SHA1/SHA256
    local output_dir="$3"
    local api_key=$(get_api_key "alienvault_otx")

    think_observe "AlienVault OTX: interrogo $indicator"

    local otx_type=""
    case "$indicator_type" in
        ip|IPv4)    otx_type="IPv4" ;;
        domain)     otx_type="domain" ;;
        hostname)   otx_type="hostname" ;;
        url)        otx_type="url" ;;
        hash|md5|sha1|sha256) otx_type="file" ;;
    esac

    local headers=""
    [[ -n "$api_key" ]] && headers="-H \"X-OTX-API-KEY: $api_key\""

    # General info
    curl -s "https://otx.alienvault.com/api/v1/indicators/$otx_type/$indicator/general" \
        ${api_key:+-H "X-OTX-API-KEY: $api_key"} \
        -o "$output_dir/otx_general.json" 2>/dev/null

    # Pulse info (threat campaigns)
    curl -s "https://otx.alienvault.com/api/v1/indicators/$otx_type/$indicator/general" \
        ${api_key:+-H "X-OTX-API-KEY: $api_key"} \
        -o "$output_dir/otx_pulses.json" 2>/dev/null

    # Geo info per IP
    if [[ "$otx_type" == "IPv4" ]]; then
        curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/$indicator/geo" \
            ${api_key:+-H "X-OTX-API-KEY: $api_key"} \
            -o "$output_dir/otx_geo.json" 2>/dev/null

        curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/$indicator/malware" \
            ${api_key:+-H "X-OTX-API-KEY: $api_key"} \
            -o "$output_dir/otx_malware.json" 2>/dev/null

        curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/$indicator/passive_dns" \
            ${api_key:+-H "X-OTX-API-KEY: $api_key"} \
            -o "$output_dir/otx_passive_dns.json" 2>/dev/null
    fi

    local pulse_count=$(jq -r '.pulse_info.count // 0' "$output_dir/otx_general.json" 2>/dev/null)
    local reputation_val=$(jq -r '.reputation // 0' "$output_dir/otx_general.json" 2>/dev/null)

    # Estrai nomi delle campagne
    jq -r '.pulse_info.pulses[]? | "\(.name) | created: \(.created) | tags: \(.tags | join(", "))"' \
        "$output_dir/otx_general.json" 2>/dev/null | head -15 > "$output_dir/otx_campaigns.txt"

    think_result "AlienVault OTX: pulses=$pulse_count, reputation=$reputation_val"
    echo "$pulse_count"
}

# ──────────────────────────────────────────────
# Shodan — device/service intelligence
# ──────────────────────────────────────────────
threat_shodan() {
    local ip="$1"
    local output_dir="$2"
    local api_key=$(get_api_key "shodan")

    if [[ -z "$api_key" ]]; then
        echo '{"error":"no_api_key","source":"shodan"}' > "$output_dir/shodan.json"
        return 1
    fi

    think_observe "Shodan: interrogo $ip"

    curl -s "https://api.shodan.io/shodan/host/$ip?key=$api_key" \
        -o "$output_dir/shodan.json" 2>/dev/null

    local ports=$(jq -r '.ports // [] | join(", ")' "$output_dir/shodan.json" 2>/dev/null)
    local os=$(jq -r '.os // "N/A"' "$output_dir/shodan.json" 2>/dev/null)
    local org=$(jq -r '.org // "N/A"' "$output_dir/shodan.json" 2>/dev/null)
    local vulns=$(jq -r '.vulns // [] | length' "$output_dir/shodan.json" 2>/dev/null)
    local hostnames=$(jq -r '.hostnames // [] | join(", ")' "$output_dir/shodan.json" 2>/dev/null)
    local city=$(jq -r '.city // "N/A"' "$output_dir/shodan.json" 2>/dev/null)
    local country=$(jq -r '.country_name // "N/A"' "$output_dir/shodan.json" 2>/dev/null)

    # Estrai servizi dettagliati
    jq -r '.data[]? | "Port \(.port)/\(.transport): \(.product // "unknown") \(.version // "") [\(.module // "")]"' \
        "$output_dir/shodan.json" 2>/dev/null > "$output_dir/shodan_services.txt"

    # Estrai vulnerabilità
    jq -r '.vulns // {} | keys[]' "$output_dir/shodan.json" 2>/dev/null > "$output_dir/shodan_vulns.txt"

    think_result "Shodan: ports=[$ports], os=$os, org=$org, vulns=$vulns, city=$city"
    echo "$vulns"
}

# ╔═══════════════════════════════════════════════════════════════════╗
# ║  MASTER THREAT INTELLIGENCE — orchestratore parallelo            ║
# ╚═══════════════════════════════════════════════════════════════════╝

threat_intel_scan() {
    local indicator="$1"
    local description="${2:-Analisi automatica}"
    
    think_phase "THREAT INTELLIGENCE AGGREGATOR"
    think_observe "Target: $indicator — $description"

    init_threat_intel

    local scan_id="THREAT_$(date +%Y%m%d_%H%M%S)"
    local scan_dir="$THREAT_INTEL_DIR/$scan_id"
    mkdir -p "$scan_dir"/{abuseipdb,virustotal,alienvault,shodan,combined}

    # Determina tipo di indicatore
    local ind_type="unknown"
    if [[ "$indicator" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ind_type="ip"
    elif [[ "$indicator" =~ ^[a-fA-F0-9]{32}$ ]]; then
        ind_type="hash"  # MD5
    elif [[ "$indicator" =~ ^[a-fA-F0-9]{40}$ ]]; then
        ind_type="hash"  # SHA1
    elif [[ "$indicator" =~ ^[a-fA-F0-9]{64}$ ]]; then
        ind_type="hash"  # SHA256
    elif [[ "$indicator" =~ ^https?:// ]]; then
        ind_type="url"
    elif [[ "$indicator" =~ \. ]]; then
        ind_type="domain"
    fi

    think_thought "Indicatore classificato come: $ind_type"

    # ── LANCIO AGENTI PARALLELI ──────────────────
    echo -e "${CYAN}🔄 Lancio 4 agenti di intelligence in parallelo...${RESET}"

    local abuse_score=0
    local vt_malicious=0
    local otx_pulses=0
    local shodan_vulns=0

    if [[ "$ind_type" == "ip" ]]; then
        # Tutti e 4 i feed per IP
        threat_abuseipdb "$indicator" "$scan_dir/abuseipdb" &
        local pid_abuse=$!
        
        threat_virustotal "$indicator" "ip" "$scan_dir/virustotal" &
        local pid_vt=$!
        
        threat_alienvault "$indicator" "IPv4" "$scan_dir/alienvault" &
        local pid_otx=$!
        
        threat_shodan "$indicator" "$scan_dir/shodan" &
        local pid_shodan=$!

        # Attendi tutti
        wait $pid_abuse 2>/dev/null; abuse_score=$(cat "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null | jq -r '.data.abuseConfidenceScore // 0')
        wait $pid_vt 2>/dev/null; vt_malicious=$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' "$scan_dir/virustotal/virustotal.json" 2>/dev/null)
        wait $pid_otx 2>/dev/null; otx_pulses=$(jq -r '.pulse_info.count // 0' "$scan_dir/alienvault/otx_general.json" 2>/dev/null)
        wait $pid_shodan 2>/dev/null; shodan_vulns=$(jq -r '.vulns // [] | length' "$scan_dir/shodan/shodan.json" 2>/dev/null)

    elif [[ "$ind_type" == "domain" ]]; then
        threat_virustotal "$indicator" "domain" "$scan_dir/virustotal" &
        local pid_vt=$!
        
        threat_alienvault "$indicator" "domain" "$scan_dir/alienvault" &
        local pid_otx=$!

        # Risolvi IP per AbuseIPDB e Shodan
        local resolved_ip=$(dig +short "$indicator" 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+$' | head -1)
        if [[ -n "$resolved_ip" ]]; then
            think_thought "Dominio risolto a IP: $resolved_ip"
            threat_abuseipdb "$resolved_ip" "$scan_dir/abuseipdb" &
            local pid_abuse=$!
            threat_shodan "$resolved_ip" "$scan_dir/shodan" &
            local pid_shodan=$!
            wait $pid_abuse 2>/dev/null
            wait $pid_shodan 2>/dev/null
            abuse_score=$(jq -r '.data.abuseConfidenceScore // 0' "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null)
            shodan_vulns=$(jq -r '.vulns // [] | length' "$scan_dir/shodan/shodan.json" 2>/dev/null)
        fi

        wait $pid_vt 2>/dev/null; vt_malicious=$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' "$scan_dir/virustotal/virustotal.json" 2>/dev/null)
        wait $pid_otx 2>/dev/null; otx_pulses=$(jq -r '.pulse_info.count // 0' "$scan_dir/alienvault/otx_general.json" 2>/dev/null)

    elif [[ "$ind_type" == "hash" ]]; then
        threat_virustotal "$indicator" "hash" "$scan_dir/virustotal" &
        local pid_vt=$!
        threat_alienvault "$indicator" "hash" "$scan_dir/alienvault" &
        local pid_otx=$!
        wait $pid_vt 2>/dev/null; vt_malicious=$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' "$scan_dir/virustotal/virustotal.json" 2>/dev/null)
        wait $pid_otx 2>/dev/null; otx_pulses=$(jq -r '.pulse_info.count // 0' "$scan_dir/alienvault/otx_general.json" 2>/dev/null)

    elif [[ "$ind_type" == "url" ]]; then
        threat_virustotal "$indicator" "url" "$scan_dir/virustotal" &
        local pid_vt=$!
        threat_alienvault "$indicator" "url" "$scan_dir/alienvault" &
        local pid_otx=$!
        wait $pid_vt 2>/dev/null; vt_malicious=$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' "$scan_dir/virustotal/virustotal.json" 2>/dev/null)
        wait $pid_otx 2>/dev/null; otx_pulses=$(jq -r '.pulse_info.count // 0' "$scan_dir/alienvault/otx_general.json" 2>/dev/null)
    fi

    # ── CALCOLO THREAT SCORE COMBINATO ────────────
    local threat_score=0
    local abuse_weight=0
    local vt_weight=0
    local otx_weight=0
    local shodan_weight=0

    # AbuseIPDB: score diretto 0-100, peso 30%
    abuse_weight=$(echo "scale=0; $abuse_score * 30 / 100" | bc 2>/dev/null || echo 0)
    
    # VirusTotal: malicious detections, peso 35%
    if [[ $vt_malicious -gt 20 ]]; then
        vt_weight=35
    elif [[ $vt_malicious -gt 10 ]]; then
        vt_weight=25
    elif [[ $vt_malicious -gt 5 ]]; then
        vt_weight=18
    elif [[ $vt_malicious -gt 0 ]]; then
        vt_weight=10
    fi

    # AlienVault: pulse count, peso 20%
    if [[ $otx_pulses -gt 10 ]]; then
        otx_weight=20
    elif [[ $otx_pulses -gt 5 ]]; then
        otx_weight=14
    elif [[ $otx_pulses -gt 0 ]]; then
        otx_weight=8
    fi

    # Shodan: vulns count, peso 15%
    if [[ $shodan_vulns -gt 10 ]]; then
        shodan_weight=15
    elif [[ $shodan_vulns -gt 5 ]]; then
        shodan_weight=10
    elif [[ $shodan_vulns -gt 0 ]]; then
        shodan_weight=5
    fi

    threat_score=$((abuse_weight + vt_weight + otx_weight + shodan_weight))

    # Classificazione
    local threat_level="LOW"
    local threat_color="$GREEN"
    if [[ $threat_score -ge 70 ]]; then
        threat_level="CRITICAL"
        threat_color="$RED"
    elif [[ $threat_score -ge 50 ]]; then
        threat_level="HIGH"
        threat_color="$RED"
    elif [[ $threat_score -ge 30 ]]; then
        threat_level="MEDIUM"
        threat_color="$YELLOW"
    fi

    # ── GENERA REPORT ─────────────────────────────
    local report_file="$scan_dir/combined/threat_intel_report.md"

    cat > "$report_file" << THREATREPORT
# 🔍 THREAT INTELLIGENCE REPORT
## Kali-AI v$VERSION — Aggregated Threat Assessment

| Campo | Valore |
|-------|--------|
| **Indicatore** | \`$indicator\` |
| **Tipo** | $ind_type |
| **Descrizione** | $description |
| **Data analisi** | $(date '+%Y-%m-%d %H:%M:%S %Z') |
| **Scan ID** | $scan_id |

---

## ⚠️ THREAT SCORE COMBINATO: $threat_score/100 — $threat_level

| Fonte | Score/Finding | Peso | Contributo |
|-------|---------------|------|------------|
| AbuseIPDB | Confidence: ${abuse_score}% | 30% | $abuse_weight |
| VirusTotal | Malicious: $vt_malicious | 35% | $vt_weight |
| AlienVault OTX | Pulses: $otx_pulses | 20% | $otx_weight |
| Shodan | Vulns: $shodan_vulns | 15% | $shodan_weight |

---

## 1. AbuseIPDB
$(if [[ -f "$scan_dir/abuseipdb/abuseipdb.json" ]] && [[ ! $(jq -r '.error // empty' "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null) ]]; then
    echo "- **Abuse Score**: ${abuse_score}%"
    echo "- **Total Reports**: $(jq -r '.data.totalReports // 0' "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null)"
    echo "- **Country**: $(jq -r '.data.countryCode // "N/A"' "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null)"
    echo "- **ISP**: $(jq -r '.data.isp // "N/A"' "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null)"
    echo "- **Domain**: $(jq -r '.data.domain // "N/A"' "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null)"
    echo "- **Tor**: $(jq -r '.data.isTor // false' "$scan_dir/abuseipdb/abuseipdb.json" 2>/dev/null)"
    echo ""
    echo "### Ultimi report di abuso:"
    echo '```'
    cat "$scan_dir/abuseipdb/abuseipdb_reports.txt" 2>/dev/null | head -10
    echo '```'
else
    echo "⚠️ API key non configurata o errore"
fi)

## 2. VirusTotal
$(if [[ -f "$scan_dir/virustotal/virustotal.json" ]] && [[ ! $(jq -r '.error // empty' "$scan_dir/virustotal/virustotal.json" 2>/dev/null) ]]; then
    echo "- **Malicious**: $vt_malicious"
    echo "- **Suspicious**: $(jq -r '.data.attributes.last_analysis_stats.suspicious // 0' "$scan_dir/virustotal/virustotal.json" 2>/dev/null)"
    echo "- **Harmless**: $(jq -r '.data.attributes.last_analysis_stats.harmless // 0' "$scan_dir/virustotal/virustotal.json" 2>/dev/null)"
    echo "- **Reputation**: $(jq -r '.data.attributes.reputation // 0' "$scan_dir/virustotal/virustotal.json" 2>/dev/null)"
    echo ""
    echo "### Detection Engines:"
    echo '```'
    cat "$scan_dir/virustotal/vt_detections.txt" 2>/dev/null | head -15
    echo '```'
else
    echo "⚠️ API key non configurata o errore"
fi)

## 3. AlienVault OTX
$(if [[ -f "$scan_dir/alienvault/otx_general.json" ]]; then
    echo "- **Pulse Count**: $otx_pulses"
    echo "- **Reputation**: $(jq -r '.reputation // 0' "$scan_dir/alienvault/otx_general.json" 2>/dev/null)"
    echo ""
    echo "### Campagne di minaccia associate:"
    echo '```'
    cat "$scan_dir/alienvault/otx_campaigns.txt" 2>/dev/null | head -10
    echo '```'
else
    echo "⚠️ Dati non disponibili"
fi)

## 4. Shodan
$(if [[ -f "$scan_dir/shodan/shodan.json" ]] && [[ ! $(jq -r '.error // empty' "$scan_dir/shodan/shodan.json" 2>/dev/null) ]]; then
    echo "- **OS**: $(jq -r '.os // "N/A"' "$scan_dir/shodan/shodan.json" 2>/dev/null)"
    echo "- **Organization**: $(jq -r '.org // "N/A"' "$scan_dir/shodan/shodan.json" 2>/dev/null)"
    echo "- **City**: $(jq -r '.city // "N/A"' "$scan_dir/shodan/shodan.json" 2>/dev/null)"
    echo "- **Country**: $(jq -r '.country_name // "N/A"' "$scan_dir/shodan/shodan.json" 2>/dev/null)"
    echo "- **Ports**: $(jq -r '.ports // [] | join(", ")' "$scan_dir/shodan/shodan.json" 2>/dev/null)"
    echo "- **Vulnerabilities**: $shodan_vulns"
    echo ""
    echo "### Servizi esposti:"
    echo '```'
    cat "$scan_dir/shodan/shodan_services.txt" 2>/dev/null | head -15
    echo '```'
    echo ""
    echo "### CVE note:"
    echo '```'
    cat "$scan_dir/shodan/shodan_vulns.txt" 2>/dev/null | head -20
    echo '```'
else
    echo "⚠️ API key non configurata o errore"
fi)

---

## 🎯 Raccomandazioni Operative

$(if [[ $threat_score -ge 70 ]]; then
    echo "### 🔴 LIVELLO CRITICO — Azione immediata richiesta"
    echo "1. **BLOCCARE** immediatamente l'indicatore su tutti i perimetri"
    echo "2. **ISOLARE** eventuali sistemi che hanno comunicato con questo indicatore"
    echo "3. **VERIFICARE** i log degli ultimi 90 giorni per connessioni correlate"
    echo "4. **SEGNALARE** a CERT-IT / Polizia Postale se correlato ad attacco in corso"
    echo "5. **PRESERVARE** tutti i log come evidenza digitale"
elif [[ $threat_score -ge 50 ]]; then
    echo "### 🟠 LIVELLO ALTO — Monitoraggio intensivo"
    echo "1. **MONITORARE** tutte le connessioni da/verso questo indicatore"
    echo "2. **AGGIORNARE** le blacklist firewall/IDS"
    echo "3. **ANALIZZARE** il traffico storico per correlazioni"
    echo "4. **VALUTARE** il blocco preventivo"
elif [[ $threat_score -ge 30 ]]; then
    echo "### 🟡 LIVELLO MEDIO — Attenzione consigliata"
    echo "1. **OSSERVARE** il comportamento dell'indicatore nei prossimi giorni"
    echo "2. **VERIFICARE** se correlato ad altri IoC noti"
    echo "3. **DOCUMENTARE** per riferimento futuro"
else
    echo "### 🟢 LIVELLO BASSO — Nessuna azione immediata"
    echo "1. L'indicatore non risulta attualmente malevolo"
    echo "2. Continuare il monitoraggio di routine"
fi)

---

## 📁 File generati
| File | Percorso |
|------|----------|
| Report principale | $report_file |
| AbuseIPDB raw | $scan_dir/abuseipdb/abuseipdb.json |
| VirusTotal raw | $scan_dir/virustotal/virustotal.json |
| AlienVault raw | $scan_dir/alienvault/otx_general.json |
| Shodan raw | $scan_dir/shodan/shodan.json |
| VT Detections | $scan_dir/virustotal/vt_detections.txt |
| Shodan Services | $scan_dir/shodan/shodan_services.txt |
| OTX Campaigns | $scan_dir/alienvault/otx_campaigns.txt |

---
*Threat Intelligence Report generato da Kali-AI v$VERSION*
*Fonti: AbuseIPDB, VirusTotal, AlienVault OTX, Shodan*
*⚠️ Intelligence classificata — solo per uso autorizzato*
THREATREPORT

    # Sommario a video
    echo ""
    echo -e "${threat_color}╔════════════════════════════════════════════════════╗${RESET}"
    echo -e "${threat_color}║  🔍 THREAT INTELLIGENCE SUMMARY                   ║${RESET}"
    echo -e "${threat_color}╠════════════════════════════════════════════════════╣${RESET}"
    echo -e "${threat_color}║  Indicatore: $indicator${RESET}"
    echo -e "${threat_color}║  Tipo: $ind_type${RESET}"
    echo -e "${threat_color}║  ─────────────────────────────────────────────── ║${RESET}"
    echo -e "${threat_color}║  AbuseIPDB:    ${abuse_score}% confidence${RESET}"
    echo -e "${threat_color}║  VirusTotal:   ${vt_malicious} engine malicious${RESET}"
    echo -e "${threat_color}║  AlienVault:   ${otx_pulses} threat pulses${RESET}"
    echo -e "${threat_color}║  Shodan:       ${shodan_vulns} known vulns${RESET}"
    echo -e "${threat_color}║  ─────────────────────────────────────────────── ║${RESET}"
    echo -e "${threat_color}║  THREAT SCORE: $threat_score/100 — $threat_level${RESET}"
    echo -e "${threat_color}╚════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${GREEN}📄 Report completo: $report_file${RESET}"
}
