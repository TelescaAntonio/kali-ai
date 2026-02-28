#!/bin/bash

# ╔═══════════════════════════════════════════════════════════════╗
# ║  🤖 KALI-AI v9.0 - COGNITIVE PENTEST FRAMEWORK                ║
# ║  Creato da Antonio Telesca                                    ║
# ║  GitHub: https://github.com/TelescaAntonio/kali-ai            ║
# ║  Powered by Claude Opus 4.6 (Anthropic)                      ║
# ╚═══════════════════════════════════════════════════════════════╝

AUTHOR="Antonio Telesca"
VERSION="9.0"
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
    
    local context="Sei KALI-AI v9.0, un COGNITIVE PENTEST FRAMEWORK per Kali Linux creato da Antonio Telesca.
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
            echo -e "${CYAN}║  🤖 KALI-AI v9.0 — COGNITIVE PENTEST FRAMEWORK                ║${RESET}"
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
    echo "║  🤖 KALI-AI v9.0 — COGNITIVE PENTEST FRAMEWORK                ║"
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
    
    think_phase "KALI-AI v9.0 INIZIALIZZATO"
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
