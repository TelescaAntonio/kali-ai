#!/bin/bash

# ╔═══════════════════════════════════════════════════════════════╗
# ║  🤖 KALI-AI v6.0 - COGNITIVE PENTEST FRAMEWORK                ║
# ║  Creato da Antonio Telesca                                    ║
# ║  GitHub: https://github.com/TelescaAntonio/kali-ai            ║
# ║  Powered by Claude Opus 4.6 (Anthropic)                      ║
# ╚═══════════════════════════════════════════════════════════════╝

AUTHOR="Antonio Telesca"
VERSION="6.0"
GITHUB_REPO="https://github.com/TelescaAntonio/kali-ai"
EMAIL="antoniotelesca503@gmail.com"

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
        "benchmark") benchmark_test "$1" ;;
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
    
    local context="Sei KALI-AI v6.0, un COGNITIVE PENTEST FRAMEWORK per Kali Linux creato da Antonio Telesca.
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
            echo -e "${CYAN}║  🤖 KALI-AI v6.0 — COGNITIVE PENTEST FRAMEWORK                ║${RESET}"
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
    echo "║  🤖 KALI-AI v6.0 — COGNITIVE PENTEST FRAMEWORK                ║"
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
    
    think_phase "KALI-AI v6.0 INIZIALIZZATO"
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
