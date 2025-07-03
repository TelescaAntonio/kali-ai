#!/bin/bash

# 🤖 Kali-AI v2.1 - ULTIMATE SYSTEM CONTROL AGENT
# Creato da Antonio Telesca
# GitHub: https://github.com/TelescaAntonio/kali-ai
# Email: antoniotelesca503@gmail.com
# Agent AI con controllo completo del sistema Kali Linux

AUTHOR="Antonio Telesca"
VERSION="2.1"
GITHUB_REPO="https://github.com/TelescaAntonio/kali-ai"
EMAIL="antoniotelesca503@gmail.com"

# IMPORTANTE: Imposta la tua API key OpenAI come variabile d'ambiente
# export OPENAI_API_KEY="tua-api-key-qui"
API_KEY="${OPENAI_API_KEY:-}"
MODEL="gpt-4o"

# Controllo API key
if [[ -z "$API_KEY" ]]; then
    echo "❌ ERRORE: API Key OpenAI non configurata!"
    echo ""
    echo "Per utilizzare Kali-AI, devi:"
    echo "1. Ottenere una API key da https://platform.openai.com"
    echo "2. Esportare la variabile d'ambiente:"
    echo "   export OPENAI_API_KEY='tua-api-key-qui'"
    echo ""
    echo "Oppure crea un file ~/.kali_ai_config con:"
    echo "   OPENAI_API_KEY=tua-api-key-qui"
    exit 1
fi

# Carica configurazione se esiste
[[ -f "$HOME/.kali_ai_config" ]] && source "$HOME/.kali_ai_config"

BASE_DIR="$HOME/.kali_ai"
LOGS_DIR="$BASE_DIR/logs"
HISTORY_FILE="$BASE_DIR/history.json"
LAST_OUTPUT=""
ANALYSIS_RESULTS=""
declare -A ACTIVE_TERMINALS

# Setup
mkdir -p "$LOGS_DIR"
[[ ! -f "$HISTORY_FILE" ]] && echo '[]' > "$HISTORY_FILE"

# Pulizia all'avvio - NON cancellare history!
cleanup_on_startup() {
    echo "🧹 Pulizia automatica..."
    
    # Pulisci solo i file vecchi
    find "$LOGS_DIR" -type f -mtime +7 -delete 2>/dev/null
    rm -f /tmp/kali_ai_*.sh 2>/dev/null
    
    # Limita la dimensione della history se troppo grande
    if [[ -f "$HISTORY_FILE" ]]; then
        local history_size=$(stat -c%s "$HISTORY_FILE" 2>/dev/null || echo 0)
        if [[ $history_size -gt 100000 ]]; then
            echo "📋 Ottimizzazione cronologia..."
            local history=$(cat "$HISTORY_FILE")
            local limited_history=$(echo "$history" | jq '.[-20:]' 2>/dev/null || echo '[]')
            echo "$limited_history" > "$HISTORY_FILE"
        fi
    fi
    
    echo "✓ Sistema pronto!"
    echo ""
}

cleanup_on_startup

# Setup sudo
setup_sudo_nopass() {
    if sudo -n true 2>/dev/null; then
        echo "✅ Sudo già configurato"
        return 0
    fi
    
    echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/kali-ai-nopass >/dev/null 2>&1
    [[ $? -eq 0 ]] && echo "✅ Sudo configurato!" || echo "⚠️ Sudo richiede password"
}

# Controlla se un programma è installato
check_tool() {
    local tool="$1"
    
    if command -v "$tool" &>/dev/null; then
        return 0
    fi
    
    if dpkg -l 2>/dev/null | grep -qw "^ii.*$tool"; then
        return 0
    fi
    
    local variants=("$tool" "${tool}-gtk" "${tool}-qt" "${tool}-cli")
    for variant in "${variants[@]}"; do
        if command -v "$variant" &>/dev/null || dpkg -l 2>/dev/null | grep -qw "^ii.*$variant"; then
            return 0
        fi
    done
    
    return 1
}

# Esecuzione in terminale semplificata
execute_in_terminal() {
    local cmd="$1"
    local title="$2"
    local wait="${3:-true}"
    local tid="T$(date +%s%N | cut -c1-6)"
    local log_file="$LOGS_DIR/${tid}.log"
    
    echo "🔧 Esecuzione comando in terminale separato..."
    echo "📁 Log file: $log_file"
    
    # Crea lo script temporaneo
    cat > "/tmp/kali_ai_${tid}.sh" << EOF
#!/bin/bash
exec > >(tee "$log_file") 2>&1

echo "╔═══════════════════════════════════════════════════════╗"
echo "║          🤖 KALI-AI - $title"
echo "║          Creato da Antonio Telesca"
echo "║          GitHub: $GITHUB_REPO"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "⚡ Esecuzione: $cmd"
echo "═══════════════════════════════════════════════════════"
echo ""

$cmd
EXIT_CODE=\$?

echo ""
echo "═══════════════════════════════════════════════════════"
[[ \$EXIT_CODE -eq 0 ]] && echo "✅ Completato con successo" || echo "❌ Errore (exit: \$EXIT_CODE)"

if [[ "$wait" == "true" ]]; then
    echo ""
    echo "📌 Premi ENTER per chiudere..."
    read -r
fi
EOF

    chmod +x "/tmp/kali_ai_${tid}.sh"
    
    # Lancia nel terminale disponibile
    if command -v xfce4-terminal &>/dev/null; then
        echo "📺 Apertura XFCE Terminal..."
        xfce4-terminal --title="🤖 $title" -e "bash /tmp/kali_ai_${tid}.sh" &
    elif command -v gnome-terminal &>/dev/null; then
        echo "📺 Apertura GNOME Terminal..."
        gnome-terminal --title="🤖 $title" -- bash "/tmp/kali_ai_${tid}.sh" &
    elif command -v xterm &>/dev/null; then
        echo "📺 Apertura XTerm..."
        xterm -title="🤖 $title" -e "bash /tmp/kali_ai_${tid}.sh" &
    elif command -v konsole &>/dev/null; then
        echo "📺 Apertura Konsole..."
        konsole --title="🤖 $title" -e "bash /tmp/kali_ai_${tid}.sh" &
    elif command -v qterminal &>/dev/null; then
        echo "📺 Apertura QTerminal..."
        qterminal -e "bash /tmp/kali_ai_${tid}.sh" &
    else
        echo "❌ Nessun terminale trovato! Esecuzione in background..."
        bash "/tmp/kali_ai_${tid}.sh" &
    fi
    
    ACTIVE_TERMINALS[$tid]="$title"
    
    if [[ "$wait" == "true" ]]; then
        echo "⏳ Attendo completamento..."
        local count=0
        while [[ $count -lt 120 ]]; do
            if [[ -f "$log_file" ]] && grep -q "═══════════════════" "$log_file" 2>/dev/null; then
                sleep 1
                break
            fi
            sleep 0.5
            ((count++))
        done
        
        if [[ -f "$log_file" ]]; then
            LAST_OUTPUT=$(cat "$log_file" 2>/dev/null)
            echo "✅ Output catturato dal terminale"
        else
            echo "⚠️ Timeout attesa output"
        fi
    fi
}

# Installa automaticamente se manca
auto_install_if_missing() {
    local tool="$1"
    
    if check_tool "$tool"; then
        ANALYSIS_RESULTS="✅ **$tool è già installato!**"
        return 0
    fi
    
    echo "📦 $tool non trovato. Installazione automatica in corso..."
    
    execute_in_terminal "
echo '📦 Installazione $tool...'
sudo apt update
sudo apt install -y $tool
if command -v $tool &>/dev/null; then
    echo '✅ $tool installato con successo!'
    $tool --version 2>/dev/null || echo 'Pronto all uso'
else
    echo '❌ Errore installazione $tool'
fi" \
    "Installazione Automatica - $tool" \
    "true"
    
    if check_tool "$tool"; then
        ANALYSIS_RESULTS="✅ **$tool installato con successo!**

Ora è pronto per essere utilizzato."
        return 0
    else
        ANALYSIS_RESULTS="❌ **Impossibile installare $tool**

Il pacchetto potrebbe non essere disponibile nei repository."
        return 1
    fi
}

# Apri browser con URL o ricerca
open_browser() {
    local query="$1"
    local site="${2:-google}"
    local url=""
    
    if [[ "$query" =~ ^https?:// ]]; then
        url="$query"
    else
        local encoded_query=$(echo "$query" | sed 's/ /+/g' | sed 's/&/%26/g')
        
        case "$site" in
            "amazon")
                url="https://www.amazon.com/s?k=$encoded_query"
                ;;
            "amazon.it")
                url="https://www.amazon.it/s?k=$encoded_query"
                ;;
            "ebay")
                url="https://www.ebay.com/sch/i.html?_nkw=$encoded_query"
                ;;
            "aliexpress")
                url="https://www.aliexpress.com/wholesale?SearchText=$encoded_query"
                ;;
            *)
                url="https://www.google.com/search?q=$encoded_query"
                ;;
        esac
    fi
    
    echo "🌐 Apertura browser..."
    echo "🔗 URL: $url"
    
    if command -v firefox &>/dev/null; then
        firefox "$url" &
        echo "✅ Firefox aperto con: $url"
        ANALYSIS_RESULTS="✅ **Browser aperto!**

Ho aperto Firefox con il link richiesto."
    elif command -v chromium &>/dev/null; then
        chromium "$url" &
        echo "✅ Chromium aperto"
        ANALYSIS_RESULTS="✅ **Browser aperto!**"
    elif command -v google-chrome &>/dev/null; then
        google-chrome "$url" &
        echo "✅ Chrome aperto"
        ANALYSIS_RESULTS="✅ **Browser aperto!**"
    elif command -v xdg-open &>/dev/null; then
        xdg-open "$url" &
        echo "✅ Browser predefinito aperto"
        ANALYSIS_RESULTS="✅ **Browser aperto!**"
    else
        echo "❌ Nessun browser trovato"
        ANALYSIS_RESULTS="❌ **Nessun browser trovato**

📋 Copia questo link: $url"
    fi
}

# Ricerca adattatori WiFi
search_wifi_adapter() {
    echo "🔍 Ricerca adattatori WiFi per Wifite/Kali Linux..."
    
    ANALYSIS_RESULTS="📡 **Migliori adattatori WiFi per Wifite:**

**1. Alfa AWUS036NHA** (⭐ Migliore per principianti)
• Chipset: Atheros AR9271
• Supporto: Monitor mode + Packet injection ✅
• Prezzo: ~30-40€

**2. Alfa AWUS036ACH** (⭐ Migliore overall)
• Chipset: Realtek RTL8812AU
• Dual Band: 2.4GHz + 5GHz ✅
• Prezzo: ~50-60€

**3. TP-Link TL-WN722N v1** (⚠️ SOLO versione 1!)
• Chipset: Atheros AR9271
• Budget friendly: ~15-20€

🛒 **Apertura ricerche su Amazon...**"
    
    echo "🛒 Apertura link per acquisto..."
    open_browser "Alfa AWUS036NHA" "amazon.it"
    sleep 2
    open_browser "Alfa AWUS036ACH wireless" "amazon.it"
}

# Comandi autonomi semplificati
autonomous_command() {
    local action="$1"
    shift
    local params="$@"
    
    echo "🔍 Debug: Esecuzione comando '$action' con parametri: $params"
    
    case "$action" in
        "check_tool")
            local tool="$1"
            echo "🔍 Controllo $tool..."
            
            if check_tool "$tool"; then
                execute_in_terminal "
echo '✅ $tool è installato!'
echo ''
echo '📍 Percorso:'
which $tool 2>/dev/null || echo 'Comando non nel PATH'
echo ''
echo '📦 Info pacchetto:'
dpkg -l | grep $tool || echo 'Info non disponibili'
echo ''
echo '🔢 Versione:'
$tool --version 2>/dev/null || $tool -v 2>/dev/null || echo 'Versione non disponibile'" \
                    "Info Tool - $tool" \
                    "true"
                    
                ANALYSIS_RESULTS="✅ **$tool è installato nel sistema**

Puoi usarlo digitando $tool nel terminale."
            else
                ANALYSIS_RESULTS="❌ **$tool NON è installato**

Vuoi che lo installi automaticamente? Dimmi \"installa $tool\""
            fi
            ;;
            
        "install_tool")
            local tool="$1"
            auto_install_if_missing "$tool"
            ;;
            
        "run_tool")
            local tool="$1"
            shift
            local args="$@"
            
            if ! check_tool "$tool"; then
                echo "⚠️ $tool non trovato. Installazione automatica..."
                auto_install_if_missing "$tool"
            fi
            
            if check_tool "$tool"; then
                execute_in_terminal "$tool $args" "Esecuzione - $tool" "false"
                ANALYSIS_RESULTS="🚀 **$tool avviato in un nuovo terminale**"
            else
                ANALYSIS_RESULTS="❌ **Impossibile eseguire $tool**"
            fi
            ;;
            
        "open_terminal")
            local cmd="${1:-bash}"
            echo "🖥️ Apertura nuovo terminale con comando: $cmd"
            
            local tool_name=$(echo "$cmd" | cut -d' ' -f1)
            if ! command -v "$tool_name" &>/dev/null; then
                echo "⚠️ $tool_name non trovato. Installazione automatica..."
                auto_install_if_missing "$tool_name"
            fi
            
            execute_in_terminal "$cmd" "Nuovo Terminale" "false"
            ANALYSIS_RESULTS="🖥️ **Nuovo terminale aperto**"
            ;;
            
        "system_info")
            echo "📊 Recupero informazioni sistema..."
            execute_in_terminal "
echo '🖥️ INFORMAZIONI SISTEMA KALI LINUX'
echo '================================='
echo ''
echo '📋 Sistema Operativo:'
lsb_release -a 2>/dev/null || cat /etc/os-release
echo ''
echo '🔧 Kernel:'
uname -a
echo ''
echo '💻 CPU:'
lscpu | grep -E 'Model name|CPU\(s\)|Thread|Core|Architecture'
echo ''
echo '💾 Memoria:'
free -h
echo ''
echo '💿 Disco:'
df -h | grep -E '^/dev/'
echo ''
echo '🌐 Rete:'
ip -br addr
echo ''
echo '👤 Utente:'
whoami
echo ''
echo '📅 Data/Ora:'
date" \
                "Informazioni Sistema" \
                "true"
                
            if [[ -n "$LAST_OUTPUT" ]]; then
                local kernel=$(echo "$LAST_OUTPUT" | grep -A1 "Kernel:" | tail -1 | awk '{print $3}')
                local os=$(echo "$LAST_OUTPUT" | grep "PRETTY_NAME" | cut -d'"' -f2)
                local cpu=$(echo "$LAST_OUTPUT" | grep "Model name:" | cut -d':' -f2 | xargs)
                local mem=$(echo "$LAST_OUTPUT" | grep "Mem:" | awk '{print $2}')
                
                ANALYSIS_RESULTS="🖥️ **Informazioni Sistema:**

**Sistema:** ${os:-Kali Linux}
**Kernel:** ${kernel:-Non disponibile}
**CPU:** ${cpu:-Non disponibile}
**RAM Totale:** ${mem:-Non disponibile}

Ho aperto un terminale con tutte le informazioni dettagliate del sistema."
            fi
            ;;
            
        "kernel_version")
            echo "🔧 Controllo versione kernel..."
            local kernel_version=$(uname -r)
            local kernel_full=$(uname -a)
            
            ANALYSIS_RESULTS="🔧 **Versione Kernel:**

**Versione:** $kernel_version
**Info complete:** $kernel_full"
            
            execute_in_terminal "
echo '🔧 VERSIONE KERNEL LINUX'
echo '======================='
echo ''
echo 'Versione kernel: '$(uname -r)
echo ''
echo 'Informazioni complete:'
uname -a
echo ''
echo 'Informazioni dettagliate:'
cat /proc/version" \
                "Versione Kernel" \
                "true"
            ;;
            
        "update_system")
            echo "📦 Aggiornamento sistema..."
            execute_in_terminal "sudo apt update && sudo apt upgrade -y" \
                "Aggiornamento Sistema" "true"
            ANALYSIS_RESULTS="✅ **Sistema aggiornato**"
            ;;
            
        "check_updates")
            echo "🔍 Controllo aggiornamenti disponibili..."
            execute_in_terminal "
echo '🔍 CONTROLLO AGGIORNAMENTI SISTEMA'
echo '================================='
echo ''
sudo apt update
echo ''
echo '📦 Pacchetti aggiornabili:'
echo '========================='
apt list --upgradable 2>/dev/null | grep -v 'Listing...' || echo 'Nessun aggiornamento disponibile'" \
                "Controllo Aggiornamenti" \
                "true"
                
            if [[ -n "$LAST_OUTPUT" ]]; then
                local upgradable=$(echo "$LAST_OUTPUT" | grep -c "upgradable from")
                if [[ $upgradable -gt 0 ]]; then
                    ANALYSIS_RESULTS="📦 **Aggiornamenti Disponibili:**

Ci sono **$upgradable pacchetti** che possono essere aggiornati.

Per aggiornare il sistema, dimmi: \"aggiorna il sistema\""
                else
                    ANALYSIS_RESULTS="✅ **Sistema Aggiornato**

Il tuo sistema Kali Linux è completamente aggiornato!"
                fi
            fi
            ;;
            
        "show_ip")
            echo "🌐 Recupero informazioni IP..."
            execute_in_terminal "ip addr show && echo -e '\n--- IP PUBBLICO ---\n' && curl -s ifconfig.me && echo" \
                "Informazioni IP" "true"
            ;;
            
        "quick_scan")
            local target="$1"
            echo "🎯 Scansione rapida di $target..."
            execute_in_terminal "nmap -F $target" "Scansione Rapida - $target" "true"
            ;;
            
        "set_dark_theme")
            echo "🎨 Impostazione tema dark..."
            execute_in_terminal "
# Imposta tema dark per XFCE Terminal
mkdir -p ~/.config/xfce4/terminal
cat > ~/.config/xfce4/terminal/terminalrc << 'THEME'
[Configuration]
ColorForeground=#f8f8f8f8f2f2
ColorBackground=#272728282222
ColorPalette=#272728282222;#f9f926267272;#a6a6e2e22e2e;#f4f4bfbf7575;#6666d9d9efef;#aeae8181ffff;#a1a1efefe4e4;#f8f8f8f8f2f2;#757571715e5e;#f9f926267272;#a6a6e2e22e2e;#f4f4bfbf7575;#6666d9d9efef;#aeae8181ffff;#a1a1efefe4e4;#f9f9f8f8f5f5
THEME

# Sistema GTK
gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark' 2>/dev/null || true
xfconf-query -c xsettings -p /Net/ThemeName -s 'Adwaita-dark' 2>/dev/null || true

echo '✅ Tema dark applicato!'" \
                "Configurazione Tema Dark" "true"
            ANALYSIS_RESULTS="🎨 **Tema dark configurato!**"
            ;;
            
        "open_browser")
            open_browser "$@"
            ;;
            
        "search_wifi_adapter")
            search_wifi_adapter
            ;;
            
        *)
            echo "⚠️ Comando non riconosciuto: $action"
            ANALYSIS_RESULTS="❌ **Comando non riconosciuto**

Il comando '$action' non è disponibile."
            ;;
    esac
}

# Processo conversazione semplificato
process_conversation() {
    local user_input="$1"
    local history=$(cat "$HISTORY_FILE" 2>/dev/null || echo "[]")
    
    local history_length=$(echo "$history" | jq '. | length' 2>/dev/null || echo 0)
    if [[ $history_length -gt 10 ]]; then
        history=$(echo "$history" | jq '.[-10:]')
    fi
    
    COMMAND_RESULTS=""
    ANALYSIS_RESULTS=""
    
    local context="Sei KALI-AI, creato da Antonio Telesca. Hai CONTROLLO COMPLETO del sistema Kali Linux.

COMANDI PRINCIPALI:
1. autonomous_command \"check_tool\" NOME - Controlla se un tool è installato
2. autonomous_command \"install_tool\" NOME - Installa un tool
3. autonomous_command \"run_tool\" NOME [ARGS] - Esegui un tool (installa automaticamente se manca)
4. autonomous_command \"open_terminal\" [COMANDO] - Apri nuovo terminale
5. autonomous_command \"update_system\" - Aggiorna sistema
6. autonomous_command \"check_updates\" - Controlla aggiornamenti disponibili
7. autonomous_command \"show_ip\" - Mostra IP
8. autonomous_command \"quick_scan\" TARGET - Scansione veloce
9. autonomous_command \"set_dark_theme\" - Imposta tema dark
10. autonomous_command \"open_browser\" \"URL_O_QUERY\" [SITO] - Apri browser con URL o ricerca
11. autonomous_command \"search_wifi_adapter\" - Cerca adattatori WiFi per Wifite
12. autonomous_command \"system_info\" - Mostra informazioni complete del sistema
13. autonomous_command \"kernel_version\" - Mostra versione del kernel

IMPORTANTE:
- Se l'utente chiede di controllare aggiornamenti, usa \"check_updates\"
- Se l'utente chiede di aggiornare il sistema, usa \"update_system\"
- DEVI SEMPRE includere il comando completo nel blocco bash
- Mostra sempre ANALYSIS_RESULTS dopo i comandi

Richiesta utente: $user_input

RISPONDI SEMPRE CON IL COMANDO COMPLETO IN UN BLOCCO BASH:
\`\`\`bash
autonomous_command \"comando\" parametri
\`\`\`"

    echo "🤔 Elaboro..."
    
    local messages=$(jq -cn \
        --argjson h "$history" \
        --arg s "$context" \
        --arg p "$user_input" \
        '$h + [{"role":"system","content":$s},{"role":"user","content":$p}]')
    
    local response=$(curl -s --max-time 30 https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"$MODEL\",
            \"messages\": $messages,
            \"temperature\": 0.3,
            \"max_tokens\": 500
        }")
    
    local answer=$(echo "$response" | jq -r '.choices[0].message.content // empty')
    
    if [[ -z "$answer" ]]; then
        echo "❌ Errore API"
        if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
            echo "Dettaglio: $(echo "$response" | jq -r '.error.message')"
        fi
        return 1
    fi
    
    echo -e "\n🤖 \e[1;36mKali-AI:\e[0m"
    
    local explanation=$(echo "$answer" | awk '/```bash/{exit}1')
    [[ -n "$explanation" ]] && echo "$explanation"
    
    # Esegui comandi
    while IFS= read -r cmd; do
        if [[ -n "$cmd" && ! "$cmd" =~ ^# ]]; then
            echo "⚡ Esecuzione: $cmd"
            eval "$cmd"
            if [[ -n "$ANALYSIS_RESULTS" ]]; then
                echo -e "\n$ANALYSIS_RESULTS"
                ANALYSIS_RESULTS=""
            fi
        fi
    done < <(echo "$answer" | awk '/```bash/{flag=1;next}/```/{flag=0}flag')
    
    # Salva storia
    history=$(jq -cn --argjson h "$messages" --arg a "$answer" '$h + [{"role":"assistant","content":$a}]')
    echo "$history" > "$HISTORY_FILE"
}

# Comandi speciali
handle_special_commands() {
    case "$1" in
        "clear"|"c") clear; return 0 ;;
        "help"|"h")
            echo "╔══════════════════════════════════════════════════════╗"
            echo "║   🤖 KALI-AI v2.1 - COMANDI RAPIDI                   ║"
            echo "╠══════════════════════════════════════════════════════╣"
            echo "║ • 'controlla [tool]' - Verifica se installato        ║"
            echo "║ • 'installa [tool]' - Installa automaticamente       ║"
            echo "║ • 'apri [tool]' - Esegui (installa se manca)         ║"
            echo "║ • 'apri [URL]' - Apri link nel browser               ║"
            echo "║ • 'cerca [prodotto]' - Cerca su internet             ║"
            echo "║ • 'scheda wifi per wifite' - Consigli acquisto       ║"
            echo "║ • 'nuovo terminale' - Apri terminale                 ║"
            echo "║ • 'controlla aggiornamenti' - Check updates          ║"
            echo "║ • 'aggiorna sistema' - Update completo               ║"
            echo "║ • 'info sistema' - Mostra info complete              ║"
            echo "║ • 'versione kernel' - Mostra versione kernel         ║"
            echo "║ • 'tema dark' - Imposta tema scuro                   ║"
            echo "║ • clear (c) - Pulisci schermo                        ║"
            echo "║ • help (h) - Questo aiuto                            ║"
            echo "║ • about (a) - Info autore                            ║"
            echo "╚══════════════════════════════════════════════════════╝"
            return 0
            ;;
        "about"|"a")
            echo "╔══════════════════════════════════════════════════════╗"
            echo "║              🤖 KALI-AI v$VERSION                    ║"
            echo "║          Creato da Antonio Telesca                   ║"
            echo "║      Email: $EMAIL                                   ║"
            echo "║      GitHub: $GITHUB_REPO                            ║"
            echo "╚══════════════════════════════════════════════════════╝"
            return 0
            ;;
        "test")
            echo "🧪 Test apertura terminale..."
            execute_in_terminal "echo 'Test completato!'; ls -la" "Test Terminale" "true"
            return 0
            ;;
    esac
    return 1
}

# Main
main() {
    trap 'echo -e "\n👋 Kali-AI by Antonio Telesca - Arrivederci!"; exit 0' EXIT INT TERM
    
    clear
    echo -e "\e[1;31m"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║      🤖  KALI-AI v2.1 - SYSTEM CONTROL AGENT                  ║"
    echo "║                  Creato da Antonio Telesca                    ║"
    echo "║                  GitHub: $GITHUB_REPO                          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "\e[0m"
    
    setup_sudo_nopass
    
    if ! command -v jq &>/dev/null; then
        echo "📦 Installo jq..."
        sudo apt install -y jq 2>/dev/null
    fi
    
    echo ""
    echo "💡 Esempi: 'controlla nmap', 'installa cmatrix', 'apri firefox'"
    echo "💡 Digita 'help' per aiuto rapido"
    echo "💡 Digita 'test' per testare l'apertura terminale"
    echo ""
    
    while true; do
        echo -ne "╭─[\e[1;31m🤖KALI-AI\e[0m]─[\e[1;34m$(date +%H:%M)\e[0m]\n╰─➤ "
        
        read -r user_input
        
        [[ "$user_input" == "exit" || "$user_input" == "quit" ]] && break
        [[ -z "$user_input" ]] && continue
        
        handle_special_commands "$user_input" && continue
        
        process_conversation "$user_input"
    done
}

main
