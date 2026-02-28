#!/bin/bash
# Kali-AI Phone Investigation Module
# Author: Antonio Telesca

phone="$1"
case_dir="$2"
evidence_log="$3"

mkdir -p "$case_dir/phone_intel"

echo "[$(date +%H:%M:%S)] Phone investigation avviata per $phone" >> "$evidence_log"

# 1. Python phonenumbers analysis
python3 << PYEOF > "$case_dir/phone_intel/phone_analysis.txt" 2>/dev/null
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

try:
    n = phonenumbers.parse("$phone")
    print(f"Numero: $phone")
    print(f"Valido: {phonenumbers.is_valid_number(n)}")
    print(f"Possibile: {phonenumbers.is_possible_number(n)}")
    print(f"Tipo: {phonenumbers.number_type(n)}")
    tipo_map = {0:'FIXED_LINE',1:'MOBILE',2:'FIXED_LINE_OR_MOBILE',3:'TOLL_FREE',4:'PREMIUM_RATE',5:'SHARED_COST',6:'VOIP',7:'PERSONAL',8:'PAGER',9:'UAN',10:'VOICEMAIL',-1:'UNKNOWN'}
    print(f"Tipo Desc: {tipo_map.get(phonenumbers.number_type(n),'UNKNOWN')}")
    print(f"Operatore: {carrier.name_for_number(n, 'it')}")
    print(f"Regione: {geocoder.description_for_number(n, 'it')}")
    print(f"Paese: {geocoder.description_for_number(n, 'en')}")
    print(f"Codice Paese: {n.country_code}")
    print(f"Numero Nazionale: {n.national_number}")
    print(f"Formato E164: {phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)}")
    print(f"Formato Intl: {phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
    print(f"Formato Nazionale: {phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL)}")
    tz = timezone.time_zones_for_number(n)
    print(f"Timezone: {', '.join(tz) if tz else 'N/A'}")
except Exception as e:
    print(f"Errore: {e}")
PYEOF

echo "[$(date +%H:%M:%S)] EVIDENCE: Phone analysis completata" >> "$evidence_log"

# 2. OSINT web search
phone_clean=$(echo "$phone" | tr -d '+- ()')
phone_spaced=$(echo "$phone" | sed 's/./& /g' | tr -s ' ')

echo "=== WEB MENTIONS ===" > "$case_dir/phone_intel/web_mentions.txt"

# Google search
for query in "$phone" "$phone_clean" "\"$phone\""; do
    curl -sL --max-time 10 -A "Mozilla/5.0" "https://www.google.com/search?q=${query}&num=10" 2>/dev/null | \
        grep -oP 'href="https?://[^"]*"' | grep -v google | head -5 >> "$case_dir/phone_intel/web_mentions.txt" 2>/dev/null
done

echo "[$(date +%H:%M:%S)] EVIDENCE: Web search completata" >> "$evidence_log"

# 3. Truecaller/NumVerify API check (free)
numverify=$(curl -s --max-time 10 "http://apilayer.net/api/validate?access_key=&number=${phone_clean}" 2>/dev/null)
echo "$numverify" > "$case_dir/phone_intel/numverify.json" 2>/dev/null

# 4. HLR lookup simulation
echo "=== HLR CHECK ===" > "$case_dir/phone_intel/hlr_check.txt"
echo "Numero: $phone" >> "$case_dir/phone_intel/hlr_check.txt"
echo "Stato: Richiede accesso HLR provider" >> "$case_dir/phone_intel/hlr_check.txt"

echo "[$(date +%H:%M:%S)] EVIDENCE: HLR check completato" >> "$evidence_log"

# 5. Generate report
cat > "$case_dir/phone_intel/analysis.txt" << REPEOF
INVESTIGAZIONE TELEFONICA: $phone
Data: $(date)

$(cat "$case_dir/phone_intel/phone_analysis.txt" 2>/dev/null)

MENZIONI WEB:
$(cat "$case_dir/phone_intel/web_mentions.txt" 2>/dev/null)

NOTE:
- Per l'intestatario serve mandato dell'autorità giudiziaria al provider
- I dati mostrati sono pubblicamente disponibili
- Per IMEI/celle serve cooperazione con operatore telefonico
REPEOF

profile_count=$(wc -l < "$case_dir/phone_intel/web_mentions.txt" 2>/dev/null || echo 0)
echo "[$(date +%H:%M:%S)] EVIDENCE: Phone OSINT completato — $profile_count menzioni web" >> "$evidence_log"

touch "$case_dir/.phone_done"
