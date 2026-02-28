#!/bin/bash
# Agent 4: Social, Academic & Professional OSINT
# Chiamato da investigate_email con: agent4_osint.sh EMAIL CASE_DIR EVIDENCE_LOG

suspect_email="$1"
case_dir="$2"
evidence_log="$3"

email_user=$(echo "$suspect_email" | grep -oP '^[^@]+')
email_domain=$(echo "$suspect_email" | grep -oP '@\K.*')
full_name=$(echo "$email_user" | sed 's/\./ /g; s/_/ /g; s/-/ /g')
last_name=$(echo "$full_name" | awk '{print $NF}')
first_name=$(echo "$full_name" | awk '{print $1}')

mkdir -p "$case_dir/social_links"
> "$case_dir/social_links/found.txt"

echo "[$(date +%H:%M:%S)] Agent 4 avviato per $suspect_email" >> "$evidence_log"

# ── 1. GITHUB — cerca tutte le varianti, tieni la migliore ──
best_gh_login=""
best_gh_repos=0
best_gh_data=""

for gh_try in "$email_user" "${email_user//.}" "${first_name}${last_name}" "${last_name}${first_name}" "$(echo ${last_name}${first_name} | sed 's/./\U&/')" "$(echo ${first_name} | sed 's/./\U&/')$(echo ${last_name} | sed 's/./\U&/')" "$(echo ${last_name} | sed 's/./\U&/')$(echo ${first_name} | sed 's/./\U&/')"; do
    gh_data=$(curl -s --max-time 8 "https://api.github.com/users/$gh_try" 2>/dev/null)
    gh_login=$(echo "$gh_data" | jq -r '.login // empty' 2>/dev/null)
    if [ -n "$gh_login" ]; then
        gh_repos=$(echo "$gh_data" | jq -r '.public_repos // 0' 2>/dev/null)
        gh_repos=${gh_repos:-0}; if [ "$gh_repos" -gt "$best_gh_repos" ]; then
            best_gh_repos=$gh_repos
            best_gh_login=$gh_login
            best_gh_data="$gh_data"
        fi
    fi
done

# Cerca anche via search API
gh_search=$(curl -s --max-time 8 "https://api.github.com/search/users?q=${last_name}+${first_name}" 2>/dev/null)
gh_search_login=$(echo "$gh_search" | jq -r '.items[0].login // empty' 2>/dev/null)
if [ -n "$gh_search_login" ]; then
    gh_data=$(curl -s --max-time 8 "https://api.github.com/users/$gh_search_login" 2>/dev/null)
    gh_repos=$(echo "$gh_data" | jq -r '.public_repos // 0' 2>/dev/null)
    gh_repos=${gh_repos:-0}; if [ "$gh_repos" -gt "$best_gh_repos" ]; then
        best_gh_repos=$gh_repos
        best_gh_login=$gh_search_login
        best_gh_data="$gh_data"
    fi
fi

if [ -n "$best_gh_login" ]; then
    gh_name=$(echo "$best_gh_data" | jq -r '.name // "N/A"' 2>/dev/null)
    gh_bio=$(echo "$best_gh_data" | jq -r '.bio // "N/A"' 2>/dev/null)
    gh_location=$(echo "$best_gh_data" | jq -r '.location // "N/A"' 2>/dev/null)
    gh_company=$(echo "$best_gh_data" | jq -r '.company // "N/A"' 2>/dev/null)
    gh_blog=$(echo "$best_gh_data" | jq -r '.blog // "N/A"' 2>/dev/null)
    gh_created=$(echo "$best_gh_data" | jq -r '.created_at // "N/A"' 2>/dev/null)
    echo "VERIFICATO: https://github.com/$best_gh_login (GitHub)" >> "$case_dir/social_links/found.txt"
    echo "  Nome: $gh_name | Bio: $gh_bio | Repos: $best_gh_repos | Location: $gh_location" >> "$case_dir/social_links/found.txt"
    echo "  Company: $gh_company | Blog: $gh_blog | Creato: $gh_created" >> "$case_dir/social_links/found.txt"
    echo "$best_gh_data" > "$case_dir/social_links/github_profile.json"
    curl -s "https://api.github.com/users/$best_gh_login/repos?sort=updated&per_page=10" 2>/dev/null > "$case_dir/social_links/github_repos.json"
fi

# ── 2. ORCID — ricerca strutturata ──
orcid_result=$(curl -s --max-time 15 "https://pub.orcid.org/v3.0/search/?q=family-name:${last_name}+AND+given-names:${first_name}" -H "Accept: application/json" 2>/dev/null)
orcid_count=$(echo "$orcid_result" | jq -r '."num-found" // 0' 2>/dev/null)

if [ "$orcid_count" -gt 0 ]; then
    max=$((orcid_count < 5 ? orcid_count : 5))
    for i in $(seq 0 $((max - 1))); do
        orcid_id=$(echo "$orcid_result" | jq -r ".result[$i].\"orcid-identifier\".path // empty" 2>/dev/null)
        if [ -n "$orcid_id" ]; then
            orcid_person=$(curl -s --max-time 10 "https://pub.orcid.org/v3.0/$orcid_id/person" -H "Accept: application/json" 2>/dev/null)
            orcid_given=$(echo "$orcid_person" | jq -r '.name."given-names".value // "N/A"' 2>/dev/null)
            orcid_family=$(echo "$orcid_person" | jq -r '.name."family-name".value // "N/A"' 2>/dev/null)
            echo "VERIFICATO: https://orcid.org/$orcid_id (ORCID — $orcid_given $orcid_family)" >> "$case_dir/social_links/found.txt"
            
            orcid_works=$(curl -s --max-time 10 "https://pub.orcid.org/v3.0/$orcid_id/works" -H "Accept: application/json" 2>/dev/null)
            works_count=$(echo "$orcid_works" | jq '.group | length' 2>/dev/null)
            echo "  Pubblicazioni: $works_count" >> "$case_dir/social_links/found.txt"
            
            echo "$orcid_person" > "$case_dir/social_links/orcid_person_${i}.json"
            echo "$orcid_works" > "$case_dir/social_links/orcid_works_${i}.json"
        fi
    done
fi

# Cerca anche per email
orcid_email=$(curl -s --max-time 10 "https://pub.orcid.org/v3.0/search/?q=email:$suspect_email" -H "Accept: application/json" 2>/dev/null)
orcid_email_count=$(echo "$orcid_email" | jq -r '."num-found" // 0' 2>/dev/null)
if [ "$orcid_email_count" -gt 0 ]; then
    orcid_id=$(echo "$orcid_email" | jq -r '.result[0]."orcid-identifier".path // empty' 2>/dev/null)
    echo "VERIFICATO: https://orcid.org/$orcid_id (ORCID — match diretto email)" >> "$case_dir/social_links/found.txt"
fi

# ── 3. Semantic Scholar ──
sem_data=$(curl -s --max-time 10 "https://api.semanticscholar.org/graph/v1/author/search?query=${first_name}+${last_name}&limit=3" 2>/dev/null)
sem_count=$(echo "$sem_data" | jq -r '.total // 0' 2>/dev/null); sem_count=${sem_count:-0}
sem_count=${sem_count:-0}; if [ "$sem_count" -gt 0 ]; then
    echo "TROVATO: Semantic Scholar — $sem_count autori per ${first_name} ${last_name}" >> "$case_dir/social_links/found.txt"
    echo "$sem_data" > "$case_dir/social_links/semantic_scholar.json"
fi

# ── 4. Google Scholar ──
scholar_page=$(curl -sL --max-time 10 -A "Mozilla/5.0" "https://scholar.google.com/scholar?q=author:\"${first_name}+${last_name}\"" 2>/dev/null)
scholar_count=$(echo "$scholar_page" | grep -c "gs_r gs_or gs_scl" 2>/dev/null || echo 0)
scholar_count=${scholar_count:-0}; if [ "$scholar_count" -gt 0 ]; then
    echo "TROVATO: Google Scholar — $scholar_count risultati per ${first_name} ${last_name}" >> "$case_dir/social_links/found.txt"
fi

# ── 5. ResearchGate ──
rg_page=$(curl -sL --max-time 10 -A "Mozilla/5.0" "https://www.researchgate.net/search/researcher?q=${first_name}+${last_name}" 2>/dev/null)
if echo "$rg_page" | grep -qi "${last_name}"; then
    echo "TROVATO: ResearchGate — risultati per ${first_name} ${last_name}" >> "$case_dir/social_links/found.txt"
fi

# ── 6. Ricerca web ──
web_results=$(curl -sL --max-time 10 -A "Mozilla/5.0" "https://www.google.com/search?q=%22${suspect_email}%22&num=20" 2>/dev/null)
echo "$web_results" | grep -oP 'href="/url\?q=([^"&]+)"' | sed 's|href="/url?q=||;s|"||g' | grep -v "google\|webcache" | head -15 > "$case_dir/social_links/web_mentions.txt"

# ── GENERA REPORT FINALE ──
cat > "$case_dir/social_links/analysis.txt" << SOCEOF
SOCIAL MEDIA & ACADEMIC OSINT: $email_user / $full_name (da $suspect_email)

PROFILI VERIFICATI:
$(cat "$case_dir/social_links/found.txt" 2>/dev/null || echo "Nessun profilo verificato")

MENZIONI WEB:
$(cat "$case_dir/social_links/web_mentions.txt" 2>/dev/null | head -15 || echo "Nessuna menzione")
SOCEOF

verified_count=$(grep -c "VERIFICATO\|TROVATO\|PROBABILE" "$case_dir/social_links/found.txt" 2>/dev/null || echo 0)
echo "[$(date +%H:%M:%S)] EVIDENCE: Social & Academic OSINT — $verified_count profili verificati per '$email_user' / '$full_name'" >> "$evidence_log"
echo "AGENT4_DONE" > "$case_dir/.agent4_done"
