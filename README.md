# Kali-AI v6.0 - Cognitive Pentest Framework

Autonomous AI-Powered Penetration Testing Agent for Kali Linux

Powered by Claude Opus 4.6 (Anthropic)

Copyright 2026 Antonio Telesca - All Rights Reserved

## AVVERTENZA LEGALE

Questo software e protetto da copyright. Tutti i diritti sono riservati.
L uso e consentito esclusivamente per ricerca accademica, programmi
Horizon Europe e testing in ambienti autorizzati.
Leggere il file LICENSE prima di qualsiasi utilizzo.

## Caratteristiche

- Ciclo Cognitivo: OBSERVE - THINK - PLAN - ACT - VERIFY - LEARN
- Esecuzione multi-terminale parallela (agenti autonomi)
- Visualizzazione ragionamento AI in tempo reale (Neural Core + Matrix)
- Penetration testing autonomo in 4 fasi
- Database vulnerabilita con analisi AI
- Memoria persistente e apprendimento tra sessioni
- Installazione automatica tool mancanti
- Monitoraggio sistema, ricognizione rete, controllo servizi
- Generazione automatica report Markdown
- Funzione export tesi

## Requisiti

- Kali Linux Rolling
- API Key Anthropic (Claude Opus 4.6)
- Connessione internet
- jq, nmap, cmatrix, inotify-tools

## Installazione

    git clone https://github.com/TelescaAntonio/kali-ai.git
    cd kali-ai
    echo ANTHROPIC_API_KEY=your-key > ~/.kali_ai_config
    chmod 600 ~/.kali_ai_config
    bash kali-ai.sh

## Comandi

    help             Mostra comandi disponibili
    pentest target   Avvia pentest autonomo
    report           Genera report sistema
    benchmark target Confronto AI vs tradizionale
    export_thesis    Esporta materiale tesi
    snapshot         Stato sistema
    monitor          Risorse sistema
    stats            Statistiche utilizzo
    exit             Esci

## Licenza

Copyright 2026 Antonio Telesca. Tutti i diritti riservati.
Vedere il file LICENSE per i dettagli completi.

## Contatti

Autore: Antonio Telesca
Email: antoniotelesca503@gmail.com
GitHub: https://github.com/TelescaAntonio
