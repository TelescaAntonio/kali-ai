#!/bin/bash
# Installer per Kali-AI

echo "🤖 Installazione Kali-AI..."

# Crea directory
mkdir -p ~/bin

# Copia lo script
cp kali-ai.sh ~/bin/kali-ai
chmod +x ~/bin/kali-ai

# Aggiungi al PATH se necessario
if ! echo $PATH | grep -q "$HOME/bin"; then
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
    echo "✅ Aggiunto ~/bin al PATH"
fi

echo "✅ Installazione completata!"
echo ""
echo "📌 Per usare Kali-AI:"
echo "1. Configura la tua API key: export OPENAI_API_KEY='tua-key'"
echo "2. Esegui: kali-ai"
echo ""
echo "Ricarica il terminale con: source ~/.bashrc"
