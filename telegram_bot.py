#!/usr/bin/env python3
"""
Kali-AI Telegram Bot - Remote Control Interface
Author: Antonio Telesca
"""
import os, subprocess, json
from datetime import datetime
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

config = {}
with open(os.path.expanduser("~/.kali_ai_config"), "r") as f:
    for line in f:
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, val = line.split("=", 1)
            config[key.strip()] = val.strip().strip('"').strip("'")

TELEGRAM_TOKEN = config.get("TELEGRAM_BOT_TOKEN", "")
ANTHROPIC_KEY = config.get("ANTHROPIC_API_KEY", "")
LOG_FILE = os.path.expanduser("~/.kali_ai/logs/telegram_bot.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")

def run_command(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = r.stdout + r.stderr
        if len(out) > 4000: out = out[:4000] + "\n... (troncato)"
        return out if out.strip() else "(nessun output)"
    except subprocess.TimeoutExpired: return "Timeout"
    except Exception as e: return f"Errore: {e}"

def ask_ai(question):
    prompt = json.dumps({"model":"claude-opus-4-6","max_tokens":2048,"system":"Sei KALI-AI, assistente AI per Kali Linux. Rispondi in modo conciso.","messages":[{"role":"user","content":question}]})
    cmd = f"curl -s --max-time 30 https://api.anthropic.com/v1/messages -H \"x-api-key: {ANTHROPIC_KEY}\" -H \"anthropic-version: 2023-06-01\" -H \"Content-Type: application/json\" -d \'{prompt}\'"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=35)
        data = json.loads(r.stdout)
        return data.get("content",[{}])[0].get("text","Nessuna risposta")
    except: return "Errore AI"

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    log(f"START da {update.effective_user.username}")
    msg = "\U0001f916 *KALI-AI v6.0 - Remote Control*\n\n/status - Stato sistema\n/ip - Mostra IP\n/scan <target> - Scansione rete\n/exec <comando> - Esegui comando\n/ai <domanda> - Chiedi all AI\n/services - Servizi attivi\n/disk - Spazio disco\n/ram - Memoria RAM\n/ports - Porte aperte\n/screenshot - Screenshot desktop\n/help - Guida"
    await update.message.reply_text(msg, parse_mode="Markdown")

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    out = run_command("echo OS: && cat /etc/os-release | head -2 && echo Uptime: && uptime -p && echo RAM: && free -h | grep Mem && echo Disco: && df -h / | tail -1 && echo IP: && hostname -I")
    await update.message.reply_text(f"```\n{out}\n```", parse_mode="Markdown")

async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    lip = run_command("hostname -I").strip()
    pip = run_command("curl -s --max-time 5 ifconfig.me").strip()
    await update.message.reply_text(f"IP Locale: {lip}\nIP Pubblico: {pip}")

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /scan <target>")
        return
    t = context.args[0]
    log(f"SCAN {t}")
    await update.message.reply_text(f"Scansione {t}...")
    out = run_command(f"nmap -sn {t}", timeout=120)
    await update.message.reply_text(f"```\n{out}\n```", parse_mode="Markdown")

async def cmd_exec(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /exec <comando>")
        return
    cmd = " ".join(context.args)
    log(f"EXEC {cmd}")
    out = run_command(cmd, timeout=60)
    await update.message.reply_text(f"```\n{out}\n```", parse_mode="Markdown")

async def cmd_ai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /ai <domanda>")
        return
    q = " ".join(context.args)
    log(f"AI {q}")
    await update.message.reply_text("Elaboro...")
    a = ask_ai(q)
    if len(a) > 4000: a = a[:4000]
    await update.message.reply_text(a)

async def cmd_services(update: Update, context: ContextTypes.DEFAULT_TYPE):
    out = run_command("systemctl list-units --type=service --state=running --no-pager | head -20")
    await update.message.reply_text(f"```\n{out}\n```", parse_mode="Markdown")

async def cmd_disk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    out = run_command("df -h")
    await update.message.reply_text(f"```\n{out}\n```", parse_mode="Markdown")

async def cmd_ram(update: Update, context: ContextTypes.DEFAULT_TYPE):
    out = run_command("free -h")
    await update.message.reply_text(f"```\n{out}\n```", parse_mode="Markdown")

async def cmd_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    out = run_command("ss -tlnp | head -20")
    await update.message.reply_text(f"```\n{out}\n```", parse_mode="Markdown")

async def cmd_screenshot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    log("SCREENSHOT")
    p = "/tmp/kali_ai_screenshot.png"
    run_command(f"scrot {p}")
    if os.path.exists(p):
        with open(p,"rb") as ph: await update.message.reply_photo(photo=ph, caption="Screenshot")
        os.remove(p)
    else: await update.message.reply_text("Errore screenshot. Installa: sudo apt install scrot")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    log(f"MSG {text}")
    await update.message.reply_text("Elaboro...")
    a = ask_ai(text)
    if len(a) > 4000: a = a[:4000]
    await update.message.reply_text(a)

def main():
    if not TELEGRAM_TOKEN:
        print("Errore: TELEGRAM_BOT_TOKEN non configurato")
        return
    print("Kali-AI Telegram Bot avviato!")
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("ip", cmd_ip))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("exec", cmd_exec))
    app.add_handler(CommandHandler("ai", cmd_ai))
    app.add_handler(CommandHandler("services", cmd_services))
    app.add_handler(CommandHandler("disk", cmd_disk))
    app.add_handler(CommandHandler("ram", cmd_ram))
    app.add_handler(CommandHandler("ports", cmd_ports))
    app.add_handler(CommandHandler("screenshot", cmd_screenshot))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
