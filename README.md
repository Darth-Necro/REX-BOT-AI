# REX-BOT-AI

```
    ^
   / \__
  (    @\___     ____  _______  __     ____   ____ _______
  /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
 /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
/_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
```

**v0.1.0-alpha** -- Local-first autonomous network security agent powered by AI. REX is a Great Dane guard dog that watches your home or small business network 24/7. He detects threats, blocks attackers, and reports everything to you.

> This project is under active development and is **not ready for production use**. Do not rely on it as your sole network security solution.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11-3.12](https://img.shields.io/badge/python-3.11%E2%80%933.12-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)]()

---

## Table of Contents

### Part 1: REX-BOT-AI for Everyone
- [What is REX?](#what-is-rex)
- [What You Need](#what-you-need)
- [Installing REX (Step by Step)](#installing-rex-step-by-step)
- [Three Ways to Use REX](#three-ways-to-use-rex)
  - [Option A: The Dashboard (Browser)](#option-a-the-dashboard-browser)
  - [Option B: The Terminal (Command Line)](#option-b-the-terminal-command-line)
  - [Option C: Docker (One-Command Setup)](#option-c-docker-one-command-setup)
- [Common Tasks Walk-Through](#common-tasks-walk-through)
- [Protection Modes](#protection-modes)
- [Troubleshooting](#troubleshooting)

### Part 2: Advanced Users & Developers
- [Configuration Reference](#configuration-reference)
- [CLI Command Reference](#cli-command-reference)
- [Architecture](#architecture)
- [Security Invariants](#security-invariants)
- [Current State](#current-state-honest)
- [Contributing](#contributing)
- [Rebuilding the Frontend](#rebuilding-the-frontend)
- [License](#license)

---

# Part 1: REX-BOT-AI for Everyone

*No experience required. This section will walk you through everything from scratch.*

---

## What is REX?

REX is a security guard dog for your computer network. Just like a real guard dog watches your house, REX watches your WiFi network for:

- **Strangers** -- unknown devices connecting to your network
- **Threats** -- hacking attempts, suspicious traffic, malware connections
- **Problems** -- misconfigured devices, DNS hijacking, data exfiltration

REX runs entirely on **your computer** -- your data never leaves your network. He uses AI (a local language model called Ollama) to understand threats, but even without AI, he can detect and block attacks using built-in rules.

**You can control REX three ways:**
1. **Dashboard** -- a website you open in your browser (like a control panel)
2. **Terminal** -- typing text commands (for power users)
3. **Docker** -- a one-command setup that runs everything automatically

---

## What You Need

Before installing REX, make sure you have these things. Don't worry -- we'll walk you through installing each one.

### Your Computer

- **Operating system:** Linux is fully supported (Ubuntu, Debian, Fedora). macOS and Windows are experimental.
- **RAM:** 2 GB minimum, 4 GB recommended
- **Disk space:** 500 MB for REX + space for any AI models you download

### Required Software

These must be installed for REX to work:

| What | Why REX Needs It | How to Check If You Have It |
|------|-----------------|----------------------------|
| **Python 3.11 or 3.12** | REX is written in Python | Type `python3 --version` in a terminal |
| **Git** | Downloads REX from the internet | Type `git --version` in a terminal |
| **Redis** | Lets REX's internal components talk to each other | Type `redis-cli ping` (should say `PONG`) |
| **libpcap** | Lets REX monitor network traffic | Usually installed by default on Linux |

### Recommended (But Optional)

| What | Why You Might Want It | What Happens Without It |
|------|----------------------|------------------------|
| **Ollama** | Gives REX an AI brain for smart threat analysis and chat | REX uses basic rules only -- still works, but less intelligent |
| **nmap** | Better network scanning | REX falls back to basic ARP scanning |
| **arp-scan** | Faster device discovery | REX still works, just slower |
| **Docker** | One-command setup for everything | You install things manually instead |
| **ChromaDB** | Long-term memory for REX's knowledge base | REX works without memory storage |

---

## Installing REX (Step by Step)

Follow these steps in order. We explain every single command and what it does.

---

### Step 1: Open a Terminal

A **terminal** (also called "command line," "console," or "shell") is a program where you type text commands instead of clicking buttons. Every command in this guide goes into a terminal.

**How to open a terminal:**

| Operating System | How to Open It |
|-----------------|----------------|
| **Ubuntu / Debian Linux** | Press `Ctrl + Alt + T` on your keyboard |
| **Fedora Linux** | Press `Ctrl + Alt + T` or search "Terminal" in Activities |
| **macOS** | Press `Cmd + Space`, type `Terminal`, press Enter |
| **Windows** | Install [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) first, then open "Ubuntu" from the Start menu |

**What you should see:** A window with a blinking cursor waiting for you to type. It might show something like `user@computer:~$`.

> **Tip:** To run a command, type it (or copy-paste it) and press **Enter**. Wait for it to finish before typing the next one. You'll know it's done when you see the blinking cursor again.

---

### Step 2: Install Required Software

This step installs all the programs REX needs. We provide one big command that installs everything at once, plus individual commands if you prefer to install things one at a time.

> **What does `sudo` mean?** It runs a command with administrator permissions (like "Run as Administrator" on Windows). Your computer will ask for your password -- type it and press Enter. **The password won't show as you type** -- that's normal, it's a security feature. Just type it and press Enter.

---

#### Option 1: Install everything at once (recommended)

Copy and paste this entire line into your terminal and press Enter:

**Ubuntu / Debian (including Linux Mint, Pop!_OS, Zorin):**
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git redis-server nmap arp-scan libpcap-dev curl wget
```

**Fedora / RHEL / CentOS:**
```bash
sudo dnf install -y python3 python3-pip git redis nmap arp-scan libpcap-devel curl wget
```

**Arch Linux / Manjaro:**
```bash
sudo pacman -Syu --noconfirm python python-pip git redis nmap arp-scan libpcap curl wget
```

**macOS (using Homebrew):**
```bash
# Install Homebrew first if you don't have it:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Then install everything:
brew install python@3.12 git redis nmap arp-scan libpcap curl wget
brew services start redis
```

**Windows (using WSL -- Windows Subsystem for Linux):**

1. Open PowerShell **as Administrator** (right-click PowerShell > "Run as administrator")
2. Run: `wsl --install`
3. Restart your computer when prompted
4. Open "Ubuntu" from the Start menu (it was installed by WSL)
5. Now follow the Ubuntu/Debian commands above inside the Ubuntu terminal

**What you should see:** A lot of text scrolling as things download and install. This may take 1-5 minutes depending on your internet speed. When it's done, you'll see your blinking cursor again.

---

#### Option 2: Install things one at a time

If the big command didn't work or you want to understand what each thing does:

**Python** (the programming language REX is written in):
```bash
sudo apt install -y python3 python3-venv python3-pip
```

**Git** (downloads code from the internet):
```bash
sudo apt install -y git
```

**Redis** (a fast database REX uses internally):
```bash
sudo apt install -y redis-server
```

**nmap** (scans your network for devices -- highly recommended):
```bash
sudo apt install -y nmap
```

**arp-scan** (discovers devices on your network quickly):
```bash
sudo apt install -y arp-scan
```

**libpcap** (lets REX capture network traffic):
```bash
sudo apt install -y libpcap-dev
```

**curl and wget** (download files from the internet):
```bash
sudo apt install -y curl wget
```

---

#### Verify everything installed correctly

Run these commands one at a time. Each one should print a version number or a response:

```bash
python3 --version
```
**Expected:** `Python 3.11.x` or `Python 3.12.x` (any 3.11 or 3.12 version is fine)

```bash
git --version
```
**Expected:** `git version 2.x.x` (any version 2+ is fine)

```bash
redis-cli ping
```
**Expected:** `PONG`

> If `redis-cli ping` shows an error like "Connection refused," start Redis:
> ```bash
> sudo systemctl start redis-server
> ```
> Then try `redis-cli ping` again.

```bash
nmap --version
```
**Expected:** `Nmap version 7.x.x` (any version is fine)

```bash
curl --version
```
**Expected:** `curl 7.x.x` or `curl 8.x.x` (any version is fine)

**If any command says "command not found"**, re-run the install command for that specific tool from Option 2 above.

---

### Step 3: Start Redis

Redis is a background service REX needs. Start it and set it to start automatically on boot:

```bash
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

**Verify it's working:**
```bash
redis-cli ping
```

**You should see:** `PONG`

If you see `PONG`, Redis is working. If you see an error, try: `sudo apt install redis-server` and then try again.

---

### Step 4: Install Ollama (Recommended)

Ollama gives REX an AI brain. Without it, REX still works but uses basic rules instead of AI intelligence. **This step is optional but recommended.**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**What this does:** Downloads and installs Ollama automatically.

Now download an AI model for REX to use:

```bash
ollama pull llama3.2
```

**What you should see:** A progress bar as the model downloads (about 2 GB). This may take a few minutes.

Start Ollama:

```bash
ollama serve &
```

The `&` at the end runs Ollama in the background so you can keep using the terminal.

> **If you skip this step:** That's OK. REX works without Ollama. The "REX Chat" feature won't respond, and threat analysis will use rules instead of AI. You can install Ollama later.

---

### Step 5: Download REX

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
```

**What this does:** Downloads the entire REX project from GitHub to your computer.

**What you should see:** Text showing files being downloaded. When done, your cursor reappears.

Now move into the REX folder:

```bash
cd REX-BOT-AI
```

---

### Step 6: Set Up Python Environment

These commands create a safe, isolated space for REX so it doesn't affect other programs on your computer:

```bash
python3 -m venv .venv
```

**What this does:** Creates a virtual environment (a private Python workspace) in a folder called `.venv`.

```bash
source .venv/bin/activate
```

**What this does:** Activates the virtual environment. **You should see `(.venv)` appear at the beginning of your terminal prompt.** This means you're now in REX's workspace.

> **Important:** Every time you open a new terminal to use REX, you need to run `cd REX-BOT-AI && source .venv/bin/activate` first. If you don't see `(.venv)` in your prompt, REX commands won't work.

Now install REX and its dependencies:

```bash
pip install --upgrade pip
pip install -e .
```

**What this does:** First upgrades pip (Python's package installer) to the latest version, then installs REX and all 30+ libraries it needs. You'll see a lot of text scrolling -- that's normal.

**What you should see:** The last few lines should include `Successfully installed` followed by a list of packages.

**Verify REX installed correctly:**
```bash
python -m rex.core.cli version
```

**Expected:** `REX-BOT-AI v0.1.0-alpha` (or similar version number)

> **If you see errors during `pip install -e .`:**
> - `error: subprocess-exited-with-error` -- try: `pip install wheel setuptools --upgrade` then retry
> - `ModuleNotFoundError` -- make sure `(.venv)` appears in your prompt. If not, run `source .venv/bin/activate` again
> - `Permission denied` -- do NOT use `sudo pip`. Make sure you're in the virtual environment.

---

### Step 7: Create REX's Data Folder

REX needs a place to store its data (logs, settings, knowledge base):

```bash
mkdir -p ~/.rex-bot-ai
export REX_DATA_DIR="$HOME/.rex-bot-ai"
```

**What this does:** Creates a folder in your home directory for REX's data and tells REX where to find it.

---

### Step 8: Start REX

This is the moment. Start REX:

```bash
sudo .venv/bin/python -m rex.core.cli start
```

**Why `sudo`?** REX needs administrator permissions to monitor network traffic and manage firewall rules.

**What you should see:** REX prints a startup banner with a Black Great Dane, then starts its 10 services:

```
[1/10] Starting Memory...        OK
[2/10] Starting Eyes...           OK
[3/10] Starting Scheduler...      OK
[4/10] Starting Interview...      OK
[5/10] Starting Brain...          OK
[6/10] Starting Bark...           OK
[7/10] Starting Teeth...          OK
[8/10] Starting Federation...     OK
[9/10] Starting Store...          OK
[10/10] Starting Dashboard...     OK

Dashboard available at: http://localhost:8443
```

**REX is now running and protecting your network.**

---

### Step 9: Choose How You Want to Use REX

Now that REX is running, you have three ways to interact with him. Pick whichever you're most comfortable with:

| Method | Best For | What It Looks Like |
|--------|---------|-------------------|
| **[Dashboard (Browser)](#option-a-the-dashboard-browser)** | Everyone -- visual, point-and-click | A website in Chrome/Firefox with buttons, charts, and menus |
| **[Terminal (Command Line)](#option-b-the-terminal-command-line)** | Power users who like typing commands | Text commands you type in the terminal |
| **[Docker](#option-c-docker-one-command-setup)** | Experienced users who want a one-command setup | Single command that runs everything in containers |

Continue to whichever section matches your preference. **If you're new, start with the Dashboard.**

---

## Three Ways to Use REX

---

### Option A: The Dashboard (Browser)

The dashboard is a web page that runs on your computer. You open it in your browser and control REX by clicking buttons -- no typing required.

> **What is a "dashboard"?** Think of it like the dashboard in a car. Instead of showing speed and fuel, REX's dashboard shows your network devices, threats, and security status.

---

#### A1. Open the Dashboard

Open your web browser (Chrome, Firefox, Edge, Safari -- any will work) and type this into the **address bar** at the top (where you normally type website addresses):

```
http://localhost:8443
```

Press **Enter**.

> **What is `localhost`?** It means "this computer." You're not going to a website on the internet -- you're connecting to REX running on your own machine. `8443` is the port number (think of it like a room number in a building).

**What you should see:** The REX login page with a Black Great Dane icon.

> **Note:** GUI mode is the default. REX automatically opens the dashboard in your browser on startup. To start without opening a browser, use:
> ```bash
> rex start --mode cli
> ```

---

#### A2. First-Time Setup Wizard

If this is your very first time, REX shows a **Setup Wizard** instead of the login page. Don't worry -- it guides you through everything:

1. **Environment Check page** -- REX tests your system and shows colored indicators:
   - Green checkmark = working
   - Yellow/amber = optional feature not available (that's OK)
   - Red X = required feature missing (needs fixing)

2. **Click the "Continue" button** to move through each step

3. **The login page appears** when the wizard is done

---

#### A3. Log In

On the login page, you'll see two text boxes and a button:

1. **Click the Username box** and type: `admin`
2. **Click the Password box** and type the random password that REX displayed in the terminal when it first started
3. **Click the "Log In" button**

| Field | What to Type |
|-------|-------------|
| Username | `admin` |
| Password | The random password from REX's first-boot terminal output |

> **Important:** REX generates a random admin password on first boot. It is displayed once in the terminal output. Write it down immediately -- it will not be shown again.

**What you should see:** The main dashboard loads. You'll see REX (the Black Great Dane) in the upper right, and network statistics in the center.

---

#### A4. Understanding the Dashboard Layout

The dashboard has three main areas:

**1. The Sidebar (left side)**
This is your navigation menu -- a vertical list of page names. Click any item to go to that page. The currently active page is highlighted with a colored bar on the left edge (dark red/black theme).

**2. The Main Content Area (center)**
This is where the selected page's content appears. It changes when you click different sidebar items.

**3. REX the Guard Dog (on the Dashboard/Overview page)**
The animated Black Great Dane in the top-right shows REX's current threat posture:

| REX's Eyes | What It Means | Your Action |
|-----------|---------------|-------------|
| Dark Red | All clear -- no threats detected | Nothing needed, REX is happy |
| Amber/Yellow | Something suspicious found | Check the Threats page for details |
| Red | Active threat detected | Check Threats page -- REX may already be blocking it |
| Orange + chains | Junkyard Dog mode active | REX is in maximum protection -- no mercy for threats |

---

#### A5. Dashboard Pages -- What Each One Does

When you first log in, you're in **Basic Mode** which shows the most important pages. You can switch to **Advanced Mode** for full access (explained below).

**Basic Mode Pages (visible by default):**

| Click This | What You'll See | What You Can Do |
|-----------|----------------|-----------------|
| **Dashboard** | Your home page: device count, threat count, blocked attacks (24h), uptime, trend charts | Just watch -- it updates automatically. Click any alert to see details. |
| **REX Chat** | A chat window where you can talk to REX in plain English | Type messages like "scan my network" or "what devices are connected?" and press Enter. REX responds like a chatbot. **Requires Ollama.** |
| **Devices** | A table of every device on your network (phones, laptops, TVs, etc.) | Click any device to see details (IP address, manufacturer, when first seen). Use **Trust** or **Block** buttons. |
| **Threats** | A list of all security threats REX has detected | Use colored filter buttons (Critical, High, Medium, etc.) to sort. Click any threat for details. Use **Resolve** or **False Positive** buttons. |
| **Scheduler** | Controls for when REX scans and sleeps | Set wake/sleep times. View scan history. Click **"Patrol Now"** to scan immediately. |
| **Diagnostics** | REX's health info: services, system resources, logs | Click **"Copy Diagnostics"** to copy a report for sharing if you need help. |
| **Settings** | Links to all settings sub-pages | Click any card to go to that settings area. |

**Advanced Mode Pages (hidden until you switch modes):**

To see these, click the **mode toggle button** at the very bottom of the sidebar -- it says "Advanced mode." Click it. New pages appear:

| Click This | What You'll See | What You Can Do |
|-----------|----------------|-----------------|
| **Network Map** | A visual map of your network | Click any device to see details. Devices are grouped by network segment. |
| **Firewall** | Firewall rules that block/allow traffic | Click **"Add Rule"** to create a rule. **Panic Mode** button blocks everything in emergencies. |
| **Knowledge Base** | REX's notebook -- what he's learned | Read, edit, save. View version history and revert old versions. |
| **Plugins** | Add-on features for REX | Click **Install** on available plugins. Click **Remove** to uninstall. |
| **Federation** | Connect multiple REX instances | Click **"Enable Federation"** to share threat info with other REX installations on different networks. |
| **Agent Actions** | Every action REX is allowed to take | Browse by category using tab buttons. See risk levels and which actions need confirmation. |
| **Services** | Health status of each REX service | Green = healthy, amber = degraded, red = error. Shows which services depend on which. |
| **Privacy** | Data privacy info: where your data goes, encryption, outbound connections | Click **"Run Audit"** for a privacy compliance score. |
| **System Config** | Fine-tune REX's settings | Change scan interval, protection mode, sleep/wake schedule, data retention. Click **"Save Changes"** when done. |

---

#### A6. Switching Between Basic and Advanced Mode

Look at the very bottom of the left sidebar. You'll see a small button with two arrows:

- If it says **"Advanced mode"** -- click it to show all pages
- If it says **"Basic mode"** -- click it to hide advanced pages

Your choice is remembered. You won't need to switch every time you log in.

---

#### A7. Accessing the Dashboard from Your Phone or Another Computer

By default, the dashboard binds to `127.0.0.1` (localhost only). To access it from other devices on your network, you must first enable LAN access:

```bash
export REX_DASHBOARD_HOST=0.0.0.0
```

Or add `REX_DASHBOARD_HOST=0.0.0.0` to your `.env` file and restart REX.

**Step 1:** Find the IP address of the computer running REX. In the terminal on that computer, type:

```bash
hostname -I
```

You'll see something like: `192.168.1.100`

**Step 2:** On your phone, tablet, or other computer, open a web browser and go to:

```
http://192.168.1.100:8443
```

(Replace `192.168.1.100` with the actual IP from Step 1)

**Step 3:** Log in with the same username and password.

> **Security note:** Only access REX over your local network. Never expose port 8443 to the public internet.

---

### Option B: The Terminal (Command Line)

If you're comfortable typing commands, the terminal gives you fast, precise control over REX. Everything you can do in the dashboard can also be done from the terminal.

> **Prerequisites:** REX must be installed (Steps 1-8 above) and running.

---

#### B1. Make Sure REX is Running

Open a terminal. If REX isn't started yet:

```bash
cd REX-BOT-AI
source .venv/bin/activate
sudo .venv/bin/python -m rex.core.cli start
```

If REX is already running, open a **second terminal** for commands:

```bash
cd REX-BOT-AI
source .venv/bin/activate
```

---

#### B2. Log In via Terminal

Before you can run commands, you need to authenticate:

```bash
rex login
```

REX will ask for your username and password:

```
Username: admin
Password: <the random password from first boot>
```

**What you should see:** `Login successful` or a token confirmation message.

> Your login session is saved in `~/.rex-tokens.json` so you don't need to log in again until the token expires.

---

#### B3. Essential Commands

Here are the commands you'll use most often. Type any of these and press Enter:

**Check REX's Status:**
```bash
rex status
```
Shows whether each service is running, device count, and threat count.

**Scan Your Network Now:**
```bash
rex scan
```
Tells REX to scan for devices and threats right now.

**See What Devices Are on Your Network:**
```bash
rex status
```
The device count appears in the status output. For full device details, use the dashboard or API.

**Activate Junkyard Dog Mode (Maximum Protection):**
```bash
rex junkyard
```
REX goes into attack mode -- blocks all threats immediately with no mercy.

**Put REX to Sleep:**
```bash
rex sleep
```
REX enters light sleep mode -- still monitoring but less actively.

**Wake REX Up:**
```bash
rex wake
```
Returns REX to full monitoring mode.

**Schedule Regular Patrols:**
```bash
rex patrol --now                      # Patrol right now
rex patrol --schedule "0 2 * * *"     # Every night at 2am
rex patrol --schedule "0 */6 * * *"   # Every 6 hours
```

**Run a Privacy Audit:**
```bash
rex privacy
```
Checks that your data isn't leaking anywhere.

**Create a Backup:**
```bash
rex backup
```
Creates a backup of REX's data and settings.

**Get Full Diagnostic Info:**
```bash
rex diag
```
Prints detailed system information -- useful if something goes wrong.

**Open the Dashboard from Terminal:**
```bash
rex gui
```
Opens the dashboard in your default web browser.

**Stop REX:**
```bash
sudo .venv/bin/python -m rex.core.cli stop
```
Gracefully shuts down all services. Or just press `Ctrl + C` in the terminal where REX is running.

**Change Your Password via Terminal:**
```bash
curl -X POST http://localhost:8443/api/auth/change-password \
  -H "Authorization: Bearer $(jq -r 'to_entries[0].value' ~/.rex-tokens.json)" \
  -H "Content-Type: application/json" \
  -d '{"old_password": "<your-current-password>", "new_password": "your-new-secure-password"}'
```

---

#### B4. Terminal Quick Reference Card

| Command | What It Does |
|---------|-------------|
| `rex start` | Start all services (auto-detects GUI/CLI mode) |
| `rex start --mode gui` | Start REX and open the dashboard in your browser |
| `rex start --mode cli` | Start REX without opening a browser |
| `rex start --mode headless` | Start REX with minimal output (for servers) |
| `rex stop` | Stop all services |
| `rex gui` | Open dashboard in browser (REX must be running) |
| `rex status` | Show service health and counts |
| `rex scan` | Trigger a network scan |
| `rex login` | Log in to the REX API |
| `rex sleep` | Put REX into light sleep mode |
| `rex wake` | Wake REX to full monitoring |
| `rex junkyard` | Activate maximum protection mode |
| `rex patrol --now` | Run a patrol scan right now |
| `rex patrol --schedule "..."` | Schedule recurring patrols (cron format) |
| `rex diag` | Full diagnostic dump |
| `rex backup` | Backup REX's data |
| `rex privacy` | Run privacy audit |
| `rex setup` | Create desktop shortcut |
| `rex version` | Show version number |

---

### Option C: Docker (One-Command Setup)

Docker runs REX and all its dependencies (Redis, Ollama, ChromaDB) in isolated containers. This is the fastest way to get started if you already have Docker installed.

> **What is Docker?** Docker is software that runs applications in isolated "containers" -- like lightweight virtual machines. It handles all the dependencies automatically so you don't need to install Redis, Ollama, etc. separately.

---

#### C1. Install Docker

If you don't have Docker yet:

**Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

**Log out and log back in** for the group change to take effect.

**Verify Docker is working:**
```bash
docker run hello-world
```

You should see "Hello from Docker!" in the output.

---

#### C2. Download REX

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI
```

---

#### C3. Configure and Start

```bash
# Create a secure Redis password
echo "REDIS_PASSWORD=$(openssl rand -base64 32)" > .env

# Start everything (REX + Redis + Ollama + ChromaDB)
docker compose up -d
```

**What you should see:** Docker downloads images and starts four containers. This may take a few minutes the first time.

**Check that everything is running:**
```bash
docker compose ps
```

You should see four containers with "Up" status.

---

#### C4. Open the Dashboard

Open your browser and go to:

```
http://localhost:8443
```

Log in with username `admin` and the random password displayed in the terminal on first boot.

---

#### C5. Docker Commands

```bash
docker compose ps          # Check status
docker compose logs -f rex # Watch REX's logs in real time
docker compose restart     # Restart all services
docker compose down        # Stop everything
docker compose up -d       # Start everything again
```

---

## Common Tasks Walk-Through

These walk-throughs work for both the dashboard and terminal. We show both methods for each task.

---

#### "I want to see what's on my network"

**Dashboard:** Click **Devices** in the sidebar. Wait a moment for the list to populate. Each row shows a device with its IP, MAC address, and manufacturer. Click any device for full details.

**Terminal:**
```bash
rex scan        # Trigger a scan first
rex status      # See device count
```

---

#### "I want to check if there are any threats"

**Dashboard:** Click **Threats** in the sidebar. Use the colored filter buttons (Critical, High, Medium, etc.) to narrow the list. Click any threat to see details and what REX did about it.

**Terminal:**
```bash
rex status      # Shows active threat count
```

---

#### "I want to resolve or dismiss a threat"

**Dashboard:** Click **Threats**, then click a threat. Use the **Resolve** button to mark it as handled, or **False Positive** if it wasn't a real threat.

---

#### "I want to talk to REX"

**Dashboard:** Click **REX Chat** in the sidebar. Type a message like "What devices are on my network?" or "Run a scan" and press Enter. (Requires Ollama to be running.)

---

#### "I want to change how often REX scans"

**Dashboard:** Click **Settings** > **System Configuration**. Change the "Scan Interval" value (in seconds -- 60 = every minute, 300 = every 5 minutes). Click **Save Changes**.

---

#### "I want to block a device"

**Dashboard:** Click **Devices**, find the device, click it, click the **Block** button.

---

#### "I want maximum protection right now"

**Dashboard:** On the **Dashboard** page, use the Quick Actions panel to activate Junkyard Dog mode.

**Terminal:**
```bash
rex junkyard
```

REX goes into BITE mode -- blocks, quarantines, and rate-limits all threats simultaneously.

---

#### "I want to change my password"

**Dashboard:** Click **Settings** > **Change Password**. Enter your current password and new password. Click **Change Password**.

---

#### "I want to schedule REX to patrol every night"

**Dashboard:** Click **Scheduler**. Set the wake/sleep times or use the patrol schedule form.

**Terminal:**
```bash
rex patrol --schedule "0 2 * * *"    # Every night at 2am
```

---

#### "I want to access REX from my phone"

1. Find your computer's IP: `hostname -I` (in terminal)
2. On your phone's browser, go to: `http://YOUR-IP:8443`
3. Log in with the same credentials

---

## Protection Modes

REX has four protection levels that control how aggressively he responds to threats:

| Mode | Aggressiveness | What REX Does | How to Activate |
|------|---------------|--------------|-----------------|
| `alert_only` | Low | Watches and logs only. No blocking. | Dashboard: Settings > System Config > Protection Mode |
| `auto_block_critical` | Medium (default) | Auto-blocks CRITICAL and HIGH threats. Logs the rest. | This is the default mode. |
| `auto_block_all` | High | Auto-blocks ALL threats regardless of severity. | Dashboard: Settings > System Config > Protection Mode |
| `junkyard_dog` | Maximum | **BITE mode.** Blocks + quarantines + rate-limits everything. No mercy. | Terminal: `rex junkyard` or Dashboard: Quick Actions |

### Junkyard Dog Mode -- BITE!

When activated, REX becomes a junkyard dog:

- **BITE action** -- block + quarantine + rate-limit all at once
- **Active threat removal** -- all threats eliminated immediately
- **Every alert escalated** -- no threat is ignored
- **Owner notified** -- you get alerts about every action
- **Aggressive bark** -- *GRRRRR WOOF WOOF!* REX communicates in fierce dog noises

### Patrol Mode

Schedule REX to wake up, patrol the network, and go back to sleep:

```bash
rex patrol --now                        # Patrol right now
rex patrol --schedule "0 2 * * *"       # Every night at 2am
rex patrol --schedule "0 */6 * * *"     # Every 6 hours
rex patrol --schedule "0 0 * * 1"       # Every Monday at midnight
```

During a patrol, REX will deep scan the network, audit for vulnerabilities, inspect all devices, and report findings.

---

## Troubleshooting

### Installation Problems

| Problem | Solution |
|---------|----------|
| `python3: command not found` | Install Python: `sudo apt install python3 python3-venv python3-pip` |
| `git: command not found` | Install Git: `sudo apt install git` |
| `pip: command not found` | You forgot to activate the venv. Run: `source .venv/bin/activate` |
| `pip install` fails with permission error | Don't use `sudo pip`. Make sure you ran `source .venv/bin/activate` first. |
| `(.venv)` doesn't appear in prompt | Run `source .venv/bin/activate` again. You must do this every time you open a new terminal. |

### Starting REX Problems

| Problem | Solution |
|---------|----------|
| `Permission denied` when starting REX | Use `sudo`: `sudo .venv/bin/python -m rex.core.cli start` |
| `redis.exceptions.ConnectionError` | Redis isn't running. Start it: `sudo systemctl start redis-server` |
| `Address already in use` (port 8443) | Something else is using that port. Find it: `sudo ss -ltnp \| grep :8443` and kill it, or change REX's port: `export REX_DASHBOARD_PORT=9443` |
| REX starts but some services show "FAILED" | Check the specific service error in the terminal output. Most common: Redis not running or port conflicts. |

### Dashboard Problems

| Problem | Solution |
|---------|----------|
| Browser shows "Connection refused" or "can't reach this page" | REX isn't running. Start it first (Step 8). Make sure you typed `http://localhost:8443` exactly. |
| Browser shows blank white page | Try a hard refresh: `Ctrl + Shift + R`. Clear browser cache if needed. |
| Login page appears but password is rejected | If this is a fresh install, you should see a "Create Admin Password" form instead of a login form. If you forgot your password, reset it: `rex reset-auth --yes` then restart REX. |
| Dashboard says "Waiting for backend connection" | Redis isn't running. Open a terminal: `redis-cli ping` -- you should see `PONG`. If not: `sudo systemctl start redis-server` |
| REX Chat says "brain isn't connected" | Ollama isn't running. Start it: `ollama serve &` |
| All pages show "--" or "No data" | This is normal on first start. REX needs a few minutes to scan. Click **Patrol Now** on the Scheduler page, or run `rex scan` in terminal. |
| Can't access dashboard from phone/tablet | Both devices must be on the same WiFi. Use your computer's IP (not `localhost`). Example: `http://192.168.1.100:8443`. Check that no firewall blocks port 8443. |

### Ollama / AI Problems

| Problem | Solution |
|---------|----------|
| `ollama: command not found` | Install Ollama: `curl -fsSL https://ollama.com/install.sh \| sh` |
| Ollama installed but REX chat doesn't work | Make sure Ollama is running: `ollama serve &`. Then verify: `curl http://localhost:11434/api/tags` |
| Ollama is slow | AI models need RAM. Try a smaller model: `ollama pull llama3.2:1b` |

### Docker Problems

| Problem | Solution |
|---------|----------|
| `docker: command not found` | Install Docker: `curl -fsSL https://get.docker.com \| sh` |
| `permission denied` with docker commands | Add yourself to the docker group: `sudo usermod -aG docker $USER` then log out and back in |
| Containers keep restarting | Check logs: `docker compose logs rex` -- look for the error message |
| Want to start over completely | `docker compose down -v` (warning: deletes all data) |

---

## Quick Start Checklist

Use this checklist to make sure everything is working. Check each item:

- [ ] Terminal open and `(.venv)` showing in prompt
- [ ] `python3 --version` shows 3.11 or 3.12
- [ ] `redis-cli ping` shows `PONG`
- [ ] `python -m rex.core.cli version` shows a version number
- [ ] REX started with `sudo .venv/bin/python -m rex.core.cli start`
- [ ] Browser opens `http://localhost:8443` and shows the login page
- [ ] Logged in with `admin` and the random password from terminal output
- [ ] Dashboard loads and shows REX the Black Great Dane

If all boxes are checked, you're fully set up. REX is protecting your network.

---

# Part 2: Advanced Users & Developers

*This section is for power users, system administrators, and developers who want to customize, extend, or contribute to REX.*

---

## Configuration Reference

### Environment Variables

Copy the example config and customize:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `REX_MODE` | `basic` | Operating mode (`basic` or `advanced`) |
| `REX_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warning`, `error` |
| `REX_DATA_DIR` | `/etc/rex-bot-ai` | Data directory (needs write access) |
| `REX_DASHBOARD_PORT` | `8443` | Dashboard web UI port |
| `REX_DASHBOARD_HOST` | `127.0.0.1` | Dashboard bind address (set to `0.0.0.0` for LAN access) |
| `REX_REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `REDIS_PASSWORD` | *(none)* | Redis authentication password |
| `REX_OLLAMA_URL` | `http://localhost:11434` | Ollama LLM endpoint (localhost only enforced) |
| `REX_OLLAMA_MODEL` | `auto` | LLM model (auto-selects based on hardware) |
| `REX_CHROMA_URL` | `http://localhost:8000` | ChromaDB vector store URL |
| `REX_NETWORK_INTERFACE` | `auto` | Network interface to monitor |
| `REX_SCAN_INTERVAL` | `300` | Seconds between periodic scans |
| `REX_PROTECTION_MODE` | `auto_block_critical` | Protection level (see Protection Modes) |

### Data Directory

REX stores configuration, logs, knowledge base, and threat data in `REX_DATA_DIR`:

```bash
# System-wide (default, needs sudo)
sudo mkdir -p /etc/rex-bot-ai
sudo chown $USER:$USER /etc/rex-bot-ai

# Per-user (no sudo needed)
export REX_DATA_DIR="$HOME/.rex-bot-ai"
mkdir -p "$REX_DATA_DIR"
```

### Credential Storage

On first boot, REX has no password. The dashboard shows a "Create Admin Password" form where you set your own password. There is no default, hardcoded, or terminal-displayed password.

To reset a forgotten password: `rex reset-auth --yes` then restart REX. The dashboard will show the "Create Admin Password" form again.

CLI tokens are stored in `~/.rex-tokens.json` (keyed by API URL).

---

## CLI Command Reference

```bash
rex start [--mode gui|cli|headless]  # Start all services
rex stop                              # Graceful shutdown
rex gui                               # Open dashboard in browser
rex status                            # Service health + counts
rex scan                              # Trigger network scan
rex login                             # Authenticate with API
rex sleep                             # Enter alert-sleep mode
rex wake                              # Resume full monitoring
rex junkyard                          # Activate BITE mode
rex patrol --now                      # Immediate patrol
rex patrol --schedule "CRON"          # Scheduled patrols
rex diag                              # Full diagnostic dump
rex backup                            # Atomic data backup
rex privacy                           # Privacy audit
rex setup                             # Create desktop shortcut
rex version                           # Print version
```

### TLS / Connection Notes

If the dashboard runs without TLS certificates (development mode):

```bash
REX_API_URL=http://127.0.0.1:8443 rex status
```

---

## Architecture

REX is built as cooperating async services, each with its own EventBus instance and Redis consumer group:

```
EYES (scan) -> Redis -> BRAIN (classify) -> TEETH (block) -> BARK (notify)
                                   |
                              MEMORY (log to REX-BOT-AI.md)
```

**Service startup order:**

```
1. Memory     -- threat logs, knowledge base, vector store
2. Eyes       -- network scanner, DNS monitor, traffic capture
3. Scheduler  -- cron jobs, patrol schedules, power state
4. Interview  -- initial setup wizard
5. Brain      -- threat classifier, LLM router
6. Bark       -- notification channels (Discord, Telegram, email, Matrix)
7. Teeth      -- firewall manager, DNS blocker, device isolator
8. Federation -- multi-instance coordination
9. Store      -- plugin registry, sandbox
10. Dashboard  -- FastAPI web UI (depends on all others)
```

Each service owns its bus connection. Consumer groups are isolated (`rex:<service>:group`) so every subscribing service sees every event.

All OS-specific operations go through the Platform Abstraction Layer (PAL). The LLM is hardcoded to localhost only -- network data never leaves the machine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full details.

---

## Security Invariants

These are enforced in code, not just policy:

- **No `shell=True`** anywhere. Commands use a whitelist with parameter validators.
- **LLM is localhost-only.** `OllamaClient` raises `PrivacyViolationError` for non-localhost URLs.
- **Network data is sanitized** before reaching the LLM (44+ prompt injection patterns stripped).
- **Firewall safety:** gateway and REX IPs are hardcoded as untargetable, with IP normalization.
- **Action whitelist:** the LLM cannot execute actions not in the registry regardless of output.
- **Scope enforcement:** out-of-scope patterns override security keyword matches.
- **CORS safety:** wildcard origins stripped when `allow_credentials=True`.
- **WebSocket auth:** first-message auth only -- JWTs never in URLs/query strings.
- **Password hashing:** bcrypt with SHA-256 pre-hashing (prevents 72-byte truncation).
- **Restart anti-flapping:** sliding-window restart budget with exponential backoff.
- **Health fail-closed:** `/api/health` returns 503 when event bus is unreachable.
- **Plugin permissions:** restricted to declared permissions; unregistered tokens rejected.

---

## Current State (Honest)

| Component | Status |
|-----------|--------|
| Platform Abstraction Layer (Linux) | Working -- 2300+ lines, real subprocess calls |
| Threat classifier (12 categories) | Working -- rule-based, no LLM required |
| Command executor (whitelisted) | Working -- zero shell=True, parameter validation |
| LLM client (localhost-only enforced) | Working -- Ollama integration with privacy boundary |
| Pydantic data models | Working -- Device, ThreatEvent, Decision, etc. |
| Redis event bus | Working -- per-service consumer groups, WAL fallback |
| Network scanner (ARP + nmap) | Working -- device discovery via PAL |
| DNS monitor | Working -- query analysis, DGA detection |
| Device fingerprinter | Working -- MAC OUI, OS detection, type classification |
| Knowledge base (markdown) | Working -- read/write/parse with git versioning |
| Privacy/encryption module | Working -- Fernet secrets, audit tools |
| Agent security | Working -- prompt injection defense (44 patterns), IP normalization, action whitelist |
| Dashboard API (FastAPI) | Working -- 11 routers, 43+ endpoints |
| Dashboard frontend (React) | **Alpha** -- 26 pages, all wired to real API endpoints |
| Notification channels | **Partial** -- channel classes exist, not integration-tested |
| Plugin system | **Minimal** -- SDK defined, sandbox is a dict not Docker |
| Orchestrator | Working -- per-service bus ownership, health monitor, auto-restart |
| Docker deployment | **Unverified** -- compose file exists, end-to-end not tested |
| Windows/macOS/BSD PAL | **Experimental** -- stub adapters, many NotImplementedError |
| Test suite | 4,289 tests, 0 failures |

---

## Contributing

This project needs help. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Priority areas:
1. Verify end-to-end Docker Compose deployment with live events
2. Integration tests with live Redis in CI
3. Replace plugin sandbox dict with real Docker isolation
4. Complete Windows/macOS/BSD PAL adapters
5. Notification channel integration testing

---

## Rebuilding the Frontend

The compiled GUI is included in the repository. Only developers who modify `frontend/src/` need to rebuild:

```bash
cd frontend
npm install
node node_modules/vite/bin/vite.js build
```

This produces `frontend/dist/` which the dashboard serves automatically.

**Dev server with hot reload:**
```bash
cd frontend
npm install
npm run dev
```

---

## License

MIT License. See [LICENSE](LICENSE).
