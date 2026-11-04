
#!/data/data/com.termux/files/usr/bin/bash

# VirusScan Installer
# Developer: KSURitam 
# Version: 5.1

RESET='\033[0m'
YELLOW='\033[93m'
GREEN='\033[92m'
RED='\033[91m'

success() {
    printf "${GREEN}[SUCCESS]${RESET} %s\n" "$1"
}

failed() {
    printf "${RED}[FAILED]${RESET} %s\n" "$1"
}

info() {
    printf "${YELLOW}%s${RESET}\n" "$1"
}

clear 2>/dev/null

printf "${GREEN}VirusScan Installer${RESET}\n"
printf "${YELLOW}Developer: KSURitam${RESET}\n"
echo "----------------------------------------"

FAIL=0

# Python
if command -v python >/dev/null 2>&1; then
    success "Python already installed"
else
    info "Installing Python..."
    if pkg install -y python >/dev/null 2>&1 &&
       command -v python >/dev/null 2>&1; then
        success "Python installed"
    else
        failed "Python installation failed"
        FAIL=1
    fi
fi

# Git
if command -v git >/dev/null 2>&1; then
    success "Git already installed"
else
    info "Installing Git..."
    if pkg install -y git >/dev/null 2>&1 &&
       command -v git >/dev/null 2>&1; then
        success "Git installed"
    else
        failed "Git installation failed"
        FAIL=1
    fi
fi

# Requests
if command -v python >/dev/null 2>&1; then
    info "Updating Requests library..."

    if python -m pip install --upgrade requests \
        --quiet --disable-pip-version-check >/dev/null 2>&1 &&
        python -c "import requests" >/dev/null 2>&1; then
        success "Requests library ready"
    else
        failed "Requests installation failed"
        FAIL=1
    fi
else
    failed "Python unavailable. Requests skipped."
    FAIL=1
fi

echo "----------------------------------------"

if [ "$FAIL" -eq 0 ]; then
    success "VirusScan setup completed!"
    info "Run: python virusscan.py"
else
    failed "Setup incomplete. Check internet and retry."
    exit 1
fi
