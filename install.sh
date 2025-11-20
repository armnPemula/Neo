#!/bin/bash

echo "Setting environment variables..."
source .env

if [ ! -d "env" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

echo "Activating Python virtual environment..."
source .venv/bin/activate

if [ ! -f server.crt ] || [ ! -f server.key ]; then
    echo "Generating SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/OU=YourOU/CN=YourDomain"
    cp server.key listeners
    cp server.crt listeners
fi

if [ -f requirements.txt ]; then
    echo "Installing requirements from requirements.txt..."
    pip install -r requirements.txt
else
    echo "requirements.txt not found. Cannot install dependencies."
    exit 1
fi

echo "Checking firewall status..."
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status | grep -w "443/tcp")
    if [ -z "$UFW_STATUS" ]; then
        echo "Port 443 is not open. Allowing port 443/tcp in ufw..."
        ufw allow 443/tcp
    else
        echo "Port 443/tcp is already allowed in ufw."
    fi
elif command -v firewall-cmd &> /dev/null; then
    FIREWALLD_STATUS=$(firewall-cmd --list-ports | grep -w "443/tcp")
    if [ -z "$FIREWALLD_STATUS" ]; then
        echo "Port 443 is not open. Allowing port 443/tcp in firewalld..."
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    else
        echo "Port 443/tcp is already allowed in firewalld."
    fi
else
    echo "Could not detect ufw or firewalld. Please ensure port 443 is open manually."
fi

pip install gevent-websocket
echo ""
echo "********************************************************************************"
echo "** IMPORTANT: Remember to allow port 443 on your VPS/cloud firewall as well! **"
echo "********************************************************************************"
echo ""


