#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  SilenceX v1.0 — Build & Install Script (Linux)
# ═══════════════════════════════════════════════════════════

echo ""
echo "  ███████╗██╗██╗     ███████╗███╗   ██╗ ██████╗███████╗██╗  ██╗"
echo "  ██╔════╝██║██║     ██╔════╝████╗  ██║██╔════╝██╔════╝╚██╗██╔╝"
echo "  ███████╗██║██║     █████╗  ██╔██╗ ██║██║     █████╗   ╚███╔╝ "
echo "  ╚════██║██║██║     ██╔══╝  ██║╚██╗██║██║     ██╔══╝   ██╔██╗ "
echo "  ███████║██║███████╗███████╗██║ ╚████║╚██████╗███████╗██╔╝ ██╗"
echo "  ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝"
echo ""
echo "  Building SilenceX v1.0..."
echo "  ═══════════════════════════════════════════"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for venv
if [ -z "$VIRTUAL_ENV" ]; then
    if [ -d "venv" ]; then
        echo "[*] Activating existing venv..."
        source venv/bin/activate
    else
        echo "[*] Creating venv..."
        python -m venv venv
        source venv/bin/activate
    fi
fi

# Step 1: Install deps
echo "[1/4] Installing dependencies..."
pip install customtkinter dnspython python-whois requests Pillow pyinstaller --quiet
echo "      ✓ Done"

# Step 2: Generate icon
echo "[2/4] Generating icon..."
python generate_icon.py
echo "      ✓ Done"

# Step 3: Check for system tools
echo "[3/4] Checking scanner tools..."
for tool in nmap nikto zaproxy; do
    if command -v $tool &> /dev/null; then
        echo "      ✓ $tool found"
    else
        echo "      ✗ $tool not found (install with: sudo pacman -S $tool)"
    fi
done

# Step 4: Build executable
echo "[4/4] Building executable (1-3 min)..."
pyinstaller --noconfirm --onefile --windowed \
    --name "SilenceX" \
    --icon "silencex.ico" \
    --add-data "silencex.ico:." \
    --add-data "silencex.png:." \
    --hidden-import customtkinter \
    --hidden-import dns \
    --hidden-import dns.resolver \
    --hidden-import dns.reversename \
    --hidden-import dns.zone \
    --hidden-import dns.query \
    --hidden-import whois \
    --hidden-import requests \
    --collect-all customtkinter \
    silencex.py

if [ $? -ne 0 ]; then
    echo ""
    echo "  ✗ Build failed! Check output above."
    exit 1
fi

# Copy to Desktop + create .desktop launcher
echo ""
echo "[+] Installing to Desktop..."

cp dist/SilenceX ~/Desktop/SilenceX
chmod +x ~/Desktop/SilenceX

# Copy icon for desktop
mkdir -p ~/.local/share/icons
cp silencex.png ~/.local/share/icons/silencex.png

# Create .desktop file
cat > ~/Desktop/SilenceX.desktop << EOF
[Desktop Entry]
Name=SilenceX
Comment=Security Scanner Suite v1.0
Exec=${SCRIPT_DIR}/dist/SilenceX
Icon=${HOME}/.local/share/icons/silencex.png
Terminal=false
Type=Application
Categories=Security;Network;
EOF

chmod +x ~/Desktop/SilenceX.desktop

# Clean up raw binary from desktop
rm -f ~/Desktop/SilenceX

echo ""
echo "  ═══════════════════════════════════════════════════════"
echo "  ✓ BUILD COMPLETE!"
echo ""
echo "  SilenceX.desktop is on your Desktop"
echo "  Right-click → Allow Launching → Double-click to run!"
echo ""
echo "  Recommended tools to install:"
echo "    sudo pacman -S nmap nikto"
echo "    yay -S zaproxy  (AUR)"
echo "  ═══════════════════════════════════════════════════════"
echo ""
