#!/bin/bash

echo "=================================================="
echo "  CineVerse Installation"
echo "=================================================="
echo ""

# Farben für Output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Prüfe ob Node.js installiert ist
if ! command -v node &> /dev/null; then
    echo -e "${RED}✗ Node.js ist nicht installiert!${NC}"
    echo "Bitte installiere Node.js von https://nodejs.org"
    exit 1
fi

echo -e "${GREEN}✓ Node.js gefunden: $(node --version)${NC}"

# Prüfe ob npm installiert ist
if ! command -v npm &> /dev/null; then
    echo -e "${RED}✗ npm ist nicht installiert!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ npm gefunden: $(npm --version)${NC}"
echo ""

# Dependencies installieren
echo "📦 Installiere Dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Fehler bei der Installation der Dependencies${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Dependencies installiert${NC}"
echo ""

# .env Datei erstellen wenn nicht vorhanden
if [ ! -f .env ]; then
    echo "📝 Erstelle .env Datei..."
    cp .env.example .env
    echo -e "${GREEN}✓ .env Datei erstellt${NC}"
    echo -e "${YELLOW}⚠  Bitte konfiguriere die .env Datei mit deinen OAuth-Credentials${NC}"
else
    echo -e "${YELLOW}ℹ  .env Datei existiert bereits${NC}"
fi

echo ""
echo "=================================================="
echo "  Installation abgeschlossen! 🎉"
echo "=================================================="
echo ""
echo "Nächste Schritte:"
echo ""
echo "1. Öffne die Datei .env und füge deine OAuth-Credentials ein"
echo "   (Siehe OAUTH_SETUP_GUIDE.md für Details)"
echo ""
echo "2. Starte den Server mit:"
echo "   ${GREEN}npm start${NC}"
echo ""
echo "3. Öffne im Browser:"
echo "   ${GREEN}http://localhost:3000${NC}"
echo ""
echo "4. Admin-Login:"
echo "   Benutzername: ${GREEN}admin${NC}"
echo "   Passwort: ${GREEN}admin123${NC}"
echo ""
echo "📚 Weitere Informationen in README.md"
echo "🔧 OAuth-Setup: OAUTH_SETUP_GUIDE.md"
echo ""