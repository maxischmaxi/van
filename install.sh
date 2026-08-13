#!/bin/sh
set -e

# ─── Konfiguration ──────────────────────────────────────────────
REPO="maxischmaxi/van"
BINARY_NAME="van"
INSTALL_DIR="${HOME}/.local/bin"
# ────────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    RED=''
    NC=''
fi

info()  { printf "${GREEN}==>${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}==>${NC} %s\n" "$1"; }
error() { printf "${RED}==>${NC} %s\n" "$1" >&2; exit 1; }

# ─── Plattform erkennen ─────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64)  ARTIFACT="${BINARY_NAME}-darwin-arm64" ;;
            *)      error "macOS Intel wird nicht unterstützt (nur ARM). Architektur: $ARCH" ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            x86_64)  ARTIFACT="${BINARY_NAME}-linux-amd64" ;;
            aarch64) ARTIFACT="${BINARY_NAME}-linux-arm64" ;;
            *)       error "Nicht unterstützte Linux-Architektur: $ARCH" ;;
        esac
        ;;
    *)
        error "Nicht unterstütztes OS: $OS (nur macOS und Linux)"
        ;;
esac

info "Plattform: $OS $ARCH"

# ─── Update oder Neuinstallation? ───────────────────────────────
if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
    info "Bestehende Installation gefunden — Update..."
else
    info "Installiere ${BINARY_NAME}..."
fi

# ─── Download ──────────────────────────────────────────────────
URL="https://github.com/${REPO}/releases/latest/download/${ARTIFACT}.tar.gz"
info "Lade herunter: $URL"

TMPFILE="$(mktemp)"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$TMPFILE" || error "Download fehlgeschlagen — Release existiert möglicherweise noch nicht. Tagge einen Release (git tag v1.0.0 && git push origin v1.0.0)."
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMPFILE" "$URL" || error "Download fehlgeschlagen — Release existiert möglicherweise noch nicht."
else
    error "Weder curl noch wget gefunden."
fi

if [ ! -s "$TMPFILE" ]; then
    rm -f "$TMPFILE"
    error "Download fehlgeschlagen — Datei ist leer. Plattform $OS/$ARCH wird eventuell nicht unterstützt."
fi

# ─── Entpacken & Installieren ───────────────────────────────────
mkdir -p "$INSTALL_DIR"
info "Entpacke..."
TMPDIR="$(mktemp -d)"
tar xzf "$TMPFILE" -C "$TMPDIR"
rm -f "$TMPFILE"

if [ ! -f "${TMPDIR}/${ARTIFACT}" ]; then
    rm -rf "$TMPDIR"
    error "Entpacken fehlgeschlagen — Binary nicht im Archiv gefunden."
fi

mv "${TMPDIR}/${ARTIFACT}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
rm -rf "$TMPDIR"

info "Installiert nach: ${INSTALL_DIR}/${BINARY_NAME}"

# ─── PATH prüfen ────────────────────────────────────────────────
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        warn "${INSTALL_DIR} ist nicht in deinem PATH."
        printf "    Füge das zu deiner Shell-Config hinzu:\n"
        printf '    export PATH="%s:$PATH"\n' "$INSTALL_DIR"
        ;;
esac

# ─── Shell-Completions ──────────────────────────────────────────
SHELL_NAME=""
if [ -n "$SHELL" ]; then
    SHELL_NAME="$(basename "$SHELL")"
fi

case "$SHELL_NAME" in
    bash)
        COMP_DIR="${HOME}/.local/share/bash-completion/completions"
        mkdir -p "$COMP_DIR"
        "${INSTALL_DIR}/${BINARY_NAME}" completions bash > "${COMP_DIR}/${BINARY_NAME}"
        info "Bash-Completions installiert nach: ${COMP_DIR}/${BINARY_NAME}"
        ;;
    zsh)
        COMP_DIR="${HOME}/.zsh/completions"
        mkdir -p "$COMP_DIR"
        "${INSTALL_DIR}/${BINARY_NAME}" completions zsh > "${COMP_DIR}/_${BINARY_NAME}"
        info "Zsh-Completions installiert nach: ${COMP_DIR}/_${BINARY_NAME}"
        printf "    Falls Completions nicht funktionieren, füge das zur .zshrc hinzu:\n"
        printf "    fpath=(%s \$fpath)\n" "$COMP_DIR"
        ;;
    fish)
        COMP_DIR="${HOME}/.config/fish/completions"
        mkdir -p "$COMP_DIR"
        "${INSTALL_DIR}/${BINARY_NAME}" completions fish > "${COMP_DIR}/${BINARY_NAME}.fish"
        info "Fish-Completions installiert nach: ${COMP_DIR}/${BINARY_NAME}.fish"
        ;;
    *)
        warn "Shell nicht erkannt: '${SHELL_NAME:-leer}' — Completions übersprungen."
        printf "    Manuell installieren mit: %s completions <bash|zsh|fish>\n" "$BINARY_NAME"
        ;;
esac

# ─── Done ───────────────────────────────────────────────────────
info "Fertig! Starte eine neue Shell oder öffne ein neues Terminal."
info "Dann: ${BINARY_NAME} list"