#!/bin/sh
# Pitboard Link — installation, mise à jour et désinstallation.
#
#   curl -fsSL https://github.com/Greg-LFT/pitboard-link/releases/latest/download/install.sh | sh
#
# Options :
#   --desinstaller          retire Pitboard Link et remet les fichiers modifiés en l'état
#   --binaire FICHIER       installe cet exécutable au lieu de le télécharger (essais)
#   --importer DOSSIER      reprend l'identité et la liaison d'un Link existant (essais)
#   --cle-api CLE           clé API Moonraker, si Moonraker refuse les connexions locales
#   --crowsnest-fps N       fixe la cadence de la webcam dans crowsnest.conf (copie de sauvegarde)
#
# Non invasif : un seul exécutable sans dépendance dans /opt/pitboard-link, un utilisateur
# système dédié, un service. Aucun paquet installé, aucun fichier de Klipper ou Moonraker
# modifié (sauf --crowsnest-fps, demandé explicitement, avec sauvegarde).

set -eu

DEPOT="Greg-LFT/pitboard-link"
DOSSIER="/opt/pitboard-link"
DONNEES="$DOSSIER/data"
UTIL="pitboard-link"
SERVICE="pitboard-link"
PORT=7130

BINAIRE=""
IMPORT=""
CLE_API=""
CROWS_FPS=""
ACTION="installer"

while [ $# -gt 0 ]; do
  case "$1" in
    --desinstaller) ACTION="desinstaller" ;;
    --binaire) BINAIRE="$2"; shift ;;
    --importer) IMPORT="$2"; shift ;;
    --cle-api) CLE_API="$2"; shift ;;
    --crowsnest-fps) CROWS_FPS="$2"; shift ;;
    *) echo "Option inconnue : $1"; exit 2 ;;
  esac
  shift
done

dire() { printf '\033[1;33m»\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
stop() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || stop "Lance ce script en root (sudo absent)."
  SUDO="sudo"
else
  SUDO=""
fi
r() { $SUDO "$@"; }

INIT="systemd"
[ -d /run/systemd/system ] || INIT="initd"

# ---------------------------------------------------------------------------
if [ "$ACTION" = "desinstaller" ]; then
  dire "Désinstallation de Pitboard Link"
  if [ "$INIT" = "systemd" ]; then
    r systemctl disable --now "$SERVICE" 2>/dev/null || true
    r rm -f "/etc/systemd/system/$SERVICE.service"
    r systemctl daemon-reload
  else
    r /etc/init.d/S99pitboard-link stop 2>/dev/null || true
    r rm -f /etc/init.d/S99pitboard-link
  fi
  r rm -f /usr/local/bin/pitboard-link
  for f in $(r sh -c "ls $DOSSIER/sauvegardes/*.chemin 2>/dev/null" || true); do
    orig="$(r cat "$f")"; sauv="${f%.chemin}"
    [ -f "$sauv" ] && r cp -a "$sauv" "$orig" && ok "Restauré : $orig"
  done
  r rm -rf "$DOSSIER"
  id "$UTIL" >/dev/null 2>&1 && r userdel "$UTIL" 2>/dev/null || true
  ok "Pitboard Link est désinstallé. Pense à le retirer aussi de ton compte dans l'app PitBoard."
  exit 0
fi

# ---------------------------------------------------------------------------
dire "Vérifications (rien n'est encore modifié)"
case "$(uname -m)" in
  aarch64|arm64) ARCH="arm64" ;;
  armv7l|armv7*|armhf) ARCH="armv7" ;;
  mips*) ARCH="mipsle" ;;
  x86_64|amd64) ARCH="amd64" ;;
  *) stop "Architecture non prise en charge : $(uname -m)" ;;
esac
ok "Architecture : $ARCH, démarrage : $INIT"

LIBRE_MO=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
[ "${LIBRE_MO:-0}" -ge 60 ] || stop "Mémoire disponible insuffisante (${LIBRE_MO} Mo, 60 Mo au moins)."
ok "Mémoire disponible : ${LIBRE_MO} Mo"

DISQUE_MO=$(df -Pm /opt 2>/dev/null | awk 'NR==2 {print $4}')
[ "${DISQUE_MO:-0}" -ge 30 ] || stop "Place insuffisante sur le disque (${DISQUE_MO} Mo)."

command -v curl >/dev/null 2>&1 || stop "curl est nécessaire."
MR_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 ${CLE_API:+-H "X-Api-Key: $CLE_API"} http://127.0.0.1:7125/server/info || true)
case "$MR_CODE" in
  200) ok "Moonraker joint en local" ;;
  401|403) stop "Moonraker refuse l'accès local : relance avec --cle-api <clé API de Mainsail/Fluidd>." ;;
  *) stop "Moonraker injoignable sur 127.0.0.1:7125 (code $MR_CODE)." ;;
esac

if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":$PORT "; then
  if ! (r systemctl is-active --quiet "$SERVICE" 2>/dev/null); then
    PORT=7131
    ss -ltn | grep -q ":$PORT " && stop "Ports 7130 et 7131 déjà pris."
    dire "Port 7130 déjà pris : Pitboard Link utilisera $PORT"
  fi
fi

# Webcam : lecture directe d'ustreamer si on le trouve (évite le passage par nginx).
CAM_URL=""
for c in /home/*/printer_data/config/crowsnest.conf; do
  [ -f "$c" ] || continue
  p=$(awk -F: '/^[[:space:]]*port[[:space:]]*:/ {v=$2; sub(/^[[:space:]]+/,"",v); sub(/[^0-9].*/,"",v); print v; exit}' "$c")
  if [ -n "$p" ] && curl -s --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/?action=snapshot" | grep -q 200; then
    CAM_URL="http://127.0.0.1:$p/?action=stream"
    CROWS_CONF=$(readlink -f "$c")
    break
  fi
done
[ -n "$CAM_URL" ] && ok "Webcam : $CAM_URL" || dire "Webcam : celle déclarée dans Moonraker"

# ---------------------------------------------------------------------------
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -n "$BINAIRE" ]; then
  cp "$BINAIRE" "$TMP/pitboard-link"
  ok "Exécutable fourni : $BINAIRE"
else
  dire "Téléchargement de Pitboard Link ($ARCH)"
  BASE="https://github.com/$DEPOT/releases/latest/download"
  curl -fsSL "$BASE/pitboard-link-linux-$ARCH" -o "$TMP/pitboard-link" || stop "Téléchargement impossible."
  curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS" || stop "Sommes de contrôle introuvables."
  ATTENDU=$(grep " pitboard-link-linux-$ARCH\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)
  OBTENU=$(sha256sum "$TMP/pitboard-link" | cut -d' ' -f1)
  [ -n "$ATTENDU" ] && [ "$ATTENDU" = "$OBTENU" ] || stop "Somme de contrôle invalide : fichier refusé."
  ok "Somme de contrôle vérifiée"
fi
chmod 755 "$TMP/pitboard-link"
"$TMP/pitboard-link" version >/dev/null 2>&1 || stop "L'exécutable ne démarre pas sur cette machine."

# ---------------------------------------------------------------------------
dire "Installation dans $DOSSIER"
if ! id "$UTIL" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    r useradd --system --home-dir "$DOSSIER" --no-create-home --shell /usr/sbin/nologin "$UTIL"
  else
    r adduser -S -H -h "$DOSSIER" -s /sbin/nologin "$UTIL"
  fi
  ok "Utilisateur système $UTIL créé"
fi
r mkdir -p "$DONNEES" "$DOSSIER/sauvegardes"
r chmod 755 "$DOSSIER"
r chmod 711 "$DONNEES"
r chmod 700 "$DOSSIER/sauvegardes"
if [ "$INIT" = "systemd" ]; then r systemctl stop "$SERVICE" 2>/dev/null || true; fi
r install -m 755 -o root -g root "$TMP/pitboard-link" "$DOSSIER/pitboard-link"
r ln -sf "$DOSSIER/pitboard-link" /usr/local/bin/pitboard-link

if [ -n "$IMPORT" ]; then
  for f in link.key token tls.crt tls.key; do
    [ -f "$IMPORT/$f" ] && r cp "$IMPORT/$f" "$DONNEES/$f"
  done
  ok "Identité et liaison reprises de $IMPORT"
fi

# Configuration : on garde l'existante, on complète ce qui manque.
r sh -c "[ -f '$DONNEES/config.json' ] || echo '{}' > '$DONNEES/config.json'"
r sh -c "command -v python3 >/dev/null" && r python3 - "$DONNEES/config.json" "$PORT" "$CAM_URL" "$CLE_API" <<'EOF' || true
import json, sys
p, port, cam, cle = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
try: c = json.load(open(p))
except Exception: c = {}
c.setdefault("port", port)
if cam and not c.get("camUrl"): c["camUrl"] = cam
if cle: c["apiKey"] = cle
json.dump(c, open(p, "w"), indent=2)
EOF
r rm -f "$DONNEES/fenetre-appairage"
r chown -R "$UTIL":"$UTIL" "$DONNEES"
r sh -c "chmod 600 '$DONNEES'/config.json '$DONNEES'/link.key '$DONNEES'/token '$DONNEES'/tls.key 2>/dev/null || true"

# Cadence de la webcam (seulement sur demande), avec sauvegarde restaurée à la désinstallation.
if [ -n "$CROWS_FPS" ] && [ -n "${CROWS_CONF:-}" ]; then
  if [ ! -f "$DOSSIER/sauvegardes/crowsnest.conf" ]; then
    r cp -a "$CROWS_CONF" "$DOSSIER/sauvegardes/crowsnest.conf"
    r sh -c "echo '$CROWS_CONF' > '$DOSSIER/sauvegardes/crowsnest.conf.chemin'"
  fi
  r sed -i "s/^\([[:space:]]*max_fps[[:space:]]*:[[:space:]]*\)[0-9]*/\1$CROWS_FPS/" "$CROWS_CONF"
  r systemctl restart crowsnest 2>/dev/null || true
  ok "Webcam réglée à $CROWS_FPS images/s (copie de l'ancien réglage gardée)"
fi

# ---------------------------------------------------------------------------
if [ "$INIT" = "systemd" ]; then
  r tee "/etc/systemd/system/$SERVICE.service" >/dev/null <<EOF
[Unit]
Description=Pitboard Link (PitBoard sur l'hôte Klipper)
After=network-online.target moonraker.service
Wants=network-online.target

[Service]
Type=simple
User=$UTIL
Group=$UTIL
ExecStart=$DOSSIER/pitboard-link run -dir $DONNEES
Restart=always
RestartSec=5
# Klipper passe toujours avant : priorité basse, mémoire plafonnée.
Nice=10
CPUWeight=20
IOSchedulingClass=idle
MemoryMax=64M
# Droits minimaux.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$DONNEES
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LogRateLimitIntervalSec=60
LogRateLimitBurst=60

[Install]
WantedBy=multi-user.target
EOF
  r systemctl daemon-reload
  r systemctl enable --now "$SERVICE" >/dev/null 2>&1
  sleep 4
  r systemctl is-active --quiet "$SERVICE" || stop "Le service ne démarre pas : journalctl -u $SERVICE -n 30"
else
  r tee /etc/init.d/S99pitboard-link >/dev/null <<EOF
#!/bin/sh
case "\$1" in
  start) start-stop-daemon -S -b -m -p /var/run/pitboard-link.pid -c $UTIL -x $DOSSIER/pitboard-link -- run -dir $DONNEES ;;
  stop) start-stop-daemon -K -p /var/run/pitboard-link.pid ;;
  restart) \$0 stop; sleep 1; \$0 start ;;
esac
EOF
  r chmod 755 /etc/init.d/S99pitboard-link
  r /etc/init.d/S99pitboard-link restart
  sleep 4
fi
ok "Service Pitboard Link démarré"

# ---------------------------------------------------------------------------
dire "Attente du relais PitBoard…"
i=0
while [ $i -lt 20 ]; do
  pitboard-link code -dir "$DONNEES" 2>/dev/null | grep -q "Relais    : connecté" && break
  sleep 2; i=$((i+1))
done
echo
pitboard-link code -dir "$DONNEES" || true
echo
ok "Installation terminée. Pour revoir le code : pitboard-link code"
