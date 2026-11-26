# Pitboard Link

Pitboard Link relie une imprimante 3D **Klipper** à l'application **PitBoard** (Android), sans boîtier
supplémentaire. Il s'installe sur l'ordinateur qui fait tourner Klipper et Moonraker (Raspberry Pi,
carte de l'imprimante…) et permet de suivre l'impression et la caméra :

- **sur le WiFi de la maison**, directement entre le téléphone et l'imprimante ;
- **à distance**, par le serveur PitBoard, sans ouvrir aucun port sur la box.

## Installation

Sur l'ordinateur Klipper, en SSH :

```sh
curl -fsSL https://github.com/Greg-LFT/pitboard-link/releases/latest/download/install.sh | sh
```

Le script affiche ensuite un code à saisir dans l'application PitBoard pour lier le Link à ton compte.

Pour mettre à jour, relance la même commande. Pour désinstaller :

```sh
curl -fsSL https://github.com/Greg-LFT/pitboard-link/releases/latest/download/install.sh | sh -s -- --desinstaller
```

Options : `--cle-api CLE` (si Moonraker exige une clé API), `--crowsnest-fps N` (cadence de la webcam
dans `crowsnest.conf`, avec copie de sauvegarde).

### Ce que fait l'installation

- un seul exécutable, sans dépendance, dans `/opt/pitboard-link` ;
- un utilisateur système dédié et un service (systemd, ou init.d) à priorité basse, mémoire limitée ;
- aucun paquet installé, aucun fichier de Klipper ou de Moonraker modifié.

Architectures : arm64, armv7, mipsle, amd64. Chaque exécutable est vérifié par son empreinte SHA-256
(`SHA256SUMS`) avant installation.

## Fonctions

- Un Link par imprimante : il suit la machine sur laquelle il est installé, et seulement elle.
- Progression, temps restant, températures, ventilateurs, objets, historique, miniature du fichier.
- Commandes : pause, reprise, annulation, ignorer un objet.
- Caméra : MJPEG (mjpg-streamer, ustreamer, crowsnest) ; vidéo H.264 sans réencodage quand la webcam
  est servie par camera-streamer ou go2rtc (mode automatique).
- Dernier état gardé par l'application quand l'imprimante est éteinte.

## Sécurité

- Aucun port ouvert vers Internet : le Link ouvre lui-même une connexion chiffrée (TLS) vers le serveur.
- Chiffrement de bout en bout entre le téléphone et le Link : le serveur ne voit en clair que l'état
  résumé de l'impression ; commandes et images caméra sont chiffrées (AES-256-GCM) avec une clé propre à
  chaque téléphone.
- Sur le réseau local : HTTPS avec certificat épinglé par l'application, et jeton d'accès.
- La clé de chiffrement de chaque téléphone est remise au Link sur le WiFi de l'imprimante, jamais
  par le serveur (depuis 1.6.3).
- Un téléphone non appairé est en lecture seule.

## Compatibilité

Vérifié sur matériel réel : **Qidi Q2** (Klipper, webcam MJPEG), en local et à distance.

Prévu pour toute imprimante **Klipper + Moonraker** (Voron, RatRig, Sovol, Elegoo Neptune 4, Creality K1
avec accès root…), sans essai à ce jour. Les vidéos H.264 (camera-streamer, go2rtc) n'ont pas encore été
essayées sur matériel réel.

Non pris en charge : Bambu Lab (à suivre avec un PitBoard S3, ou directement par l'application sur le
WiFi), OctoPrint, Prusa, Marlin.

## Compiler

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o pitboard-link-linux-arm64 .
go test ./...
```

Go 1.22 ou plus récent, bibliothèque standard seulement.
