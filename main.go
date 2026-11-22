package main

// Pitboard Link — service PitBoard installé sur l'hôte Klipper.
//
//   pitboard-link run  [-dir DOSSIER]   service (lancé par systemd ou init.d)
//   pitboard-link code [-dir DOSSIER]   affiche l'état et le code d'appairage
//   pitboard-link id   [-dir DOSSIER]   affiche l'identifiant du Link
//   pitboard-link version

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"time"
)

var linkVersion = "1.6.1"

const defaultDir = "/opt/pitboard-link/data"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "dossier des données")
	fs.Parse(os.Args[2:])

	switch cmd {
	case "version":
		fmt.Println(linkVersion)
	case "id":
		st, err := openStore(*dir)
		if err != nil {
			fatal(err)
		}
		_, id, err := st.Identity()
		if err != nil {
			fatal(err)
		}
		fmt.Println(id)
	case "appairage":
		// 1.6.1 : ouvre 30 min la liaison au compte depuis le WiFi local (l'app le trouve et le lie d'un geste).
		st := &Store{dir: *dir}
		if err := st.OuvrirFenetre(); err != nil {
			fmt.Fprintln(os.Stderr, "Impossible d'ouvrir la fenêtre d'appairage (lance la commande avec sudo) :", err)
			os.Exit(1)
		}
		fmt.Println("Appairage depuis le WiFi local ouvert pour 30 minutes : dans l'app PitBoard, Ajouter une imprimante > Pitboard Link.")
	case "code":
		// Lecture seule de etat.json (lisible par tous) : pas besoin des droits du service.
		showCode(&Store{dir: *dir})
	case "run":
		run(*dir)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage : pitboard-link run|code|appairage|id|version [-dir DOSSIER]")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "erreur :", err)
	os.Exit(1)
}

func showCode(st *Store) {
	e, err := st.ReadEtat()
	if err != nil {
		fmt.Println("Pitboard Link n'a pas encore démarré (aucun état enregistré).")
		os.Exit(1)
	}
	fmt.Printf("Pitboard Link %s, identifiant %s\n", e.Version, e.ID)
	fmt.Printf("  Moonraker : %s\n", ouiNon(e.Moonraker, "joint", "injoignable"))
	fmt.Printf("  Relais    : %s\n", ouiNon(e.Relais, "connecté", "non connecté"))
	switch {
	case e.Lie:
		fmt.Println("  Compte    : lié à un compte PitBoard")
	case e.Code != "" && time.Now().Unix() < e.CodeExpire:
		c := e.Code
		if len(c) == 8 {
			c = c[:4] + "-" + c[4:]
		}
		fmt.Printf("\n  Code d'appairage : %s\n", c)
		fmt.Printf("  À saisir dans l'app (Ajouter une imprimante > Pitboard Link), dans les %d min.\n",
			max(1, int(time.Until(time.Unix(e.CodeExpire, 0)).Minutes())))
	default:
		fmt.Println("  Compte    : pas encore lié ; le code d'appairage arrive dès que le relais est joint.")
	}
	if !e.Lie {
		if fin := st.FenetreAppairage(); !fin.IsZero() {
			fmt.Printf("  Sur le même WiFi, l'app le trouve et le lie d'un geste jusqu'à %s.\n", fin.Format("15:04"))
		} else {
			fmt.Println("  Liaison depuis le WiFi fermée : « sudo pitboard-link appairage » l'ouvre pour 30 minutes.")
		}
	}
}

func ouiNon(b bool, oui, non string) string {
	if b {
		return oui
	}
	return non
}

func run(dir string) {
	log.SetFlags(0)
	log.SetPrefix("")
	// Garde-fous mémoire : le service reste petit, même si systemd ne le limite pas.
	debug.SetMemoryLimit(40 << 20)
	debug.SetGCPercent(100)

	st, err := openStore(dir)
	if err != nil {
		fatal(err)
	}
	priv, id, err := st.Identity()
	if err != nil {
		fatal(err)
	}
	cert, fp, err := st.TLSCert(id)
	if err != nil {
		fatal(err)
	}
	log.Printf("Pitboard Link %s démarré, identifiant %s", linkVersion, id)

	app := &App{store: st, id: id, fp: fp, started: time.Now(), changed: make(chan struct{}, 1)}
	app.e2e = newE2E(st, id)
	app.syncImprimantes() // 1.2.0 : une lecture par imprimante suivie
	tun := newTunnel(app, priv)
	app.tun = tun

	go app.serveLocal(cert)
	go tun.Run()
	go updater(app)
	select {}
}
