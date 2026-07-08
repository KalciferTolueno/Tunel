//go:build gui

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"tunel/internal/client"
	"tunel/internal/config"
	"tunel/internal/crypto"
)

func guiAvailable() bool { return true }

func run(mode runMode, _ []string) error {
	if mode == modeGUI {
		return runGUI()
	}
	return runCLI()
}

type uiEvent struct {
	Text   string
	Status status
}
type status struct {
	Set   bool
	State client.State
	Msg   string
}

// tunnelRow is one editable tunnel in the Túneles tab.
type tunnelRow struct {
	proto *widget.Select
	port  *widget.Entry
	local *widget.Entry
	del   *widget.Button
}

func runGUI() error {
	a := app.New()
	w := a.NewWindow("Tunel - Cliente")
	w.Resize(fyne.NewSize(560, 620))

	profPath := config.DefaultProfilePath()
	prof, _ := config.LoadProfile(profPath)

	// ── shared settings (above tabs) ──
	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("vps.ejemplo.com:9000")
	tokenEntry := widget.NewPasswordEntry()
	tokenEntry.SetPlaceHolder("secreto compartido")
	cacertEntry := widget.NewEntry()
	cacertEntry.SetPlaceHolder("ruta a ca.crt")
	insecureCheck := widget.NewCheck("Insecure (dev)", nil)
	tlsCheck := widget.NewCheck("TLS (cifrado)", nil)

	serverEntry.SetText(prof.Server)
	tokenEntry.SetText(prof.Token)
	cacertEntry.SetText(prof.CACert)
	insecureCheck.SetChecked(prof.Insecure)
	tlsCheck.SetChecked(false)

	browseBtn := widget.NewButtonWithIcon("Examinar...", theme.FileIcon(), func() {
		dialog.ShowFileOpen(func(rr fyne.URIReadCloser, err error) {
			if err != nil || rr == nil {
				return
			}
			cacertEntry.SetText(rr.URI().Path())
		}, w)
	})

	sharedForm := container.NewGridWithColumns(2,
		widget.NewLabel("Server:"), serverEntry,
		widget.NewLabel("Token:"), tokenEntry,
		widget.NewLabel("Cert CA:"), container.NewBorder(nil, nil, nil, browseBtn, cacertEntry),
		widget.NewLabel(""), insecureCheck,
		widget.NewLabel(""), tlsCheck,
	)

	// ── logs + status (shared across tabs) ──
	logView := widget.NewMultiLineEntry()
	logView.Wrapping = fyne.TextWrapWord
	logView.SetMinRowsVisible(12)
	logView.Disable()

	statusLabel := widget.NewLabel("●")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}
	statusLabel.Importance = widget.LowImportance
	statusText := widget.NewLabel("Desconectado")
	statusText.TextStyle = fyne.TextStyle{Bold: true}

	evCh := make(chan uiEvent, 256)
	var evMu sync.Mutex
	appendLog := func(line string) {
		evMu.Lock()
		select { case evCh <- uiEvent{Text: line}: default: }
		evMu.Unlock()
	}
	emitStatus := func(s client.State, msg string) {
		evMu.Lock()
		select { case evCh <- uiEvent{Status: status{Set: true, State: s, Msg: msg}}: default: }
		evMu.Unlock()
	}

	go func() {
		t := time.NewTicker(33 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			var pending []uiEvent
			evMu.Lock()
			for len(evCh) > 0 {
				pending = append(pending, <-evCh)
			}
			evMu.Unlock()
			if len(pending) == 0 {
				continue
			}
			for _, ev := range pending {
				if ev.Text != "" {
					cur := logView.Text
					if cur != "" {
						cur += "\n"
					}
					logView.SetText(cur + ev.Text)
				}
				if ev.Status.Set {
					applyStatus(statusLabel, statusText, ev.Status.State, ev.Status.Msg)
				}
			}
		}
	}()

	// ── connect / disconnect engine ──
	var (
		mu     sync.Mutex
		cancel context.CancelFunc
	)
	connectBtn := widget.NewButton("Conectar", nil)
	disconnectBtn := widget.NewButton("Desconectar", nil)
	disconnectBtn.Disable()

	doDisconnect := func() {
		mu.Lock()
		if cancel != nil {
			cancel()
		}
		cancel = nil
		mu.Unlock()
		emitStatus(client.StateStopped, "detenido")
		disconnectBtn.Disable()
		connectBtn.Enable()
	}

	// ── TAB 1: Sala Virtual ──
	roomEntry := widget.NewEntry()
	roomEntry.SetPlaceHolder("lobby")
	roomPassEntry := widget.NewPasswordEntry()
	roomPassEntry.SetPlaceHolder("(opcional)")

	vpnForm := container.NewGridWithColumns(2,
		widget.NewLabel("Room:"), roomEntry,
		widget.NewLabel("Password:"), roomPassEntry,
	)

	vpnInfo := widget.NewLabel("")
	vpnInfo.TextStyle = fyne.TextStyle{Italic: true}

	salaContent := container.NewVBox(
		widget.NewLabelWithStyle("Requiere ejecutar tunelc como administrador", fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
		vpnForm,
		vpnInfo,
	)

	// ── TAB 2: Túneles ──
	var rows []*tunnelRow
	tunBox := container.NewVBox()
	tunScroll := container.NewVScroll(tunBox)
	tunScroll.SetMinSize(fyne.NewSize(0, 140))

	rebuildTun := func() {
		tunBox.Objects = nil
		for _, r := range rows {
			tunBox.Add(container.NewHBox(r.proto, widget.NewLabel(":"), r.port,
				widget.NewLabel("→"), r.local, r.del))
		}
		tunBox.Refresh()
	}

	addRow := func(proto, port, local string) {
		r := &tunnelRow{
			proto: widget.NewSelect([]string{"tcp", "udp"}, nil),
			port:  widget.NewEntry(),
			local: widget.NewEntry(),
			del:   widget.NewButtonWithIcon("", theme.DeleteIcon(), nil),
		}
		r.proto.SetSelected(proto)
		if r.proto.Selected == "" { r.proto.SetSelected("tcp") }
		r.port.SetPlaceHolder("25565")
		r.port.SetText(port)
		r.local.SetPlaceHolder("localhost:25565")
		r.local.SetText(local)
		idx := len(rows)
		r.del.OnTapped = func() {
			rows = append(rows[:idx], rows[idx+1:]...)
			rebuildTun()
		}
		rows = append(rows, r)
	}

	if len(prof.Tunnels) > 0 {
		for _, t := range prof.Tunnels {
			addRow(t.Proto, fmt.Sprintf("%d", t.PublicPort), t.LocalTarget)
		}
	} else {
		addRow("tcp", "25565", "localhost:25565")
	}
	rebuildTun()

	addBtn := widget.NewButtonWithIcon("Añadir", theme.ContentAddIcon(), func() {
		addRow("tcp", "", "")
		rebuildTun()
	})

	quickBtn := widget.NewButtonWithIcon("Juego", theme.MediaPlayIcon(), func() {
		presets := []struct{ Name, Port, Proto, Local string }{
			{"Minecraft Java", "25565", "tcp", "localhost:25565"},
			{"Minecraft Bedrock", "19132", "udp", "localhost:19132"},
			{"Terraria", "7777", "tcp", "localhost:7777"},
			{"Valheim", "2456", "udp", "localhost:2456"},
			{"Factorio", "34197", "udp", "localhost:34197"},
			{"Project Zomboid", "16262", "udp", "localhost:16262"},
		}
		items := make([]string, len(presets))
		for i, p := range presets { items[i] = p.Name }
		radios := widget.NewRadioGroup(items, nil)
		dialog.ShowCustom("Añadir juego", "Cerrar", container.NewVBox(
			widget.NewLabel("Elige un juego:"),
			radios,
			widget.NewButton("Añadir", func() {
				for _, p := range presets {
					if radios.Selected == p.Name {
						addRow(p.Proto, p.Port, p.Local)
						rebuildTun()
						break
					}
				}
			}),
		), w)
	})

	toolbar := container.NewHBox(quickBtn, addBtn)
	tunContent := container.NewBorder(toolbar, nil, nil, nil, tunScroll)

	// ── Tabs ──
	tabs := container.NewAppTabs(
		container.NewTabItem("🏠 Sala Virtual", salaContent),
		container.NewTabItem("🔧 Túneles", tunContent),
	)
	// Always show status row + buttons below the tabs.
	statusRow := container.NewHBox(statusLabel, statusText)

	// ── doConnect ──
	doConnect := func() {
		isVPN := tabs.SelectedIndex() == 0 // Sala Virtual tab

		cfg := client.Config{
			Server:       serverEntry.Text,
			Token:        tokenEntry.Text,
			TLS:          tlsCheck.Checked,
			CACert:       cacertEntry.Text,
			Insecure:     insecureCheck.Checked,
			MaxAttempts:  0,
			Room:         roomEntry.Text,
			RoomPassword: roomPassEntry.Text,
			OnEvent: func(e client.Event) {
				emitStatus(e.State, e.Msg)
				appendLog(fmt.Sprintf("[%s] %s", e.Time.Format("15:04:05"), e.Msg))
			},
		}

		if !isVPN {
			// Collect tunnels from the Túneles tab rows.
			var specs []client.TunnelSpec
			for _, r := range rows {
				port, _ := strconv.Atoi(strings.TrimSpace(r.port.Text))
				if port == 0 {
					continue
				}
				specs = append(specs, client.TunnelSpec{
					Proto: r.proto.Selected, PublicPort: port, LocalTarget: strings.TrimSpace(r.local.Text),
				})
			}
			if len(specs) == 0 {
				dialog.ShowInformation("Sin túneles", "Añade al menos un túnel en la pestaña Túneles.", w)
				return
			}
			cfg.Tunnels = specs
		} else {
			// VPN: load identity from profile or generate.
			profVPN, _ := config.LoadProfile(profPath)
			cfg.IdentityPubkeyHex = profVPN.IdentityKey
			cfg.IdentityPrivkeyHex = profVPN.PrivateKey
			cfg.EdPubkeyHex = profVPN.EdPubKey
			cfg.EdPrivkeyHex = profVPN.EdPrivKey
			if profVPN.IdentityKey == "" {
				kp, _ := crypto.GenerateKeypair()
				if kp != nil {
					cfg.IdentityPubkeyHex = kp.PublicHex()
					cfg.IdentityPrivkeyHex = kp.PrivateHex()
					appendLog(fmt.Sprintf("Key generada: %s...", kp.PublicHex()[:12]))
				}
				epub, epriv, _ := crypto.GenerateED25519Keypair()
				if epriv != nil {
					cfg.EdPubkeyHex = crypto.EDKeyHex(epub)
					cfg.EdPrivkeyHex = crypto.EDKeyHex(epriv)
				}
			}
		}

		// Save profile.
		var pt []config.TunnelEntry
		for _, r := range rows {
			port, _ := strconv.Atoi(strings.TrimSpace(r.port.Text))
			if port > 0 {
				pt = append(pt, config.TunnelEntry{
					Proto: r.proto.Selected, PublicPort: port, LocalTarget: strings.TrimSpace(r.local.Text),
				})
			}
		}
		_ = config.SaveProfile(profPath, &config.Profile{
			Server:       cfg.Server,
			Token:        cfg.Token,
			CACert:       cfg.CACert,
			Insecure:     cfg.Insecure,
			LogLevel:     "info",
			Tunnels:      pt,
			IdentityKey:  cfg.IdentityPubkeyHex,
			PrivateKey:   cfg.IdentityPrivkeyHex,
			EdPubKey:     cfg.EdPubkeyHex,
			EdPrivKey:    cfg.EdPrivkeyHex,
		})

		ctx, cancelFn := context.WithCancel(context.Background())
		mu.Lock()
		cancel = cancelFn
		mu.Unlock()
		connectBtn.Disable()
		disconnectBtn.Enable()

		guiHandler := &guiLogHandler{appendLog: appendLog, level: slog.LevelInfo}
		c, err := client.New(cfg, slog.New(guiHandler))
		if err != nil {
			emitStatus(client.StateError, "config: "+err.Error())
			connectBtn.Enable()
			disconnectBtn.Disable()
			return
		}

		go func() {
			var runErr error
			if isVPN {
				runErr = c.RunVPN(ctx)
			} else {
				runErr = c.Run(ctx)
			}
			if runErr != nil && ctx.Err() == nil {
				appendLog(fmt.Sprintf("Error: %v", runErr))
				dialog.ShowError(runErr, w)
			}
			emitStatus(client.StateStopped, "sesión terminada")
			connectBtn.Enable()
			disconnectBtn.Disable()
		}()

		// P2P stats polling (VPN only).
		if isVPN {
			go func() {
				tck := time.NewTicker(3 * time.Second)
				defer tck.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-tck.C:
						known, active := c.P2PStats()
						vpnInfo.SetText(fmt.Sprintf("P2P: %d peers, %d direct", known, active))
						vpnInfo.Refresh()
					}
				}
			}()
		}
	}

	connectBtn.OnTapped = doConnect
	disconnectBtn.OnTapped = doDisconnect

	// ── layout ──
	buttons := container.NewGridWithColumns(2, connectBtn, disconnectBtn)
	logGroup := container.NewBorder(
		widget.NewLabelWithStyle("Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil, container.NewScroll(logView),
	)

	content := container.NewBorder(
		container.NewVBox(sharedForm, tabs, statusRow, buttons),
		nil, nil, nil,
		logGroup,
	)
	w.SetContent(content)

	w.SetCloseIntercept(func() {
		doDisconnect()
		time.Sleep(150 * time.Millisecond)
		w.Close()
	})

	w.ShowAndRun()
	return nil
}

func applyStatus(dot *widget.Label, txt *widget.Label, state client.State, msg string) {
	var imp widget.Importance
	var label string
	switch state {
	case client.StateIdle:        imp, label = widget.LowImportance, "Inactivo"
	case client.StateConnecting:  imp, label = widget.WarningImportance, "Conectando"
	case client.StateConnected:   imp, label = widget.SuccessImportance, "Conectado"
	case client.StateReconnecting:imp, label = widget.WarningImportance, "Reconectando"
	case client.StateError:       imp, label = widget.DangerImportance, "Error"
	case client.StateStopped:     imp, label = widget.LowImportance, "Detenido"
	default:                      imp, label = widget.LowImportance, state.String()
	}
	dot.Importance = imp
	dot.Text = "●"
	dot.Refresh()
	txt.SetText(label + " — " + msg)
}

type guiLogHandler struct {
	appendLog func(string)
	level    slog.Level
}

func (h *guiLogHandler) Enabled(_ context.Context, lvl slog.Level) bool { return lvl >= h.level }
func (h *guiLogHandler) Handle(_ context.Context, r slog.Record) error {
	msg := r.Message
	r.Attrs(func(a slog.Attr) bool { msg += " " + a.Key + "=" + a.Value.String(); return true })
	h.appendLog(fmt.Sprintf("[%s] %s", r.Time.Format("15:04:05"), msg))
	fmt.Fprintln(os.Stdout, msg)
	return nil
}
func (*guiLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return nil }
func (*guiLogHandler) WithGroup(_ string) slog.Handler        { return nil }

var _ = errors.New