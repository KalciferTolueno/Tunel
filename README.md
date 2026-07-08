# Tunel

Tunel es un túnel TCP reverso estilo ngrok/frp, escrito en Go. Te permite
exponer un servicio corriendo en tu máquina local (sin IP pública) a través de
un VPS con IP pública, **sin abrir puertos en tu router**.

> **tunelc** dispone de **interfaz gráfica (Fyne)** además del modo CLI. Si
> haces doble clic en `tunelc.exe` se abre una ventana con los campos
> rellenables, indicador de estado `●` y panel de logs en vivo. La
> configuración se guarda en `tunelc.json` junto al .exe. Ver
> [Compilar con GUI (Windows)](#compilar-con-gui-windows).

```
[Usuario] ──TCP──► [VPS:8080 público]
                        │ (yamux stream)
                        ▼
                   [tunels TLS :9000] ◄──TLS + yamux──► [tunelc local]
                                                          │ dial localhost:3000
                                                          ▼
                                                   [Tu app local]
```

- **Transporte**: TLS con CA auto-firmada y *pinning* (no requiere dominio).
- **Multiplexación**: `github.com/hashicorp/yamux` (una sola conexión
  persistente porta muchas conexiones públicas).
- **Auth**: un secreto compartido entre `tunels` y `tunelc`.
- **Logs**: `log/slog` en JSON.
- **Sin reframing**: bytes crudos vía `io.Copy` bidireccional.

## Binarios

| Comando       | Corre en      | Rol                                    |
|---------------|---------------|----------------------------------------|
| `tunels`      | VPS público   | Acepta túneles y expone puertos públicos|
| `tunelc`      | Tu PC local   | Se conecta al VPS y redirige a tu app  |
| `tunel-cert`  | Donde quieras | Genera CA + cert del server (PEM)      |

## Desplegar en VPS (Docker + Easypanel)

El servidor `tunels` se puede desplegar en cualquier VPS con Docker. El
proyecto incluye `Dockerfile` + `docker-compose.yml` listos para Easypanel.

### Requisitos previos

1. **VPS con Docker** (Easypanel, o bare Docker + Traefik para HTTPS).
2. **Certificados TLS** generados con `tunel-cert.exe` en tu PC:

   ```powershell
   .\tunel-cert.exe -out .\certs-tunel -hosts "IP_DE_TU_VPS,tu-dominio.com"
   ```

   Esto crea:
   - `certs-tunel\ca.crt` → quédate con él (va al lado de `tunelc.exe`).
   - `certs-tunel\server.crt` → súbelo a `./certs/` en el VPS.
   - `certs-tunel\server.key` → súbelo a `./certs/` en el VPS.

### Docker standalone

```bash
# 1) Clonar el repo en el VPS
git clone <repo> tunel && cd tunel

# 2) Crear carpeta certs/ y copiar server.crt + server.key
mkdir certs
# (copia los archivos con scp o sftp)

# 3) Crear archivo .env con las variables
echo "TUNEL_TOKEN=S3CR3T0-MUY-LARG0" > .env
echo "TUNEL_ALLOWED_PORTS=25565,19132,2456,7777,8080" >> .env

# 4) Construir y arrancar
docker compose up -d --build

# 5) Verificar
docker compose logs -f
# Debe mostrar: "tunels listening" + "vpn hub habilitado" + "dashboard listening"
```

Accede al dashboard en `http://IP_DEL_VPS:9001`.

### Easypanel (solo Dockerfile)

1. En Easypanel, crea un **nuevo servicio** → elige **Dockerfile**.
2. Conecta el repo `KalciferTolueno/Tunel` (o sube los archivos manualmente).
3. En la pestaña **Environment**, configura:
   - `TUNEL_TOKEN` = tu secreto
   - `TUNEL_ALLOWED_PORTS` = `25565,19132,2456,7777`
4. En **Volumes**, crea un volumen que monte tu carpeta `certs/` (con `server.crt` + `server.key`) en `/certs` (read-only).
5. En **Network**, activa **Host mode** (para que tunels pueda abrir puertos de juego dinámicamente).
6. En **Ports**, expón:
   - `9000/tcp`
   - `3478/udp`
   - `9001/tcp`
7. **Deploy**.

### Dashboard con HTTPS via Traefik

El `docker-compose.yml` incluye labels de Traefik listas. Para que funcionen:

1. Asegúrate de que el servicio Traefik de Easypanel tiene el `extra_hosts`:
   ```
   host.docker.internal:host-gateway
   ```
   (En Easypanel: ve al servicio `traefik` → Advanced → añade el extra_host).

2. El dashboard estará en `https://tunel.tudominio.com` (cambia el dominio
   en las labels del compose si prefieres otro subdominio).

3. **No hace falta abrir el puerto 9001 en el firewall** — solo Traefik (443) y
   los puertos de juego.

### Puertos que abrir en el firewall del VPS

| Puerto | Protocolo | Para qué |
|---|---|---|
| `443` | TCP | Traefik HTTPS (dashboard) — ya debería estar abierto |
| `9000` | TCP | Control TLS (tunelc se conecta aquí) |
| `3478` | UDP | STUN (ayuda a tunelc a descubrir su IP pública) |
| `25565` | TCP | Ejemplo: Minecraft Java |
| `19132` | UDP | Ejemplo: Minecraft Bedrock |
| `2456-2458` | UDP | Ejemplo: Valheim |
| ... | ... | Los que hayas puesto en `TUNEL_ALLOWED_PORTS` |

### Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `TUNEL_TOKEN` | (obligatorio) | Secreto compartido con tunelc |
| `TUNEL_ALLOWED_PORTS` | `25565,19132,2456,7777,8080` | CSV de puertos que los clientes pueden pedir |
| `TUNEL_VPN_SUBNET` | `10.99.0.0/24` | Subred base para rooms VPN |
| `DOMAIN` | - | Tu dominio (para la label Traefik del dashboard) |

## Build

La forma más rápida es el script que construye los 4 binarios:

```powershell
.\scripts\build.ps1           # CLI + GUI (requiere MinGW-w64 en PATH, ver abajo)
.\scripts\build.ps1 -NoCGO    # sólo CLI (sin MinGW-w64, sin CGO)
```

A mano (sin GUI):

```powershell
go build -o tunels.exe      ./cmd/tunels
go build -o tunelc.exe      ./cmd/tunelc
go build -o tunel-cert.exe  ./cmd/tunel-cert
go build -o tunel-echo.exe  ./cmd/tunel-echo
go build ./...
```

### Compilar con GUI (Windows)

`tunelc` incluye una GUI escrita con [Fyne](https://fyne.io) que se compila
con el build tag `gui`. Fyne requiere **CGO + un compilador C** en Windows
(MinGW-w64). Pasos:

1. **Instalar MinGW-w64 portable** (sin permisos de admin):
   - Baja la versión **POSIX + SEH** de <https://winlibs.com/> (archivo
     `.7z`).
   - Descomprime en `C:\Tools\mingw64`.
   - Añade `C:\Tools\mingw64\bin` a tu PATH de usuario.
   - Verifica: `gcc --version` debe responder algo como
     `gcc.exe (MinGW-W64 ...) 16.x.x`.

2. **Compilar**:

   ```powershell
   $env:CGO_ENABLED = "1"
   go build -tags gui -ldflags "-H windowsgui" -o tunelc.exe ./cmd/tunelc
   ```

   La flag `-H windowsgui` suprime la consola negra que normalmente aparece
   al hacer doble clic en un .exe de Go; con ella, abrir `tunelc.exe` muestra
   solo la ventana de Fyne.

3. **Probar**: doble clic en `tunelc.exe` → se abre la ventana
   "Tunel - Cliente". Rellenar Server / Token / Remote / Local / CA, clic en
   **Conectar** y verás el indicador `●` ponerse verde. La configuración se
   guarda automáticamente en `tunelc.json` al lado del .exe, así que la
   próxima vez los campos vienen rellenados.

### Modos dual CLI/GUI del binario

| Arranque                                | Comportamiento                          |
|------------------------------------------|------------------------------------------|
| `tunelc.exe` (doble clic, sin args)     | Abre la GUI (si fue compilado con `gui`) |
| `tunelc.exe --gui`                       | Fuerza abrir la GUI                      |
| `tunelc.exe --server X --token Y ...`    | Modo CLI por flags (igual que antes)     |
| `tunelc.exe` compilado **sin** tag `gui` | Modo CLI: se queja de flags faltantes    |

## Quickstart (todo en localhost para probar)

1. Generar certificados:

   ```powershell
   .\tunel-cert.exe -out .\certs -hosts 127.0.0.1,localhost
   ```

   Esto crea `certs\ca.crt`, `certs\ca.key`, `certs\server.crt`,
   `certs\server.key`. Copia `ca.crt` a la máquina cliente; copia
   `server.crt` + `server.key` al VPS.

2. Lanzar el server (simula tu VPS):

   ```powershell
   .\tunels.exe `
     --bind 127.0.0.1:9000 `
     --token abc123 `
     --cert certs\server.crt `
     --key  certs\server.key `
     --allowed-ports 8080,8081 `
     --log-level debug
   ```

3. Lanzar tu servicio local de prueba (pe. un HTTP server):

   ```powershell
   python -m http.server 3000 --bind 127.0.0.1
   ```

4. Lanzar el cliente:

   ```powershell
   .\tunelc.exe `
     --server 127.0.0.1:9000 `
     --token abc123 `
     --remote 8080 `
     --local 127.0.0.1:3000 `
     --cacert certs\ca.crt `
     --log-level debug
   ```

5. Probar:

   ```powershell
   curl http://127.0.0.1:8080/
   ```

## Uso de la GUI (tunelc)

1. Doble clic en `tunelc.exe` (o `tunelc.exe --gui`).
2. Rellena los campos compartidos:
   - **Server**: `host:port` de tu `tunels` (ej. `vps.ejemplo.com:9000`).
   - **Token**: secreto compartido con el server.
   - **Cert CA**: ruta a `ca.crt` (botón **Examinar...** para elegirlo).
   - **Insecure**: opcional, saltar verificación TLS (solo dev).
3. Abajo verás la sección **Túneles**: una tabla con columnas Nombre, Proto,
   Puerto público y Local host:port. Por defecto se crea un túnel de ejemplo
   para Minecraft Java (TCP 25565).
4. **Añadir túnel** crea una fila nueva. **Quitar** elimina la fila.
   Cada túnel puede ser TCP o UDP. Ejemplos típicos para juegos:
   - Minecraft Java: `tcp`, `25565`, `localhost:25565`.
   - Minecraft Bedrock: `udp`, `19132`, `localhost:19132`.
   - Valheim dedicado: `udp`, `2456`, `localhost:2456`.
   - Terraria: `tcp`, `7777`, `localhost:7777`.
5. **Conectar**: persiste la config en `tunelc.json`, lanza sesión yamux, abre
   un control stream **por cada túnel** y empieza a mostrar estado y logs en
   vivo. El indicador (`●`) pasa por:
   - 🟠 naranja — conectando / reconectando.
   - 🟢 verde — túneles activos.
   - 🔴 rojo — error (`bad token`, `local target refused`, etc.).
   - ⚪ gris — detenido.
6. **Desconectar**: cierra todos los túneles sin cerrar la app.
7. Al cerrar la ventana se cancela cualquier sesión activa y el proceso se
   termina limpio.
8. En modo GUI `MaxAttempts=0` (reconecta para siempre); el cliente solo
   aborta si el server rechaza explícitamente la auth.

## Cómo jugar con amigos por internet (multi-túnel)

Tunel soporta **TCP y UDP** y **múltiples túneles simultáneos** sobre una sola
conexión TLS, así que puedes exponer tu mundo local de Minecraft (Java o
Bedrock), Terraria, Valheim, Factorio o casi cualquier juego co-op a tus amigos
sin abrir puertos en tu router.

Existen **dos modos de juego**:

1. **Modo túnel (recomendado para ~99% de los juegos)**: tus amigos se conectan
   a `IP_DEL_VPS:PUERTO` en vez de esperar al auto-descubrimiento LAN.
2. **Modo VPN (Network Neighborhood)**: cada extremo ejecuta `--vpn`, abre una
   NIC virtual y obtiene una IP en `10.99.0.0/24`. Los juegos con auto-
   descubrimiento LAN (broadcast UDP) funcionan como si estuvieran en la misma
   red física. **Requiere permisos de admin en todos los clientes** y un
   compilado con `-tags vpn`.

### Setup del VPS

Sube al VPS: `tunels.exe`, `server.crt`, `server.key`. Abre en el firewall del
VPS:
- el puerto de control (default `9000`)
- todos los puertos públicos que quieras exponer (ej. `25565`, `19132`, ...)

Arranca el server (modo túnel):

```bash
./tunels --bind :9000 \
  --token SUPER_SECRETO \
  --cert server.crt --key server.key \
  --allowed-ports 25565,19132,2456,7777
```

O en modo VPN + túnel coexistiendo (los peers VPN y los túneles TCP/UDP usan
el mismo `tunels`):

```bash
./tunels --bind :9000 --token SUPER_SECRETO \
  --cert server.crt --key server.key \
  --vpn --vpn-subnet 10.99.0.0/24
```

### Setup del cliente (donde corre el juego)

En tu PC, genera los certs (si hiciste el server en otro equipo): copia `ca.crt`
al lado de `tunelc.exe`. Arranca twoclic en `tunelc.exe`, rellena Server / Token
y añade los túneles que necesites. **Conectar** y a jugar.

Por CLI:

```powershell
.\tunelc.exe `
  --server vps.ejemplo.com:9000 `
  --token SUPER_SECRETO `
  --cacert ca.crt `
  --tunnel "tcp:25565:localhost:25565" `
  --tunnel "udp:19132:localhost:19132"
```

### Túneles típicos por juego (modo túnel)

| Juego                    | Proto | Puerto (público y local) | Notas |
|---------------------------|-------|---------------------------|-------|
| Minecraft Java            | tcp   | 25565                     | `server.properties` |
| Minecraft Bedrock         | udp   | 19132                     | `server.properties` |
| Terraria                 | tcp   | 7777                      | |
| Valheim                  | udp   | 2456, 2457, 2458          | Abre 3 túneles (juego + steam + ping) |
| Don't Starve Together    | udp   | 10999                     | |
| Factorio                 | tcp+udp | 34197 (UDP), 27015 (TCP) | Necesitas 2 túneles |
| Project Zomboid           | udp   | 16262 (juego), 16261 (rcon) | 2 túneles |
| Starbound                | tcp   | 21025                     | |

Tus amigos se conectan a `IP_DEL_VPS:PUERTO_PUBLICO` como si tuvieras el puerto
abierto en tu casa. El tráfico fluye `amigo → VPS → túnel TLS → tu tunelc →
tu juego local`.

## Modo VPN (auto-descubrimiento LAN con broadcast)

Para juegos que confían en UDP broadcast en la LAN local (ves "servidor
local" en la lista automáticamente), necesitamos un segmento IP común para
todos los jugadores. `Tunel` lo emula con `--vpn`:

```
[Host con minecraft server]    [Amigo 1]    [Amigo 2]
        │                            │            │
     tunelc --vpn                 tunelc --vpn   tunelc --vpn
     TUN 10.99.0.1               TUN 10.99.0.2  TUN 10.99.0.3
        └─────────┬──────────────────┴────────────┘
                  │
              tunels --vpn (VPS público)
              Hub: routea unicast + replica broadcasts
              Subnet: 10.99.0.0/24
```

### Cómo activar el modo VPN

1. Compila con el flag `vpn`:

   ```powershell
   $env:CGO_ENABLED = "1"
   go build -tags "gui,vpn" -ldflags "-H windowsgui" -o tunelc.exe ./cmd/tunelc
   go build -tags vpn -o tunels.exe ./cmd/tunels
   ```

   `scripts\build.ps1` (no `-NoCGO`/-`NoVPN`) incluye `vpn` automáticamente.

2. Arranca el server en el VPS con `--vpn`:

   ```bash
   ./tunels --bind :9000 --token SUPER_SECRETO --vpn --vpn-subnet 10.99.0.0/24
   ```

3. En cada PC de juego (HOST y AMIGOS), abre PowerShell **como
   administrador** (wintun lo requiere para crear el adaptador virtual):

   ```powershell
   .\tunelc.exe --server vps.ejemplo.com:9000 --token SUPER_SECRETO --cacert ca.crt --vpn
   ```

4. Cada peer recibe su IP automática: el primero `.1`, el siguiente `.2`, etc.
5. Los juegos verán la red como una LAN real: las pestañas "Multijugador →
   Red local" mostrarán el mundo del host automáticamente.

### Limitaciones y advertencias de la VPN (MVP)

- **Admin rights**: wintun.dll necesita crear un adaptador de red; en Windows
  la primera vez, y en Linux/macOS siempre, el proceso tiene que ser root /
  Administrador.
- **Hub-and-spoke**: todos los paquetes fluyen `peer A → VPS → peer B`. No
  hay NAT traversal P2P como Tailscale; el VPS ve y reenvía TODO el tráfico.
  Esto consume ancho de banda del VPS y añade latencia extra.
- **Sólo IPv4**: el hub mira bytes 12-20 del paquete para el src/dst. IPv6
  no funciona todavía.
- **Broadcast limitado a /24**: las destinations `255.255.255.255` y
  `x.x.x.255` se consideran broadcast. Otros broadcasts no funcionan.
- **Mi código NO enruta fuera del VPN subnet**: si un juego intenta alcanzar
  internet a través del túnel (por ej. saliendo por el gateway `10.99.0.1`),
  el paquete se descarta. La VPN aquí es para inter-peers, no para
  "internet-wide tunneling".
- **MTU = 1400**: limita el overhead por fragmetación bajo TLS+yamux. Si
  notas conexiones trabadas en juegos específicos, prueba bajar a 1280.
- **Subnet fija**: `10.99.0.0/24` por defecto. Si colisiona con otra red
  existente en algún PC de tus amigos, ajusta `--vpn-subnet` tanto en
  `tunels` como en `tunelc` (en una próxima release, el cliente heredará la
  subnet del server en AuthOK; de momento es fija).

### Script de prueba VPN (requiere admin)

`scripts/test-vpn.ps1` levanta `tunels --vpn` en localhost y dos `tunelc-cli
--vpn` simultáneos para verificar que se asignan IPs y rutean paquetes.
Pasos:

1. Click derecho en PowerShell → "Ejecutar como administrador".
2. `cd C:\ruta\al\Tunel`
3. `.\scripts\test-vpn.ps1`

Verás:
- `vpn hub habilitado` en el server.
- `vpn peer granted` por cada peer (IP `10.99.0.1`, `10.99.0.2`).
- `Test-Connection -ComputerName 10.99.0.1` con reply de 1ms.

Si ves `Error creating interface: Access is denied`, es porque **olvidaste
elevar** el PowerShell.

## Uso real con VPS

1. Compila `tunels.exe` y `tunel-cert.exe` (o genera los certs en local y los
   copias).
2. Sube `tunels.exe`, `server.crt`, `server.key` al VPS. Nota: si el host del
   VPS está en `--hosts` al generar certs, el SAN coincidirá. Por ejemplo:

   ```powershell
   .\tunel-cert.exe -out .\certs -hosts mipublic.example.com,1.2.3.4
   ```

   Como usamos CA pinning, el nombre no se valida automáticamente — el cliente
   confía en la CA, no en el hostname, así que puedes omitir esto. Pero es
   buena práctica listar los hosts que usarás.

3. En el VPS:

   ```bash
   ./tunels \
     --bind :9000 \
     --token SUPER_SECRETO \
     --cert server.crt \
     --key  server.key \
     --allowed-ports 80,443,25565
   ```

   Y abre el puerto `9000` (control) y los puertos públicos que vayas a
   exponer en el firewall del VPS.

4. En tu PC local:

   ```powershell
   .\tunelc.exe `
     --server mipublic.example.com:9000 `
     --token SUPER_SECRETO `
     --remote 80 `
     --local localhost:8080 `
     --cacert certs\ca.crt
   ```

5. Cualquiera en Internet ya puede entrar a
   `http://mipublic.example.com:80/` y llegará a tu app local.

## Flags

### `tunels`

| Flag              | Default    | Descripción                                |
|-------------------|------------|---------------------------------------------|
| `--bind`          | `:9000`    | Host:port del listener de control TLS      |
| `--token`         | (required) | Secreto compartido                          |
| `--cert`          | `server.crt` | Path al cert del server (PEM)            |
| `--key`           | `server.key` | Path a la private key del server (PEM)   |
| `--allowed-ports` | (vacío = any) | CSV de puertos públicos permitidos      |
| `--vpn`           | `false` | Habilita el hub VPN (todas las sesiones `tunelc --vpn` se enrutan por aquí) |
| `--vpn-subnet`    | `10.99.0.0/24` | Subnet que el hub asigna IPs desde. Sólo /24 soportado. |
| `--log-level`     | `info`     | `debug`/`info`/`warn`/`error`               |

### `tunelc`

| Flag         | Default | Descripción                                  |
|--------------|---------|-----------------------------------------------|
| `--server`   | (req)   | `host:port` del `tunels`                      |
| `--token`    | (req)   | Secreto compartido                            |
| `--tunnel`   | (req*)  | Repetible: `[proto:]port:local`. Ej: `tcp:8080:localhost:8080`, `udp:19132:127.0.0.1:19132` |
| `--remote`   | 0       | (legacy) puerto público TCP, implica un solo túnel TCP |
| `--local`    | ""      | (legacy) target local, con `--remote` |
| `--cacert`   | (req*)  | CA PEM para pinning. \*Requerido salvo `--insecure` |
| `--insecure` | `false` | Desactiva verificación. Solo dev.             |
| `--max-attempts` | `5` | Intentos máximos al reconectar (0 = infinito) |
| `--log-level`| `info`  | `debug`/`info`/`warn`/`error`                 |
| `--gui`      | `false` | Abre la GUI (sólo binarios compilados con `-tags gui`) |
| `--vpn`      | `false` | Modo VPN: abre NIC virtual y enruta IP packets vía el hub del server (requiere build `-tags vpn` y admin) |

### `tunel-cert`

| Flag      | Default                          | Descripción                          |
|-----------|----------------------------------|--------------------------------------|
| `--out`   | `.`                              | Directorio de salida                 |
| `--hosts` | `127.0.0.1,localhost`            | CSV de SANs (DNS/IP) del server cert |
| `--bits`  | `2048`                           | Tamaño de clave RSA                  |

## Arquitectura

- **Control stream**: primer stream yamux abierto por el cliente. Envía un
  `Auth{token, public_port, local_target}` y espera `AuthOK` o `AuthErr`.
- **Data streams**: cada stream yamux abierto por el servidor corresponde a
  una conexión pública entrante. El cliente hace dial al `--local` y hace
  `io.Copy` bidireccional de bytes crudos (sin reframing). El cierre de
  cualquiera de las dos mitades propaga EOF al otro lado vía `CloseWrite`.
- **Keepalive**: el cliente envía `Ping` cada 30s al control stream. yamux
  también envía su propio keepalive a nivel sesión.
- **Reconexión**: si el túnel cae, `tunelc` reintenta con backoff exponencial
  (1s → 2s → 4s → 8s → 30s cap) hasta 5 intentos; luego aborta.
- **Multi-stream sobre 1 socket**: gracias a yamux, una sola conexión TLS del
  cliente al server es suficiente para multiplexar miles de conexiones
  públicas simultáneas.

## Estructura del proyecto

```
tunel/
├── go.mod
├── cmd/
│   ├── tunels/main.go        # entrypoint del server (VPS)
│   ├── tunelc/main.go       # entrypoint del cliente (local)
│   └── tunel-cert/main.go   # generador de certificados
├── internal/
│   ├── protocol/protocol.go # wire format JSON line-delimited
│   ├── server/               # server.go / session.go / tunnel.go
│   ├── client/               # client.go / tunnel.go
│   └── config/config.go      # flags + slog setup
└── README.md
```

## Limitaciones actuales (MVP)

- Un solo túnel por cliente (un par `--remote`/`--local`).
- Sin dashboard web ni métricas.
- Sin HTTP-host routing ni TLS termination en el puerto público (es TCP puro).
- Reconexión no reanuda sesiones idénticas; genera un nuevo session ID.

## Seguridad

- TLS 1.2+ entre `tunelc` y `tunels`, con la CA compartida fuera de banda.
- Token compartido; trátalo como secreto (no lo commitees).
- `--allowed-ports` limita qué puertos públicos puede pedir un cliente
  autenticado. Si no lo configuras, un cliente válido podría abrir cualquier
  puerto libre en el VPS (incluyendo shockers como 22 si está libre).
- `--insecure` del cliente solo es para dev. En producción usa CA pinning.

## Licencia

Personal / uso libre.