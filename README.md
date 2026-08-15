# MemReader

Herramienta de **análisis de memoria de procesos** para Windows 11, pensada para
pentesting, análisis de malware en laboratorio, forense y CTF. El análisis es de
solo lectura; además incluye un **editor de valores acotado** (tipo *trainer*) para
procesos que tú abras. Es una aplicación de escritorio (WinForms, .NET 8) que:

- Lista todos los procesos en ejecución.
- Abre el proceso que selecciones **en modo solo lectura**, mostrando su
  **arquitectura** (x64 / x86-WOW64) y su ruta.
- Enumera sus regiones de memoria (dirección, tamaño, protección, tipo).
- Lista los **módulos cargados** (DLL/EXE) con su dirección base — doble clic para
  saltar a su memoria.
- **Entropía por región** (bajo demanda): resalta zonas de alta entropía (>7.2),
  posible código empaquetado o cifrado.
- **Lista de hilos** con su **dirección de inicio**; un inicio fuera de todo módulo
  se marca en rojo (posible código inyectado).
- Muestra la memoria en un **visor hexadecimal** (hex + ASCII).
- **Panel de interpretación**: ve los bytes de una dirección como int8/16/32/64,
  float, double, puntero y cadena.
- **Desensamblado x86/x64** (Iced): traduce los bytes de una dirección a
  instrucciones de ensamblador, con selección automática de 32/64 bits.
- **Búsqueda tipada**: por texto (ASCII y UTF-16), o por valor **Int32 / Int64 /
  Float / Double / bytes hex**. Útil para encontrar dónde vive un valor en *tu* app.
- **Escaneo iterativo (next-scan)**: primer escaneo por valor y refinado sucesivo
  (cambió / no cambió / aumentó / disminuyó / exacto) hasta dejar pocas direcciones;
  doble clic manda la dirección al visor y a la pestaña Punteros como objetivo.
- **Punteros y offsets** (reversing): dada una dirección objetivo, encuentra qué la
  apunta (1 nivel) y **rutas de puntero estáticas** `modulo+offset -> +off -> ...`
  multinivel, ancladas a un módulo. Doble clic **resuelve la ruta en vivo** y salta
  a la dirección final — para reencontrar un valor aunque la app se reinicie. Todo
  cálculo, sin modificar memoria.
- **Auto-refresco (1 s)** del visor para vigilar cómo cambia un valor en vivo.
- **Copiar / exportar** el volcado (texto) y los resultados de búsqueda (CSV).
- **Análisis de seguridad / postura** del proceso: detecta indicadores como
  regiones **RWX**, **memoria ejecutable no respaldada por imagen** (posible
  shellcode/inyección) y **módulos sin ASLR/DEP/CFG** (parseando el PE en memoria).
  Es detección/reporte, no explotación.
- **Extracción de strings** (tipo `strings`): saca todas las cadenas ASCII/UTF-16
  imprimibles de la memoria, con su dirección; útil para triage/forense.
- **Vuelca** una región a `.bin`, o **todas** las regiones legibles a una carpeta
  (con índice) para análisis forense en tu laboratorio.
- **Export a minidump `.dmp`** (memoria completa) compatible con WinDbg — la misma
  capacidad que "Crear archivo de volcado" del Administrador de tareas.
- **Informe de triage (HTML + JSON)**: genera de un tirón un informe con los
  metadatos del proceso, resumen de regiones, regiones de alta entropía,
  indicadores de seguridad, hilos sospechosos, módulos e IOCs. Pensado como
  entregable de pentest/DFIR.
- **Extractor de IOCs**: saca IPs, URLs, dominios, correos, rutas de Windows/UNC,
  claves de registro y GUIDs de la memoria, deduplicados y con su dirección.
- **Análisis PE en memoria**: secciones (con entropía por sección), imports,
  exports, TLS callbacks y anomalías de cabecera; incluye un escáner de imágenes
  `MZ` mapeadas que detecta módulos mapeados manualmente que el cargador no lista.
- **Integridad de módulos (anti-hollowing)**: compara el código en memoria con el
  archivo en disco (aplicando las relocations a una copia propia, para no confundir
  ASLR con manipulación) y marca posibles parches o *process hollowing*.
- **Detección de hooks (inline + IAT)**: marca exports de `ntdll`/`kernel32`/… cuyo
  prólogo empieza con un salto, **y** entradas de la tabla de importación (IAT) que
  apuntan fuera de todo módulo — ambos indicio de hook de EDR/AV o inyección. Es solo
  detección: no quita hooks ni "limpia" DLLs.
- **Hashing de módulos**: SHA-256 del archivo en disco de cada módulo, con URL de
  VirusTotal copiable (sin conexiones de red automáticas).
- **Enumeración de handles**: ficheros, claves, *mutex* y eventos que abre el
  proceso; los nombres de mutex/evento con nombre son IOCs muy útiles.
- **Diff de snapshots**: captura una zona de memoria en dos momentos y resalta los
  bytes que cambiaron (útil para observar un valor en vivo o cómo se desempaqueta
  código).
- **Triage de toda la máquina**: recorre los procesos accesibles y los ordena por
  sospecha (regiones RWX, ejecutable no respaldado, hilos con inicio anómalo).
- **Búsqueda AOB con comodines**: patrones de bytes tipo `48 8B ?? ?? E8`.
- **Editor de valores (tipo *trainer*)**: escribe un valor tipado o bytes en una
  dirección y **"congela"** valores (los reescribe cada 250 ms), sobre procesos que
  tú abras. Sin inyección de código; solo para tus procesos/juegos o laboratorio.
- **Contexto del proceso**: línea de comandos, PID padre (cadena padre-hijo),
  sesión y hora de inicio — IOCs de primer nivel para triage.
- **Nivel de protección y mitigaciones**: PPL/Protected y su firmante, más CFG,
  ACG y "solo firmado por Microsoft"; explica por qué un proceso no se puede abrir.
- **Bundle del caso (.zip)**: empaqueta el informe (HTML + JSON con hashes e IOCs),
  un minidump y el índice de regiones en un único `.zip` listo para archivar.
- **Modo CLI headless** para automatizar todo lo anterior por línea de comandos.

Todo se apoya en APIs **documentadas y soportadas** de Windows
(`OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`, `WriteProcessMemory`,
`NtQuerySystemInformation`…). El análisis es de **solo lectura** por defecto.

Sobre ese mínimo hay dos ampliaciones, ambas explícitas y acotadas:
- Un handle aparte con `PROCESS_DUP_HANDLE`, solo para la función de enumerar handles
  (duplicar y consultar tipo/nombre).
- Un handle aparte con `PROCESS_VM_WRITE`, que se abre **solo cuando tú usas el editor**
  (pestaña *Editar* o el verbo `write`) para **modificar valores** en procesos que tú
  abres — un editor tipo *trainer* para tu laboratorio o tus juegos.

Lo que **no** hace, a propósito: no inyecta código, no crea hilos remotos, no incluye
driver de kernel y no intenta evadir antivirus/EDR. Es un editor de valores, no un
cargador de código. Úsalo solo sobre procesos **propios o autorizados**.

---

## Sobre el nivel "kernel" (léelo antes de nada)

Pediste una herramienta que "opere a nivel kernel". Voy a ser honesto sobre por
qué **esta herramienta funciona en modo usuario** y no incluye un driver de kernel:

- Para el objetivo real —**leer la memoria de un proceso que tú eliges**— el modo
  usuario con privilegios de Administrador (`SeDebugPrivilege`) es suficiente y es
  el enfoque estándar que usan herramientas como Process Hacker/System Informer,
  x64dbg o Cheat Engine para la mayoría de casos.
- Un driver de kernel propio cuyo único fin es leer la memoria de **cualquier**
  proceso, incluidos los **protegidos** (PPL: LSASS, antivirus/EDR, anti-cheat),
  es precisamente la primitiva que usan los rootkits y las técnicas de evasión de
  EDR (p. ej. el patrón *Bring Your Own Vulnerable Driver*). Escribir ese
  componente equivale a entregar una herramienta para saltarse controles de
  seguridad, así que no lo incluyo.
- Además, desde Windows Vista todo driver debe ir **firmado** por Microsoft para
  cargarse (KMCS + integridad de la firma). Un driver "casero" no cargará en un
  Windows 11 normal sin desactivar protecciones del sistema, lo que en la práctica
  descarta el enfoque para un uso legítimo fuera de un laboratorio con Test Mode.

Si tu caso **legítimo** necesita inspeccionar memoria de kernel o de procesos
protegidos (por ejemplo, investigación en un laboratorio aislado), el camino
soportado por Microsoft es el **depurador de kernel local con WinDbg/KD**:

```
bcdedit /debug on            (en la VM de laboratorio)
```

y luego abrir WinDbg como *Local Kernel Debugging*, o depuración de kernel remota
por red entre dos máquinas. Eso te da lectura de memoria de kernel de forma legal,
firmada y reversible, sin construir un rootkit.

> **Uso responsable.** Usa MemReader solo sobre sistemas y procesos que te
> pertenezcan o para los que tengas **autorización escrita** (un contrato de
> pentesting, tu propio laboratorio, un reto de CTF). Leer la memoria de procesos
> ajenos sin permiso puede ser delito.

---

## Descarga rápida (sin compilar nada)

Cada vez que se sube código a la rama, un **GitHub Action** compila
`MemReader.exe` en un runner de Windows y lo publica automáticamente. Tienes dos
formas de descargarlo ya hecho:

- **Release "latest" (enlace directo):** el `.exe` siempre está disponible en la
  página de *Releases* del repo, en la release llamada **Latest build**. Enlace
  directo:
  `https://github.com/Sumico8/Coding1/releases/download/latest/MemReader.exe`
- **Artefacto de la ejecución:** entra en la pestaña **Actions** del repo, abre la
  última ejecución de *Build MemReader* y descarga el artefacto
  `MemReader-windows-x64` (es un `.zip` con el `.exe` dentro).

> El `.exe` no está firmado, así que la primera vez Windows SmartScreen mostrará
> "Windows protegió tu PC": pulsa **Más información → Ejecutar de todas formas**.
> Recuerda ejecutarlo **como Administrador**.

Si prefieres compilarlo tú mismo, sigue las secciones de abajo.

## Modo CLI (automatización)

Además de la interfaz gráfica, MemReader tiene un **modo de línea de comandos**
(sin ventana) para automatizar el análisis y encadenarlo en scripts. Si le pasas
argumentos actúa como herramienta de consola; sin argumentos abre la GUI.

> **Ejecútalo desde una consola ya elevada (Administrador).** El ejecutable pide
> elevación, y lanzarlo sin elevar desde una consola normal rompe la redirección de
> la salida (UAC abre un proceso nuevo). Por eso los comandos que generan artefactos
> aceptan `--out <ruta>` para escribir el resultado a un archivo.

Verbos disponibles:

```text
MemReader.exe list      [--filter <txt>] [--out procs.csv]
MemReader.exe regions   --pid <N> [--all] [--out regiones.csv]
MemReader.exe strings   --pid <N> [--min 6] [--out cadenas.csv]
MemReader.exe security  --pid <N> [--out seguridad.csv]
MemReader.exe report    --pid <N> [--out informe.html] [--hash] [--ioc]
MemReader.exe ioc       --pid <N> [--min 5] [--out iocs.csv]
MemReader.exe pe        --pid <N> [--base 0x...] [--out pe.csv]
MemReader.exe integrity --pid <N> [--out integridad.csv]
MemReader.exe hooks     --pid <N> [--out hooks.csv]
MemReader.exe handles   --pid <N> [--no-names] [--out handles.csv]
MemReader.exe hashes    --pid <N> [--out hashes.csv]
MemReader.exe search    --pid <N> --aob "48 8B ?? E8" [--out hits.csv]
MemReader.exe scan-all  [--filter <txt>] [--out maquina.csv]
MemReader.exe info      --pid <N> [--out info.csv]
MemReader.exe bundle    --pid <N> [--out caso.zip] [--full]
MemReader.exe rules     --pid <N> [--out reglas.csv]
MemReader.exe write     --pid <N> --addr 0x... --int32 <v>   (editor)
MemReader.exe dump      --pid <N> --out <carpeta>
MemReader.exe minidump  --pid <N> [--out pid.dmp]
MemReader.exe help
```

El comando `report` genera el informe HTML y, junto a él, un `.json` con el mismo
nombre base. Códigos de salida: `0` ok, `1` error de uso, `2` acceso denegado,
`3` error.

Ejemplos:

```powershell
MemReader.exe scan-all --out maquina.csv
MemReader.exe report --pid 1234 --hash --ioc --out informe.html
MemReader.exe search --pid 1234 --aob "48 8B ?? ?? E8" --out firmas.csv
```

## Requisitos (para compilar en local)

- Windows 10/11 de 64 bits.
- [.NET SDK 8.0](https://dotnet.microsoft.com/download/dotnet/8.0) para compilar.
- Ejecutar la app **como Administrador** (el manifiesto ya lo solicita).

## Compilar

Desde la carpeta del proyecto, en una terminal de Windows:

```powershell
# Compilación rápida para desarrollo
dotnet build -c Release

# O generar un único .exe autocontenido (no necesita .NET instalado en destino)
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

El ejecutable quedará en:

```
bin\Release\net8.0-windows\win-x64\publish\MemReader.exe
```

También puedes usar el script incluido:

```powershell
.\build.ps1
```

## Ejecutar

1. Clic derecho en `MemReader.exe` → **Ejecutar como administrador**.
2. Pulsa **Actualizar procesos** y selecciona uno (doble clic o *Analizar*).
3. Elige una **región** para verla en el visor hexadecimal, o escribe una
   dirección/tamaño manualmente.
4. Usa la pestaña **Buscar en memoria** para encontrar texto.
5. **Volcar región a archivo** guarda los bytes crudos en disco.

## Notas técnicas

- El binario se compila como **x64**; el struct `MEMORY_BASIC_INFORMATION` usa el
  layout de 64 bits.
- El lector de memoria solo solicita `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.
  El acceso de escritura (`PROCESS_VM_WRITE | PROCESS_VM_OPERATION`) se pide en un
  handle aparte y **solo cuando usas el editor** (pestaña *Editar* / verbo `write`).
  La enumeración de handles abre otro handle aparte con `PROCESS_DUP_HANDLE`. Ningún
  camino inyecta código ni crea hilos en el proceso objetivo.
- Windows **denegará** el acceso a procesos protegidos (PPL) aunque seas
  Administrador. Es el comportamiento correcto y esperado; verás un error Win32
  (normalmente `5 = Acceso denegado`).

## Estructura

```
.github/workflows/build.yml   Compila el .exe en la nube y lo publica
MemReader.csproj              Proyecto .NET (WinForms, x64)
app.manifest                  Solicita elevación (Administrador) + DPI
src/NativeMethods.cs          P/Invoke a kernel32/ntdll (APIs documentadas)
src/Privileges.cs             Habilita SeDebugPrivilege (advapi32)
src/ProcessMemoryReader.cs    Núcleo: abrir proceso, enumerar, leer, módulos, dump
src/PointerScanner.cs         Motor de punteros/offsets (índice, escaneo, resolución)
src/ScanSession.cs            Escaneo iterativo de valores (next-scan)
src/ValueInterpreter.cs       Interpreta bytes como tipos, patrones y AOB
src/EntropyAnalyzer.cs        Entropía de Shannon por región/sección
src/StringsExtractor.cs       Extracción de cadenas ASCII/UTF-16
src/ThreadInspector.cs        Hilos y su dirección de inicio
src/SecurityAnalyzer.cs       Indicadores de seguridad (RWX, exec no respaldado…)
src/Disassembler.cs           Desensamblado x86/x64 (Iced) con símbolos
src/PeImage.cs                Parser PE (secciones, imports/exports/TLS)
src/PeAnalyzer.cs             Análisis PE en memoria + anomalías
src/IntegrityScanner.cs       Integridad de módulos (anti-hollowing)
src/HookScanner.cs            Detección de hooks inline
src/IatHookScanner.cs         Detección de hooks de IAT
src/HandleInspector.cs        Enumeración de handles/mutex
src/ModuleHasher.cs           SHA-256 de módulos + URL de VirusTotal
src/IocExtractor.cs           Extracción de IOCs
src/SnapshotDiff.cs           Diff de capturas de memoria
src/BatchTriage.cs            Triage ligero de toda la máquina
src/ProcessInfo.cs            Contexto del proceso (cmdline, padre, protección)
src/CaseBundle.cs             Bundle del caso en .zip (informe + dump + regiones)
src/Report/                   Informe de triage (modelo + HTML + JSON)
src/Cli/CliRunner.cs          Modo CLI headless (automatización)
src/HexFormatter.cs           Volcado hexadecimal
src/MainForm.cs               Interfaz gráfica
src/Program.cs                Punto de entrada (GUI o CLI)
```
