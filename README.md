# MemReader

Herramienta de **lectura de memoria de procesos** para Windows 11, pensada para
pentesting, análisis de malware en laboratorio, forense y CTF. Es una aplicación
de escritorio (WinForms, .NET 8) que:

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

Todo se apoya en APIs **documentadas y soportadas** de Windows
(`OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`). No modifica la memoria de
otros procesos: solo la lee.

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
- Solo se solicitan los permisos `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.
  No se pide acceso de escritura.
- Windows **denegará** el acceso a procesos protegidos (PPL) aunque seas
  Administrador. Es el comportamiento correcto y esperado; verás un error Win32
  (normalmente `5 = Acceso denegado`).

## Estructura

```
.github/workflows/build.yml   Compila el .exe en la nube y lo publica
MemReader.csproj              Proyecto .NET (WinForms, x64)
app.manifest                  Solicita elevación (Administrador) + DPI
src/NativeMethods.cs          P/Invoke a kernel32 (APIs documentadas)
src/Privileges.cs             Habilita SeDebugPrivilege (advapi32)
src/ProcessMemoryReader.cs    Núcleo: abrir proceso, enumerar, leer, módulos, dump
src/PointerScanner.cs         Motor de punteros/offsets (índice, escaneo, resolución)
src/ValueInterpreter.cs       Interpreta bytes como tipos y construye patrones
src/HexFormatter.cs           Volcado hexadecimal
src/MainForm.cs               Interfaz gráfica
src/Program.cs                Punto de entrada
```
