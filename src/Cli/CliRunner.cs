using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace MemReader;

/// <summary>
/// Modo CLI headless para automatizacion / scripting. Reutiliza exactamente el
/// mismo nucleo de solo lectura que la interfaz grafica (ProcessMemoryReader y
/// los analizadores estaticos). No escribe en la memoria de otros procesos.
///
/// Notas de consola: MemReader se compila como WinExe (subsistema GUI). Cuando
/// se lanza desde una consola no "espera" (el prompt vuelve enseguida) y, para
/// escribir en esa consola, hay que engancharse a ella con AttachConsole. Si la
/// salida esta redirigida a un archivo o tuberia (p. ej. "> salida.csv"), el
/// handle heredado ya sirve y NO hay que enganchar nada. Por eso el contrato
/// principal de los comandos que generan artefactos es la opcion --out <ruta>.
/// </summary>
internal static class CliRunner
{
    private sealed class CliUsageException : Exception
    {
        public CliUsageException(string message) : base(message) { }
    }

    public static int Run(string[] args)
    {
        SetupConsole();

        string verb = args[0].ToLowerInvariant().TrimStart('-', '/');
        var opts = ParseOptions(args);

        // Igual que la GUI: si estamos elevados activamos SeDebugPrivilege.
        bool elevated = Program.IsElevated();
        if (elevated) Privileges.EnableDebugPrivilege();

        try
        {
            switch (verb)
            {
                case "help":
                case "h":
                case "?":
                    return PrintHelp();
                case "version":
                    Console.WriteLine("MemReader " + AppVersion());
                    return 0;
                case "list":
                    return CmdList(opts);
                case "regions":
                    return CmdRegions(opts, elevated);
                case "strings":
                    return CmdStrings(opts, elevated);
                case "security":
                    return CmdSecurity(opts, elevated);
                case "dump":
                    return CmdDump(opts, elevated);
                case "minidump":
                    return CmdMinidump(opts, elevated);
                case "report":
                    return CmdReport(opts, elevated);
                case "hashes":
                    return CmdHashes(opts, elevated);
                case "ioc":
                case "iocs":
                    return CmdIoc(opts, elevated);
                case "search":
                    return CmdSearch(opts, elevated);
                case "pe":
                    return CmdPe(opts, elevated);
                case "integrity":
                    return CmdIntegrity(opts, elevated);
                case "hooks":
                    return CmdHooks(opts, elevated);
                case "handles":
                    return CmdHandles(opts, elevated);
                case "scan-all":
                case "scanall":
                    return CmdScanAll(opts, elevated);
                case "info":
                    return CmdInfo(opts, elevated);
                case "bundle":
                    return CmdBundle(opts, elevated);
                case "rules":
                    return CmdRules(opts, elevated);
                case "write":
                    return CmdWrite(opts, elevated);
                default:
                    Console.Error.WriteLine(
                        $"Verbo desconocido: '{verb}'. Ejecuta 'MemReader.exe help' para ver el uso.");
                    return 1;
            }
        }
        catch (CliUsageException ex)
        {
            Console.Error.WriteLine("Error de uso: " + ex.Message);
            return 1;
        }
        catch (Win32Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            return 3;
        }
        finally
        {
            try { Console.Out.Flush(); Console.Error.Flush(); } catch { /* sin consola */ }
        }
    }

    // ---------------- Comandos ----------------

    private static int CmdList(Dictionary<string, string> opts)
    {
        string? filter = Get(opts, "filter");
        var rows = new StringBuilder();
        rows.AppendLine("pid,name");
        var procs = Process.GetProcesses()
            .Select(p => (p.Id, Name: SafeName(p)))
            .Where(t => string.IsNullOrEmpty(filter) ||
                        t.Name.Contains(filter!, StringComparison.OrdinalIgnoreCase) ||
                        t.Id.ToString().Contains(filter!))
            .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var (id, name) in procs)
            rows.AppendLine($"{id},{Csv(name)}");
        WriteOutput(rows.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{procs.Count} procesos.");
        return 0;
    }

    private static int CmdRegions(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        using var reader = new ProcessMemoryReader(pid);
        bool onlyReadable = !opts.ContainsKey("all");
        var regions = reader.EnumerateRegions(onlyReadable);

        var sb = new StringBuilder();
        sb.AppendLine("base,size,protect,type");
        foreach (var r in regions)
            sb.AppendLine($"0x{r.BaseAddress:X},{r.RegionSize},{r.ProtectText},{r.TypeText}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{regions.Count} regiones.");
        return 0;
    }

    private static int CmdStrings(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        int min = GetInt(opts, "min", 5);
        int max = GetInt(opts, "max", 100000);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var found = StringsExtractor.Extract(reader, min, max, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("address,encoding,text");
        foreach (var s in found)
            sb.AppendLine($"0x{s.Address:X},{s.Encoding},{Csv(s.Text)}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{found.Count} cadenas.");
        return 0;
    }

    private static int CmdSecurity(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var findings = SecurityAnalyzer.Analyze(reader, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("severity,category,detail,address");
        foreach (var f in findings)
            sb.AppendLine($"{Csv(f.Severity)},{Csv(f.Category)},{Csv(f.Detail)},0x{f.Address:X}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        int alta = findings.Count(x => x.Severity == "Alta");
        Console.Error.WriteLine($"{findings.Count} hallazgos ({alta} de severidad alta).");
        return 0;
    }

    private static int CmdDump(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        string folder = Get(opts, "out")
            ?? throw new CliUsageException("Falta --out <carpeta> donde volcar las regiones.");
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var (files, bytes) = reader.DumpAllReadableRegions(folder, progress, CancellationToken.None);
        EndProgress();
        Console.Error.WriteLine($"Volcados {files} archivos ({bytes} bytes) en {folder}.");
        return 0;
    }

    private static int CmdMinidump(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        string outFile = Get(opts, "out") ?? $"pid{pid}.dmp";
        bool full = !opts.ContainsKey("normal");
        using var reader = new ProcessMemoryReader(pid);
        reader.WriteMiniDump(outFile, full);
        var fi = new FileInfo(outFile);
        Console.Error.WriteLine($"Minidump guardado: {fi.Length} bytes en {outFile}.");
        return 0;
    }

    private static int CmdReport(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        var progress = Progress(opts);
        bool hash = opts.ContainsKey("hash");
        bool ioc = opts.ContainsKey("ioc");
        bool rules = opts.ContainsKey("rules");
        var report = TriageEngine.Analyze(pid, progress, CancellationToken.None, hash, ioc, rules);
        EndProgress();

        string htmlPath = Get(opts, "out") ?? $"informe_pid{pid}.html";
        string jsonPath = Path.ChangeExtension(htmlPath, ".json");
        File.WriteAllText(htmlPath, HtmlReportWriter.Write(report));
        File.WriteAllText(jsonPath, JsonReportWriter.Write(report));
        Console.Error.WriteLine(
            $"Informe generado: {htmlPath} (+ {jsonPath}). " +
            $"{report.HighSeverityCount} hallazgos de severidad alta, " +
            $"{report.HighEntropyRegions.Count} regiones de alta entropia, " +
            $"{report.SuspiciousThreads.Count} hilos sospechosos.");
        return 0;
    }

    private static int CmdHashes(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var hashes = ModuleHasher.Compute(reader, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("module,base,sha256,path,virustotal");
        foreach (var h in hashes)
            sb.AppendLine($"{Csv(h.Name)},{h.BaseText},{h.Sha256 ?? ""},{Csv(h.Path ?? "")},{h.VirusTotalUrl}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{hashes.Count} modulos.");
        return 0;
    }

    private static int CmdIoc(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        int min = GetInt(opts, "min", 5);
        int max = GetInt(opts, "max", 300000);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var iocs = IocExtractor.Extract(reader, min, max, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("type,value,address");
        foreach (var io in iocs)
            sb.AppendLine($"{io.Type},{Csv(io.Value)},{io.AddressText}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{iocs.Count} IOCs unicos.");
        return 0;
    }

    private static int CmdSearch(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        int maxHits = GetInt(opts, "max", 5000);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);

        List<SearchHit> hits;
        if (opts.TryGetValue("aob", out var aob))
        {
            var (pat, mask) = ValueInterpreter.ParseAob(aob);
            hits = reader.SearchMasked(pat, mask, "AOB", maxHits, progress, CancellationToken.None);
        }
        else if (opts.TryGetValue("text", out var text))
        {
            var patterns = new List<(byte[] pattern, string label, string preview)>
            {
                (System.Text.Encoding.Latin1.GetBytes(text), "ASCII", text),
                (System.Text.Encoding.Unicode.GetBytes(text), "UTF-16", text),
            };
            hits = reader.SearchPatterns(patterns, maxHits, progress, CancellationToken.None);
        }
        else if (opts.TryGetValue("bytes", out var bytesHex))
        {
            hits = reader.SearchPatterns(
                new List<(byte[] pattern, string label, string preview)> { ValueInterpreter.BuildPattern("Bytes hex", bytesHex) },
                maxHits, progress, CancellationToken.None);
        }
        else if (opts.TryGetValue("int32", out var i32))
        {
            hits = reader.SearchPatterns(
                new List<(byte[] pattern, string label, string preview)> { ValueInterpreter.BuildPattern("Int32", i32) },
                maxHits, progress, CancellationToken.None);
        }
        else if (opts.TryGetValue("int64", out var i64))
        {
            hits = reader.SearchPatterns(
                new List<(byte[] pattern, string label, string preview)> { ValueInterpreter.BuildPattern("Int64", i64) },
                maxHits, progress, CancellationToken.None);
        }
        else
        {
            throw new CliUsageException("Indica que buscar: --text, --aob, --bytes, --int32 o --int64.");
        }
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("address,encoding,preview");
        foreach (var h in hits)
            sb.AppendLine($"0x{h.Address:X},{h.Encoding},{Csv(h.Preview)}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{hits.Count} coincidencias.");
        return 0;
    }

    private static int CmdPe(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        using var reader = new ProcessMemoryReader(pid);

        ulong baseAddr;
        if (opts.TryGetValue("base", out var bt))
        {
            if (!TryParseHex(bt, out baseAddr))
                throw new CliUsageException("--base invalido (usa hexadecimal, p. ej. 0x7FF6...).");
        }
        else
        {
            baseAddr = 0;
            try { using var p = Process.GetProcessById(pid); baseAddr = (ulong)(p.MainModule?.BaseAddress ?? IntPtr.Zero).ToInt64(); }
            catch { /* se valida abajo */ }
            if (baseAddr == 0)
                throw new CliUsageException("No se pudo obtener el modulo principal; indica --base <hex>.");
        }

        var a = PeAnalyzer.Analyze(reader, baseAddr);
        if (!a.Valid)
        {
            Console.Error.WriteLine(a.Error ?? "PE invalido.");
            return 3;
        }

        var sb = new StringBuilder();
        sb.AppendLine("section,rva,vsize,raw,perms,entropy");
        foreach (var s in a.Sections)
            sb.AppendLine($"{Csv(s.Name)},{s.Rva},{s.VirtualSize},{s.RawSize},{s.Perms},{s.Entropy:0.00}");
        WriteOutput(sb.ToString(), Get(opts, "out"));

        Console.Error.WriteLine(
            $"PE {(a.Is64Bit ? "x64" : "x86")} base 0x{a.BaseAddress:X}: {a.Sections.Count} secciones, " +
            $"{a.ExportCount} exports, {a.ImportedModules.Count} DLLs, {a.TlsCallbacks.Count} TLS, " +
            $"{a.Anomalies.Count} anomalias.");
        foreach (var an in a.Anomalies) Console.Error.WriteLine("  ! " + an);
        return 0;
    }

    private static int CmdIntegrity(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var results = IntegrityScanner.Scan(reader, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("module,base,verdict,diff_pct,compared_bytes,detail");
        foreach (var r in results)
            sb.AppendLine($"{Csv(r.Name)},{r.BaseText},{r.Verdict},{r.DiffPercent:0.####},{r.ComparedBytes},{Csv(r.Detail)}");
        WriteOutput(sb.ToString(), Get(opts, "out"));

        int susp = results.Count(r => r.Verdict == "SOSPECHOSO");
        Console.Error.WriteLine($"{results.Count} modulos comprobados ({susp} sospechosos).");
        foreach (var r in results.Where(r => r.Verdict == "SOSPECHOSO"))
            Console.Error.WriteLine($"  ! {r.Name}: {r.Detail}");
        return 0;
    }

    private static int CmdHooks(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var hooks = HookScanner.Scan(reader, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("module,function,address,type,target,bytes");
        foreach (var h in hooks)
            sb.AppendLine($"{h.Module},{Csv(h.Function)},{h.AddressText},{h.HookType},{Csv(h.Target)},{h.PrologueHex}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{hooks.Count} posibles hooks inline.");
        return 0;
    }

    private static int CmdHandles(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        bool names = !opts.ContainsKey("no-names");
        var progress = Progress(opts);
        var handles = HandleInspector.Enumerate(pid, names, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("type,name,handle,access");
        foreach (var h in handles)
            sb.AppendLine($"{Csv(h.Type)},{Csv(h.Name)},{h.HandleText},{h.AccessText}");
        WriteOutput(sb.ToString(), Get(opts, "out"));
        Console.Error.WriteLine($"{handles.Count} handles.");
        return 0;
    }

    private static int CmdScanAll(Dictionary<string, string> opts, bool elevated)
    {
        WarnIfNotElevated(elevated);
        string? filter = Get(opts, "filter");
        var progress = Progress(opts);
        var results = BatchTriage.ScanAll(filter, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("pid,name,arch,rwx,unbacked_exec,suspicious_threads,score,error");
        foreach (var r in results)
            sb.AppendLine($"{r.Pid},{Csv(r.Name)},{r.Arch},{r.RwxRegions},{r.UnbackedExec},{r.SuspiciousThreads},{r.Score},{Csv(r.Error ?? "")}");
        WriteOutput(sb.ToString(), Get(opts, "out"));

        int flagged = results.Count(r => r.Score > 0);
        Console.Error.WriteLine($"{results.Count} procesos, {flagged} con indicadores. Mas sospechosos:");
        foreach (var r in results.Where(r => r.Score > 0).Take(10))
            Console.Error.WriteLine($"  [{r.Score}] {r.Name} (pid {r.Pid}): RWX={r.RwxRegions} exec-no-img={r.UnbackedExec} hilos={r.SuspiciousThreads}");
        return 0;
    }

    private static int CmdInfo(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        var d = ProcessInfo.Get(pid);

        var sb = new StringBuilder();
        sb.AppendLine("field,value");
        sb.AppendLine($"pid,{d.Pid}");
        sb.AppendLine($"parent_pid,{d.ParentPid}");
        sb.AppendLine($"parent_name,{Csv(d.ParentName)}");
        sb.AppendLine($"session,{d.SessionId}");
        sb.AppendLine($"start,{Csv(d.StartTime)}");
        sb.AppendLine($"protection,{Csv(d.Protection)}");
        sb.AppendLine($"mitigations,{Csv(d.Mitigations)}");
        sb.AppendLine($"command_line,{Csv(d.CommandLine)}");
        WriteOutput(sb.ToString(), Get(opts, "out"));

        Console.Error.WriteLine($"pid {d.Pid} <- padre {d.ParentPid} ({d.ParentName}); sesion {d.SessionId}; inicio {d.StartTime}.");
        if (!string.IsNullOrEmpty(d.Protection) && d.Protection != "None")
            Console.Error.WriteLine($"  proteccion: {d.Protection}   mitigaciones: {d.Mitigations}");
        if (!string.IsNullOrEmpty(d.CommandLine)) Console.Error.WriteLine("  cmdline: " + d.CommandLine);
        return 0;
    }

    private static int CmdBundle(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        string outPath = Get(opts, "out") ?? $"caso_pid{pid}.zip";
        bool full = opts.ContainsKey("full");
        var progress = Progress(opts);
        string result = CaseBundle.Create(pid, outPath, full, progress, CancellationToken.None);
        EndProgress();
        var fi = new FileInfo(result);
        Console.Error.WriteLine($"Bundle del caso: {result} ({fi.Length} bytes).");
        return 0;
    }

    private static int CmdRules(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        using var reader = new ProcessMemoryReader(pid);
        var progress = Progress(opts);
        var hits = RuleEngine.Scan(reader, progress, CancellationToken.None);
        EndProgress();

        var sb = new StringBuilder();
        sb.AppendLine("severity,rule,matches,evidence,address");
        foreach (var h in hits)
            sb.AppendLine($"{h.Severity},{Csv(h.Rule)},{h.Matches},{Csv(h.Evidence)},{h.FirstAddressText}");
        WriteOutput(sb.ToString(), Get(opts, "out"));

        Console.Error.WriteLine($"{hits.Count} reglas coincidieron.");
        foreach (var h in hits)
            Console.Error.WriteLine($"  [{h.Severity}] {h.Rule}: {h.Description}");
        return 0;
    }

    private static int CmdWrite(Dictionary<string, string> opts, bool elevated)
    {
        int pid = RequirePid(opts);
        WarnIfNotElevated(elevated);
        if (!opts.TryGetValue("addr", out var addrStr) || !TryParseHex(addrStr, out ulong addr))
            throw new CliUsageException("Falta o es invalida la opcion --addr <hex>.");

        var (kind, value) = ResolveWriteValue(opts);
        byte[] bytes;
        try { bytes = ValueInterpreter.ToBytes(kind, value); }
        catch (Exception ex) { throw new CliUsageException($"Valor invalido para {kind}: {ex.Message}"); }

        using var reader = new ProcessMemoryReader(pid);
        int n = reader.WriteBytes(addr, bytes);
        Console.Error.WriteLine($"Escritos {n} bytes en 0x{addr:X} ({kind} = {value}).");
        return 0;
    }

    private static (string kind, string value) ResolveWriteValue(Dictionary<string, string> opts)
    {
        if (opts.TryGetValue("int32", out var v)) return ("Int32", v);
        if (opts.TryGetValue("int64", out v)) return ("Int64", v);
        if (opts.TryGetValue("float", out v)) return ("Float", v);
        if (opts.TryGetValue("double", out v)) return ("Double", v);
        if (opts.TryGetValue("bytes", out v)) return ("Bytes hex", v);
        if (opts.TryGetValue("text", out v)) return ("Texto", v);
        throw new CliUsageException("Indica que escribir: --int32, --int64, --float, --double, --bytes o --text.");
    }

    private static int PrintHelp()
    {
        Console.WriteLine(
@"MemReader " + AppVersion() + @" - lector/analizador de memoria de procesos (solo lectura)

USO:
  MemReader.exe                         Abre la interfaz grafica (GUI).
  MemReader.exe <verbo> [opciones]      Modo CLI headless (automatizacion).

VERBOS:
  list      [--filter <txt>] [--out <archivo.csv>]
            Lista los procesos (pid,name).
  regions   --pid <N> [--all] [--out <archivo.csv>]
            Enumera regiones de memoria. --all incluye no legibles.
  strings   --pid <N> [--min <n>] [--max <n>] [--out <archivo.csv>]
            Extrae cadenas ASCII/UTF-16 imprimibles.
  security  --pid <N> [--out <archivo.csv>]
            Analiza indicadores de seguridad (RWX, exec no respaldado, ASLR/DEP/CFG).
  dump      --pid <N> --out <carpeta>
            Vuelca todas las regiones legibles a una carpeta (con indice).
  minidump  --pid <N> [--out <archivo.dmp>] [--normal]
            Genera un minidump (memoria completa por defecto).
  report    --pid <N> [--out <archivo.html>] [--hash] [--ioc] [--rules]
            Informe de triage completo en HTML + JSON (mismo nombre base).
            --hash anade SHA-256; --ioc anade IOCs; --rules anade reglas.
  hashes    --pid <N> [--out <archivo.csv>]
            SHA-256 de cada modulo en disco + URL de VirusTotal.
  ioc       --pid <N> [--min <n>] [--out <archivo.csv>]
            Extrae IOCs (IPs, URLs, dominios, correos, rutas, registro, GUIDs).
  search    --pid <N> (--text <s> | --aob <patron> | --bytes <hex> |
            --int32 <n> | --int64 <n>) [--out <archivo.csv>]
            Busca en memoria. AOB admite comodines, p. ej. --aob 48 8B ?? E8
  pe        --pid <N> [--base <hex>] [--out <archivo.csv>]
            Analiza el PE (secciones, imports, exports, TLS, anomalias).
            Sin --base usa el modulo principal.
  integrity --pid <N> [--out <archivo.csv>]
            Compara el codigo en memoria vs el archivo en disco (hollowing/hooks).
  hooks     --pid <N> [--out <archivo.csv>]
            Detecta hooks inline en exports de ntdll/kernel32/etc.
  handles   --pid <N> [--no-names] [--out <archivo.csv>]
            Lista los handles (ficheros, claves, mutex...) del proceso.
  scan-all  [--filter <txt>] [--out <archivo.csv>]
            Triage ligero de todos los procesos, ordenados por sospecha.
  info      --pid <N> [--out <archivo.csv>]
            Linea de comandos, PID padre, sesion y hora de inicio.
  bundle    --pid <N> [--out <caso.zip>] [--full]
            Empaqueta informe + minidump + indice de regiones en un .zip.
            --full incluye un minidump de memoria completa (grande).
  rules     --pid <N> [--out <archivo.csv>]
            Aplica reglas heuristicas de triage (inyeccion, shellcode, packers...).
  write     --pid <N> --addr <hex> (--int32 V | --int64 V | --float V |
            --double V | --bytes <hex> | --text <s>)
            Escribe un valor en una direccion (editor tipo trainer, procesos
            propios/autorizados). No inyecta codigo.
  version   Muestra la version.
  help      Muestra esta ayuda.

NOTAS:
  - Ejecuta el modo CLI desde una consola YA elevada (Administrador). El
    manifiesto pide elevacion; lanzarlo sin elevar rompe la redireccion de la
    salida, asi que usa --out para escribir el resultado a un archivo.
  - Codigos de salida: 0 ok, 1 uso, 2 acceso denegado, 3 error.
  - Es solo lectura: nunca modifica la memoria de otros procesos.

EJEMPLOS:
  MemReader.exe list --filter chrome --out procs.csv
  MemReader.exe security --pid 1234 --out seguridad.csv
  MemReader.exe report --pid 1234 --out informe.html
  MemReader.exe strings --pid 1234 --min 6 > cadenas.csv");
        return 0;
    }

    // ---------------- Utilidades de consola / opciones ----------------

    /// <summary>
    /// Prepara la salida de consola para el modo CLI. Si la salida esta
    /// redirigida (archivo/tuberia) el handle heredado ya sirve; si no, se
    /// engancha a la consola padre. En ambos casos se reasignan los flujos con
    /// AutoFlush para evitar el fallo tipico de "la salida no aparece".
    /// </summary>
    private static void SetupConsole()
    {
        try
        {
            IntPtr h = NativeMethods.GetStdHandle(NativeMethods.STD_OUTPUT_HANDLE);
            uint ft = NativeMethods.GetFileType(h);
            bool redirected = ft == NativeMethods.FILE_TYPE_DISK || ft == NativeMethods.FILE_TYPE_PIPE;

            if (!redirected)
                NativeMethods.AttachConsole(NativeMethods.ATTACH_PARENT_PROCESS);

            var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
            Console.SetOut(stdout);
            var stderr = new StreamWriter(Console.OpenStandardError()) { AutoFlush = true };
            Console.SetError(stderr);
        }
        catch
        {
            // Sin consola disponible (p. ej. lanzado desde el Explorador): los
            // comandos con --out siguen funcionando escribiendo a disco.
        }
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < args.Length; i++)
        {
            string a = args[i];
            if (a.StartsWith("--")) a = a[2..];
            else if (a.StartsWith("-")) a = a[1..];
            else continue;
            if (a.Length == 0) continue;

            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
            {
                d[a] = args[i + 1];
                i++;
            }
            else
            {
                d[a] = "true"; // interruptor (flag) sin valor
            }
        }
        return d;
    }

    private static string? Get(Dictionary<string, string> opts, string key)
        => opts.TryGetValue(key, out var v) ? v : null;

    private static int GetInt(Dictionary<string, string> opts, string key, int def)
        => opts.TryGetValue(key, out var v) && int.TryParse(v, out int n) ? n : def;

    private static bool TryParseHex(string text, out ulong value)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        return ulong.TryParse(
            text, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }

    private static int RequirePid(Dictionary<string, string> opts)
    {
        if (!opts.TryGetValue("pid", out var v) || !int.TryParse(v, out int pid))
            throw new CliUsageException("Falta o es invalida la opcion --pid <N>.");
        return pid;
    }

    private static void WarnIfNotElevated(bool elevated)
    {
        if (!elevated)
            Console.Error.WriteLine(
                "Aviso: no se esta ejecutando como Administrador; abrir el proceso puede fallar.");
    }

    /// <summary>Escribe a un archivo si se dio --out; si no, a la salida estandar.</summary>
    private static void WriteOutput(string content, string? outPath)
    {
        if (!string.IsNullOrEmpty(outPath))
        {
            File.WriteAllText(outPath, content);
            Console.Error.WriteLine($"Guardado en {outPath}.");
        }
        else
        {
            Console.Out.Write(content);
        }
    }

    private static IProgress<string> Progress(Dictionary<string, string> opts)
        => new StderrProgress(opts.ContainsKey("quiet"));

    private static void EndProgress()
    {
        try { Console.Error.WriteLine(); } catch { /* sin consola */ }
    }

    private sealed class StderrProgress : IProgress<string>
    {
        private readonly bool _quiet;
        public StderrProgress(bool quiet) => _quiet = quiet;
        public void Report(string value)
        {
            if (_quiet) return;
            try { Console.Error.Write("\r" + value.PadRight(72)); } catch { /* sin consola */ }
        }
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName; }
        catch { return "(desconocido)"; }
    }

    /// <summary>Escapa un campo para CSV (comillas dobles si hace falta).</summary>
    private static string Csv(string s)
    {
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    private static string AppVersion()
        => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";
}
