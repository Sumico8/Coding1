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
        var report = TriageEngine.Analyze(pid, progress, CancellationToken.None, hash);
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
  report    --pid <N> [--out <archivo.html>] [--hash]
            Informe de triage completo en HTML + JSON (mismo nombre base).
            --hash calcula el SHA-256 de cada modulo (mas lento).
  hashes    --pid <N> [--out <archivo.csv>]
            SHA-256 de cada modulo en disco + URL de VirusTotal.
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
