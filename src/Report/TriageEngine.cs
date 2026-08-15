using System.Diagnostics;
using System.Reflection;

namespace MemReader;

/// <summary>
/// Ejecuta la bateria de analisis de solo lectura sobre un proceso y devuelve un
/// <see cref="TriageReport"/>. Es el unico camino compartido por la interfaz
/// grafica (pestana Informe) y el modo CLI (verbo report), para que ambos den el
/// mismo resultado. No modifica nada del proceso analizado.
/// </summary>
public static class TriageEngine
{
    private const double HighEntropyThreshold = 7.2;

    /// <summary>Analiza un proceso ya abierto.</summary>
    public static TriageReport Analyze(
        ProcessMemoryReader reader, string processName,
        IProgress<string>? progress, CancellationToken ct,
        bool hashModules = false, bool extractIocs = false)
    {
        var r = new TriageReport
        {
            ToolVersion = AppVersion(),
            GeneratedUtc = DateTime.UtcNow.ToString("o"),
            Pid = reader.ProcessId,
            ProcessName = processName,
            Path = reader.GetProcessPath(),
            Architecture = reader.IsTargetWow64() ? "x86 (WOW64)" : "x64",
            AnalyzerElevated = Program.IsElevated(),
        };

        var info = ProcessInfo.Get(reader.ProcessId);
        r.ParentPid = info.ParentPid;
        r.ParentName = info.ParentName;
        r.CommandLine = info.CommandLine;
        r.SessionId = info.SessionId;
        r.StartTime = info.StartTime;

        progress?.Report("Enumerando regiones...");
        var regions = reader.EnumerateRegions(onlyReadable: false);
        ulong committed = 0;
        int regionCount = 0;
        foreach (var reg in regions)
        {
            if (reg.State != NativeMethods.MEM_COMMIT) continue;
            regionCount++;
            committed += reg.RegionSize;
        }
        r.RegionCount = regionCount;
        r.CommittedBytes = committed;

        // Indicadores de seguridad (RWX, ejecutable no respaldado, ASLR/DEP/CFG).
        var findings = SecurityAnalyzer.Analyze(reader, progress, ct);
        r.Findings = findings
            .Select(f => new ReportFinding(f.Severity, f.Category, f.Detail, $"0x{f.Address:X}"))
            .ToList();
        r.HighSeverityCount = findings.Count(f => f.Severity == "Alta");

        // Regiones de alta entropia (posible empaquetado/cifrado). Muestra 64 KB.
        progress?.Report("Calculando entropia por region...");
        foreach (var reg in regions)
        {
            ct.ThrowIfCancellationRequested();
            if (reg.State != NativeMethods.MEM_COMMIT || !reg.IsReadable) continue;
            int sample = (int)Math.Min(reg.RegionSize, (ulong)65536);
            double ent;
            try { ent = EntropyAnalyzer.Shannon(reader.ReadBytes(reg.BaseAddress, sample)); }
            catch { continue; }
            if (ent >= HighEntropyThreshold)
                r.HighEntropyRegions.Add(new ReportRegion(
                    $"0x{reg.BaseAddress:X}", reg.SizeText, reg.ProtectText, reg.TypeText, Math.Round(ent, 2)));
        }

        // Modulos y sus rangos (para clasificar los hilos).
        var modules = reader.EnumerateModules();
        var ranges = modules
            .Select(m => (start: m.BaseAddress, end: m.BaseAddress + (ulong)m.Size))
            .ToList();
        if (hashModules) progress?.Report("Calculando hashes de modulos...");
        foreach (var m in modules)
        {
            ct.ThrowIfCancellationRequested();
            string? sha = null;
            if (hashModules && !string.IsNullOrEmpty(m.Path) && File.Exists(m.Path))
                sha = ModuleHasher.HashFile(m.Path);
            r.Modules.Add(new ReportModule(
                m.Name, m.BaseText, m.SizeText,
                string.IsNullOrEmpty(m.Path) ? null : m.Path, sha));
        }

        // Hilos con inicio fuera de todo modulo (posible codigo inyectado).
        progress?.Report("Analizando hilos...");
        foreach (var t in ThreadInspector.Enumerate(reader.ProcessId))
        {
            if (t.StartAddress == 0) continue;
            bool inModule = ranges.Any(rg => t.StartAddress >= rg.start && t.StartAddress < rg.end);
            if (!inModule)
                r.SuspiciousThreads.Add(new ReportThread(
                    t.Tid, $"0x{t.StartAddress:X}",
                    "Inicio fuera de todo modulo (posible codigo inyectado)"));
        }

        // IOCs (opcional: implica extraer todas las cadenas, es lo mas lento).
        if (extractIocs)
        {
            progress?.Report("Extrayendo IOCs...");
            var iocs = IocExtractor.Extract(reader, 5, 200000, progress, ct);
            r.Iocs = iocs.Select(i => new ReportIoc(i.Type, i.Value, i.AddressText)).ToList();
        }

        return r;
    }

    /// <summary>Abre el proceso por PID, lo analiza y cierra el handle.</summary>
    public static TriageReport Analyze(
        int pid, IProgress<string>? progress, CancellationToken ct,
        bool hashModules = false, bool extractIocs = false)
    {
        string name = "(desconocido)";
        try { using var p = Process.GetProcessById(pid); name = p.ProcessName; }
        catch { /* el nombre no es imprescindible */ }

        using var reader = new ProcessMemoryReader(pid);
        return Analyze(reader, name, progress, ct, hashModules, extractIocs);
    }

    private static string AppVersion()
        => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";
}
