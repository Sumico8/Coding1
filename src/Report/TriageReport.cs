namespace MemReader;

/// <summary>
/// Modelo de un informe de triage de un proceso (solo lectura). Es el formato
/// comun que consumen tanto la interfaz grafica como el modo CLI, y del que se
/// derivan las salidas HTML y JSON.
/// </summary>
public sealed class TriageReport
{
    public int SchemaVersion { get; set; } = 1;
    public string Tool { get; set; } = "MemReader";
    public string ToolVersion { get; set; } = "";
    public string GeneratedUtc { get; set; } = "";

    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string? Path { get; set; }
    public string Architecture { get; set; } = "";
    public bool AnalyzerElevated { get; set; }
    public int ParentPid { get; set; }
    public string ParentName { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public int SessionId { get; set; }
    public string StartTime { get; set; } = "";

    public int RegionCount { get; set; }
    public ulong CommittedBytes { get; set; }
    public int HighSeverityCount { get; set; }

    public List<ReportFinding> Findings { get; set; } = new();
    public List<ReportRegion> HighEntropyRegions { get; set; } = new();
    public List<ReportThread> SuspiciousThreads { get; set; } = new();
    public List<ReportModule> Modules { get; set; } = new();
    public List<ReportIoc> Iocs { get; set; } = new();
    public List<string> Notes { get; set; } = new();
}

public sealed record ReportFinding(string Severity, string Category, string Detail, string Address);
public sealed record ReportRegion(string Address, string Size, string Protect, string Type, double Entropy);
public sealed record ReportThread(uint Tid, string StartAddress, string Note);
public sealed record ReportModule(string Name, string BaseAddress, string Size, string? Path, string? Sha256);
public sealed record ReportIoc(string Type, string Value, string Address);
