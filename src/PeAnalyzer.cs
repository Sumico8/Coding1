namespace MemReader;

/// <summary>Una seccion del PE tal como se muestra en el analisis (con entropia).</summary>
public sealed record PeSectionInfo(
    string Name, string Rva, string VirtualSize, string RawSize, string Perms, double Entropy);

/// <summary>Resultado del analisis de un PE en memoria.</summary>
public sealed class PeAnalysis
{
    public ulong BaseAddress { get; set; }
    public bool Valid { get; set; }
    public string? Error { get; set; }
    public bool Is64Bit { get; set; }
    public string ImageBase { get; set; } = "";
    public string SizeOfImage { get; set; } = "";
    public string EntryPoint { get; set; } = "";
    public List<PeSectionInfo> Sections { get; set; } = new();
    public List<string> ImportedModules { get; set; } = new();
    public int ExportCount { get; set; }
    public List<string> ExportSample { get; set; } = new();
    public List<string> TlsCallbacks { get; set; } = new();
    public List<string> Anomalies { get; set; } = new();
}

/// <summary>
/// Analiza un PE cargado en memoria a partir de su direccion base: secciones con
/// entropia, DLL importadas, exports, TLS callbacks y anomalias de cabecera.
/// Todo de solo lectura, apoyandose en <see cref="PeImage"/>.
/// </summary>
public static class PeAnalyzer
{
    private const double HighEntropy = 7.2;

    public static PeAnalysis Analyze(ProcessMemoryReader reader, ulong baseAddr)
    {
        var a = new PeAnalysis { BaseAddress = baseAddr };
        var pe = PeImage.FromMemory(reader, baseAddr);
        if (pe == null || !pe.IsValid)
        {
            a.Error = "No se encontro un PE valido en esa direccion.";
            return a;
        }

        a.Valid = true;
        a.Is64Bit = pe.Is64Bit;
        a.ImageBase = $"0x{pe.ImageBase:X}";
        a.SizeOfImage = $"0x{pe.SizeOfImage:X}";
        a.EntryPoint = $"0x{baseAddr + pe.AddressOfEntryPoint:X}";

        foreach (var s in pe.Sections)
        {
            double ent;
            try
            {
                int sample = (int)Math.Min(Math.Max(s.VirtualSize, 1u), 65536u);
                ent = EntropyAnalyzer.Shannon(reader.ReadBytes(baseAddr + s.VirtualAddress, sample));
            }
            catch { ent = -1; }
            a.Sections.Add(new PeSectionInfo(
                s.Name, $"0x{s.VirtualAddress:X}", $"0x{s.VirtualSize:X}",
                $"0x{s.SizeOfRawData:X}", s.PermText, Math.Round(ent, 2)));
        }

        a.ImportedModules = pe.EnumerateImportedModules(reader, baseAddr);
        var exports = pe.EnumerateExports(reader, baseAddr);
        a.ExportCount = exports.Count;
        a.ExportSample = exports.Take(40).Select(e => e.name).ToList();
        a.TlsCallbacks = pe.EnumerateTlsCallbacks(reader, baseAddr).Select(v => $"0x{v:X}").ToList();

        // Anomalias de triage.
        uint epRva = pe.AddressOfEntryPoint;
        if (epRva != 0 && pe.SectionForRva(epRva) == null)
            a.Anomalies.Add($"El entry point (RVA 0x{epRva:X}) no cae en ninguna seccion.");

        foreach (var s in pe.Sections)
            if (s.IsWritable && s.IsExecutable)
                a.Anomalies.Add($"Seccion '{s.Name}' es escribible y ejecutable (W+X).");

        foreach (var si in a.Sections)
            if (si.Perms.Contains('X') && si.Entropy >= HighEntropy)
                a.Anomalies.Add($"Seccion '{si.Name}' ejecutable con entropia alta ({si.Entropy:0.00}); posible empaquetado.");

        if (a.TlsCallbacks.Count > 0)
            a.Anomalies.Add($"{a.TlsCallbacks.Count} TLS callback(s): se ejecutan antes del entry point.");

        return a;
    }
}
