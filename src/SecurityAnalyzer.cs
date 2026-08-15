namespace MemReader;

/// <summary>Un hallazgo de postura de seguridad del proceso.</summary>
public sealed record SecurityFinding(int Rank, string Severity, string Category, string Detail, ulong Address);

/// <summary>
/// Analiza la postura de seguridad de un proceso en ejecucion (solo lectura):
/// regiones anomalas (RWX, ejecutable no respaldado por imagen = posible shellcode
/// o inyeccion) y modulos sin mitigaciones (ASLR/DEP/CFG), parseando las cabeceras
/// PE directamente desde memoria. Es DETECCION/REPORTE, no explotacion: no genera
/// exploits ni modifica nada.
/// </summary>
public static class SecurityAnalyzer
{
    private const ushort HIGH_ENTROPY_VA = 0x0020;
    private const ushort DYNAMIC_BASE = 0x0040; // ASLR
    private const ushort FORCE_INTEGRITY = 0x0080;
    private const ushort NX_COMPAT = 0x0100;    // DEP
    private const ushort GUARD_CF = 0x4000;     // CFG

    public static List<SecurityFinding> Analyze(
        ProcessMemoryReader reader, IProgress<string>? progress, CancellationToken ct)
    {
        var findings = new List<SecurityFinding>();

        // 1) Regiones de memoria anomalas.
        progress?.Report("Analizando regiones de memoria...");
        var regions = reader.EnumerateRegions(onlyReadable: false);
        foreach (var r in regions)
        {
            ct.ThrowIfCancellationRequested();
            if (r.State != NativeMethods.MEM_COMMIT) continue;

            bool exec = IsExecutable(r.Protect);
            bool rwx = (r.Protect & 0xFF) == NativeMethods.PAGE_EXECUTE_READWRITE;
            bool backed = r.Type == NativeMethods.MEM_IMAGE;

            if (rwx)
                findings.Add(new SecurityFinding(3, "Alta", "Region RWX",
                    $"Region ejecutable+escribible en 0x{r.BaseAddress:X} ({r.SizeText}). Indicio clasico de codigo inyectado.", r.BaseAddress));

            if (exec && !backed)
                findings.Add(new SecurityFinding(3, "Alta", "Ejecutable no respaldado",
                    $"Memoria ejecutable {r.ProtectText} en 0x{r.BaseAddress:X} ({r.SizeText}) tipo {r.TypeText}, no respaldada por una imagen/modulo. Posible shellcode o inyeccion.", r.BaseAddress));
        }

        // 2) Mitigaciones de cada modulo (PE en memoria).
        var modules = reader.EnumerateModules();
        int idx = 0;
        foreach (var m in modules)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"Analizando modulos... {idx}/{modules.Count}");

            ushort? dll = ReadDllCharacteristics(reader, m.BaseAddress);
            if (dll == null) continue;
            ushort v = dll.Value;

            if ((v & DYNAMIC_BASE) == 0)
                findings.Add(new SecurityFinding(2, "Media", "Sin ASLR",
                    $"{m.Name} no tiene DYNAMIC_BASE (ASLR) en 0x{m.BaseAddress:X}.", m.BaseAddress));
            if ((v & NX_COMPAT) == 0)
                findings.Add(new SecurityFinding(2, "Media", "Sin DEP",
                    $"{m.Name} no tiene NX_COMPAT (DEP) en 0x{m.BaseAddress:X}.", m.BaseAddress));
            if ((v & GUARD_CF) == 0)
                findings.Add(new SecurityFinding(1, "Baja", "Sin CFG",
                    $"{m.Name} no tiene GUARD_CF (Control Flow Guard) en 0x{m.BaseAddress:X}.", m.BaseAddress));
            // ASLR presente pero sin alta entropia -> aleatorizacion de 64 bits mas debil.
            if ((v & DYNAMIC_BASE) != 0 && (v & HIGH_ENTROPY_VA) == 0 && !reader.IsTargetWow64())
                findings.Add(new SecurityFinding(1, "Baja", "ASLR sin alta entropia",
                    $"{m.Name} tiene ASLR pero sin HIGH_ENTROPY_VA (aleatorizacion de 64 bits mas debil) en 0x{m.BaseAddress:X}.", m.BaseAddress));
            // FORCE_INTEGRITY: solo carga codigo firmado (mitigacion fuerte, poco comun).
            if ((v & FORCE_INTEGRITY) != 0)
                findings.Add(new SecurityFinding(0, "Info", "Integridad de codigo",
                    $"{m.Name} exige FORCE_INTEGRITY (solo carga codigo firmado) en 0x{m.BaseAddress:X}.", m.BaseAddress));
        }

        findings.Sort((a, b) => b.Rank.CompareTo(a.Rank));
        return findings;
    }

    private static bool IsExecutable(uint protect)
    {
        uint p = protect & 0xFF;
        return p == NativeMethods.PAGE_EXECUTE
            || p == NativeMethods.PAGE_EXECUTE_READ
            || p == NativeMethods.PAGE_EXECUTE_READWRITE
            || p == NativeMethods.PAGE_EXECUTE_WRITECOPY;
    }

    /// <summary>Lee DllCharacteristics de la cabecera PE de un modulo desde memoria.</summary>
    private static ushort? ReadDllCharacteristics(ProcessMemoryReader reader, ulong baseAddr)
    {
        byte[] hdr;
        try { hdr = reader.ReadBytes(baseAddr, 0x400); }
        catch { return null; }
        if (hdr.Length < 0x40) return null;
        if (hdr[0] != 0x4D || hdr[1] != 0x5A) return null; // "MZ"

        int eLfanew = BitConverter.ToInt32(hdr, 0x3C);
        if (eLfanew < 0 || eLfanew + 0x60 > hdr.Length) return null;

        // Firma "PE\0\0"
        if (hdr[eLfanew] != 0x50 || hdr[eLfanew + 1] != 0x45 ||
            hdr[eLfanew + 2] != 0x00 || hdr[eLfanew + 3] != 0x00) return null;

        // Optional header comienza tras firma (4) + COFF header (20).
        int optStart = eLfanew + 24;
        // DllCharacteristics esta en offset 0x46 del optional header en PE32 y PE32+.
        int off = optStart + 0x46;
        if (off + 2 > hdr.Length) return null;
        return BitConverter.ToUInt16(hdr, off);
    }
}
