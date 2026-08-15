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

            var pe = PeImage.FromMemory(reader, m.BaseAddress);
            if (pe == null || !pe.IsValid) continue;

            if (!pe.HasAslr)
                findings.Add(new SecurityFinding(2, "Media", "Sin ASLR",
                    $"{m.Name} no tiene DYNAMIC_BASE (ASLR) en 0x{m.BaseAddress:X}.", m.BaseAddress));
            if (!pe.HasDep)
                findings.Add(new SecurityFinding(2, "Media", "Sin DEP",
                    $"{m.Name} no tiene NX_COMPAT (DEP) en 0x{m.BaseAddress:X}.", m.BaseAddress));
            if (!pe.HasCfg)
                findings.Add(new SecurityFinding(1, "Baja", "Sin CFG",
                    $"{m.Name} no tiene GUARD_CF (Control Flow Guard) en 0x{m.BaseAddress:X}.", m.BaseAddress));
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
}
