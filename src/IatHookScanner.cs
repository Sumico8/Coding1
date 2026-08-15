namespace MemReader;

/// <summary>
/// Detecta hooks de IAT: entradas de la tabla de importacion de un modulo cuyo
/// valor resuelto NO cae dentro de ningun modulo cargado (apuntan a memoria no
/// respaldada por imagen, tipico de un trampolin de hook/inyeccion). Resolver a
/// otro modulo (p. ej. un forwarder a kernelbase) se considera normal y no se
/// marca. Solo deteccion/lectura. Devuelve <see cref="HookFinding"/> para
/// mostrarse junto a los hooks inline.
/// </summary>
public static class IatHookScanner
{
    public static List<HookFinding> Scan(
        ProcessMemoryReader reader, IProgress<string>? progress, CancellationToken ct)
    {
        var findings = new List<HookFinding>();
        var modules = reader.EnumerateModules();
        var ranges = modules
            .Select(m => (m.Name, s: m.BaseAddress, e: m.BaseAddress + (ulong)m.Size))
            .ToList();

        int idx = 0;
        foreach (var m in modules)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"IAT... {idx}/{modules.Count}: {m.Name}");

            var pe = PeImage.FromMemory(reader, m.BaseAddress);
            if (pe == null || !pe.IsValid) continue;

            foreach (var imp in pe.EnumerateImports(reader, m.BaseAddress))
            {
                ct.ThrowIfCancellationRequested();
                if (imp.ResolvedValue == 0) continue;

                bool inModule = false;
                foreach (var r in ranges)
                    if (imp.ResolvedValue >= r.s && imp.ResolvedValue < r.e) { inModule = true; break; }

                if (!inModule)
                {
                    string fn = string.IsNullOrEmpty(imp.Function) ? "(?)" : imp.Function;
                    findings.Add(new HookFinding(
                        m.Name, $"{imp.Dll}!{fn}", imp.IatAddress, "",
                        "IAT", $"0x{imp.ResolvedValue:X} (fuera de modulos)"));
                }
            }
        }
        return findings;
    }
}
