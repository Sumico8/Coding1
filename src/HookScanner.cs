using System.Text;

namespace MemReader;

/// <summary>Un hook inline detectado en el prologo de una funcion exportada.</summary>
public sealed record HookFinding(
    string Module, string Function, ulong Address, string PrologueHex, string HookType, string Target)
{
    public string AddressText => $"0x{Address:X}";
}

/// <summary>
/// Detecta hooks inline en las funciones exportadas de las DLL del sistema mas
/// habituales (ntdll, kernel32, ...). Lee el prologo en memoria y marca los que
/// empiezan con un salto (E9 / FF25 / push+ret / mov rax;jmp rax), resolviendo a
/// que modulo apunta el salto (normalmente el EDR/antivirus o una DLL inyectada).
/// Es SOLO deteccion/reporte: no quita hooks ni "limpia" ninguna DLL.
/// </summary>
public static class HookScanner
{
    private static readonly string[] TargetModules =
    {
        "ntdll.dll", "kernelbase.dll", "kernel32.dll",
        "user32.dll", "advapi32.dll", "ws2_32.dll",
    };

    public static List<HookFinding> Scan(
        ProcessMemoryReader reader, IProgress<string>? progress, CancellationToken ct)
    {
        var findings = new List<HookFinding>();
        var modules = reader.EnumerateModules();
        var ranges = modules
            .Select(m => (m.Name, start: m.BaseAddress, end: m.BaseAddress + (ulong)m.Size))
            .ToList();
        bool wow64 = reader.IsTargetWow64();

        foreach (var m in modules)
        {
            ct.ThrowIfCancellationRequested();
            if (!TargetModules.Contains(m.Name, StringComparer.OrdinalIgnoreCase)) continue;
            progress?.Report($"Buscando hooks en {m.Name}...");

            var pe = PeImage.FromMemory(reader, m.BaseAddress);
            if (pe == null || !pe.IsValid) continue;
            var (expRva, expSize) = pe.Directory(PeImage.DIR_EXPORT);

            foreach (var (name, funcRva) in pe.EnumerateExports(reader, m.BaseAddress))
            {
                ct.ThrowIfCancellationRequested();
                if (funcRva == 0) continue;
                // Saltar exports "forwarded" (su RVA apunta al propio export directory).
                if (expRva != 0 && funcRva >= expRva && funcRva < expRva + expSize) continue;

                ulong addr = m.BaseAddress + funcRva;
                byte[] p;
                try { p = reader.ReadBytes(addr, 16); }
                catch { continue; }
                if (p.Length < 5) continue;

                var (type, targetVa) = Classify(p, addr, wow64);
                if (type == null) continue;

                findings.Add(new HookFinding(
                    m.Name, name, addr, HexBytes(p, 8), type, ResolveTarget(targetVa, ranges)));
            }
        }
        return findings;
    }

    private static (string? type, ulong targetVa) Classify(byte[] p, ulong addr, bool wow64)
    {
        // E9 rel32: jmp
        if (p[0] == 0xE9 && p.Length >= 5)
        {
            int rel = BitConverter.ToInt32(p, 1);
            return ("jmp rel32", unchecked(addr + 5 + (ulong)(long)rel));
        }
        // EB rel8: jmp corto
        if (p[0] == 0xEB && p.Length >= 2)
        {
            sbyte rel = (sbyte)p[1];
            return ("jmp rel8", unchecked(addr + 2 + (ulong)(long)rel));
        }
        // FF 25 disp32: jmp [rip+disp] (x64) o jmp [addr] (x86). Destino indirecto.
        if (p[0] == 0xFF && p[1] == 0x25 && p.Length >= 6)
            return ("jmp [mem]", 0);
        // 68 imm32 C3: push imm; ret
        if (p[0] == 0x68 && p.Length >= 6 && p[5] == 0xC3)
            return ("push/ret", BitConverter.ToUInt32(p, 1));
        // 48 B8 imm64 ... FF E0: mov rax, imm64; jmp rax
        if (p[0] == 0x48 && p[1] == 0xB8 && p.Length >= 12 && p[10] == 0xFF && p[11] == 0xE0)
            return ("mov rax;jmp rax", BitConverter.ToUInt64(p, 2));

        return (null, 0);
    }

    private static string ResolveTarget(ulong va, List<(string Name, ulong start, ulong end)> ranges)
    {
        if (va == 0) return "(indirecto)";
        foreach (var r in ranges)
            if (va >= r.start && va < r.end)
                return $"{r.Name}+0x{va - r.start:X}";
        return $"0x{va:X} (fuera de modulos)";
    }

    private static string HexBytes(byte[] d, int len)
    {
        var sb = new StringBuilder(len * 3);
        for (int i = 0; i < len && i < d.Length; i++)
            sb.Append(d[i].ToString("X2")).Append(' ');
        return sb.ToString().TrimEnd();
    }
}
