using System.Text;

namespace MemReader;

/// <summary>Una regla heuristica que ha coincidido en la memoria del proceso.</summary>
public sealed record RuleHit(
    string Rule, string Severity, string Description, int Matches, ulong FirstAddress, string Evidence)
{
    public string FirstAddressText => FirstAddress == 0 ? "" : $"0x{FirstAddress:X}";
}

/// <summary>
/// Motor de reglas heuristicas de triage (solo lectura). Cada regla es un conjunto
/// de patrones (texto o AOB) con un umbral: si coinciden suficientes, se reporta.
/// Reutiliza <see cref="StringsExtractor"/> (una sola pasada) para los patrones de
/// texto y la busqueda enmascarada para los AOB. Es deteccion heuristica: una
/// coincidencia sugiere, no confirma. No modifica nada.
/// </summary>
public static class RuleEngine
{
    private sealed record Pattern(bool IsAob, string Value);
    private sealed record Rule(string Name, string Severity, string Description, int Threshold, Pattern[] Patterns);

    private static Pattern T(string s) => new(false, s);
    private static Pattern A(string s) => new(true, s);

    private static readonly Rule[] Rules =
    {
        new("Tooling de inyeccion", "Alta",
            "APIs de inyeccion de codigo presentes en memoria", 3, new[]
            {
                T("VirtualAllocEx"), T("WriteProcessMemory"), T("CreateRemoteThread"),
                T("NtUnmapViewOfSection"), T("QueueUserAPC"), T("SetThreadContext"),
            }),
        new("Acceso al PEB (shellcode x64)", "Media",
            "Acceso directo al PEB via gs:[0x60], tipico de shellcode", 1, new[]
            {
                A("65 48 8B 04 25 60 00 00 00"),
            }),
        new("Packer UPX", "Media",
            "Marcadores del empaquetador UPX", 1, new[]
            {
                T("UPX0"), T("UPX1"), T("UPX!"),
            }),
        new("Acceso a credenciales (LSASS)", "Alta",
            "Referencias a volcado de credenciales de LSASS", 2, new[]
            {
                T("lsass.exe"), T("MiniDumpWriteDump"), T("SeDebugPrivilege"), T("sekurlsa"),
            }),
        new("Evasion AMSI/ETW", "Alta",
            "Cadenas asociadas a la evasion de AMSI o ETW", 1, new[]
            {
                T("AmsiScanBuffer"), T("EtwEventWrite"), T("amsi.dll"),
            }),
        new("Comandos de reconocimiento", "Baja",
            "Comandos de reconocimiento del sistema en memoria", 3, new[]
            {
                T("whoami"), T("ipconfig"), T("net user"), T("systeminfo"),
                T("tasklist"), T("nltest"), T("net group"),
            }),
        new("Persistencia (Run keys)", "Media",
            "Rutas de registro de arranque automatico", 1, new[]
            {
                T(@"CurrentVersion\Run"), T(@"CurrentVersion\RunOnce"),
            }),
        new("Descarga / C2", "Media",
            "APIs de red usadas para descarga o C2", 2, new[]
            {
                T("URLDownloadToFile"), T("InternetOpenUrl"), T("WinHttpConnect"),
                T("socket"), T("WSAStartup"),
            }),
    };

    public static List<RuleHit> Scan(
        ProcessMemoryReader reader, IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Extrayendo cadenas para las reglas...");
        var strings = StringsExtractor.Extract(reader, 3, 500000, progress, ct);

        var hits = new List<RuleHit>();
        int idx = 0;
        foreach (var rule in Rules)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"Reglas... {idx}/{Rules.Length}: {rule.Name}");

            int matched = 0;
            ulong first = 0;
            var evidence = new List<string>();

            foreach (var pat in rule.Patterns)
            {
                ct.ThrowIfCancellationRequested();
                bool found = false;
                ulong addr = 0;

                if (pat.IsAob)
                {
                    try
                    {
                        var (p, m) = ValueInterpreter.ParseAob(pat.Value);
                        var ph = reader.SearchMasked(p, m, "AOB", 1, null, ct);
                        if (ph.Count > 0) { found = true; addr = ph[0].Address; }
                    }
                    catch { /* patron invalido: se ignora */ }
                }
                else
                {
                    foreach (var s in strings)
                    {
                        if (s.Text.Contains(pat.Value, StringComparison.OrdinalIgnoreCase))
                        {
                            found = true;
                            addr = s.Address;
                            break;
                        }
                    }
                }

                if (found)
                {
                    matched++;
                    evidence.Add(pat.Value);
                    if (first == 0) first = addr;
                }
            }

            if (matched >= rule.Threshold)
                hits.Add(new RuleHit(
                    rule.Name, rule.Severity, rule.Description, matched, first, string.Join(", ", evidence)));
        }

        return hits;
    }
}
