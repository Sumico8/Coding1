using System.Text.RegularExpressions;

namespace MemReader;

/// <summary>Un indicador de compromiso (IOC) hallado en la memoria del proceso.</summary>
public sealed record Ioc(string Type, string Value, ulong Address)
{
    public string AddressText => $"0x{Address:X}";
}

/// <summary>
/// Extrae indicadores de compromiso (IOCs) de las cadenas en memoria: IPs, URLs,
/// dominios, correos, rutas de Windows/UNC, claves de registro y GUIDs. Reutiliza
/// <see cref="StringsExtractor"/> y clasifica con expresiones regulares. Es solo
/// lectura y sin conexion: no consulta ningun servicio externo.
/// </summary>
public static class IocExtractor
{
    // Timeout por coincidencia: evita retrocesos patologicos sobre datos raros.
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(1);

    private static Regex R(string pattern) =>
        new(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, MatchTimeout);

    private static readonly (string type, Regex rx)[] Patterns =
    {
        ("IPv4", R(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
        ("URL", R(@"\b(?:https?|ftp)://[^\s""'<>\[\]]{3,}")),
        ("Email", R(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")),
        ("RutaWin", R(@"\b[A-Za-z]:\\[^\s""'<>|?*\r\n]{2,}")),
        ("RutaUNC", R(@"\\\\[A-Za-z0-9._\-]+\\[^\s""'<>|?*\r\n]{2,}")),
        ("Registro", R(@"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)\\[^\s""'<>|?*\r\n]{2,}")),
        ("GUID", R(@"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")),
        ("Dominio", R(@"\b(?:[A-Za-z0-9\-]{1,63}\.)+(?:com|net|org|io|gov|edu|mil|info|biz|co|us|uk|ru|cn|de|fr|jp|br|xyz|top|online|site|club|shop|app|dev|cloud|onion)\b")),
    };

    /// <summary>Extrae IOCs abriendo el proceso y sacando primero sus cadenas.</summary>
    public static List<Ioc> Extract(
        ProcessMemoryReader reader, int minLen, int maxStrings,
        IProgress<string>? progress, CancellationToken ct)
    {
        var strings = StringsExtractor.Extract(reader, minLen, maxStrings, progress, ct);
        return ExtractFrom(strings, progress, ct);
    }

    /// <summary>Clasifica IOCs sobre un conjunto de cadenas ya extraidas.</summary>
    public static List<Ioc> ExtractFrom(
        IEnumerable<FoundString> strings, IProgress<string>? progress, CancellationToken ct)
    {
        var seen = new HashSet<string>();
        var result = new List<Ioc>();
        int i = 0;
        foreach (var s in strings)
        {
            ct.ThrowIfCancellationRequested();
            if ((++i & 0x3FFF) == 0)
                progress?.Report($"Extrayendo IOCs... {result.Count:N0} unicos");

            foreach (var (type, rx) in Patterns)
            {
                MatchCollection matches;
                try { matches = rx.Matches(s.Text); }
                catch (RegexMatchTimeoutException) { continue; }

                foreach (Match m in matches)
                {
                    string val = m.Value;
                    if (val.Length > 512) continue; // descarta rachas absurdamente largas
                    string key = type + "|" + val;
                    if (seen.Add(key))
                        result.Add(new Ioc(type, val, s.Address + (ulong)m.Index));
                }
            }
        }
        return result;
    }
}
