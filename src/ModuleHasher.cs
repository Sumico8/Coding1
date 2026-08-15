using System.Security.Cryptography;

namespace MemReader;

/// <summary>SHA-256 del archivo en disco de un modulo cargado (mas su URL de VirusTotal).</summary>
public sealed record ModuleHash(string Name, ulong BaseAddress, string? Path, string? Sha256, string? Note)
{
    public string BaseText => $"0x{BaseAddress:X}";

    /// <summary>URL de consulta en VirusTotal (no se hace ninguna peticion de red).</summary>
    public string VirusTotalUrl => string.IsNullOrEmpty(Sha256)
        ? ""
        : "https://www.virustotal.com/gui/file/" + Sha256;
}

/// <summary>
/// Calcula el SHA-256 del ARCHIVO EN DISCO de cada modulo cargado en un proceso.
/// Sirve para comparar contra listas de conocidos-buenos/maliciosos o para armar
/// una URL de consulta de VirusTotal. No realiza ninguna peticion de red: solo
/// genera el hash y la URL, que el usuario decide si copia. Solo lectura.
/// </summary>
public static class ModuleHasher
{
    public static string? HashFile(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            byte[] h = sha.ComputeHash(fs);
            return Convert.ToHexString(h).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    public static List<ModuleHash> Compute(
        ProcessMemoryReader reader, IProgress<string>? progress, CancellationToken ct)
    {
        var list = new List<ModuleHash>();
        var modules = reader.EnumerateModules();
        int i = 0;
        foreach (var m in modules)
        {
            ct.ThrowIfCancellationRequested();
            i++;
            progress?.Report($"Calculando hashes... {i}/{modules.Count}");

            if (string.IsNullOrEmpty(m.Path) || !File.Exists(m.Path))
            {
                list.Add(new ModuleHash(m.Name, m.BaseAddress, m.Path, null, "ruta no disponible"));
                continue;
            }

            string? hash = HashFile(m.Path);
            list.Add(new ModuleHash(
                m.Name, m.BaseAddress, m.Path, hash,
                hash == null ? "no se pudo leer el archivo" : null));
        }
        return list;
    }
}
