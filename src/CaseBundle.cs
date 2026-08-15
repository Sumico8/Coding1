using System.IO.Compression;
using System.Text;

namespace MemReader;

/// <summary>
/// Empaqueta en un solo .zip todo lo necesario para archivar el analisis de un
/// proceso: el informe de triage (HTML + JSON, con hashes e IOCs), un minidump y
/// un indice de regiones de memoria. Pensado como entregable de un caso de DFIR.
/// Reutiliza el motor de informe, el minidump y la enumeracion de regiones. Solo
/// lectura del proceso.
/// </summary>
public static class CaseBundle
{
    public static string Create(
        int pid, string outPath, bool fullMinidump,
        IProgress<string>? progress, CancellationToken ct)
    {
        if (!outPath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            outPath += ".zip";

        progress?.Report("Generando informe...");
        var report = TriageEngine.Analyze(pid, progress, ct, hashModules: true, extractIocs: true);
        string html = HtmlReportWriter.Write(report);
        string json = JsonReportWriter.Write(report);

        string regionsIndex;
        string tmpDmp = Path.Combine(Path.GetTempPath(), $"memreader_{Guid.NewGuid():N}.dmp");
        using (var reader = new ProcessMemoryReader(pid))
        {
            var sb = new StringBuilder();
            sb.AppendLine("base\tsize\tprotect\ttype");
            foreach (var rg in reader.EnumerateRegions(onlyReadable: false))
                sb.AppendLine($"0x{rg.BaseAddress:X}\t{rg.RegionSize}\t{rg.ProtectText}\t{rg.TypeText}");
            regionsIndex = sb.ToString();

            progress?.Report("Generando minidump...");
            try { reader.WriteMiniDump(tmpDmp, fullMinidump); }
            catch { tmpDmp = ""; }
        }

        progress?.Report("Empaquetando .zip...");
        using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            AddText(zip, "informe.html", html);
            AddText(zip, "informe.json", json);
            AddText(zip, "regiones.txt", regionsIndex);

            if (!string.IsNullOrEmpty(tmpDmp) && File.Exists(tmpDmp))
            {
                var entry = zip.CreateEntry($"pid{pid}.dmp", CompressionLevel.Fastest);
                using var es = entry.Open();
                using var dfs = File.OpenRead(tmpDmp);
                dfs.CopyTo(es);
            }
        }

        if (!string.IsNullOrEmpty(tmpDmp))
            try { File.Delete(tmpDmp); } catch { /* archivo temporal */ }

        return outPath;
    }

    private static void AddText(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var w = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        w.Write(content);
    }
}
