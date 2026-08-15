using System.Diagnostics;

namespace MemReader;

/// <summary>Resumen ligero de triage de un proceso, con una puntuacion de sospecha.</summary>
public sealed record ProcessTriage(
    int Pid, string Name, string Arch, int RwxRegions, int UnbackedExec,
    int SuspiciousThreads, int Score, string? Error);

/// <summary>
/// Recorre todos los procesos accesibles y hace un triage LIGERO de cada uno
/// (regiones RWX, memoria ejecutable no respaldada por imagen e hilos con inicio
/// anomalo), asignando una puntuacion para ordenar los mas sospechosos primero.
/// Es resistente: si un proceso no se puede abrir, se anota y se sigue. Solo
/// lectura. No hace el analisis profundo (strings/IOCs) de cada proceso para no
/// ser lento ni intrusivo; para eso usa el informe por PID.
/// </summary>
public static class BatchTriage
{
    public static List<ProcessTriage> ScanAll(
        string? filter, IProgress<string>? progress, CancellationToken ct)
    {
        var results = new List<ProcessTriage>();
        var procs = Process.GetProcesses();
        int i = 0;
        foreach (var p in procs)
        {
            ct.ThrowIfCancellationRequested();
            i++;
            string name;
            try { name = p.ProcessName; } catch { name = "(desconocido)"; }
            if (!string.IsNullOrEmpty(filter) &&
                !name.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                p.Dispose();
                continue;
            }
            progress?.Report($"Triage {i}/{procs.Length}: {name}");
            results.Add(TriageOne(p.Id, name, ct));
            p.Dispose();
        }
        results.Sort((x, y) => y.Score.CompareTo(x.Score));
        return results;
    }

    private static ProcessTriage TriageOne(int pid, string name, CancellationToken ct)
    {
        try
        {
            using var reader = new ProcessMemoryReader(pid);
            string arch = reader.IsTargetWow64() ? "x86" : "x64";

            int rwx = 0, unbacked = 0;
            foreach (var r in reader.EnumerateRegions(onlyReadable: false))
            {
                ct.ThrowIfCancellationRequested();
                if (r.State != NativeMethods.MEM_COMMIT) continue;
                uint prot = r.Protect & 0xFF;
                bool exec = prot == NativeMethods.PAGE_EXECUTE
                    || prot == NativeMethods.PAGE_EXECUTE_READ
                    || prot == NativeMethods.PAGE_EXECUTE_READWRITE
                    || prot == NativeMethods.PAGE_EXECUTE_WRITECOPY;
                if (prot == NativeMethods.PAGE_EXECUTE_READWRITE) rwx++;
                if (exec && r.Type != NativeMethods.MEM_IMAGE) unbacked++;
            }

            var ranges = reader.EnumerateModules()
                .Select(m => (s: m.BaseAddress, e: m.BaseAddress + (ulong)m.Size))
                .ToList();
            int susp = 0;
            foreach (var t in ThreadInspector.Enumerate(pid))
            {
                if (t.StartAddress == 0) continue;
                if (!ranges.Any(rg => t.StartAddress >= rg.s && t.StartAddress < rg.e)) susp++;
            }

            int score = rwx * 3 + unbacked * 3 + susp * 2;
            return new ProcessTriage(pid, name, arch, rwx, unbacked, susp, score, null);
        }
        catch (Exception ex)
        {
            return new ProcessTriage(pid, name, "?", 0, 0, 0, 0, ex.Message);
        }
    }
}
