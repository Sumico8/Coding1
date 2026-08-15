using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>Datos de contexto de un proceso: linea de comandos, padre, sesion...</summary>
public sealed record ProcessDetails(
    int Pid, int ParentPid, string ParentName, string CommandLine,
    string StartTime, int SessionId, string? Error);

/// <summary>
/// Obtiene contexto de triage de un proceso: linea de comandos y PID padre (via
/// NtQueryInformationProcess) mas hora de inicio y sesion (via el API gestionado).
/// La linea de comandos y la cadena padre-hijo son IOCs de primer nivel. Solo
/// consulta informacion; no lee ni modifica la memoria del proceso.
/// </summary>
public static class ProcessInfo
{
    public static ProcessDetails Get(int pid)
    {
        int ppid = 0;
        string cmdline = "";
        string parentName = "";
        string start = "";
        int session = -1;
        string? error = null;

        IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                ppid = QueryParentPid(h);
                cmdline = QueryCommandLine(h);
            }
            finally { NativeMethods.CloseHandle(h); }
        }
        else
        {
            error = "no se pudo abrir el proceso para consultarlo.";
        }

        try
        {
            using var p = Process.GetProcessById(pid);
            try { start = p.StartTime.ToString("yyyy-MM-dd HH:mm:ss"); } catch { /* acceso denegado */ }
            try { session = p.SessionId; } catch { /* ignore */ }
        }
        catch { /* el proceso pudo terminar */ }

        if (ppid > 0)
        {
            try { using var pp = Process.GetProcessById(ppid); parentName = pp.ProcessName; }
            catch { /* el padre pudo terminar */ }
        }

        return new ProcessDetails(pid, ppid, parentName, cmdline, start, session, error);
    }

    private static int QueryParentPid(IntPtr h)
    {
        // PROCESS_BASIC_INFORMATION. Como este binario es x64, el layout es de 64
        // bits: InheritedFromUniqueProcessId esta en el offset 40.
        int size = IntPtr.Size == 8 ? 48 : 24;
        int off = IntPtr.Size == 8 ? 40 : 20;
        IntPtr b = Marshal.AllocHGlobal(size);
        try
        {
            uint st = NativeMethods.NtQueryInformationProcess(
                h, NativeMethods.ProcessBasicInformation, b, size, out _);
            if (st != 0) return 0;
            return (int)Marshal.ReadIntPtr(b, off).ToInt64();
        }
        catch { return 0; }
        finally { Marshal.FreeHGlobal(b); }
    }

    private static string QueryCommandLine(IntPtr h)
    {
        int len = 0x1000;
        IntPtr b = Marshal.AllocHGlobal(len);
        try
        {
            uint st = NativeMethods.NtQueryInformationProcess(
                h, NativeMethods.ProcessCommandLineInformation, b, len, out int need);
            if (st == NativeMethods.STATUS_INFO_LENGTH_MISMATCH && need > 0)
            {
                Marshal.FreeHGlobal(b);
                len = need;
                b = Marshal.AllocHGlobal(len);
                st = NativeMethods.NtQueryInformationProcess(
                    h, NativeMethods.ProcessCommandLineInformation, b, len, out _);
            }
            if (st != 0) return "";
            var us = Marshal.PtrToStructure<NativeMethods.UNICODE_STRING>(b);
            if (us.Buffer == IntPtr.Zero || us.Length == 0) return "";
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? "";
        }
        catch { return ""; }
        finally { Marshal.FreeHGlobal(b); }
    }
}
