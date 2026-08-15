using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>Un handle abierto por el proceso: tipo, nombre y acceso concedido.</summary>
public sealed record HandleInfo(string Type, string Name, ulong Handle, uint GrantedAccess)
{
    public string HandleText => $"0x{Handle:X}";
    public string AccessText => $"0x{GrantedAccess:X}";
}

/// <summary>
/// Enumera los handles que tiene abiertos un proceso (via NtQuerySystemInformation)
/// y resuelve su tipo y, opcionalmente, su nombre. Nombres como los de mutex o
/// eventos con nombre son IOCs valiosos en triage. La resolucion de nombres se
/// hace en un hilo con timeout porque NtQueryObject puede colgarse con algunos
/// handles (p. ej. named pipes sincronas). Solo lectura del estado; se abre un
/// handle con PROCESS_DUP_HANDLE solo para duplicar y consultar.
/// </summary>
public static class HandleInspector
{
    private const int MaxHandles = 20000;
    private const int NameTimeoutMs = 50;

    public static List<HandleInfo> Enumerate(
        int pid, bool resolveNames, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new List<HandleInfo>();

        int len = 0x100000;
        IntPtr buf = Marshal.AllocHGlobal(len);
        IntPtr targetProc = IntPtr.Zero;
        try
        {
            uint status;
            while ((status = NativeMethods.NtQuerySystemInformation(
                       NativeMethods.SystemExtendedHandleInformation, buf, len, out int need))
                   == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal(buf);
                len = Math.Max(need, len * 2);
                if (len > 256 * 1024 * 1024) { buf = IntPtr.Zero; break; }
                buf = Marshal.AllocHGlobal(len);
            }
            if (status != 0 || buf == IntPtr.Zero) return result;

            long n = Marshal.ReadIntPtr(buf).ToInt64(); // NumberOfHandles
            int entrySize = Marshal.SizeOf<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
            IntPtr entriesBase = buf + IntPtr.Size * 2; // salta NumberOfHandles + Reserved

            targetProc = NativeMethods.OpenProcess(NativeMethods.PROCESS_DUP_HANDLE, false, pid);
            IntPtr self = NativeMethods.GetCurrentProcess();
            var typeCache = new Dictionary<ushort, string>();

            for (long i = 0; i < n && result.Count < MaxHandles; i++)
            {
                ct.ThrowIfCancellationRequested();
                IntPtr entryPtr = entriesBase + (int)(i * entrySize);
                var e = Marshal.PtrToStructure<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(entryPtr);
                if (e.UniqueProcessId.ToInt64() != pid) continue;
                if ((result.Count & 0x1FF) == 0) progress?.Report($"Enumerando handles... {result.Count}");

                string type = "(?)";
                string name = "";
                if (targetProc != IntPtr.Zero &&
                    NativeMethods.DuplicateHandle(targetProc, e.HandleValue, self, out IntPtr dup,
                        0, false, NativeMethods.DUPLICATE_SAME_ACCESS))
                {
                    type = QueryType(dup, e.ObjectTypeIndex, typeCache);
                    if (resolveNames) name = QueryNameWithTimeout(dup);
                    NativeMethods.CloseHandle(dup);
                }
                result.Add(new HandleInfo(type, name, (ulong)e.HandleValue.ToInt64(), e.GrantedAccess));
            }
        }
        finally
        {
            if (targetProc != IntPtr.Zero) NativeMethods.CloseHandle(targetProc);
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
        return result;
    }

    private static string QueryType(IntPtr h, ushort typeIndex, Dictionary<ushort, string> cache)
    {
        if (cache.TryGetValue(typeIndex, out var cached)) return cached;
        string type = QueryObjectString(h, NativeMethods.ObjectTypeInformation);
        if (type.Length == 0) type = "(?)";
        cache[typeIndex] = type;
        return type;
    }

    private static string QueryNameWithTimeout(IntPtr h)
    {
        string name = "";
        var t = new Thread(() =>
        {
            try { name = QueryObjectString(h, NativeMethods.ObjectNameInformation); }
            catch { /* ignore */ }
        })
        { IsBackground = true };
        t.Start();
        return t.Join(NameTimeoutMs) ? name : "(timeout)";
    }

    private static string QueryObjectString(IntPtr h, int infoClass)
    {
        int len = 0x1000;
        IntPtr b = Marshal.AllocHGlobal(len);
        try
        {
            uint st = NativeMethods.NtQueryObject(h, infoClass, b, len, out int need);
            if (st == NativeMethods.STATUS_INFO_LENGTH_MISMATCH && need > 0)
            {
                Marshal.FreeHGlobal(b);
                len = need;
                b = Marshal.AllocHGlobal(len);
                st = NativeMethods.NtQueryObject(h, infoClass, b, len, out _);
            }
            if (st != 0) return "";
            // Tanto OBJECT_TYPE_INFORMATION como OBJECT_NAME_INFORMATION empiezan por
            // un UNICODE_STRING con el texto.
            var us = Marshal.PtrToStructure<NativeMethods.UNICODE_STRING>(b);
            if (us.Buffer == IntPtr.Zero || us.Length == 0) return "";
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? "";
        }
        catch { return ""; }
        finally { Marshal.FreeHGlobal(b); }
    }
}
