using System.Runtime.InteropServices;

namespace MemReader;

public sealed record ThreadInfo(uint Tid, ulong StartAddress, int BasePriority);

/// <summary>
/// Enumera los hilos de un proceso (via Toolhelp) y obtiene su direccion de inicio
/// (NtQueryInformationThread). Un start address fuera de todo modulo suele indicar
/// codigo inyectado. Solo lectura.
/// </summary>
public static class ThreadInspector
{
    private const int ThreadQuerySetWin32StartAddress = 9;

    public static List<ThreadInfo> Enumerate(int pid)
    {
        var list = new List<ThreadInfo>();
        IntPtr snap = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
        if (snap == NativeMethods.INVALID_HANDLE_VALUE || snap == IntPtr.Zero)
            return list;

        try
        {
            var te = new NativeMethods.THREADENTRY32
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>()
            };

            if (NativeMethods.Thread32First(snap, ref te))
            {
                do
                {
                    if (te.th32OwnerProcessID != (uint)pid) continue;

                    ulong start = 0;
                    IntPtr h = NativeMethods.OpenThread(
                        NativeMethods.THREAD_QUERY_LIMITED_INFORMATION, false, te.th32ThreadID);
                    if (h != IntPtr.Zero)
                    {
                        ulong buf = 0;
                        int status = NativeMethods.NtQueryInformationThread(
                            h, ThreadQuerySetWin32StartAddress, ref buf, 8, out _);
                        if (status == 0) start = buf;
                        NativeMethods.CloseHandle(h);
                    }
                    list.Add(new ThreadInfo(te.th32ThreadID, start, te.tpBasePri));
                }
                while (NativeMethods.Thread32Next(snap, ref te));
            }
        }
        finally
        {
            NativeMethods.CloseHandle(snap);
        }
        return list;
    }
}
