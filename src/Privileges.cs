using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>
/// Habilita SeDebugPrivilege en el token del proceso actual usando la API
/// documentada AdjustTokenPrivileges. Este privilegio solo esta disponible si
/// la aplicacion ya se ejecuta elevada (Administrador); no otorga permisos que
/// el sistema no conceda por si mismo, simplemente activa un privilegio que ya
/// posee el token de administrador. Sigue sin poder abrir procesos protegidos (PPL).
/// </summary>
internal static class Privileges
{
    private const int SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const string SE_DEBUG_NAME = "SeDebugPrivilege";

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? host, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>Devuelve true si se logro habilitar SeDebugPrivilege.</summary>
    public static bool EnableDebugPrivilege()
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                return false;

            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out LUID luid))
                return false;

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED
            };

            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;

            // AdjustTokenPrivileges puede devolver true pero fijar ERROR_NOT_ALL_ASSIGNED
            // si el token no tiene el privilegio (p. ej. no elevado).
            return Marshal.GetLastWin32Error() == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }
}
