using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>
/// P/Invoke a las APIs documentadas de Windows (kernel32 / advapi32).
/// Todo lo que hace esta herramienta se apoya en funciones publicas y
/// soportadas por Microsoft. No hay drivers ni tecnicas para saltarse las
/// protecciones del sistema operativo.
/// </summary>
internal static class NativeMethods
{
    // ---- Derechos de acceso a procesos ----
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_VM_READ = 0x0010;

    // ---- Estado de las regiones de memoria (MEMORY_BASIC_INFORMATION.State) ----
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_FREE = 0x10000;
    public const uint MEM_RESERVE = 0x2000;

    // ---- Tipo de region (MEMORY_BASIC_INFORMATION.Type) ----
    public const uint MEM_IMAGE = 0x1000000;
    public const uint MEM_MAPPED = 0x40000;
    public const uint MEM_PRIVATE = 0x20000;

    // ---- Proteccion de paginas (MEMORY_BASIC_INFORMATION.Protect) ----
    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;

    /// <summary>
    /// Estructura de 64 bits para VirtualQueryEx. El binario se compila como
    /// x64 (ver .csproj), por eso usamos el layout de 64 bits con relleno.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint __alignment2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        IntPtr nSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer,
        IntPtr dwLength);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

    /// <summary>Devuelve true si la proteccion de la pagina permite lectura.</summary>
    public static bool IsReadable(uint protect)
    {
        // Una pagina con PAGE_GUARD o PAGE_NOACCESS no se puede leer directamente.
        if ((protect & PAGE_GUARD) != 0) return false;
        if (protect == 0 || protect == PAGE_NOACCESS) return false;

        uint readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        return (protect & readable) != 0;
    }

    public static string ProtectToString(uint protect)
    {
        uint baseProtect = protect & ~PAGE_GUARD;
        string s = baseProtect switch
        {
            PAGE_NOACCESS => "NOACCESS",
            PAGE_READONLY => "R",
            PAGE_READWRITE => "RW",
            PAGE_WRITECOPY => "WC",
            PAGE_EXECUTE => "X",
            PAGE_EXECUTE_READ => "RX",
            PAGE_EXECUTE_READWRITE => "RWX",
            PAGE_EXECUTE_WRITECOPY => "RWXC",
            _ => $"0x{protect:X}"
        };
        if ((protect & PAGE_GUARD) != 0) s += "+GUARD";
        return s;
    }

    public static string TypeToString(uint type) => type switch
    {
        MEM_IMAGE => "IMAGE",
        MEM_MAPPED => "MAPPED",
        MEM_PRIVATE => "PRIVATE",
        _ => $"0x{type:X}"
    };
}
