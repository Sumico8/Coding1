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

    // Tipos de minidump (subconjunto). WithFullMemory produce un volcado grande
    // pero completo, analizable en WinDbg. Es la misma capacidad que "Crear
    // archivo de volcado" del Administrador de tareas.
    public const int MiniDumpNormal = 0x00000000;
    public const int MiniDumpWithFullMemory = 0x00000002;

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        int dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    // ---- Enumeracion de hilos (Toolhelp + ntdll) ----
    public const uint TH32CS_SNAPTHREAD = 0x00000004;
    public const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    // ThreadQuerySetWin32StartAddress = 9
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(
        IntPtr threadHandle, int threadInformationClass,
        ref ulong threadInformation, int threadInformationLength, out int returnLength);

    // ---- Consola para el modo CLI headless (kernel32) ----
    // Permiten que un binario WinExe escriba en la consola que lo lanzo, o
    // detectar si su salida esta redirigida a un archivo/tuberia. Es solo E/S
    // de consola: nada que ver con leer la memoria de otros procesos.
    public const int ATTACH_PARENT_PROCESS = -1;
    public const int STD_OUTPUT_HANDLE = -11;
    public const uint FILE_TYPE_UNKNOWN = 0x0000;
    public const uint FILE_TYPE_DISK = 0x0001;
    public const uint FILE_TYPE_CHAR = 0x0002;
    public const uint FILE_TYPE_PIPE = 0x0003;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetFileType(IntPtr hFile);

    // ---- Enumeracion de handles (ntdll + kernel32) ----
    // Para resolver el TIPO/NOMBRE de los handles de otro proceso hace falta
    // DuplicateHandle, que exige PROCESS_DUP_HANDLE sobre el objetivo. Es la unica
    // ampliacion sobre el minimo de solo-lectura, y solo para esta funcion: se abre
    // un handle aparte y nunca se pide acceso de escritura a la memoria del proceso.
    public const uint PROCESS_DUP_HANDLE = 0x0040;
    public const int SystemExtendedHandleInformation = 64;
    public const int ObjectNameInformation = 1;
    public const int ObjectTypeInformation = 2;
    public const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(
        int systemInformationClass, IntPtr systemInformation,
        int systemInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryObject(
        IntPtr handle, int objectInformationClass, IntPtr objectInformation,
        int objectInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle, uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    // ---- Informacion de proceso (ntdll) ----
    // ProcessBasicInformation (0) da el PID padre; ProcessCommandLineInformation
    // (60, Win8.1+) da la linea de comandos. Solo consulta, sin escribir nada.
    public const int ProcessBasicInformation = 0;
    public const int ProcessCommandLineInformation = 60;

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass, IntPtr processInformation,
        int processInformationLength, out int returnLength);

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
