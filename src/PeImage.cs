using System.Text;

namespace MemReader;

/// <summary>Una seccion del PE (.text, .data, .rdata, ...).</summary>
public sealed record PeSection(
    string Name, uint VirtualAddress, uint VirtualSize,
    uint PointerToRawData, uint SizeOfRawData, uint Characteristics)
{
    private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private const uint IMAGE_SCN_MEM_READ = 0x40000000;
    private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

    public bool IsExecutable => (Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    public bool IsReadable => (Characteristics & IMAGE_SCN_MEM_READ) != 0;
    public bool IsWritable => (Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    /// <summary>Permisos como texto "RWX" (- si no aplica).</summary>
    public string PermText
    {
        get
        {
            Span<char> c = stackalloc char[3];
            c[0] = IsReadable ? 'R' : '-';
            c[1] = IsWritable ? 'W' : '-';
            c[2] = IsExecutable ? 'X' : '-';
            return new string(c);
        }
    }
}

/// <summary>
/// Parser de cabeceras PE (PE32 y PE32+), desde un buffer de bytes o desde la
/// memoria de un proceso. Es solo parseo/lectura: no ejecuta ni modifica nada.
/// Base compartida para el analisis de modulos (secciones, mitigaciones),
/// integridad (comparar con el archivo en disco) y deteccion de hooks.
/// </summary>
public sealed class PeImage
{
    // Indices de data directory (IMAGE_DIRECTORY_ENTRY_*).
    public const int DIR_EXPORT = 0;
    public const int DIR_IMPORT = 1;
    public const int DIR_BASERELOC = 5;
    public const int DIR_TLS = 9;

    // Bits de DllCharacteristics (mitigaciones).
    public const ushort HIGH_ENTROPY_VA = 0x0020;
    public const ushort DYNAMIC_BASE = 0x0040; // ASLR
    public const ushort FORCE_INTEGRITY = 0x0080;
    public const ushort NX_COMPAT = 0x0100;    // DEP
    public const ushort GUARD_CF = 0x4000;     // CFG

    public bool Is64Bit { get; private set; }
    public ushort Machine { get; private set; }
    public ushort NumberOfSections { get; private set; }
    public ulong ImageBase { get; private set; }
    public uint SizeOfImage { get; private set; }
    public uint SizeOfHeaders { get; private set; }
    public uint AddressOfEntryPoint { get; private set; }
    public ushort DllCharacteristics { get; private set; }
    public bool IsValid { get; private set; }

    private readonly List<PeSection> _sections = new();
    private (uint rva, uint size)[] _dirs = Array.Empty<(uint, uint)>();

    public IReadOnlyList<PeSection> Sections => _sections;

    public bool HasAslr => (DllCharacteristics & DYNAMIC_BASE) != 0;
    public bool HasDep => (DllCharacteristics & NX_COMPAT) != 0;
    public bool HasCfg => (DllCharacteristics & GUARD_CF) != 0;

    /// <summary>Devuelve (rva, size) del data directory indicado, o (0,0).</summary>
    public (uint rva, uint size) Directory(int index)
        => index >= 0 && index < _dirs.Length ? _dirs[index] : (0u, 0u);

    /// <summary>La seccion que contiene un RVA dado, si existe.</summary>
    public PeSection? SectionForRva(uint rva)
    {
        foreach (var s in _sections)
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
                return s;
        return null;
    }

    /// <summary>Parsea desde un buffer que contiene al menos las cabeceras.</summary>
    public static PeImage? Parse(byte[] d)
    {
        var pe = new PeImage();
        return pe.TryParse(d) ? pe : null;
    }

    /// <summary>Parsea las cabeceras leyendolas de la memoria del proceso.</summary>
    public static PeImage? FromMemory(ProcessMemoryReader reader, ulong baseAddr)
    {
        byte[] probe;
        try { probe = reader.ReadBytes(baseAddr, 0x1000); }
        catch { return null; }
        var pe = Parse(probe);
        if (pe == null) return null;

        // Si la tabla de secciones excede lo leido, releemos SizeOfHeaders.
        uint needed = pe.SizeOfHeaders;
        if (needed > (uint)probe.Length && needed <= 0x10000)
        {
            try
            {
                byte[] more = reader.ReadBytes(baseAddr, (int)needed);
                var pe2 = Parse(more);
                if (pe2 != null) return pe2;
            }
            catch { /* nos quedamos con lo ya parseado */ }
        }
        return pe;
    }

    private bool TryParse(byte[] d)
    {
        if (d.Length < 0x40) return false;
        if (d[0] != 0x4D || d[1] != 0x5A) return false; // "MZ"
        int e = BitConverter.ToInt32(d, 0x3C);
        if (e < 0 || e + 24 > d.Length) return false;
        // Firma "PE\0\0".
        if (d[e] != 0x50 || d[e + 1] != 0x45 || d[e + 2] != 0 || d[e + 3] != 0) return false;

        int coff = e + 4;
        Machine = BitConverter.ToUInt16(d, coff + 0);
        NumberOfSections = BitConverter.ToUInt16(d, coff + 2);
        ushort sizeOpt = BitConverter.ToUInt16(d, coff + 16);
        int opt = coff + 20; // inicio del optional header
        if (opt + 2 > d.Length) return false;

        ushort magic = BitConverter.ToUInt16(d, opt + 0);
        if (magic != 0x10B && magic != 0x20B) return false;
        Is64Bit = magic == 0x20B;

        // Campos comunes a PE32 y PE32+ (mismos offsets).
        if (!ReadU32(d, opt + 0x10, out uint aoep)) return false;
        AddressOfEntryPoint = aoep;
        if (!ReadU32(d, opt + 0x38, out uint soi)) return false;
        SizeOfImage = soi;
        if (!ReadU32(d, opt + 0x3C, out uint soh)) return false;
        SizeOfHeaders = soh;
        if (opt + 0x48 > d.Length) return false;
        DllCharacteristics = BitConverter.ToUInt16(d, opt + 0x46);

        // ImageBase difiere entre PE32 (uint32 @0x1C) y PE32+ (uint64 @0x18).
        if (Is64Bit)
        {
            if (opt + 0x20 > d.Length) return false;
            ImageBase = BitConverter.ToUInt64(d, opt + 0x18);
        }
        else if (ReadU32(d, opt + 0x1C, out uint ib))
        {
            ImageBase = ib;
        }

        // Data directories: cuenta y arranque difieren por magic.
        int nrvaOff = Is64Bit ? opt + 0x6C : opt + 0x5C;
        int dirStart = Is64Bit ? opt + 0x70 : opt + 0x60;
        uint nrva = ReadU32(d, nrvaOff, out uint tmp) ? Math.Min(tmp, 16u) : 0;
        var dirs = new List<(uint, uint)>((int)nrva);
        for (int i = 0; i < nrva; i++)
        {
            int o = dirStart + i * 8;
            if (o + 8 > d.Length) break;
            dirs.Add((BitConverter.ToUInt32(d, o), BitConverter.ToUInt32(d, o + 4)));
        }
        _dirs = dirs.ToArray();

        // Tabla de secciones: justo despues del optional header.
        int sec = opt + sizeOpt;
        for (int i = 0; i < NumberOfSections; i++)
        {
            int o = sec + i * 40;
            if (o + 40 > d.Length) break;
            string name = ReadName(d, o);
            uint vsize = BitConverter.ToUInt32(d, o + 8);
            uint vaddr = BitConverter.ToUInt32(d, o + 12);
            uint rawSize = BitConverter.ToUInt32(d, o + 16);
            uint rawPtr = BitConverter.ToUInt32(d, o + 20);
            uint chars = BitConverter.ToUInt32(d, o + 36);
            _sections.Add(new PeSection(name, vaddr, vsize, rawPtr, rawSize, chars));
        }

        IsValid = true;
        return true;
    }

    private static bool ReadU32(byte[] d, int off, out uint value)
    {
        if (off < 0 || off + 4 > d.Length) { value = 0; return false; }
        value = BitConverter.ToUInt32(d, off);
        return true;
    }

    private static string ReadName(byte[] d, int off)
    {
        var sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++)
        {
            byte b = d[off + i];
            if (b == 0) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }
}
