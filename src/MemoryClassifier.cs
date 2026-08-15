using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>Categoria estructural de una direccion (para color e icono).</summary>
public enum AddrCategory { Modulo, Imagen, Mapeado, Pila, PrivadoDatos, Libre, Desconocido }

/// <summary>Clasificacion de una direccion: categoria + texto legible.</summary>
public sealed record AddressClass(AddrCategory Category, string Text);

/// <summary>
/// Clasifica automaticamente cualquier direccion del proceso segun DONDE vive:
/// dentro de un modulo (game.exe+offset), en una region mapeada, en la pila de un
/// hilo, o en memoria privada (monton/datos). Se construye una vez al abrir el
/// proceso y cachea modulos, regiones y rangos de pila para clasificar en O(log n)
/// sin I/O por consulta. Solo lectura.
/// </summary>
public sealed class MemoryClassifier
{
    private readonly PointerScanner _scanner;
    private readonly MemoryRegion[] _regions;   // ordenadas por BaseAddress
    private readonly (ulong lo, ulong hi, uint tid)[] _stacks;

    public MemoryClassifier(ProcessMemoryReader reader, PointerScanner scanner)
    {
        _scanner = scanner;
        _regions = reader.EnumerateRegions(onlyReadable: false)
            .OrderBy(r => r.BaseAddress).ToArray();
        int ptrSize = reader.IsTargetWow64() ? 4 : 8;
        _stacks = DetectStacks(reader, reader.ProcessId, ptrSize);
    }

    public AddressClass Classify(ulong addr)
    {
        // 1) Modulo (game.exe+offset): la respuesta mas util.
        var mo = _scanner.ResolveModuleOffset(addr);
        if (mo != null)
            return new AddressClass(AddrCategory.Modulo, $"{mo.Value.mod.Name}+0x{mo.Value.offset:X}");

        // 2) Pila de un hilo.
        foreach (var s in _stacks)
            if (addr >= s.lo && addr < s.hi)
                return new AddressClass(AddrCategory.Pila, $"pila (hilo {s.tid})");

        // 3) Region contenedora (mapeada / imagen sin modulo / privada).
        var region = FindRegion(addr);
        if (region != null)
        {
            if (region.Type == NativeMethods.MEM_MAPPED)
                return new AddressClass(AddrCategory.Mapeado, "mapeado (archivo)");
            if (region.Type == NativeMethods.MEM_IMAGE)
                return new AddressClass(AddrCategory.Imagen, "imagen (sin modulo)");
            return new AddressClass(AddrCategory.PrivadoDatos, "monton / datos privados");
        }
        return new AddressClass(AddrCategory.Libre, "libre / no asignado");
    }

    private MemoryRegion? FindRegion(ulong addr)
    {
        int lo = 0, hi = _regions.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            var r = _regions[mid];
            if (addr < r.BaseAddress) hi = mid - 1;
            else if (addr >= r.BaseAddress + r.RegionSize) lo = mid + 1;
            else return r;
        }
        return null;
    }

    /// <summary>Localiza los rangos de pila leyendo el TEB de cada hilo (best-effort).</summary>
    private static (ulong lo, ulong hi, uint tid)[] DetectStacks(
        ProcessMemoryReader reader, int pid, int ptrSize)
    {
        var stacks = new List<(ulong, ulong, uint)>();
        int tbiSize = Marshal.SizeOf<NativeMethods.THREAD_BASIC_INFORMATION>();

        foreach (var t in ThreadInspector.Enumerate(pid))
        {
            IntPtr h = NativeMethods.OpenThread(
                NativeMethods.THREAD_QUERY_LIMITED_INFORMATION, false, t.Tid);
            if (h == IntPtr.Zero) continue;
            try
            {
                var tbi = new NativeMethods.THREAD_BASIC_INFORMATION();
                int st = NativeMethods.NtQueryInformationThread(h, 0, ref tbi, tbiSize, out _);
                if (st != 0 || tbi.TebBaseAddress == IntPtr.Zero) continue;

                ulong teb = (ulong)tbi.TebBaseAddress.ToInt64();
                // NT_TIB: StackBase en +ptrSize, StackLimit en +2*ptrSize.
                byte[] b;
                try { b = reader.ReadBytes(teb + (ulong)ptrSize, ptrSize * 2); }
                catch { continue; }
                if (b.Length < ptrSize * 2) continue;

                ulong stackBase = ptrSize == 8 ? BitConverter.ToUInt64(b, 0) : BitConverter.ToUInt32(b, 0);
                ulong stackLimit = ptrSize == 8 ? BitConverter.ToUInt64(b, ptrSize) : BitConverter.ToUInt32(b, ptrSize);
                if (stackBase != 0 && stackLimit != 0 && stackLimit < stackBase)
                    stacks.Add((stackLimit, stackBase, t.Tid));
            }
            catch { /* hilo inaccesible */ }
            finally { NativeMethods.CloseHandle(h); }
        }
        return stacks.ToArray();
    }
}
