namespace MemReader;

/// <summary>Resultado de comparar un modulo en memoria contra su archivo en disco.</summary>
public sealed record ModuleIntegrity(
    string Name, ulong BaseAddress, string? Path, string Verdict,
    double DiffPercent, long DiffBytes, long ComparedBytes, string Detail)
{
    public string BaseText => $"0x{BaseAddress:X}";
}

/// <summary>
/// Detecta parcheo de codigo / hollowing comparando las secciones EJECUTABLES de
/// cada modulo en memoria contra su archivo en disco. Para no confundir las
/// reubicaciones por ASLR con manipulacion, mapea el archivo por RVA y le aplica
/// las base relocations en UNA COPIA PROPIA (nunca escribe en el proceso). Es
/// deteccion/reporte de solo lectura.
/// </summary>
public static class IntegrityScanner
{
    private const uint MaxImageSize = 512u * 1024 * 1024;

    public static List<ModuleIntegrity> Scan(
        ProcessMemoryReader reader, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new List<ModuleIntegrity>();
        var modules = reader.EnumerateModules();
        int i = 0;
        foreach (var m in modules)
        {
            ct.ThrowIfCancellationRequested();
            i++;
            progress?.Report($"Comprobando integridad... {i}/{modules.Count}");
            try { result.Add(CheckModule(reader, m)); }
            catch (Exception ex)
            {
                result.Add(new ModuleIntegrity(m.Name, m.BaseAddress, m.Path, "error", 0, 0, 0, ex.Message));
            }
        }
        return result;
    }

    private static ModuleIntegrity CheckModule(ProcessMemoryReader reader, ModuleInfo m)
    {
        if (string.IsNullOrEmpty(m.Path) || !File.Exists(m.Path))
            return new ModuleIntegrity(m.Name, m.BaseAddress, m.Path, "n/d", 0, 0, 0, "ruta en disco no disponible");

        byte[] disk;
        try { disk = File.ReadAllBytes(m.Path); }
        catch { return new ModuleIntegrity(m.Name, m.BaseAddress, m.Path, "n/d", 0, 0, 0, "no se pudo leer el archivo"); }

        var pe = PeImage.Parse(disk);
        if (pe == null || !pe.IsValid)
            return new ModuleIntegrity(m.Name, m.BaseAddress, m.Path, "n/d", 0, 0, 0, "PE en disco invalido");

        byte[]? mapped = MapAndRelocate(disk, pe, m.BaseAddress);
        if (mapped == null)
            return new ModuleIntegrity(m.Name, m.BaseAddress, m.Path, "n/d", 0, 0, 0, "no se pudo mapear/relocalizar");

        long diff = 0, compared = 0;
        var hot = new List<string>();
        foreach (var s in pe.Sections)
        {
            if (!s.IsExecutable) continue;
            uint len = s.SizeOfRawData;
            if (s.VirtualSize > 0 && s.VirtualSize < len) len = s.VirtualSize;
            if (len == 0) continue;
            if (s.VirtualAddress >= (uint)mapped.Length) continue;
            if (s.VirtualAddress + len > (uint)mapped.Length) len = (uint)mapped.Length - s.VirtualAddress;

            byte[] mem;
            try { mem = reader.ReadBytes(m.BaseAddress + s.VirtualAddress, (int)len); }
            catch { continue; }

            int n = Math.Min(mem.Length, (int)len);
            long sectionDiff = 0;
            for (int k = 0; k < n; k++)
            {
                if (mapped[s.VirtualAddress + k] != mem[k]) { diff++; sectionDiff++; }
                compared++;
            }
            if (sectionDiff > 0 && n > 0)
                hot.Add($"{s.Name}: {sectionDiff} bytes ({100.0 * sectionDiff / n:0.00}%)");
        }

        double ratio = compared > 0 ? (double)diff / compared : 0;
        string verdict = compared == 0 ? "n/d"
            : ratio == 0 ? "OK"
            : ratio < 0.005 ? "menor"
            : "SOSPECHOSO";
        string detail = compared == 0
            ? "sin secciones ejecutables comparables"
            : hot.Count > 0 ? "Difieren " + string.Join("; ", hot) : "coincide con el disco";

        return new ModuleIntegrity(
            m.Name, m.BaseAddress, m.Path, verdict, Math.Round(ratio * 100, 4), diff, compared, detail);
    }

    /// <summary>Coloca las secciones del archivo por RVA y aplica relocations en una copia.</summary>
    private static byte[]? MapAndRelocate(byte[] disk, PeImage pe, ulong actualBase)
    {
        uint sizeOfImage = pe.SizeOfImage;
        if (sizeOfImage == 0 || sizeOfImage > MaxImageSize) return null;

        var img = new byte[sizeOfImage];
        int hdr = (int)Math.Min(Math.Min(pe.SizeOfHeaders, (uint)disk.Length), sizeOfImage);
        Array.Copy(disk, 0, img, 0, hdr);

        foreach (var s in pe.Sections)
        {
            if (s.SizeOfRawData == 0) continue;
            if (s.PointerToRawData >= (uint)disk.Length) continue;
            if (s.VirtualAddress >= sizeOfImage) continue;
            int copy = (int)Math.Min(s.SizeOfRawData, (uint)disk.Length - s.PointerToRawData);
            copy = (int)Math.Min((uint)copy, sizeOfImage - s.VirtualAddress);
            if (copy <= 0) continue;
            Array.Copy(disk, (int)s.PointerToRawData, img, (int)s.VirtualAddress, copy);
        }

        long delta = unchecked((long)actualBase - (long)pe.ImageBase);
        if (delta != 0) ApplyRelocations(img, pe, delta);
        return img;
    }

    private static void ApplyRelocations(byte[] img, PeImage pe, long delta)
    {
        var (rva, size) = pe.Directory(PeImage.DIR_BASERELOC);
        if (rva == 0 || size == 0) return;

        long end = Math.Min((long)rva + size, img.Length);
        long pos = rva;
        while (pos + 8 <= end)
        {
            uint pageRva = BitConverter.ToUInt32(img, (int)pos);
            uint blockSize = BitConverter.ToUInt32(img, (int)pos + 4);
            if (blockSize < 8 || pos + blockSize > end) break;

            int entries = (int)((blockSize - 8) / 2);
            for (int i = 0; i < entries; i++)
            {
                int eoff = (int)pos + 8 + i * 2;
                if (eoff + 2 > img.Length) break;
                ushort entry = BitConverter.ToUInt16(img, eoff);
                int type = entry >> 12;
                long target = (long)pageRva + (entry & 0xFFF);

                if (type == 10 && target + 8 <= img.Length) // IMAGE_REL_BASED_DIR64
                {
                    ulong v = unchecked(BitConverter.ToUInt64(img, (int)target) + (ulong)delta);
                    BitConverter.GetBytes(v).CopyTo(img, (int)target);
                }
                else if (type == 3 && target + 4 <= img.Length) // IMAGE_REL_BASED_HIGHLOW
                {
                    uint v = unchecked(BitConverter.ToUInt32(img, (int)target) + (uint)delta);
                    BitConverter.GetBytes(v).CopyTo(img, (int)target);
                }
                // type 0 (ABSOLUTE) = relleno, se ignora
            }
            pos += blockSize;
        }
    }
}
