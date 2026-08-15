namespace MemReader;

/// <summary>
/// Traduce codigos tecnicos (protecciones de memoria, tipos de region) y
/// direcciones a nombres claros en espanol, para que la interfaz sea legible
/// por personas no tecnicas. Clase pura: no depende de WinForms, asi que
/// compila trivialmente y se puede reutilizar en cualquier parte.
/// </summary>
public static class FriendlyNames
{
    /// <summary>
    /// Traduce el codigo corto de proteccion (el que emite
    /// <see cref="NativeMethods.ProtectToString"/>: R, RW, RWX, RX, WC...) a
    /// una descripcion clara. Los codigos desconocidos se devuelven sin cambios.
    /// </summary>
    public static string Protection(string code)
    {
        if (string.IsNullOrEmpty(code)) return "(desconocido)";

        // Separa el sufijo "+GUARD" (pagina guardia) si esta presente.
        bool guard = code.EndsWith("+GUARD", StringComparison.Ordinal);
        string baseCode = guard ? code[..^6] : code;

        string name = baseCode switch
        {
            "NOACCESS" => "Sin acceso",
            "R" => "Solo lectura",
            "RW" => "Lectura y escritura",
            "WC" => "Escritura-copia (datos)",
            "X" => "Solo ejecucion",
            "RX" => "Codigo ejecutable (solo lectura)",
            "RWX" => "Ejecutable + escritura (PELIGROSO)",
            "RWXC" => "Ejecutable + escritura-copia (PELIGROSO)",
            _ => baseCode // codigo no reconocido (p.ej. "0x...") -> se deja igual
        };

        return guard ? name + " - pagina guardia" : name;
    }

    /// <summary>Como <see cref="Protection(string)"/> pero partiendo del valor crudo.</summary>
    public static string ProtectionFromRaw(uint protect)
        => Protection(NativeMethods.ProtectToString(protect));

    /// <summary>
    /// Traduce el tipo de region (IMAGE/MAPPED/PRIVATE, el que emite
    /// <see cref="NativeMethods.TypeToString"/>) a una descripcion clara.
    /// </summary>
    public static string RegionType(string code) => code switch
    {
        "IMAGE" => "Archivo de programa (DLL/EXE)",
        "MAPPED" => "Archivo mapeado en disco",
        "PRIVATE" => "Memoria privada",
        _ => code
    };

    /// <summary>Como <see cref="RegionType(string)"/> pero partiendo del valor crudo.</summary>
    public static string RegionTypeFromRaw(uint type)
        => RegionType(NativeMethods.TypeToString(type));

    /// <summary>
    /// Describe a que pertenece una direccion a partir de una resolucion
    /// modulo+offset ya calculada (ver <see cref="PointerScanner.ResolveModuleOffset"/>).
    /// Esto es la "identificacion automatica de offsets" que pide el usuario:
    /// convierte un numero crudo en "Pertenece a kernel32.dll (+0x1234)".
    /// </summary>
    public static string DescribeAddress((ModuleInfo mod, ulong offset)? resolved)
    {
        if (resolved == null) return "Memoria dinamica (sin modulo)";
        return $"Pertenece a {resolved.Value.mod.Name} (+0x{resolved.Value.offset:X})";
    }

    /// <summary>
    /// Nombre corto del modulo al que pertenece una direccion (para columnas
    /// estrechas). Devuelve "(dinamica)" si no cae en ningun modulo.
    /// </summary>
    public static string ModuleShort((ModuleInfo mod, ulong offset)? resolved)
        => resolved == null ? "(dinamica)" : resolved.Value.mod.Name;

    /// <summary>
    /// Describe una direccion buscando en una lista de modulos, para cuando no
    /// hay un <see cref="PointerScanner"/> disponible.
    /// </summary>
    public static string DescribeAddress(ulong address, IReadOnlyList<ModuleInfo> modules)
    {
        foreach (var m in modules)
        {
            ulong end = m.BaseAddress + (ulong)m.Size;
            if (address >= m.BaseAddress && address < end)
                return $"Pertenece a {m.Name} (+0x{address - m.BaseAddress:X})";
        }
        return "Memoria dinamica (sin modulo)";
    }
}
