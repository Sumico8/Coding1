using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MemReader;

/// <summary>Como esta anclada una etiqueta a la memoria del proceso.</summary>
public enum AnchorKind
{
    /// <summary>Ruta de puntero modulo+offset -> +off ... (sobrevive a reinicios/ASLR).</summary>
    PointerPath,
    /// <summary>Direccion estatica dentro de un modulo (modulo+offset).</summary>
    ModuleOffset,
    /// <summary>Direccion absoluta (solo valida en la sesion actual).</summary>
    Absolute
}

/// <summary>Tipo con el que interpretar el valor de una etiqueta.</summary>
public enum LabelType { Auto, Int32, Int64, Float, Double, Bytes, TextAscii, TextUtf16 }

/// <summary>
/// Una etiqueta que el usuario pone a una direccion/puntero ("Barra de stamina"
/// [Jugador], "Arbol" [Entorno]...). DTO plano con propiedades get/set para que
/// System.Text.Json haga round-trip sin friccion. Se persiste lo RELATIVO al
/// modulo (ModuleName + BaseOffset + Offsets), nunca una base viva: asi la
/// etiqueta se reencuentra aunque la app objetivo se reinicie.
/// </summary>
public sealed class Annotation
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public LabelType Type { get; set; } = LabelType.Auto;
    public string? Notes { get; set; }
    public AnchorKind Kind { get; set; } = AnchorKind.Absolute;

    // Ancla relativa a modulo (PointerPath / ModuleOffset).
    public string? ModuleName { get; set; }
    public long BaseOffset { get; set; }
    public List<long> Offsets { get; set; } = new();

    // Ancla absoluta (solo sesion).
    public ulong AbsoluteAddress { get; set; }

    // Ultima direccion resuelta con exito (informativo).
    public ulong LastKnownAddress { get; set; }

    /// <summary>Texto legible del ancla, estilo Cheat Engine.</summary>
    [JsonIgnore]
    public string AnchorText => Kind switch
    {
        AnchorKind.PointerPath => BuildPathText(),
        AnchorKind.ModuleOffset => $"{ModuleName}+0x{BaseOffset:X}",
        _ => $"0x{AbsoluteAddress:X}"
    };

    /// <summary>Etiqueta corta del estado de resolucion.</summary>
    [JsonIgnore]
    public string KindText => Kind switch
    {
        AnchorKind.PointerPath => "ruta",
        AnchorKind.ModuleOffset => "estatica",
        _ => "sesion"
    };

    private string BuildPathText()
    {
        var sb = new StringBuilder();
        sb.Append($"[\"{ModuleName}\"+0x{BaseOffset:X}]");
        foreach (var o in Offsets)
            sb.Append($" -> +0x{o:X}");
        return sb.ToString();
    }

    /// <summary>Tamano en bytes a leer para el tipo dado.</summary>
    public static int SizeOf(LabelType t) => t switch
    {
        LabelType.Int32 or LabelType.Float => 4,
        LabelType.Int64 or LabelType.Double => 8,
        LabelType.Bytes => 8,
        LabelType.TextAscii => 32,
        LabelType.TextUtf16 => 64,
        _ => 8 // Auto
    };
}

/// <summary>
/// Almacen de etiquetas persistente por proceso, en
/// %APPDATA%\MemReader\tables\&lt;proceso&gt;.json. Se autocarga al abrir un proceso
/// del mismo nombre y se autoguarda en cada cambio.
/// </summary>
public sealed class AnnotationStore
{
    public List<Annotation> Items { get; private set; } = new();
    public event EventHandler? Changed;

    private string? _procName;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private static string TablesDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MemReader", "tables");

    private static string Sanitize(string name)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return string.IsNullOrWhiteSpace(name) ? "proceso" : name;
    }

    private string? CurrentPath =>
        _procName == null ? null : Path.Combine(TablesDir, Sanitize(_procName) + ".json");

    public void Add(Annotation a)
    {
        Items.Add(a);
        Save();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Update(Annotation a)
    {
        int i = Items.FindIndex(x => x.Id == a.Id);
        if (i >= 0) Items[i] = a; else Items.Add(a);
        Save();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Remove(string id)
    {
        Items.RemoveAll(x => x.Id == id);
        Save();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public IEnumerable<string> Categories() =>
        Items.Select(i => i.Category)
             .Where(s => !string.IsNullOrWhiteSpace(s))
             .Distinct(StringComparer.OrdinalIgnoreCase)
             .OrderBy(s => s, StringComparer.OrdinalIgnoreCase);

    /// <summary>Carga (o vacia) la tabla del proceso indicado por nombre.</summary>
    public void LoadForProcess(string procName)
    {
        _procName = procName;
        Items = new List<Annotation>();
        try
        {
            var path = CurrentPath;
            if (path != null && File.Exists(path))
            {
                var list = JsonSerializer.Deserialize<List<Annotation>>(File.ReadAllText(path), JsonOpts);
                if (list != null) Items = list;
            }
        }
        catch { Items = new List<Annotation>(); }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Save()
    {
        try
        {
            var path = CurrentPath;
            if (path == null) return;
            Directory.CreateDirectory(TablesDir);
            File.WriteAllText(path, JsonSerializer.Serialize(Items, JsonOpts));
        }
        catch { /* guardado best-effort */ }
    }

    public void Export(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(Items, JsonOpts));

    public void Import(string path)
    {
        var list = JsonSerializer.Deserialize<List<Annotation>>(File.ReadAllText(path), JsonOpts);
        if (list == null) return;
        // Fusiona por Id (los nuevos reemplazan; el resto se agrega).
        foreach (var a in list)
        {
            int i = Items.FindIndex(x => x.Id == a.Id);
            if (i >= 0) Items[i] = a; else Items.Add(a);
        }
        Save();
        Changed?.Invoke(this, EventArgs.Empty);
    }
}

/// <summary>Una etiqueta que resuelve cerca de una direccion consultada.</summary>
public readonly record struct AnnotationMatch(Annotation Ann, ulong Resolved, long Delta);

/// <summary>Resultado de identificar una direccion.</summary>
public sealed record IdentifyResult(
    ulong Address,
    string? ModuleName,
    ulong ModuleOffset,
    bool IsStatic,
    MemoryRegion? Region,
    IReadOnlyList<AnnotationMatch> Matches,
    string TypeGuess);

/// <summary>
/// Motor de identificacion: dada una direccion, dice su modulo+offset, la region
/// donde vive (protección/tipo, estatica vs dinamica), que etiquetas guardadas
/// coinciden (re-resolviendolas en vivo) y una conjetura del tipo de dato.
/// </summary>
public sealed class Identifier
{
    private readonly PointerScanner _scanner;
    private readonly ProcessMemoryReader _reader;
    private readonly AnnotationStore _store;
    private readonly int _ptrSize;

    private const long MatchWindow = 0x400; // ventana de "cercania"

    public Identifier(PointerScanner scanner, ProcessMemoryReader reader, AnnotationStore store)
    {
        _scanner = scanner;
        _reader = reader;
        _store = store;
        _ptrSize = reader.IsTargetWow64() ? 4 : 8;
    }

    public List<ModuleInfo> CurrentModules() => _reader.EnumerateModules();

    public IdentifyResult Identify(ulong address, IReadOnlyList<MemoryRegion> regions)
    {
        var mo = _scanner.ResolveModuleOffset(address);
        string? modName = mo?.mod.Name;
        ulong modOff = mo?.offset ?? 0;
        bool isStatic = mo != null;

        MemoryRegion? region = null;
        foreach (var r in regions)
        {
            if (address >= r.BaseAddress && address < r.BaseAddress + r.RegionSize)
            {
                region = r;
                break;
            }
        }

        var modules = _reader.EnumerateModules();
        var matches = new List<AnnotationMatch>();
        foreach (var a in _store.Items)
        {
            ulong? resolved = Resolve(a, modules);
            if (resolved == null) continue;
            long delta = unchecked((long)(address - resolved.Value));
            if (Math.Abs(delta) <= MatchWindow)
                matches.Add(new AnnotationMatch(a, resolved.Value, delta));
        }
        matches.Sort((x, y) => Math.Abs(x.Delta).CompareTo(Math.Abs(y.Delta)));

        return new IdentifyResult(address, modName, modOff, isStatic, region, matches, GuessType(address));
    }

    public ulong? Resolve(Annotation a) => Resolve(a, _reader.EnumerateModules());

    public ulong? Resolve(Annotation a, List<ModuleInfo> modules)
    {
        switch (a.Kind)
        {
            case AnchorKind.Absolute:
                return a.AbsoluteAddress == 0 ? null : a.AbsoluteAddress;

            case AnchorKind.ModuleOffset:
            {
                var m = FindModule(modules, a.ModuleName);
                if (m == null) return null;
                return m.BaseAddress + (ulong)a.BaseOffset;
            }

            case AnchorKind.PointerPath:
            {
                var m = FindModule(modules, a.ModuleName);
                if (m == null) return null;
                var res = _scanner.ResolvePath(m.BaseAddress, a.BaseOffset, a.Offsets, _ptrSize);
                return res?.finalAddress;
            }
        }
        return null;
    }

    public string LiveValue(Annotation a, List<ModuleInfo> modules)
    {
        var addr = Resolve(a, modules);
        if (addr == null) return "(no resuelve)";
        int size = Annotation.SizeOf(a.Type);
        byte[] d;
        try { d = _reader.ReadBytes(addr.Value, size); }
        catch { return "(ilegible)"; }
        return FormatValue(a.Type, d);
    }

    private static ModuleInfo? FindModule(List<ModuleInfo> modules, string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        return modules.FirstOrDefault(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    public static string FormatValue(LabelType t, byte[] d)
    {
        if (d.Length == 0) return "(sin datos)";
        switch (t)
        {
            case LabelType.Int32: return d.Length >= 4 ? BitConverter.ToInt32(d, 0).ToString() : "(?)";
            case LabelType.Int64: return d.Length >= 8 ? BitConverter.ToInt64(d, 0).ToString() : "(?)";
            case LabelType.Float: return d.Length >= 4 ? BitConverter.ToSingle(d, 0).ToString("R") : "(?)";
            case LabelType.Double: return d.Length >= 8 ? BitConverter.ToDouble(d, 0).ToString("R") : "(?)";
            case LabelType.Bytes: return BitConverter.ToString(d);
            case LabelType.TextAscii: return "\"" + PrintableAscii(d, 32) + "\"";
            case LabelType.TextUtf16: return "\"" + PrintableUtf16(d, 32) + "\"";
            default:
                // Auto: entero + hex.
                if (d.Length >= 4)
                    return $"{BitConverter.ToInt32(d, 0)}  (0x{BitConverter.ToUInt32(d, 0):X})";
                return BitConverter.ToString(d);
        }
    }

    private string GuessType(ulong address)
    {
        byte[] d;
        try { d = _reader.ReadBytes(address, 16); }
        catch { return "(ilegible)"; }
        if (d.Length == 0) return "(sin datos)";

        // Texto?
        string ascii = PrintableAscii(d, 8);
        if (ascii.Length >= 4) return $"texto ASCII \"{ascii}\"";
        string utf16 = PrintableUtf16(d, 8);
        if (utf16.Length >= 4) return $"texto UTF-16 \"{utf16}\"";

        // Puntero a un modulo conocido?
        if (d.Length >= _ptrSize)
        {
            ulong v = _ptrSize == 8 ? BitConverter.ToUInt64(d, 0) : BitConverter.ToUInt32(d, 0);
            var mo = _scanner.ResolveModuleOffset(v);
            if (mo != null) return $"puntero -> {mo.Value.mod.Name}+0x{mo.Value.offset:X}";
        }

        int i32 = d.Length >= 4 ? BitConverter.ToInt32(d, 0) : d[0];
        float f = d.Length >= 4 ? BitConverter.ToSingle(d, 0) : 0;
        string fstr = (f > -1e9 && f < 1e9 && f != 0) ? $", float {f:0.###}" : "";
        return $"numero int32 {i32}{fstr}";
    }

    private static string PrintableAscii(byte[] d, int maxChars)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < d.Length && sb.Length < maxChars; i++)
        {
            byte b = d[i];
            if (b == 0) break;
            if (b < 0x20 || b >= 0x7F) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    private static string PrintableUtf16(byte[] d, int maxChars)
    {
        var sb = new StringBuilder();
        for (int i = 0; i + 1 < d.Length && sb.Length < maxChars; i += 2)
        {
            char c = (char)BitConverter.ToUInt16(d, i);
            if (c == 0) break;
            if (c < 0x20 || c == 0x7F || char.IsControl(c)) break;
            sb.Append(c);
        }
        return sb.ToString();
    }
}
