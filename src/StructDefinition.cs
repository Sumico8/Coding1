using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MemReader;

/// <summary>Tipo de un campo de una estructura.</summary>
public enum FieldType { Byte, Int16, Int32, Int64, Float, Double, Pointer, TextAscii }

/// <summary>Un campo de una estructura: offset dentro del objeto + tipo + nombre.</summary>
public sealed class StructField
{
    public long Offset { get; set; }
    public FieldType Type { get; set; }
    public string Name { get; set; } = "";

    public static int SizeOf(FieldType t) => t switch
    {
        FieldType.Byte => 1,
        FieldType.Int16 => 2,
        FieldType.Int32 or FieldType.Float => 4,
        FieldType.Int64 or FieldType.Double or FieldType.Pointer => 8,
        FieldType.TextAscii => 32,
        _ => 4,
    };

    public static string Format(FieldType t, byte[] d)
    {
        if (d.Length < SizeOf(t) && t != FieldType.TextAscii) return "(?)";
        switch (t)
        {
            case FieldType.Byte: return d[0].ToString();
            case FieldType.Int16: return BitConverter.ToInt16(d, 0).ToString();
            case FieldType.Int32: return BitConverter.ToInt32(d, 0).ToString();
            case FieldType.Int64: return BitConverter.ToInt64(d, 0).ToString();
            case FieldType.Float: return BitConverter.ToSingle(d, 0).ToString("R");
            case FieldType.Double: return BitConverter.ToDouble(d, 0).ToString("R");
            case FieldType.Pointer: return "0x" + BitConverter.ToUInt64(d, 0).ToString("X");
            case FieldType.TextAscii:
                var sb = new StringBuilder();
                for (int i = 0; i < d.Length && sb.Length < 32; i++)
                {
                    if (d[i] == 0) break;
                    sb.Append(d[i] >= 0x20 && d[i] < 0x7F ? (char)d[i] : '.');
                }
                return "\"" + sb + "\"";
            default: return "(?)";
        }
    }
}

/// <summary>Una definicion de estructura con nombre.</summary>
public sealed class StructDefinition
{
    public string Name { get; set; } = "";
    public List<StructField> Fields { get; set; } = new();
}

/// <summary>
/// Guarda/carga definiciones de estructura en %APPDATA%\MemReader\structs.json
/// (global, no por proceso: las estructuras suelen reutilizarse).
/// </summary>
public sealed class StructStore
{
    public List<StructDefinition> Items { get; private set; } = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private static string Dir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MemReader");
    private static string FilePath => Path.Combine(Dir, "structs.json");

    public void Load()
    {
        try
        {
            if (File.Exists(FilePath))
                Items = JsonSerializer.Deserialize<List<StructDefinition>>(File.ReadAllText(FilePath), JsonOpts)
                        ?? new List<StructDefinition>();
        }
        catch { Items = new List<StructDefinition>(); }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Dir);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(Items, JsonOpts));
        }
        catch { /* best-effort */ }
    }

    public void Upsert(StructDefinition d)
    {
        int i = Items.FindIndex(x => string.Equals(x.Name, d.Name, StringComparison.OrdinalIgnoreCase));
        if (i >= 0) Items[i] = d; else Items.Add(d);
        Save();
    }
}
