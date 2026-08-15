using System.Text;

namespace MemReader;

/// <summary>
/// Interpreta un bloque de bytes como los tipos numericos y de texto habituales.
/// Util para inspeccionar tus propias apps: ver que representa una direccion.
/// </summary>
public static class ValueInterpreter
{
    public static string Describe(byte[] d)
    {
        if (d == null || d.Length == 0) return "(sin datos)";

        var sb = new StringBuilder();
        sb.AppendLine($"int8:   {(sbyte)d[0],-22} uint8:  {d[0]}");

        if (d.Length >= 2)
        {
            short i16 = BitConverter.ToInt16(d, 0);
            ushort u16 = BitConverter.ToUInt16(d, 0);
            sb.AppendLine($"int16:  {i16,-22} uint16: {u16}");
        }

        if (d.Length >= 4)
        {
            int i32 = BitConverter.ToInt32(d, 0);
            uint u32 = BitConverter.ToUInt32(d, 0);
            float f = BitConverter.ToSingle(d, 0);
            sb.AppendLine($"int32:  {i32,-22} uint32: {u32}");
            sb.AppendLine($"float:  {f}");
        }

        if (d.Length >= 8)
        {
            long i64 = BitConverter.ToInt64(d, 0);
            ulong u64 = BitConverter.ToUInt64(d, 0);
            double db = BitConverter.ToDouble(d, 0);
            sb.AppendLine($"int64:  {i64,-22} uint64: {u64}");
            sb.AppendLine($"double: {db}");
            sb.AppendLine($"puntero (x64): 0x{u64:X}");
        }

        // Texto: mostramos el prefijo imprimible.
        sb.AppendLine($"ascii:  \"{ToPrintableAscii(d, 32)}\"");
        sb.AppendLine($"utf16:  \"{ToPrintableUtf16(d, 32)}\"");

        return sb.ToString();
    }

    private static string ToPrintableAscii(byte[] d, int maxChars)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < d.Length && sb.Length < maxChars; i++)
        {
            byte b = d[i];
            if (b == 0) break;
            sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
        }
        return sb.ToString();
    }

    private static string ToPrintableUtf16(byte[] d, int maxChars)
    {
        var sb = new StringBuilder();
        for (int i = 0; i + 1 < d.Length && sb.Length < maxChars; i += 2)
        {
            char c = (char)BitConverter.ToUInt16(d, i);
            if (c == 0) break;
            sb.Append(c >= 0x20 && c != 0x7F && !char.IsControl(c) ? c : '.');
        }
        return sb.ToString();
    }

    /// <summary>
    /// Construye el patron de bytes a buscar segun el tipo elegido en la UI.
    /// Devuelve (patron, etiqueta, textoPrevio) o lanza si el valor es invalido.
    /// </summary>
    public static (byte[] pattern, string label, string preview) BuildPattern(string kind, string text)
    {
        text = text.Trim();
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        switch (kind)
        {
            case "Int32":
                return (BitConverter.GetBytes(int.Parse(text, inv)), "Int32", text);
            case "Int64":
                return (BitConverter.GetBytes(long.Parse(text, inv)), "Int64", text);
            case "Float":
                return (BitConverter.GetBytes(float.Parse(text, inv)), "Float", text);
            case "Double":
                return (BitConverter.GetBytes(double.Parse(text, inv)), "Double", text);
            case "Bytes hex":
                return (ParseHexBytes(text), "Bytes", text);
            default:
                throw new ArgumentException("Tipo de busqueda no soportado: " + kind);
        }
    }

    private static byte[] ParseHexBytes(string text)
    {
        // Acepta "DE AD BE EF", "DEADBEEF" o "0xDE,0xAD".
        var parts = text.Replace(",", " ").Replace("-", " ")
                        .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        static string StripPrefix(string s) =>
            s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;

        var bytes = new List<byte>();
        try
        {
            if (parts.Length == 1)
            {
                // Cadena hex continua sin separadores.
                string s = StripPrefix(parts[0]);
                if (s.Length == 0 || s.Length % 2 != 0)
                    throw new ArgumentException(
                        "La cadena hex debe tener un numero par de digitos (p.ej. DEADBEEF).");
                for (int i = 0; i < s.Length; i += 2)
                    bytes.Add(Convert.ToByte(s.Substring(i, 2), 16));
            }
            else
            {
                foreach (var p in parts)
                    bytes.Add(Convert.ToByte(StripPrefix(p), 16));
            }
        }
        catch (Exception ex) when (ex is FormatException or OverflowException)
        {
            throw new ArgumentException("Bytes hex invalidos: " + ex.Message);
        }

        if (bytes.Count == 0) throw new ArgumentException("No hay bytes hex validos.");
        return bytes.ToArray();
    }
}
