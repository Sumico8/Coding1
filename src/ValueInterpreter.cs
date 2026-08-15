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
        switch (kind)
        {
            case "Int32":
                return (BitConverter.GetBytes(int.Parse(text)), "Int32", text);
            case "Int64":
                return (BitConverter.GetBytes(long.Parse(text)), "Int64", text);
            case "Float":
                return (BitConverter.GetBytes(float.Parse(text, System.Globalization.CultureInfo.InvariantCulture)), "Float", text);
            case "Double":
                return (BitConverter.GetBytes(double.Parse(text, System.Globalization.CultureInfo.InvariantCulture)), "Double", text);
            case "Bytes hex":
                return (ParseHexBytes(text), "Bytes", text);
            default:
                throw new ArgumentException("Tipo de busqueda no soportado: " + kind);
        }
    }

    /// <summary>
    /// Interpreta un patron AOB con comodines, p. ej. "48 8B ?? ?? E8" o
    /// "488B????E8". Devuelve (patron, mascara) donde mascara 0xFF = coincide y
    /// 0x00 = comodin. Acepta "?" o "??" como comodin.
    /// </summary>
    public static (byte[] pattern, byte[] mask) ParseAob(string text)
    {
        var clean = text.Replace(",", " ").Replace("-", " ");
        var tokens = clean.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

        // Caso sin separadores: "488B??E8" -> partir en pares de caracteres.
        if (tokens.Length == 1 && tokens[0].Length > 2 && tokens[0].IndexOf('?') < 0)
        {
            string s = tokens[0];
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
            if (s.Length % 2 == 0)
            {
                var list = new List<string>(s.Length / 2);
                for (int i = 0; i < s.Length; i += 2) list.Add(s.Substring(i, 2));
                tokens = list.ToArray();
            }
        }

        var pat = new List<byte>(tokens.Length);
        var mask = new List<byte>(tokens.Length);
        foreach (var raw in tokens)
        {
            string t = raw;
            if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) t = t[2..];
            if (t == "?" || t == "??" || t == "*")
            {
                pat.Add(0);
                mask.Add(0);
            }
            else
            {
                pat.Add(Convert.ToByte(t, 16));
                mask.Add(0xFF);
            }
        }
        if (pat.Count == 0) throw new ArgumentException("Patron AOB vacio.");
        if (mask.TrueForAll(b => b == 0)) throw new ArgumentException("El patron AOB es todo comodines.");
        return (pat.ToArray(), mask.ToArray());
    }

    private static byte[] ParseHexBytes(string text)
    {
        // Acepta "DE AD BE EF", "DEADBEEF" o "0xDE,0xAD".
        var clean = text.Replace("0x", "", StringComparison.OrdinalIgnoreCase)
                        .Replace(",", " ")
                        .Replace("-", " ");
        var parts = clean.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var bytes = new List<byte>();
        if (parts.Length == 1 && parts[0].Length % 2 == 0)
        {
            // Cadena hex continua sin separadores.
            string s = parts[0];
            for (int i = 0; i < s.Length; i += 2)
                bytes.Add(Convert.ToByte(s.Substring(i, 2), 16));
        }
        else
        {
            foreach (var p in parts)
                bytes.Add(Convert.ToByte(p, 16));
        }

        if (bytes.Count == 0) throw new ArgumentException("No hay bytes hex validos.");
        return bytes.ToArray();
    }
}
