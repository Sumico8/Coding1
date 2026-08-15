using System.Text;

namespace MemReader;

/// <summary>Formatea bytes crudos como un volcado hexadecimal clasico (offset | hex | ASCII).</summary>
public static class HexFormatter
{
    public static string Format(byte[] data, ulong baseAddress, int bytesPerLine = 16)
    {
        if (data.Length == 0) return "(sin datos legibles)";

        var sb = new StringBuilder(data.Length * 4);
        for (int offset = 0; offset < data.Length; offset += bytesPerLine)
        {
            sb.Append((baseAddress + (ulong)offset).ToString("X16"));
            sb.Append("  ");

            int lineLen = Math.Min(bytesPerLine, data.Length - offset);

            // Columna hexadecimal.
            for (int i = 0; i < bytesPerLine; i++)
            {
                if (i < lineLen)
                    sb.Append(data[offset + i].ToString("X2")).Append(' ');
                else
                    sb.Append("   ");
                if (i == bytesPerLine / 2 - 1) sb.Append(' ');
            }

            sb.Append(' ');

            // Columna ASCII.
            for (int i = 0; i < lineLen; i++)
            {
                byte b = data[offset + i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }

            sb.Append('\n');
        }
        return sb.ToString();
    }
}
