using Iced.Intel;

namespace MemReader;

/// <summary>
/// Desensambla bytes de memoria a instrucciones x86/x64 usando Iced. Solo lectura.
/// </summary>
public static class Disassembler
{
    public static string Disassemble(byte[] code, ulong ip, int bitness, int maxInstructions)
    {
        if (code.Length == 0) return "(sin bytes)";

        var reader = new ByteArrayCodeReader(code);
        var decoder = Decoder.Create(bitness, reader);
        decoder.IP = ip;
        ulong endIp = ip + (ulong)code.Length;

        var formatter = new IntelFormatter();
        var output = new StringOutput();
        var sb = new System.Text.StringBuilder();

        int count = 0;
        while (decoder.IP < endIp && count < maxInstructions)
        {
            decoder.Decode(out var instr);
            formatter.Format(instr, output);
            string text = output.ToStringAndReset();

            int start = (int)(instr.IP - ip);
            var bytesHex = new System.Text.StringBuilder(instr.Length * 2);
            for (int i = 0; i < instr.Length && start + i < code.Length; i++)
                bytesHex.Append(code[start + i].ToString("X2"));

            sb.Append(instr.IP.ToString("X16"));
            sb.Append("  ");
            sb.Append(bytesHex.ToString().PadRight(20));
            sb.Append(' ');
            sb.Append(text);
            sb.Append('\n');

            count++;
        }
        return sb.ToString();
    }
}
