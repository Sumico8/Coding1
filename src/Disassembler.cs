using Iced.Intel;

namespace MemReader;

/// <summary>
/// Desensambla bytes de memoria a instrucciones x86/x64 usando Iced. Solo lectura.
/// </summary>
public static class Disassembler
{
    public static string Disassemble(
        byte[] code, ulong ip, int bitness, int maxInstructions,
        Func<ulong, string?>? resolve = null)
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

            // Resolver el destino de saltos/llamadas directas a modulo+offset.
            if (resolve != null)
            {
                var fc = instr.FlowControl;
                bool directBranch = fc == FlowControl.Call
                    || fc == FlowControl.UnconditionalBranch
                    || fc == FlowControl.ConditionalBranch;
                if (directBranch &&
                    (instr.Op0Kind == OpKind.NearBranch16 ||
                     instr.Op0Kind == OpKind.NearBranch32 ||
                     instr.Op0Kind == OpKind.NearBranch64))
                {
                    string? sym = resolve(instr.NearBranchTarget);
                    if (sym != null) sb.Append("  ; -> ").Append(sym);
                }
            }

            // Marcar instrucciones sensibles para reversing/triage.
            var mn = instr.Mnemonic;
            if (mn == Mnemonic.Syscall || mn == Mnemonic.Sysenter)
                sb.Append("  ; SYSCALL");
            else if (mn == Mnemonic.Int && instr.Immediate8 == 0x2E)
                sb.Append("  ; int 2Eh (syscall legado)");
            else if (instr.FlowControl == FlowControl.IndirectCall ||
                     instr.FlowControl == FlowControl.IndirectBranch)
                sb.Append("  ; indirecto");

            sb.Append('\n');

            count++;
        }
        return sb.ToString();
    }
}
