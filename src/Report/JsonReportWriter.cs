using System.Text.Json;

namespace MemReader;

/// <summary>Serializa un <see cref="TriageReport"/> a JSON (indentado).</summary>
public static class JsonReportWriter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    public static string Write(TriageReport report)
        => JsonSerializer.Serialize(report, Options);
}
