namespace MemReader;

/// <summary>
/// Paleta de colores pura (sin comportamiento). Define dos instancias estaticas
/// (Dark / Light) y helpers semanticos para que el codigo no use literales de
/// color: verde = legible/OK, rojo = peligro/RWX/severidad alta, azul = modulos/
/// estatico, ambar = aviso/severidad media, purpura = categorias.
/// Los acentos se eligen legibles sobre AMBOS fondos.
/// </summary>
public sealed class Theme
{
    // ----- Superficies -----
    public Color Background { get; init; }
    public Color Surface { get; init; }
    public Color SurfaceAlt { get; init; }
    public Color Border { get; init; }
    public Color HeaderBack { get; init; }
    public Color Selection { get; init; }
    public Color SelectionText { get; init; }

    // ----- Texto -----
    public Color TextPrimary { get; init; }
    public Color TextMuted { get; init; }

    // ----- Acentos -----
    public Color AccentBlue { get; init; }
    public Color AccentGreen { get; init; }
    public Color AccentRed { get; init; }
    public Color AccentAmber { get; init; }
    public Color AccentPurple { get; init; }

    // ----- Helpers semanticos (fuente unica de verdad) -----
    public Color SeverityHigh => AccentRed;
    public Color SeverityMedium => AccentAmber;
    public Color Readable => AccentGreen;
    public Color Rwx => AccentRed;
    public Color ModuleColor => AccentBlue;
    public Color OkText => AccentGreen;
    public Color BadText => AccentRed;

    /// <summary>
    /// Color determinista por categoria: misma categoria -> mismo acento siempre,
    /// repartido entre los cinco acentos. Sirve para colorear filas de etiquetas.
    /// </summary>
    public Color CategoryColor(string? category)
    {
        if (string.IsNullOrEmpty(category)) return TextPrimary;
        // Hash estable e independiente de la cultura/ejecucion (string.GetHashCode
        // no es estable entre procesos).
        uint h = 2166136261;
        foreach (char c in category)
        {
            h ^= c;
            h *= 16777619;
        }
        return (h % 5) switch
        {
            0 => AccentBlue,
            1 => AccentGreen,
            2 => AccentAmber,
            3 => AccentPurple,
            _ => AccentRed,
        };
    }

    /// <summary>Tema oscuro (por defecto): base gris oscuro, acentos vivos.</summary>
    public static readonly Theme Dark = new()
    {
        Background = Color.FromArgb(0x1E, 0x1E, 0x1E),
        Surface = Color.FromArgb(0x25, 0x25, 0x26),
        SurfaceAlt = Color.FromArgb(0x2D, 0x2D, 0x30),
        Border = Color.FromArgb(0x3F, 0x3F, 0x46),
        HeaderBack = Color.FromArgb(0x33, 0x33, 0x37),
        Selection = Color.FromArgb(0x09, 0x47, 0x71),
        SelectionText = Color.FromArgb(0xFF, 0xFF, 0xFF),
        TextPrimary = Color.FromArgb(0xDC, 0xDC, 0xDC),
        TextMuted = Color.FromArgb(0x9A, 0x9A, 0x9A),
        AccentBlue = Color.FromArgb(0x4A, 0x90, 0xE2),
        AccentGreen = Color.FromArgb(0x4E, 0xC9, 0x7A),
        AccentRed = Color.FromArgb(0xE0, 0x55, 0x61),
        AccentAmber = Color.FromArgb(0xE0, 0xA5, 0x4B),
        AccentPurple = Color.FromArgb(0xB0, 0x7C, 0xE0),
    };

    /// <summary>Tema claro: fondo claro, mismos acentos legibles.</summary>
    public static readonly Theme Light = new()
    {
        Background = Color.FromArgb(0xF3, 0xF3, 0xF3),
        Surface = Color.FromArgb(0xFF, 0xFF, 0xFF),
        SurfaceAlt = Color.FromArgb(0xF0, 0xF0, 0xF0),
        Border = Color.FromArgb(0xC8, 0xC8, 0xC8),
        HeaderBack = Color.FromArgb(0xE7, 0xE7, 0xE7),
        Selection = Color.FromArgb(0xCC, 0xE4, 0xF7),
        SelectionText = Color.FromArgb(0x10, 0x10, 0x10),
        TextPrimary = Color.FromArgb(0x1E, 0x1E, 0x1E),
        TextMuted = Color.FromArgb(0x60, 0x60, 0x60),
        // Acentos algo mas oscuros para contraste sobre blanco.
        AccentBlue = Color.FromArgb(0x25, 0x63, 0xEB),
        AccentGreen = Color.FromArgb(0x16, 0xA3, 0x4A),
        AccentRed = Color.FromArgb(0xDC, 0x26, 0x26),
        AccentAmber = Color.FromArgb(0xB4, 0x76, 0x0A),
        AccentPurple = Color.FromArgb(0x7C, 0x3A, 0xED),
    };
}
