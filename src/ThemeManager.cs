using System.Text.Json;
using System.Text.Json.Serialization;

namespace MemReader;

/// <summary>
/// Gestor de tema global. Mantiene el tema actual, aplica colores recursivamente a
/// un arbol de controles (SOLO asigna propiedades, nunca engancha eventos) y
/// persiste la preferencia en %APPDATA%\MemReader\settings.json.
///
/// Alternar el tema = re-aplicar colores + Invalidate. Las subclases owner-draw
/// (ThemedListView / ThemedTabControl / ThemedComboBox) leen ThemeManager.Current
/// al pintar, asi que no hace falta re-enganchar nada.
/// </summary>
public static class ThemeManager
{
    public static Theme Current { get; private set; } = Theme.Dark;
    public static bool IsDark { get; private set; } = true;

    /// <summary>Se dispara cuando cambia el tema (para re-aplicar y repintar).</summary>
    public static event EventHandler? ThemeChanged;

    private static string SettingsDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MemReader");
    private static string SettingsPath => Path.Combine(SettingsDir, "settings.json");

    private sealed class Settings
    {
        public string Theme { get; set; } = "Dark";
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Carga la preferencia guardada. Ante cualquier fallo, usa Dark.</summary>
    public static void Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var s = JsonSerializer.Deserialize<Settings>(File.ReadAllText(SettingsPath), JsonOpts);
                bool dark = !string.Equals(s?.Theme, "Light", StringComparison.OrdinalIgnoreCase);
                Set(dark);
                return;
            }
        }
        catch { /* archivo ausente o corrupto: caemos a Dark */ }
        Set(true);
    }

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            var s = new Settings { Theme = IsDark ? "Dark" : "Light" };
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(s, JsonOpts));
        }
        catch { /* si no se puede guardar, no es critico */ }
    }

    private static void Set(bool dark)
    {
        IsDark = dark;
        Current = dark ? Theme.Dark : Theme.Light;
    }

    /// <summary>Alterna claro/oscuro, persiste y notifica.</summary>
    public static void Toggle()
    {
        Set(!IsDark);
        Save();
        ThemeChanged?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>Recorre el arbol de controles asignando colores segun el tema.</summary>
    public static void Apply(Control root)
    {
        if (root == null) return;
        var t = Current;
        ApplyOne(root, t);
        ApplyChildren(root, t);
    }

    private static void ApplyChildren(Control parent, Theme t)
    {
        foreach (Control c in parent.Controls)
        {
            ApplyOne(c, t);
            ApplyChildren(c, t);
        }

        // Las TabPage viven en TabControl.TabPages (tambien estan en .Controls,
        // pero recorrerlas explicitamente asegura sus hijos).
        if (parent is TabControl tc)
        {
            foreach (TabPage page in tc.TabPages)
            {
                ApplyOne(page, t);
                ApplyChildren(page, t);
            }
        }
    }

    private static void ApplyOne(Control c, Theme t)
    {
        switch (c)
        {
            // Subclases owner-draw: solo colores base, se autopintan.
            case ThemedListView lv:
                lv.BackColor = t.Surface;
                lv.ForeColor = t.TextPrimary;
                break;
            case ThemedComboBox cmb:
                cmb.BackColor = t.Surface;
                cmb.ForeColor = t.TextPrimary;
                break;
            case ThemedTabControl tabs:
                tabs.BackColor = t.Background;
                break;

            case Form form:
                form.BackColor = t.Background;
                form.ForeColor = t.TextPrimary;
                break;

            case TabPage page:
                page.UseVisualStyleBackColor = false; // necesario o ignora BackColor
                page.BackColor = t.Surface;
                page.ForeColor = t.TextPrimary;
                break;

            case Button btn:
                btn.FlatStyle = FlatStyle.Flat;
                btn.ForeColor = t.TextPrimary;
                btn.FlatAppearance.MouseOverBackColor = t.Selection;
                btn.FlatAppearance.MouseDownBackColor = t.AccentBlue;
                if (btn.Tag as string == "nav")
                {
                    // Boton de la barra lateral: plano, sin borde. El activo lo
                    // resalta ShowSection con el color de acento.
                    btn.BackColor = t.SurfaceAlt;
                    btn.FlatAppearance.BorderSize = 0;
                }
                else
                {
                    btn.BackColor = t.SurfaceAlt;
                    btn.FlatAppearance.BorderColor = t.Border;
                    btn.FlatAppearance.BorderSize = 1;
                }
                break;

            case CheckBox chk:
                chk.FlatStyle = FlatStyle.Flat;
                chk.ForeColor = t.TextPrimary;
                chk.BackColor = Color.Transparent;
                break;

            case TextBox tb:
                // Respetamos las cajas oscuras dedicadas (hex/interp/disasm), que
                // ya fijan su propio color mediante la marca Tag == "keepdark".
                if (!IsKeepDark(tb))
                {
                    tb.BackColor = t.Surface;
                    tb.ForeColor = t.TextPrimary;
                    tb.BorderStyle = BorderStyle.FixedSingle;
                }
                break;

            case Label lbl:
                lbl.BackColor = Color.Transparent;
                // Las pistas (marcadas) usan texto atenuado; el resto, primario,
                // salvo que el codigo les fije un color semantico despues.
                if (IsHint(lbl))
                    lbl.ForeColor = t.TextMuted;
                else if (!IsSemantic(lbl))
                    lbl.ForeColor = t.TextPrimary;
                break;

            case StatusStrip ss:
                ApplyToToolStrip(ss, t);
                break;

            case SplitContainer sc:
                sc.BackColor = t.Border; // barra divisoria
                break;

            case FlowLayoutPanel:
            case TableLayoutPanel:
            case Panel:
                c.BackColor = t.Surface;
                c.ForeColor = t.TextPrimary;
                break;
        }
    }

    private static bool IsKeepDark(Control c) => c.Tag as string == "keepdark";
    private static bool IsHint(Control c) => c.Tag as string == "hint";
    private static bool IsSemantic(Control c) => c.Tag as string == "semantic";

    /// <summary>Tematiza un ToolStrip/StatusStrip via renderer + colores base.</summary>
    public static void ApplyToToolStrip(ToolStrip strip, Theme t)
    {
        strip.RenderMode = ToolStripRenderMode.Professional;
        strip.Renderer = new ToolStripProfessionalRenderer(new ThemeColorTable(t)) { RoundedEdges = false };
        strip.BackColor = t.Background;
        strip.ForeColor = t.TextPrimary;
        foreach (ToolStripItem item in strip.Items)
        {
            item.BackColor = t.Background;
            item.ForeColor = t.TextPrimary;
        }
    }
}
