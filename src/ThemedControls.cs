namespace MemReader;

/// <summary>
/// ListView con dibujado propio para respetar el tema (cabeceras y filas) tanto en
/// claro como en oscuro. Lee ThemeManager.Current al pintar, asi que cambiar de
/// tema solo requiere Invalidate(). Preserva el ForeColor semantico de cada fila
/// (severidad, entropia, etc.) y el color de seleccion del tema.
/// </summary>
public sealed class ThemedListView : ListView
{
    public ThemedListView()
    {
        OwnerDraw = true;
        DoubleBuffered = true;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
    }

    protected override void OnDrawColumnHeader(DrawListViewColumnHeaderEventArgs e)
    {
        var t = ThemeManager.Current;
        using var back = new SolidBrush(t.HeaderBack);
        e.Graphics.FillRectangle(back, e.Bounds);

        // Separadores sutiles (derecha + inferior).
        using var pen = new Pen(t.Border);
        e.Graphics.DrawLine(pen, e.Bounds.Right - 1, e.Bounds.Top, e.Bounds.Right - 1, e.Bounds.Bottom - 1);
        e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);

        var textRect = Rectangle.Inflate(e.Bounds, -6, 0);
        TextRenderer.DrawText(e.Graphics, e.Header?.Text ?? string.Empty, Font, textRect,
            t.TextPrimary,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }

    protected override void OnDrawItem(DrawListViewItemEventArgs e)
    {
        // En vista Details el pintado real ocurre por subitem.
        e.DrawDefault = false;
    }

    protected override void OnDrawSubItem(DrawListViewSubItemEventArgs e)
    {
        var t = ThemeManager.Current;
        bool selected = e.Item?.Selected ?? false;
        Color back = selected ? t.Selection : t.Surface;
        Color fore = selected ? t.SelectionText : (e.Item?.ForeColor ?? t.TextPrimary);

        using (var b = new SolidBrush(back))
            e.Graphics.FillRectangle(b, e.Bounds);

        // Linea inferior tenue a modo de rejilla limpia.
        using (var pen = new Pen(t.Border))
            e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);

        var textRect = Rectangle.Inflate(e.Bounds, -6, 0);
        TextRenderer.DrawText(e.Graphics, e.SubItem?.Text ?? string.Empty, Font, textRect, fore,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }
}

/// <summary>TabControl con pestanas dibujadas segun el tema, con barra de acento
/// en la pestana activa.</summary>
public sealed class ThemedTabControl : TabControl
{
    public ThemedTabControl()
    {
        DrawMode = TabDrawMode.OwnerDrawFixed;
        SizeMode = TabSizeMode.Fixed;
        Multiline = true;                 // que quepan las 10 pestanas en varias filas
        ItemSize = new Size(132, 26);
        DoubleBuffered = true;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
    }

    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        if (e.Index < 0 || e.Index >= TabPages.Count) return;
        var t = ThemeManager.Current;
        bool selected = e.Index == SelectedIndex;
        Rectangle r = GetTabRect(e.Index);

        using (var b = new SolidBrush(selected ? t.SurfaceAlt : t.Surface))
            e.Graphics.FillRectangle(b, r);

        if (selected)
        {
            using var accent = new SolidBrush(t.AccentBlue);
            e.Graphics.FillRectangle(accent, r.Left, r.Top, r.Width, 3);
        }

        TextRenderer.DrawText(e.Graphics, TabPages[e.Index].Text, Font, r,
            selected ? t.TextPrimary : t.TextMuted,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }
}

/// <summary>ComboBox plano y tematizado. La flecha del desplegable en modo
/// DropDownList mantiene algo de estilo del sistema (limitacion conocida de
/// WinForms); FlatStyle.Flat lo minimiza.</summary>
public sealed class ThemedComboBox : ComboBox
{
    public ThemedComboBox()
    {
        FlatStyle = FlatStyle.Flat;
        DrawMode = DrawMode.OwnerDrawFixed;
    }

    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        var t = ThemeManager.Current;
        if (e.Index < 0)
        {
            using var bg = new SolidBrush(t.Surface);
            e.Graphics.FillRectangle(bg, e.Bounds);
            return;
        }

        bool selected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
        using (var b = new SolidBrush(selected ? t.Selection : t.Surface))
            e.Graphics.FillRectangle(b, e.Bounds);

        string text = Items[e.Index]?.ToString() ?? string.Empty;
        TextRenderer.DrawText(e.Graphics, text, Font, e.Bounds,
            selected ? t.SelectionText : t.TextPrimary,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
    }
}

/// <summary>Tabla de colores para el renderer del StatusStrip.</summary>
public sealed class ThemeColorTable : ProfessionalColorTable
{
    private readonly Theme _t;
    public ThemeColorTable(Theme t) => _t = t;

    public override Color ToolStripGradientBegin => _t.Background;
    public override Color ToolStripGradientMiddle => _t.Background;
    public override Color ToolStripGradientEnd => _t.Background;
    public override Color StatusStripGradientBegin => _t.Background;
    public override Color StatusStripGradientEnd => _t.Background;
    public override Color ToolStripBorder => _t.Border;
    public override Color MenuStripGradientBegin => _t.Background;
    public override Color MenuStripGradientEnd => _t.Background;
    public override Color ToolStripContentPanelGradientBegin => _t.Background;
    public override Color ToolStripContentPanelGradientEnd => _t.Background;
}
