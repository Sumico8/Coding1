namespace MemReader;

/// <summary>
/// Dialogo modal para crear o editar una etiqueta. Permite nombre, categoria
/// (editable, autocompletada), tipo, notas, y sugerir una ruta de puntero estable
/// para una direccion dinamica (reutiliza PointerScanner.ScanChains).
/// </summary>
public sealed class AnnotationDialog : Form
{
    private readonly Annotation _work;
    private readonly PointerScanner? _scanner;
    private readonly ulong? _scanAddress;

    private readonly TextBox _txtName;
    private readonly ThemedComboBox _cmbCategory;
    private readonly ThemedComboBox _cmbType;
    private readonly TextBox _txtNotes;
    private readonly TextBox _txtAnchor;
    private readonly Button _btnSuggest;
    private readonly Label _lblStatus;

    public Annotation Result => _work;

    public AnnotationDialog(Annotation seed, ulong? scanAddress, PointerScanner? scanner,
                            IEnumerable<string> knownCategories)
    {
        _scanner = scanner;
        _scanAddress = scanAddress ?? (seed.Kind == AnchorKind.Absolute && seed.AbsoluteAddress != 0
            ? seed.AbsoluteAddress : null);

        // Trabajamos sobre una copia para no mutar hasta aceptar.
        _work = new Annotation
        {
            Id = seed.Id,
            Name = seed.Name,
            Category = seed.Category,
            Type = seed.Type,
            Notes = seed.Notes,
            Kind = seed.Kind,
            ModuleName = seed.ModuleName,
            BaseOffset = seed.BaseOffset,
            Offsets = new List<long>(seed.Offsets),
            AbsoluteAddress = seed.AbsoluteAddress,
            LastKnownAddress = seed.LastKnownAddress,
        };

        Text = string.IsNullOrEmpty(seed.Name) ? "Nueva etiqueta" : "Editar etiqueta";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;
        ClientSize = new Size(520, 340);

        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 2,
            RowCount = 5,
            Height = 210,
            Padding = new Padding(12, 12, 12, 4),
            AutoSize = false,
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        _txtName = new TextBox { Dock = DockStyle.Fill, Text = _work.Name };
        _cmbCategory = new ThemedComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDown };
        _cmbCategory.Items.AddRange(knownCategories.Cast<object>().ToArray());
        // Sugerencias por defecto habituales en juegos.
        foreach (var def in new[] { "Jugador", "Entorno", "Arboles", "Plantas", "Enemigos", "Inventario", "Camara" })
            if (!_cmbCategory.Items.Contains(def)) _cmbCategory.Items.Add(def);
        _cmbCategory.Text = _work.Category;

        _cmbType = new ThemedComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
        _cmbType.Items.AddRange(Enum.GetNames(typeof(LabelType)).Cast<object>().ToArray());
        _cmbType.SelectedIndex = (int)_work.Type;

        _txtNotes = new TextBox { Dock = DockStyle.Fill, Multiline = true, Height = 46, Text = _work.Notes ?? "" };

        grid.Controls.Add(new Label { Text = "Nombre:", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
        grid.Controls.Add(_txtName, 1, 0);
        grid.Controls.Add(new Label { Text = "Categoria:", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 1);
        grid.Controls.Add(_cmbCategory, 1, 1);
        grid.Controls.Add(new Label { Text = "Tipo:", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 2);
        grid.Controls.Add(_cmbType, 1, 2);
        grid.Controls.Add(new Label { Text = "Notas:", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 3);
        grid.Controls.Add(_txtNotes, 1, 3);

        // ----- Ancla -----
        var anchorPanel = new Panel { Dock = DockStyle.Top, Height = 84, Padding = new Padding(12, 4, 12, 4) };
        var lblAnchor = new Label { Text = "Ancla (donde vive):", Dock = DockStyle.Top, Height = 20 };
        _txtAnchor = new TextBox
        {
            Dock = DockStyle.Top,
            ReadOnly = true,
            Font = new Font("Consolas", 9F),
            Text = _work.AnchorText,
        };
        _btnSuggest = new Button { Text = "Sugerir ruta estable", Dock = DockStyle.Top, Height = 28 };
        _btnSuggest.Click += async (_, _) => await SuggestPathAsync();
        _btnSuggest.Enabled = _scanner != null && _scanAddress != null;
        anchorPanel.Controls.Add(_btnSuggest);
        anchorPanel.Controls.Add(_txtAnchor);
        anchorPanel.Controls.Add(lblAnchor);

        // ----- Botonera -----
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            Height = 44,
            Padding = new Padding(8),
        };
        var btnOk = new Button { Text = "Aceptar", Width = 90, DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancelar", Width = 90, DialogResult = DialogResult.Cancel };
        btnOk.Click += (_, _) => OnAccept();
        buttons.Controls.Add(btnOk);
        buttons.Controls.Add(btnCancel);

        _lblStatus = new Label { Dock = DockStyle.Bottom, Height = 20, Text = "", Tag = "hint" };

        Controls.Add(grid);
        Controls.Add(anchorPanel);
        Controls.Add(_lblStatus);
        Controls.Add(buttons);

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        ThemeManager.Apply(this);
    }

    private async Task SuggestPathAsync()
    {
        if (_scanner == null || _scanAddress == null) return;
        _btnSuggest.Enabled = false;
        _lblStatus.Text = "Escaneando rutas de puntero...";
        var scanner = _scanner;
        ulong addr = _scanAddress.Value;
        using var cts = new CancellationTokenSource();
        var progress = new Progress<string>(m => _lblStatus.Text = m);
        try
        {
            var paths = await Task.Run(() =>
            {
                if (!scanner.IndexBuilt) scanner.BuildIndex(20, progress, cts.Token);
                return scanner.ScanChains(addr, 4, 0x1000, 200, progress, cts.Token);
            }, cts.Token);

            if (paths.Count > 0)
            {
                var p = paths[0];
                _work.Kind = AnchorKind.PointerPath;
                _work.ModuleName = p.ModuleName;
                _work.BaseOffset = p.BaseOffset;
                _work.Offsets = new List<long>(p.Offsets);
                _txtAnchor.Text = _work.AnchorText;
                _lblStatus.Text = $"Ruta estable encontrada (de {paths.Count}). Ahora sobrevive a reinicios.";
            }
            else
            {
                _lblStatus.Text = "No se hallo ruta estable; se mantiene la direccion de sesion.";
            }
        }
        catch (Exception ex)
        {
            _lblStatus.Text = "Error al escanear: " + ex.Message;
        }
        finally
        {
            _btnSuggest.Enabled = true;
        }
    }

    private void OnAccept()
    {
        if (string.IsNullOrWhiteSpace(_txtName.Text))
        {
            _lblStatus.Text = "El nombre es obligatorio.";
            DialogResult = DialogResult.None; // no cerrar
            return;
        }
        _work.Name = _txtName.Text.Trim();
        _work.Category = _cmbCategory.Text.Trim();
        _work.Type = (LabelType)Math.Max(0, _cmbType.SelectedIndex);
        _work.Notes = string.IsNullOrWhiteSpace(_txtNotes.Text) ? null : _txtNotes.Text.Trim();
    }
}
