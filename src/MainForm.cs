using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace MemReader;

/// <summary>
/// Interfaz de la herramienta: lista de procesos -> regiones de memoria ->
/// visor hexadecimal y buscador de cadenas. Todo en modo usuario y solo lectura.
/// </summary>
public sealed class MainForm : Form
{
    private ListView _lvProcesses = null!;
    private ListView _lvRegions = null!;
    private readonly ListView _lvResults;
    private TextBox _txtFilter = null!;
    private readonly TextBox _txtAddress;
    private readonly TextBox _txtSize;
    private readonly TextBox _txtHex;
    private readonly TextBox _txtSearch;
    private CheckBox _chkOnlyReadable = null!;
    private Label _lblProcess = null!;
    private readonly Label _lblAdmin;
    private readonly ToolStripStatusLabel _status;
    private readonly Button _btnSearch;

    private ComboBox _cmbSearchType = null!;
    private TextBox _txtInterp = null!;
    private CheckBox _chkAutoRefresh = null!;
    private ListView _lvModules = null!;
    private ListView _lvPointers = null!;
    private TextBox _ptrTarget = null!;
    private TextBox _ptrDepth = null!;
    private TextBox _ptrMaxOff = null!;
    private PointerScanner? _scanner;
    private CancellationTokenSource? _ptrCts;
    private ListView _lvStrings = null!;
    private TextBox _txtMinLen = null!;
    private CancellationTokenSource? _stringsCts;
    private ListView _lvScan = null!;
    private ComboBox _cmbScanType = null!;
    private TextBox _txtScanValue = null!;
    private ComboBox _cmbScanFilter = null!;
    private ScanSession? _scanSession;
    private CancellationTokenSource? _scanCts;
    private ListView _lvSecurity = null!;
    private CancellationTokenSource? _secCts;
    private ListView _lvThreads = null!;
    private TextBox _disasmAddr = null!;
    private TextBox _disasmCount = null!;
    private TextBox _txtDisasm = null!;
    private readonly System.Windows.Forms.Timer _refreshTimer;

    private ProcessMemoryReader? _reader;
    private List<MemoryRegion> _regions = new();
    private CancellationTokenSource? _searchCts;

    // --- Interfaz nueva: navegacion lateral, tema, busqueda e identificador ---
    private Panel _content = null!;
    private FlowLayoutPanel _sidebar = null!;
    private TabPage _activePage = null!;
    private TabPage _hexPage = null!;
    private TabPage _procPage = null!;
    private TabPage _regionsPage = null!;
    private readonly Dictionary<TabPage, Button> _navButtons = new();
    private Button _btnTheme = null!;
    private TextBox _txtGlobalFind = null!;
    private readonly AnnotationStore _store = new();
    private Identifier? _identifier;
    private ThemedListView _lvLabels = null!;
    private TextBox _lblIdentity = null!;
    private ContextMenuStrip _ctxLabel = null!;
    private readonly Dictionary<TabPage, ListViewFilter> _tabFilters = new();
    private ListViewFilter? _filterResults, _filterScan, _filterStrings, _filterPointers,
        _filterSecurity, _filterThreads, _filterModules, _filterLabels, _filterRegions;

    private static readonly Font Mono = new("Consolas", 9F);

    public MainForm()
    {
        Text = "MemReader - Lector de memoria de procesos (user-mode, solo lectura)";
        Width = 1240;
        Height = 820;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1040, 660);
        Font = new Font("Segoe UI", 9.75F);

        // ---------- Cabecera ----------
        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Top, Height = 54, ColumnCount = 4, RowCount = 1,
            Padding = new Padding(12, 8, 12, 8),
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var lblTitle = new Label
        {
            Text = "MemReader", AutoSize = true, Tag = "semantic",
            Font = new Font("Segoe UI", 13F, FontStyle.Bold), Margin = new Padding(0, 6, 18, 0),
        };

        _lblProcess = new Label
        {
            Text = "Ningun proceso abierto.", AutoSize = true,
            Font = new Font("Segoe UI", 9.75F, FontStyle.Bold), Margin = new Padding(0, 3, 8, 0),
        };
        _lblAdmin = new Label { AutoSize = true, Margin = new Padding(0, 2, 0, 0), ForeColor = Color.DarkRed, Tag = "semantic" };
        var infoStack = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true,
            Dock = DockStyle.Fill, Margin = new Padding(0),
        };
        infoStack.Controls.Add(_lblProcess);
        infoStack.Controls.Add(_lblAdmin);

        var findStack = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, WrapContents = false, AutoSize = true, Margin = new Padding(0) };
        var lblFind = new Label { Text = "🔎", AutoSize = true, Margin = new Padding(0, 8, 4, 0), Tag = "hint" };
        _txtGlobalFind = new TextBox { Width = 200, Margin = new Padding(0, 6, 12, 0) };
        _txtGlobalFind.TextChanged += (_, _) => OnGlobalFindChanged();
        findStack.Controls.Add(lblFind);
        findStack.Controls.Add(_txtGlobalFind);

        _btnTheme = new Button { Text = ThemeManager.IsDark ? "☀ Claro" : "🌙 Oscuro", Width = 104, Height = 30, Margin = new Padding(0, 5, 0, 0) };
        _btnTheme.Click += (_, _) => ThemeManager.Toggle();

        header.Controls.Add(lblTitle, 0, 0);
        header.Controls.Add(infoStack, 1, 0);
        header.Controls.Add(findStack, 2, 0);
        header.Controls.Add(_btnTheme, 3, 0);

        // ---------- Contenido: todas las secciones alojadas en un panel ----------
        _content = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8) };

        _procPage = BuildProcessSection();
        _hexPage = BuildHexTab();
        var searchPage = BuildSearchTab(out _txtSearch, out _lvResults, out _btnSearch);
        _regionsPage = BuildRegionsSection();
        var modulesPage = BuildModulesTab();
        var pointersPage = BuildPointersTab();
        var scanPage = BuildScanTab();
        var labelsPage = BuildLabelsTab();
        var stringsPage = BuildStringsTab();
        var securityPage = BuildSecurityTab();
        var threadsPage = BuildThreadsTab();
        var disasmPage = BuildDisasmTab();

        var sections = new (string label, TabPage page)[]
        {
            ("👁   Procesos", _procPage),
            ("🗺   Regiones", _regionsPage),
            ("🔢   Visor hex", _hexPage),
            ("🔎   Buscar", searchPage),
            ("📈   Escaneo", scanPage),
            ("📌   Punteros", pointersPage),
            ("🏷   Etiquetas", labelsPage),
            ("🔡   Strings", stringsPage),
            ("🧩   Modulos", modulesPage),
            ("🔐   Seguridad", securityPage),
            ("🧠   Hilos", threadsPage),
            ("⌨   Ensamblador", disasmPage),
        };

        // ---------- Navegacion lateral ----------
        _sidebar = new FlowLayoutPanel
        {
            Dock = DockStyle.Left, Width = 178, FlowDirection = FlowDirection.TopDown,
            WrapContents = false, Padding = new Padding(6, 10, 6, 10), AutoScroll = true,
        };
        foreach (var (label, page) in sections)
        {
            page.Dock = DockStyle.Fill;
            page.Visible = false;
            _content.Controls.Add(page);
            var btn = MakeNavButton(label, page);
            _navButtons[page] = btn;
            _sidebar.Controls.Add(btn);
        }

        // Menu contextual "Etiquetar esta direccion..." compartido por las listas.
        _ctxLabel = new ContextMenuStrip();
        var miLabel = new ToolStripMenuItem("Etiquetar esta direccion...");
        miLabel.Click += (_, _) => { if (_ctxLabel.SourceControl is ListView lv) EtiquetarFromContext(lv); };
        _ctxLabel.Items.Add(miLabel);
        foreach (var lv in new ListView[] { _lvResults, _lvScan, _lvPointers, _lvStrings })
            lv.ContextMenuStrip = _ctxLabel;

        // Temporizador (1 s): auto-refresco del visor hex y valores en vivo de etiquetas.
        _refreshTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _refreshTimer.Tick += (_, _) =>
        {
            if (_reader == null) return;
            if (_chkAutoRefresh.Checked) ReadHexAtAddress();
            if (_lvLabels != null && _activePage == _lvLabels.Parent) RefreshLabelLiveValues();
        };

        // ---------- Barra de estado ----------
        var statusStrip = new StatusStrip();
        _status = new ToolStripStatusLabel { Text = "Listo." };
        statusStrip.Items.Add(_status);

        // Orden de anadido para el docking: Fill, luego Left, luego Bottom, luego Top.
        Controls.Add(_content);
        Controls.Add(_sidebar);
        Controls.Add(statusStrip);
        Controls.Add(header);

        // Campos que se inicializan en los builders.
        _txtAddress = _hexAddress!;
        _txtSize = _hexSize!;
        _txtHex = _hexView!;

        ApplyThemeNow();
        ThemeManager.ThemeChanged += OnThemeChanged;
        _store.Changed += (_, _) => RefreshLabelsList();

        ShowSection(_procPage);

        Load += (_, _) =>
        {
            ShowElevationState();
            LoadProcesses();
        };
        FormClosing += (_, _) =>
        {
            _refreshTimer.Stop();
            _searchCts?.Cancel();
            _ptrCts?.Cancel();
            _stringsCts?.Cancel();
            _scanCts?.Cancel();
            _secCts?.Cancel();
            ThemeManager.ThemeChanged -= OnThemeChanged;
            _store.Save();
            _reader?.Dispose();
        };
    }

    // ---------------- Navegacion lateral ----------------

    private Button MakeNavButton(string text, TabPage page)
    {
        var btn = new Button
        {
            Text = text,
            Width = 162,
            Height = 36,
            TextAlign = ContentAlignment.MiddleLeft,
            FlatStyle = FlatStyle.Flat,
            Margin = new Padding(2, 2, 2, 3),
            Padding = new Padding(6, 0, 0, 0),
            Tag = "nav",
        };
        btn.FlatAppearance.BorderSize = 0;
        btn.Click += (_, _) => ShowSection(page);
        return btn;
    }

    private void ShowSection(TabPage page)
    {
        if (page == null) return;
        _activePage = page;
        foreach (Control c in _content.Controls)
            c.Visible = c == page;
        page.BringToFront();

        var t = ThemeManager.Current;
        foreach (var kv in _navButtons)
        {
            bool active = kv.Key == page;
            kv.Value.BackColor = active ? t.AccentBlue : t.Surface;
            kv.Value.ForeColor = active ? t.SelectionText : t.TextPrimary;
        }

        if (_tabFilters.TryGetValue(page, out var f)) f.Apply(_txtGlobalFind.Text);
        UpdateTimerState();
    }

    private TabPage BuildProcessSection()
    {
        var page = new TabPage("Procesos");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };
        var btnRefresh = new Button { Text = "Actualizar", Width = 110, Margin = new Padding(0, 4, 6, 0) };
        btnRefresh.Click += (_, _) => LoadProcesses();
        var lblFilter = new Label { Text = "Filtrar:", AutoSize = true, Margin = new Padding(6, 8, 3, 0), Tag = "hint" };
        _txtFilter = new TextBox { Width = 220, Margin = new Padding(0, 5, 0, 0) };
        _txtFilter.TextChanged += (_, _) => LoadProcesses();
        bar.Controls.AddRange(new Control[] { btnRefresh, lblFilter, _txtFilter });

        _lvProcesses = new ThemedListView
        {
            Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
            GridLines = true, MultiSelect = false, HideSelection = false,
        };
        _lvProcesses.Columns.Add("PID", 80);
        _lvProcesses.Columns.Add("Proceso", 300);
        _lvProcesses.DoubleClick += (_, _) => AnalyzeSelectedProcess();

        var btnAnalyze = new Button { Text = "Analizar proceso seleccionado", Dock = DockStyle.Bottom, Height = 38 };
        btnAnalyze.Click += (_, _) => AnalyzeSelectedProcess();

        var hint = new Label
        {
            Dock = DockStyle.Bottom, Height = 22,
            Text = "Doble clic o 'Analizar' para abrir el proceso.",
            ForeColor = Color.Gray, Tag = "hint", Padding = new Padding(4, 2, 0, 0),
        };

        page.Controls.Add(_lvProcesses);
        page.Controls.Add(hint);
        page.Controls.Add(btnAnalyze);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildRegionsSection()
    {
        var page = new TabPage("Regiones");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(4, 4, 4, 4) };
        _chkOnlyReadable = new CheckBox { Text = "Solo legibles", Checked = true, AutoSize = true, Margin = new Padding(4, 8, 10, 0) };
        _chkOnlyReadable.CheckedChanged += (_, _) => { if (_reader != null) EnumerateRegions(); };
        var btnDump = new Button { Text = "Volcar region...", Width = 140, Margin = new Padding(0, 4, 4, 0) };
        btnDump.Click += (_, _) => DumpSelectedRegion();
        var btnDumpAll = new Button { Text = "Volcar TODO...", Width = 140, Margin = new Padding(0, 4, 4, 0) };
        btnDumpAll.Click += (_, _) => DumpAllRegions();
        var btnMinidump = new Button { Text = "Minidump...", Width = 120, Margin = new Padding(0, 4, 4, 0) };
        btnMinidump.Click += (_, _) => WriteMinidump();
        var btnEntropy = new Button { Text = "Entropia", Width = 90, Margin = new Padding(0, 4, 4, 0) };
        btnEntropy.Click += (_, _) => ComputeEntropy();
        bar.Controls.AddRange(new Control[] { _chkOnlyReadable, btnDump, btnDumpAll, btnMinidump, btnEntropy });

        _lvRegions = new ThemedListView
        {
            Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
            GridLines = true, MultiSelect = false, HideSelection = false,
        };
        _lvRegions.Columns.Add("Direccion base", 150);
        _lvRegions.Columns.Add("Tamano", 90);
        _lvRegions.Columns.Add("Proteccion", 85);
        _lvRegions.Columns.Add("Tipo", 85);
        _lvRegions.Columns.Add("Entropia", 70);
        _lvRegions.Columns.Add("Que es", 240);
        _lvRegions.SelectedIndexChanged += (_, _) => OnRegionSelected();
        _filterRegions = AddFilter(bar, _lvRegions, page);

        page.Controls.Add(_lvRegions);
        page.Controls.Add(bar);
        return page;
    }

    // ---------------- Tema ----------------

    private void OnThemeChanged(object? sender, EventArgs e) => ApplyThemeNow();

    private void ApplyThemeNow()
    {
        ThemeManager.Apply(this);
        if (_sidebar != null) _sidebar.BackColor = ThemeManager.Current.Background;
        if (_ctxLabel != null)
        {
            _ctxLabel.BackColor = ThemeManager.Current.Surface;
            _ctxLabel.ForeColor = ThemeManager.Current.TextPrimary;
        }
        if (_btnTheme != null)
            _btnTheme.Text = ThemeManager.IsDark ? "☀ Claro" : "🌙 Oscuro";
        ReapplySemanticColors();
        if (_activePage != null) ShowSection(_activePage); // re-resalta el boton activo
        Invalidate(true);
    }

    /// <summary>Recalcula los colores semanticos de las filas desde sus datos, para
    /// que sigan legibles tras cambiar de tema.</summary>
    private void ReapplySemanticColors()
    {
        var t = ThemeManager.Current;

        _lblAdmin.ForeColor = _lblAdmin.Text.StartsWith("Ejecutando", StringComparison.Ordinal)
            ? t.OkText : t.BadText;

        // Regiones: entropia > 7.2 en rojo.
        foreach (ListViewItem it in _lvRegions.Items)
        {
            if (it.SubItems.Count > 4 &&
                double.TryParse(it.SubItems[4].Text, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out double h))
                it.ForeColor = h >= 7.2 ? t.SeverityHigh : t.TextPrimary;
        }
        // Hilos: inicio dinamico (fuera de modulo) en rojo.
        foreach (ListViewItem it in _lvThreads.Items)
            it.ForeColor = it.SubItems.Count > 2 && it.SubItems[2].Text == "(dinamica)"
                ? t.SeverityHigh : t.TextPrimary;
        // Seguridad: por severidad.
        foreach (ListViewItem it in _lvSecurity.Items)
            it.ForeColor = it.Text switch
            {
                "Alta" => t.SeverityHigh,
                "Media" => t.SeverityMedium,
                _ => t.TextPrimary,
            };
        // Etiquetas: color por categoria.
        foreach (ListViewItem it in _lvLabels.Items)
            if (it.Tag is Annotation a)
                it.ForeColor = t.CategoryColor(a.Category);
    }

    // ---------------- Busqueda (filtros por lista) ----------------

    /// <summary>Anade una caja de filtro rapido a una barra y la asocia al ListView.</summary>
    private ListViewFilter AddFilter(FlowLayoutPanel bar, ListView lv, TabPage page)
    {
        var lbl = new Label { Text = "Filtrar:", AutoSize = true, Margin = new Padding(12, 8, 3, 0), Tag = "hint" };
        var box = new TextBox { Width = 150, Margin = new Padding(3, 5, 3, 0) };
        var f = new ListViewFilter(lv);
        box.TextChanged += (_, _) => f.Apply(box.Text);
        _tabFilters[page] = f;
        bar.Controls.Add(lbl);
        bar.Controls.Add(box);
        return f;
    }

    private void OnGlobalFindChanged()
    {
        if (_activePage != null && _tabFilters.TryGetValue(_activePage, out var f))
            f.Apply(_txtGlobalFind.Text);
    }

    private void UpdateTimerState()
    {
        bool labelsActive = _lvLabels != null && _activePage == _lvLabels.Parent;
        if (_reader != null && (_chkAutoRefresh.Checked || labelsActive))
            _refreshTimer.Start();
        else
            _refreshTimer.Stop();
    }

    // ---------------- Etiquetas / Identificador ----------------

    private TabPage BuildLabelsTab()
    {
        var page = new TabPage("Etiquetas");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var btnAdd = new Button { Text = "Anadir", Width = 90, Margin = new Padding(0, 4, 4, 0) };
        btnAdd.Click += (_, _) => AddOrEditLabel(null);
        var btnEdit = new Button { Text = "Editar", Width = 80, Margin = new Padding(0, 4, 4, 0) };
        btnEdit.Click += (_, _) =>
        {
            if (_lvLabels.SelectedItems.Count > 0 && _lvLabels.SelectedItems[0].Tag is Annotation a)
                AddOrEditLabel(a);
        };
        var btnDel = new Button { Text = "Eliminar", Width = 90, Margin = new Padding(0, 4, 4, 0) };
        btnDel.Click += (_, _) => DeleteLabel();
        var btnImport = new Button { Text = "Importar...", Width = 100, Margin = new Padding(0, 4, 4, 0) };
        btnImport.Click += (_, _) => ImportLabels();
        var btnExport = new Button { Text = "Exportar...", Width = 100, Margin = new Padding(0, 4, 4, 0) };
        btnExport.Click += (_, _) => SaveLabels();
        bar.Controls.AddRange(new Control[] { btnAdd, btnEdit, btnDel, btnImport, btnExport });

        _lvLabels = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false,
        };
        _lvLabels.Columns.Add("Nombre", 180);
        _lvLabels.Columns.Add("Categoria", 110);
        _lvLabels.Columns.Add("Tipo", 80);
        _lvLabels.Columns.Add("Ancla / ruta", 320);
        _lvLabels.Columns.Add("Valor en vivo", 140);
        _lvLabels.Columns.Add("Estado", 90);
        _lvLabels.DoubleClick += (_, _) => JumpFromLabel();

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic salta a la direccion viva. Clic derecho en resultados para etiquetar.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0),
        };

        _filterLabels = AddFilter(bar, _lvLabels, page);

        page.Controls.Add(_lvLabels);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private void RefreshLabelsList()
    {
        if (_lvLabels == null) return;
        _identifier?.RefreshLabelIndex(); // para que la columna "Que es" incluya etiquetas
        var t = ThemeManager.Current;
        List<ModuleInfo>? modules = _identifier?.CurrentModules();
        _lvLabels.BeginUpdate();
        _lvLabels.Items.Clear();
        foreach (var a in _store.Items)
        {
            var it = new ListViewItem(a.Name) { Tag = a };
            it.SubItems.Add(a.Category);
            it.SubItems.Add(a.Type.ToString());
            it.SubItems.Add(a.AnchorText);
            string val = "-";
            string estado = a.KindText;
            if (_identifier != null && modules != null)
            {
                var addr = _identifier.Resolve(a, modules);
                estado = addr == null ? "no resuelve" : a.KindText;
                val = _identifier.LiveValue(a, modules);
            }
            it.SubItems.Add(val);
            it.SubItems.Add(estado);
            it.ForeColor = t.CategoryColor(a.Category);
            _lvLabels.Items.Add(it);
        }
        _lvLabels.EndUpdate();
        _filterLabels?.Reset();
    }

    private void RefreshLabelLiveValues()
    {
        if (_identifier == null || _lvLabels == null || _lvLabels.Items.Count == 0) return;
        var modules = _identifier.CurrentModules();
        foreach (ListViewItem it in _lvLabels.Items)
        {
            if (it.Tag is not Annotation a || it.SubItems.Count <= 5) continue;
            var addr = _identifier.Resolve(a, modules);
            it.SubItems[4].Text = _identifier.LiveValue(a, modules);
            it.SubItems[5].Text = addr == null ? "no resuelve" : a.KindText;
        }
    }

    private void AddOrEditLabel(Annotation? existing)
    {
        Annotation seed = existing ?? new Annotation();
        ulong? scanAddr = existing != null ? _identifier?.Resolve(existing) : null;
        using var dlg = new AnnotationDialog(seed, scanAddr, _scanner, _store.Categories());
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        if (existing == null) _store.Add(dlg.Result);
        else _store.Update(dlg.Result);
    }

    private void EtiquetarFromContext(ListView lv)
    {
        if (lv.SelectedItems.Count == 0) { _status.Text = "Selecciona una fila para etiquetar."; return; }
        var row = lv.SelectedItems[0];
        var seed = new Annotation();
        ulong? scanAddr = null;

        switch (row.Tag)
        {
            case PointerPath p:
                seed.Kind = AnchorKind.PointerPath;
                seed.ModuleName = p.ModuleName;
                seed.BaseOffset = p.BaseOffset;
                seed.Offsets = new List<long>(p.Offsets);
                scanAddr = _identifier?.Resolve(seed);
                break;

            case ulong addr:
                seed.AbsoluteAddress = addr;
                seed.LastKnownAddress = addr;
                seed.Kind = AnchorKind.Absolute;
                scanAddr = addr;
                var mo = _scanner?.ResolveModuleOffset(addr);
                if (mo != null)
                {
                    // Si cae dentro de un modulo, proponemos ancla estatica.
                    seed.Kind = AnchorKind.ModuleOffset;
                    seed.ModuleName = mo.Value.mod.Name;
                    seed.BaseOffset = (long)mo.Value.offset;
                }
                break;

            default:
                _status.Text = "Esta fila no tiene una direccion etiquetable.";
                return;
        }

        using var dlg = new AnnotationDialog(seed, scanAddr, _scanner, _store.Categories());
        if (dlg.ShowDialog(this) == DialogResult.OK)
        {
            _store.Add(dlg.Result);
            _status.Text = $"Etiqueta «{dlg.Result.Name}» guardada.";
        }
    }

    private void DeleteLabel()
    {
        if (_lvLabels.SelectedItems.Count == 0) return;
        if (_lvLabels.SelectedItems[0].Tag is Annotation a)
            _store.Remove(a.Id);
    }

    private void SaveLabels()
    {
        if (_store.Items.Count == 0) { _status.Text = "No hay etiquetas que exportar."; return; }
        using var sfd = new SaveFileDialog
        {
            Title = "Exportar etiquetas",
            FileName = "etiquetas.json",
            Filter = "JSON (*.json)|*.json|Todos los archivos (*.*)|*.*"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try { _store.Export(sfd.FileName); _status.Text = "Etiquetas exportadas a " + sfd.FileName; }
        catch (Exception ex) { _status.Text = "Error al exportar: " + ex.Message; }
    }

    private void ImportLabels()
    {
        using var ofd = new OpenFileDialog
        {
            Title = "Importar etiquetas",
            Filter = "JSON (*.json)|*.json|Todos los archivos (*.*)|*.*"
        };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;
        try { _store.Import(ofd.FileName); _status.Text = "Etiquetas importadas."; }
        catch (Exception ex) { _status.Text = "Error al importar: " + ex.Message; }
    }

    private void JumpFromLabel()
    {
        if (_identifier == null || _lvLabels.SelectedItems.Count == 0) return;
        if (_lvLabels.SelectedItems[0].Tag is not Annotation a) return;
        var addr = _identifier.Resolve(a);
        if (addr == null) { _status.Text = "La etiqueta no resuelve ahora mismo."; return; }
        _txtAddress.Text = "0x" + addr.Value.ToString("X");
        _txtSize.Text = "256";
        ReadHexAtAddress();
        ShowSection(_hexPage);
    }

    private Color WhatIsColor(AddrCategory c)
    {
        var t = ThemeManager.Current;
        return c switch
        {
            AddrCategory.Modulo or AddrCategory.Imagen => t.ModuleColor,
            AddrCategory.Pila => t.AccentPurple,
            AddrCategory.Mapeado => t.AccentAmber,
            _ => t.TextPrimary,
        };
    }

    private void UpdateIdentityPanel(ulong address)
    {
        if (_identifier == null) { _lblIdentity.Text = "Identidad: abre un proceso."; return; }
        var r = _identifier.Identify(address, _regions);
        var sb = new StringBuilder();
        sb.Append("Identidad: ");
        sb.Append(r.ModuleName != null ? $"{r.ModuleName}+0x{r.ModuleOffset:X}" : $"0x{address:X}");
        sb.Append(r.IsStatic ? " · estatica" : " · dinamica");
        var reg = r.Region;
        if (reg != null) sb.Append($" · {reg.ProtectText}/{reg.TypeText}");

        var t = ThemeManager.Current;
        if (r.Matches.Count > 0)
        {
            var m = r.Matches[0];
            string near = m.Delta == 0 ? "exacto" : $"+0x{Math.Abs(m.Delta):X}";
            sb.Append($"   =>   «{m.Ann.Name}» [{m.Ann.Category}] ({near})");
            if (r.Matches.Count > 1) sb.Append($"  (+{r.Matches.Count - 1} mas)");
            _lblIdentity.ForeColor = t.CategoryColor(m.Ann.Category);
        }
        else
        {
            sb.Append($" · {r.TypeGuess}");
            _lblIdentity.ForeColor = t.TextPrimary;
        }
        _lblIdentity.Text = sb.ToString();
    }

    // Referencias temporales usadas al construir las pestanas.
    private TextBox? _hexAddress;
    private TextBox? _hexSize;
    private TextBox? _hexView;

    private TabPage BuildHexTab()
    {
        var page = new TabPage("Visor hexadecimal");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var lblAddr = new Label { Text = "Direccion (hex):", Left = 4, Top = 9, Width = 100 };
        _hexAddress = new TextBox { Left = 106, Top = 6, Width = 150, Font = Mono };
        var lblSize = new Label { Text = "Bytes:", Left = 262, Top = 9, Width = 45 };
        _hexSize = new TextBox { Left = 308, Top = 6, Width = 70, Text = "4096", Font = Mono };
        var btnRead = new Button { Text = "Leer", Left = 384, Top = 4, Width = 64 };
        btnRead.Click += (_, _) => ReadHexAtAddress();
        var btnCopy = new Button { Text = "Copiar", Left = 452, Top = 4, Width = 72 };
        btnCopy.Click += (_, _) => CopyHexToClipboard();
        var btnExport = new Button { Text = "Exportar...", Left = 528, Top = 4, Width = 88 };
        btnExport.Click += (_, _) => ExportHexToFile();
        _chkAutoRefresh = new CheckBox { Text = "Auto 1s", Left = 624, Top = 7, Width = 80 };
        _chkAutoRefresh.CheckedChanged += (_, _) => ToggleAutoRefresh();

        bar.Controls.AddRange(new Control[]
        {
            lblAddr, _hexAddress, lblSize, _hexSize, btnRead, btnCopy, btnExport, _chkAutoRefresh
        });

        _hexView = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = Mono,
            Tag = "keepdark",
            BackColor = Color.FromArgb(24, 24, 24),
            ForeColor = Color.FromArgb(220, 220, 220)
        };

        // Panel de interpretacion de valores (abajo).
        var interpPanel = new Panel { Dock = DockStyle.Bottom, Height = 150 };
        var lblInterp = new Label
        {
            Dock = DockStyle.Top,
            Height = 20,
            Text = "Interpretacion de los primeros bytes de la direccion:",
            Padding = new Padding(4, 3, 0, 0),
            ForeColor = Color.Gray
        };
        _txtInterp = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            WordWrap = false,
            Font = Mono,
            Tag = "keepdark",
            BackColor = Color.FromArgb(30, 30, 30),
            ForeColor = Color.FromArgb(180, 220, 180)
        };
        interpPanel.Controls.Add(_txtInterp);
        interpPanel.Controls.Add(lblInterp);

        // Banda "Identidad": que es la direccion que estas viendo.
        _lblIdentity = new TextBox
        {
            Dock = DockStyle.Top,
            ReadOnly = true,
            BorderStyle = BorderStyle.FixedSingle,
            Font = Mono,
            Text = "Identidad: abre un proceso y lee una direccion.",
        };

        page.Controls.Add(_hexView);
        page.Controls.Add(interpPanel);
        page.Controls.Add(_lblIdentity);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildSearchTab(out TextBox txtSearch, out ListView lvResults, out Button btnSearch)
    {
        var page = new TabPage("Buscar en memoria");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var lblType = new Label { Text = "Tipo:", Left = 4, Top = 9, Width = 38 };
        _cmbSearchType = new ThemedComboBox
        {
            Left = 44, Top = 6, Width = 100,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cmbSearchType.Items.AddRange(new object[] { "Texto", "Int32", "Int64", "Float", "Double", "Bytes hex" });
        _cmbSearchType.SelectedIndex = 0;

        var lbl = new Label { Text = "Valor:", Left = 150, Top = 9, Width = 45 };
        txtSearch = new TextBox { Left = 196, Top = 6, Width = 260, Font = Mono };
        btnSearch = new Button { Text = "Buscar", Left = 462, Top = 4, Width = 84 };
        var localBtn = btnSearch;
        btnSearch.Click += (_, _) => ToggleSearch();
        var btnCsv = new Button { Text = "Exportar CSV...", Left = 552, Top = 4, Width = 120 };
        btnCsv.Click += (_, _) => ExportResultsCsv();

        bar.Controls.AddRange(new Control[] { lblType, _cmbSearchType, lbl, txtSearch, localBtn, btnCsv });

        lvResults = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        lvResults.Columns.Add("Direccion", 160);
        lvResults.Columns.Add("Tipo", 90);
        lvResults.Columns.Add("Valor", 240);
        lvResults.Columns.Add("Que es", 260);
        var localResults = lvResults;
        lvResults.DoubleClick += (_, _) => JumpToResult(localResults);
        _filterResults = AddFilter(bar, lvResults, page);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en un resultado para verlo en el visor hexadecimal.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(lvResults);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildModulesTab()
    {
        var page = new TabPage("Modulos");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        _lvModules = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _lvModules.Columns.Add("Direccion base", 150);
        _lvModules.Columns.Add("Tamano", 90);
        _lvModules.Columns.Add("Modulo", 180);
        _lvModules.Columns.Add("Ruta", 460);
        _lvModules.DoubleClick += (_, _) => JumpToModule();
        _filterModules = AddFilter(bar, _lvModules, page);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en un modulo para ir a su direccion base en el visor hexadecimal.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvModules);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildPointersTab()
    {
        var page = new TabPage("Punteros");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 72, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var lblT = new Label { Text = "Objetivo (hex):", Left = 4, Top = 9, Width = 100 };
        _ptrTarget = new TextBox { Left = 106, Top = 6, Width = 160, Font = Mono };
        var lblD = new Label { Text = "Prof.:", Left = 276, Top = 9, Width = 45 };
        _ptrDepth = new TextBox { Left = 322, Top = 6, Width = 40, Text = "4", Font = Mono };
        var lblO = new Label { Text = "Offset max (hex):", Left = 372, Top = 9, Width = 110 };
        _ptrMaxOff = new TextBox { Left = 484, Top = 6, Width = 80, Text = "1000", Font = Mono };

        var btnScan = new Button { Text = "Escanear rutas", Left = 4, Top = 34, Width = 130 };
        btnScan.Click += (_, _) => _ = DoPointerScanAsync();
        var btnOne = new Button { Text = "Que apunta aqui (1 nivel)", Left = 140, Top = 34, Width = 190 };
        btnOne.Click += (_, _) => _ = DoFindPointersAsync();
        var btnStop = new Button { Text = "Detener", Left = 336, Top = 34, Width = 80 };
        btnStop.Click += (_, _) => _ptrCts?.Cancel();

        bar.Controls.AddRange(new Control[]
        {
            lblT, _ptrTarget, lblD, _ptrDepth, lblO, _ptrMaxOff, btnScan, btnOne, btnStop
        });

        _lvPointers = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _lvPointers.Columns.Add("Ruta / direccion", 640);
        _lvPointers.Columns.Add("Base / modulo", 220);
        _lvPointers.DoubleClick += (_, _) => ResolveSelectedPointer();
        _filterPointers = AddFilter(bar, _lvPointers, page);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en una ruta para resolverla en vivo y saltar a la direccion final en el visor hex.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvPointers);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildScanTab()
    {
        var page = new TabPage("Escaneo");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 72, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var lblType = new Label { Text = "Tipo:", Left = 4, Top = 9, Width = 38 };
        _cmbScanType = new ThemedComboBox { Left = 44, Top = 6, Width = 90, DropDownStyle = ComboBoxStyle.DropDownList };
        _cmbScanType.Items.AddRange(new object[] { "Int32", "Int64", "Float", "Double" });
        _cmbScanType.SelectedIndex = 0;

        var lblVal = new Label { Text = "Valor:", Left = 142, Top = 9, Width = 45 };
        _txtScanValue = new TextBox { Left = 188, Top = 6, Width = 150, Font = Mono };

        var btnFirst = new Button { Text = "Primer escaneo", Left = 4, Top = 34, Width = 130 };
        btnFirst.Click += (_, _) => _ = DoFirstScanAsync();

        var lblF = new Label { Text = "Filtro:", Left = 142, Top = 38, Width = 45 };
        _cmbScanFilter = new ThemedComboBox { Left = 188, Top = 35, Width = 130, DropDownStyle = ComboBoxStyle.DropDownList };
        _cmbScanFilter.Items.AddRange(new object[] { "Exacto", "Cambio", "No cambio", "Aumento", "Disminuyo" });
        _cmbScanFilter.SelectedIndex = 1;
        var btnNext = new Button { Text = "Siguiente escaneo", Left = 324, Top = 34, Width = 150 };
        btnNext.Click += (_, _) => _ = DoNextScanAsync();
        var btnStop = new Button { Text = "Detener", Left = 480, Top = 34, Width = 80 };
        btnStop.Click += (_, _) => _scanCts?.Cancel();

        bar.Controls.AddRange(new Control[]
        {
            lblType, _cmbScanType, lblVal, _txtScanValue, btnFirst, lblF, _cmbScanFilter, btnNext, btnStop
        });

        _lvScan = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _lvScan.Columns.Add("Direccion", 170);
        _lvScan.Columns.Add("Valor", 140);
        _lvScan.Columns.Add("Que es", 320);
        _lvScan.DoubleClick += (_, _) => JumpFromScan();
        _filterScan = AddFilter(bar, _lvScan, page);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic: manda la direccion al visor hex y a la pestana Punteros como objetivo.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvScan);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildDisasmTab()
    {
        var page = new TabPage("Desensamblado");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var lblA = new Label { Text = "Direccion (hex):", Left = 4, Top = 9, Width = 100 };
        _disasmAddr = new TextBox { Left = 106, Top = 6, Width = 160, Font = Mono };
        var lblC = new Label { Text = "Instr.:", Left = 276, Top = 9, Width = 45 };
        _disasmCount = new TextBox { Left = 322, Top = 6, Width = 50, Text = "40", Font = Mono };
        var btnGo = new Button { Text = "Desensamblar", Left = 384, Top = 4, Width = 120 };
        btnGo.Click += (_, _) => DoDisassemble();

        bar.Controls.AddRange(new Control[] { lblA, _disasmAddr, lblC, _disasmCount, btnGo });

        _txtDisasm = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = Mono,
            Tag = "keepdark",
            BackColor = Color.FromArgb(24, 24, 24),
            ForeColor = Color.FromArgb(220, 220, 180)
        };

        page.Controls.Add(_txtDisasm);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildThreadsTab()
    {
        var page = new TabPage("Hilos");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };
        var btnGo = new Button { Text = "Listar hilos", Left = 4, Top = 4, Width = 120 };
        btnGo.Click += (_, _) => ListThreads();
        bar.Controls.Add(btnGo);

        _lvThreads = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _lvThreads.Columns.Add("TID", 90);
        _lvThreads.Columns.Add("Direccion de inicio", 180);
        _lvThreads.Columns.Add("Modulo de inicio", 260);
        _lvThreads.Columns.Add("Prioridad", 80);
        _lvThreads.DoubleClick += (_, _) => JumpFromThread();
        _filterThreads = AddFilter(bar, _lvThreads, page);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Un inicio '(dinamica)' fuera de todo modulo puede indicar codigo inyectado. Doble clic para verlo.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvThreads);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildSecurityTab()
    {
        var page = new TabPage("Seguridad");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var btnGo = new Button { Text = "Analizar seguridad", Left = 4, Top = 4, Width = 150 };
        btnGo.Click += (_, _) => _ = DoSecurityAnalysisAsync();
        var btnStop = new Button { Text = "Detener", Left = 160, Top = 4, Width = 80 };
        btnStop.Click += (_, _) => _secCts?.Cancel();
        var btnCsv = new Button { Text = "Exportar CSV...", Left = 246, Top = 4, Width = 120 };
        btnCsv.Click += (_, _) => ExportSecurityCsv();

        bar.Controls.AddRange(new Control[] { btnGo, btnStop, btnCsv });

        _lvSecurity = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _lvSecurity.Columns.Add("Severidad", 80);
        _lvSecurity.Columns.Add("Categoria", 180);
        _lvSecurity.Columns.Add("Detalle", 560);
        _lvSecurity.DoubleClick += (_, _) => JumpFromSecurity();
        _filterSecurity = AddFilter(bar, _lvSecurity, page);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Deteccion de indicadores (RWX, ejecutable no respaldado, modulos sin ASLR/DEP/CFG). Doble clic para ver la direccion.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvSecurity);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildStringsTab()
    {
        var page = new TabPage("Strings");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = true, Padding = new Padding(6, 4, 6, 4) };

        var lbl = new Label { Text = "Long. min:", Left = 4, Top = 9, Width = 70 };
        _txtMinLen = new TextBox { Left = 76, Top = 6, Width = 50, Text = "5", Font = Mono };
        var btnGo = new Button { Text = "Extraer strings", Left = 134, Top = 4, Width = 130 };
        btnGo.Click += (_, _) => _ = DoExtractStringsAsync();
        var btnStop = new Button { Text = "Detener", Left = 270, Top = 4, Width = 80 };
        btnStop.Click += (_, _) => _stringsCts?.Cancel();
        var btnCsv = new Button { Text = "Exportar CSV...", Left = 356, Top = 4, Width = 120 };
        btnCsv.Click += (_, _) => ExportStringsCsv();

        bar.Controls.AddRange(new Control[] { lbl, _txtMinLen, btnGo, btnStop, btnCsv });

        _lvStrings = new ThemedListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _lvStrings.Columns.Add("Direccion", 150);
        _lvStrings.Columns.Add("Cod.", 60);
        _lvStrings.Columns.Add("Texto", 420);
        _lvStrings.Columns.Add("Que es", 220);
        _lvStrings.DoubleClick += (_, _) => JumpToString();
        _filterStrings = AddFilter(bar, _lvStrings, page);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en una cadena para verla en el visor hexadecimal.",
            ForeColor = Color.Gray, Tag = "hint",
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvStrings);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    // ---------------- Procesos ----------------

    private void LoadProcesses()
    {
        string filter = _txtFilter.Text.Trim();
        _lvProcesses.BeginUpdate();
        _lvProcesses.Items.Clear();
        try
        {
            var procs = Process.GetProcesses()
                .Select(p =>
                {
                    string name;
                    try { name = p.ProcessName; }
                    catch { name = "(desconocido)"; }
                    return (p.Id, Name: name);
                })
                .Where(t => string.IsNullOrEmpty(filter) ||
                            t.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                            t.Id.ToString().Contains(filter))
                .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var (id, name) in procs)
            {
                var item = new ListViewItem(id.ToString()) { Tag = id };
                item.SubItems.Add(name);
                _lvProcesses.Items.Add(item);
            }
            _status.Text = $"{procs.Count} procesos listados.";
        }
        catch (Exception ex)
        {
            _status.Text = "Error al listar procesos: " + ex.Message;
        }
        finally
        {
            _lvProcesses.EndUpdate();
        }
    }

    private void AnalyzeSelectedProcess()
    {
        if (_lvProcesses.SelectedItems.Count == 0)
        {
            MessageBox.Show("Selecciona un proceso de la lista.", "Sin seleccion",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        int pid = (int)_lvProcesses.SelectedItems[0].Tag!;
        string name = _lvProcesses.SelectedItems[0].SubItems[1].Text;

        // Al cambiar de proceso, paramos el auto-refresco y cualquier escaneo.
        _chkAutoRefresh.Checked = false;
        _ptrCts?.Cancel();
        _stringsCts?.Cancel();
        _scanCts?.Cancel();
        _secCts?.Cancel();

        try
        {
            _reader?.Dispose();
            _reader = new ProcessMemoryReader(pid);
            _scanner = new PointerScanner(_reader);
            // El identificador (con su clasificador de memoria) se crea antes de
            // enumerar regiones para poder rellenar la columna "Que es".
            _identifier = new Identifier(_scanner, _reader, _store);

            string arch = _reader.IsTargetWow64() ? "x86 (WOW64)" : "x64";
            string? path = _reader.GetProcessPath();
            _lblProcess.Text = $"{name} · PID {pid} · {arch}"
                + (string.IsNullOrEmpty(path) ? "" : $" · {path}");

            EnumerateRegions();
            LoadModules();

            // Tabla de etiquetas de este proceso (por nombre) -> RefreshLabelsList.
            _store.LoadForProcess(name);

            _txtHex.Text = string.Empty;
            _txtInterp.Text = string.Empty;
            _lblIdentity.Text = "Identidad: lee una direccion para identificarla.";
            _lvResults.Items.Clear();
            _lvPointers.Items.Clear();
            _lvStrings.Items.Clear();
            _lvScan.Items.Clear();
            _lvSecurity.Items.Clear();
            _lvThreads.Items.Clear();
            _scanSession = null;
            UpdateTimerState();
            ShowSection(_regionsPage); // ir directo a las regiones del proceso abierto
        }
        catch (Win32Exception ex)
        {
            _reader = null;
            _scanner = null;
            _identifier = null;
            _scanSession = null;
            _lblProcess.Text = "Ningun proceso abierto.";
            _lvRegions.Items.Clear();
            _lvModules.Items.Clear();
            _lvPointers.Items.Clear();
            _lvStrings.Items.Clear();
            _lvScan.Items.Clear();
            _lvSecurity.Items.Clear();
            _lvThreads.Items.Clear();
            _lvLabels.Items.Clear();
            MessageBox.Show(ex.Message, "No se pudo abrir el proceso",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            _status.Text = $"Fallo al abrir PID {pid}.";
        }
    }

    // ---------------- Regiones ----------------

    private void EnumerateRegions()
    {
        if (_reader == null) return;
        _lvRegions.BeginUpdate();
        _lvRegions.Items.Clear();
        try
        {
            _regions = _reader.EnumerateRegions(_chkOnlyReadable.Checked);
            foreach (var r in _regions)
            {
                var item = new ListViewItem(r.BaseText) { Tag = r };
                item.SubItems.Add(r.SizeText);
                item.SubItems.Add(r.ProtectText);
                item.SubItems.Add(r.TypeText);
                item.SubItems.Add(""); // entropia (se rellena bajo demanda)
                item.SubItems.Add(_identifier?.WhatIs(r.BaseAddress).Text ?? "");
                _lvRegions.Items.Add(item);
            }
            ulong totalBytes = 0;
            foreach (var r in _regions) totalBytes += r.RegionSize;
            _status.Text = $"{_regions.Count} regiones ({FormatBytes(totalBytes)} en total).";
        }
        catch (Exception ex)
        {
            _status.Text = "Error al enumerar regiones: " + ex.Message;
        }
        finally
        {
            _lvRegions.EndUpdate();
            _filterRegions?.Reset();
        }
    }

    private void OnRegionSelected()
    {
        if (_reader == null || _lvRegions.SelectedItems.Count == 0) return;
        var region = (MemoryRegion)_lvRegions.SelectedItems[0].Tag!;
        _txtAddress.Text = "0x" + region.BaseAddress.ToString("X");

        // Vista previa limitada para no bloquear la interfaz con regiones enormes.
        int preview = (int)Math.Min(region.RegionSize, 4096);
        _txtSize.Text = preview.ToString();
        ReadHexAtAddress();
    }

    // ---------------- Visor hex ----------------

    private void ReadHexAtAddress()
    {
        if (_reader == null)
        {
            _status.Text = "Abre un proceso primero.";
            return;
        }
        if (!TryParseAddress(_txtAddress.Text, out ulong address))
        {
            _status.Text = "Direccion invalida. Usa formato hexadecimal, p.ej. 0x7FF6ABCD1000.";
            return;
        }
        if (!int.TryParse(_txtSize.Text.Trim(), out int size) || size <= 0)
        {
            _status.Text = "Tamano invalido.";
            return;
        }
        size = Math.Min(size, 1 << 20); // Tope de 1 MB en el visor.

        try
        {
            byte[] data = _reader.ReadBytes(address, size);
            _txtHex.Text = HexFormatter.Format(data, address);
            _txtInterp.Text = ValueInterpreter.Describe(data);
            UpdateIdentityPanel(address);
            _status.Text = $"Leidos {data.Length} bytes desde 0x{address:X}.";
        }
        catch (Win32Exception ex)
        {
            _txtHex.Text = string.Empty;
            _txtInterp.Text = string.Empty;
            _chkAutoRefresh.Checked = false; // Evita reintentos en bucle si falla.
            _status.Text = ex.Message;
        }
    }

    // ---------------- Busqueda ----------------

    private void ToggleSearch()
    {
        if (_searchCts != null)
        {
            _searchCts.Cancel();
            return;
        }
        _ = DoSearchAsync();
    }

    private async Task DoSearchAsync()
    {
        if (_reader == null)
        {
            MessageBox.Show("Abre un proceso primero.", "Sin proceso",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        string needle = _txtSearch.Text;
        if (string.IsNullOrEmpty(needle))
        {
            _status.Text = "Escribe el valor a buscar.";
            return;
        }

        string kind = _cmbSearchType.SelectedItem?.ToString() ?? "Texto";
        List<(byte[] pattern, string label, string preview)> patterns;
        try
        {
            if (kind == "Texto")
            {
                patterns = new()
                {
                    (System.Text.Encoding.Latin1.GetBytes(needle), "ASCII", needle),
                    (System.Text.Encoding.Unicode.GetBytes(needle), "UTF-16", needle),
                };
            }
            else
            {
                patterns = new() { ValueInterpreter.BuildPattern(kind, needle) };
            }
        }
        catch (Exception ex)
        {
            _status.Text = $"Valor invalido para el tipo {kind}: {ex.Message}";
            return;
        }

        _lvResults.Items.Clear();
        _searchCts = new CancellationTokenSource();
        var ct = _searchCts.Token;
        _btnSearch.Text = "Detener";
        var reader = _reader;

        var progress = new Progress<string>(msg => _status.Text = msg);
        const int maxHits = 5000;

        try
        {
            List<SearchHit> hits = await Task.Run(
                () => reader.SearchPatterns(patterns, maxHits, progress, ct), ct);

            _lvResults.BeginUpdate();
            foreach (var h in hits)
            {
                var item = new ListViewItem("0x" + h.Address.ToString("X")) { Tag = h.Address };
                item.SubItems.Add(h.Encoding);
                item.SubItems.Add(h.Preview);
                var w = _identifier?.WhatIs(h.Address);
                item.SubItems.Add(w?.Text ?? "");
                if (w is { } wi) item.ForeColor = WhatIsColor(wi.Category);
                _lvResults.Items.Add(item);
            }
            _lvResults.EndUpdate();
            _filterResults?.Reset();
            _status.Text = hits.Count >= maxHits
                ? $"Busqueda detenida al alcanzar {maxHits} coincidencias."
                : $"Busqueda finalizada: {hits.Count} coincidencias.";
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Busqueda cancelada.";
        }
        catch (Exception ex)
        {
            _status.Text = "Error en la busqueda: " + ex.Message;
        }
        finally
        {
            _searchCts?.Dispose();
            _searchCts = null;
            _btnSearch.Text = "Buscar";
        }
    }

    private void JumpToResult(ListView results)
    {
        if (_reader == null || results.SelectedItems.Count == 0) return;
        ulong address = (ulong)results.SelectedItems[0].Tag!;
        // Retrocedemos un poco para dar contexto alrededor de la coincidencia.
        ulong start = address >= 64 ? address - 64 : address;
        _txtAddress.Text = "0x" + start.ToString("X");
        _txtSize.Text = "512";
        ReadHexAtAddress();

        // Cambiar a la pestana del visor.
        ShowSection(_hexPage);
    }

    // ---------------- Volcado ----------------

    private void DumpSelectedRegion()
    {
        if (_reader == null || _lvRegions.SelectedItems.Count == 0)
        {
            _status.Text = "Selecciona una region para volcar.";
            return;
        }
        var region = (MemoryRegion)_lvRegions.SelectedItems[0].Tag!;
        using var sfd = new SaveFileDialog
        {
            Title = "Guardar volcado de la region",
            FileName = $"pid{_reader.ProcessId}_0x{region.BaseAddress:X}.bin",
            Filter = "Binario (*.bin)|*.bin|Todos los archivos (*.*)|*.*"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            using var cts = new CancellationTokenSource();
            long written = _reader.DumpRegionToFile(region, sfd.FileName, cts.Token);
            _status.Text = $"Volcados {FormatBytes((ulong)written)} a {sfd.FileName}.";
        }
        catch (Exception ex)
        {
            _status.Text = "Error al volcar: " + ex.Message;
        }
    }

    // ---------------- Modulos ----------------

    private void LoadModules()
    {
        if (_reader == null) return;
        _lvModules.BeginUpdate();
        _lvModules.Items.Clear();
        try
        {
            var mods = _reader.EnumerateModules();
            foreach (var m in mods)
            {
                var item = new ListViewItem(m.BaseText) { Tag = m.BaseAddress };
                item.SubItems.Add(m.SizeText);
                item.SubItems.Add(m.Name);
                item.SubItems.Add(m.Path);
                _lvModules.Items.Add(item);
            }
            if (mods.Count == 0)
                _status.Text = "No se pudieron enumerar modulos (proceso protegido o de otra arquitectura).";
        }
        finally
        {
            _lvModules.EndUpdate();
            _filterModules?.Reset();
        }
    }

    private void JumpToModule()
    {
        if (_reader == null || _lvModules.SelectedItems.Count == 0) return;
        ulong baseAddr = (ulong)_lvModules.SelectedItems[0].Tag!;
        _txtAddress.Text = "0x" + baseAddr.ToString("X");
        _txtSize.Text = "512";
        ReadHexAtAddress();
        ShowSection(_hexPage);
    }

    // ---------------- Copiar / exportar ----------------

    private void CopyHexToClipboard()
    {
        if (string.IsNullOrEmpty(_txtHex.Text))
        {
            _status.Text = "No hay nada que copiar.";
            return;
        }
        try
        {
            Clipboard.SetText(_txtHex.Text);
            _status.Text = "Volcado copiado al portapapeles.";
        }
        catch (Exception ex)
        {
            _status.Text = "No se pudo copiar: " + ex.Message;
        }
    }

    private void ExportHexToFile()
    {
        if (string.IsNullOrEmpty(_txtHex.Text))
        {
            _status.Text = "No hay nada que exportar.";
            return;
        }
        using var sfd = new SaveFileDialog
        {
            Title = "Guardar volcado hexadecimal",
            FileName = "volcado.txt",
            Filter = "Texto (*.txt)|*.txt|Todos los archivos (*.*)|*.*"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(sfd.FileName, _txtHex.Text);
            _status.Text = "Guardado en " + sfd.FileName;
        }
        catch (Exception ex)
        {
            _status.Text = "Error al guardar: " + ex.Message;
        }
    }

    private void ExportResultsCsv()
    {
        if (_lvResults.Items.Count == 0)
        {
            _status.Text = "No hay resultados que exportar.";
            return;
        }
        using var sfd = new SaveFileDialog
        {
            Title = "Guardar resultados de la busqueda",
            FileName = "resultados.csv",
            Filter = "CSV (*.csv)|*.csv|Todos los archivos (*.*)|*.*"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("direccion,tipo,valor");
            foreach (ListViewItem it in _lvResults.Items)
            {
                string val = it.SubItems[2].Text.Replace("\"", "\"\"");
                sb.AppendLine($"{it.Text},{it.SubItems[1].Text},\"{val}\"");
            }
            File.WriteAllText(sfd.FileName, sb.ToString());
            _status.Text = "Guardado en " + sfd.FileName;
        }
        catch (Exception ex)
        {
            _status.Text = "Error al guardar: " + ex.Message;
        }
    }

    // ---------------- Volcado completo ----------------

    private async void DumpAllRegions()
    {
        if (_reader == null)
        {
            _status.Text = "Abre un proceso primero.";
            return;
        }
        using var fbd = new FolderBrowserDialog
        {
            Description = "Elige la carpeta donde volcar todas las regiones legibles"
        };
        if (fbd.ShowDialog(this) != DialogResult.OK) return;

        string folder = fbd.SelectedPath;
        var reader = _reader;
        using var cts = new CancellationTokenSource();
        var progress = new Progress<string>(m => _status.Text = m);
        try
        {
            var (files, bytes) = await Task.Run(
                () => reader.DumpAllReadableRegions(folder, progress, cts.Token), cts.Token);
            _status.Text = $"Volcados {files} archivos ({FormatBytes((ulong)bytes)}) en {folder}.";
        }
        catch (Exception ex)
        {
            _status.Text = "Error al volcar: " + ex.Message;
        }
    }

    // ---------------- Auto-refresco ----------------

    private void ToggleAutoRefresh()
    {
        if (_chkAutoRefresh.Checked && _reader == null)
        {
            _chkAutoRefresh.Checked = false;
            _status.Text = "Abre un proceso primero.";
            return;
        }
        UpdateTimerState();
    }

    // ---------------- Punteros / offsets ----------------

    private async Task DoPointerScanAsync()
    {
        if (_reader == null || _scanner == null) { _status.Text = "Abre un proceso primero."; return; }
        if (!TryParseAddress(_ptrTarget.Text, out ulong target)) { _status.Text = "Objetivo invalido (hex)."; return; }
        if (!int.TryParse(_ptrDepth.Text.Trim(), out int depth) || depth < 1 || depth > 8)
        { _status.Text = "Profundidad valida: 1-8."; return; }
        if (!TryParseAddress(_ptrMaxOff.Text, out ulong maxOff)) { _status.Text = "Offset max invalido (hex)."; return; }

        _lvPointers.Items.Clear();
        _ptrCts = new CancellationTokenSource();
        var ct = _ptrCts.Token;
        var scanner = _scanner;
        var progress = new Progress<string>(m => _status.Text = m);
        try
        {
            var paths = await Task.Run(() =>
            {
                if (!scanner.IndexBuilt) scanner.BuildIndex(20, progress, ct);
                return scanner.ScanChains(target, depth, maxOff, 1000, progress, ct);
            }, ct);

            _lvPointers.BeginUpdate();
            foreach (var p in paths)
            {
                var it = new ListViewItem(p.Text) { Tag = p };
                it.SubItems.Add($"{p.ModuleName} @ 0x{p.ModuleBase:X}");
                _lvPointers.Items.Add(it);
            }
            _lvPointers.EndUpdate();
            _filterPointers?.Reset();
            _status.Text = $"{paths.Count} rutas de puntero (indice: {scanner.IndexCount:N0} punteros, tam. {scanner.PointerSize} bytes).";
        }
        catch (OperationCanceledException) { _status.Text = "Escaneo cancelado."; }
        catch (Exception ex) { _status.Text = "Error en el escaneo: " + ex.Message; }
        finally { _ptrCts?.Dispose(); _ptrCts = null; }
    }

    private async Task DoFindPointersAsync()
    {
        if (_reader == null || _scanner == null) { _status.Text = "Abre un proceso primero."; return; }
        if (!TryParseAddress(_ptrTarget.Text, out ulong target)) { _status.Text = "Objetivo invalido (hex)."; return; }
        if (!TryParseAddress(_ptrMaxOff.Text, out ulong maxOff)) { _status.Text = "Offset max invalido (hex)."; return; }

        _lvPointers.Items.Clear();
        _ptrCts = new CancellationTokenSource();
        var ct = _ptrCts.Token;
        var scanner = _scanner;
        var progress = new Progress<string>(m => _status.Text = m);
        try
        {
            var hits = await Task.Run(() =>
            {
                if (!scanner.IndexBuilt) scanner.BuildIndex(20, progress, ct);
                return scanner.FindPointersTo(target, maxOff);
            }, ct);

            _lvPointers.BeginUpdate();
            foreach (var h in hits.Take(5000))
            {
                var mod = scanner.ResolveModuleOffset(h.Address);
                string baseText = mod != null
                    ? $"{mod.Value.mod.Name}+0x{mod.Value.offset:X} (estatica)"
                    : "(dinamica)";
                var it = new ListViewItem($"0x{h.Address:X}  (+0x{h.Offset:X})") { Tag = h.Address };
                it.SubItems.Add(baseText);
                _lvPointers.Items.Add(it);
            }
            _lvPointers.EndUpdate();
            _filterPointers?.Reset();
            _status.Text = $"{hits.Count} punteros apuntan cerca de 0x{target:X} (mostrando hasta 5000).";
        }
        catch (OperationCanceledException) { _status.Text = "Cancelado."; }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
        finally { _ptrCts?.Dispose(); _ptrCts = null; }
    }

    private void ResolveSelectedPointer()
    {
        if (_reader == null || _scanner == null || _lvPointers.SelectedItems.Count == 0) return;
        object? tag = _lvPointers.SelectedItems[0].Tag;
        ulong finalAddr;

        if (tag is PointerPath p)
        {
            var res = _scanner.ResolvePath(p.ModuleBase, p.BaseOffset, p.Offsets, _scanner.PointerSize);
            if (res == null) { _status.Text = "La ruta ya no resuelve (la base/valor cambio)."; return; }
            finalAddr = res.Value.finalAddress;
            _status.Text = $"Ruta resuelta -> 0x{finalAddr:X}";
        }
        else if (tag is ulong a)
        {
            finalAddr = a;
        }
        else return;

        _txtAddress.Text = "0x" + finalAddr.ToString("X");
        _txtSize.Text = "256";
        ReadHexAtAddress();
        ShowSection(_hexPage);
    }

    // ---------------- Escaneo iterativo ----------------

    private async Task DoFirstScanAsync()
    {
        if (_reader == null) { _status.Text = "Abre un proceso primero."; return; }
        if (string.IsNullOrWhiteSpace(_txtScanValue.Text)) { _status.Text = "Indica el valor a buscar."; return; }

        var type = (ScanType)_cmbScanType.SelectedIndex;
        string value = _txtScanValue.Text;
        _scanSession = new ScanSession(_reader, type);
        _lvScan.Items.Clear();
        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;
        var session = _scanSession;
        var progress = new Progress<string>(m => _status.Text = m);
        const int maxCandidates = 2_000_000;
        try
        {
            await Task.Run(() => session.FirstScan(value, maxCandidates, progress, ct), ct);
            RefreshScanList();
            _status.Text = $"Primer escaneo: {session.Count:N0} candidatos.";
        }
        catch (OperationCanceledException) { _status.Text = "Escaneo cancelado."; }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
        finally { _scanCts?.Dispose(); _scanCts = null; }
    }

    private async Task DoNextScanAsync()
    {
        if (_reader == null || _scanSession == null) { _status.Text = "Haz primero un 'Primer escaneo'."; return; }

        var filter = (NextFilter)_cmbScanFilter.SelectedIndex;
        string? value = _txtScanValue.Text;
        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;
        var session = _scanSession;
        var progress = new Progress<string>(m => _status.Text = m);
        try
        {
            await Task.Run(() => session.NextScan(filter, value, progress, ct), ct);
            RefreshScanList();
            _status.Text = $"Refinado: {session.Count:N0} candidatos.";
        }
        catch (OperationCanceledException) { _status.Text = "Escaneo cancelado."; }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
        finally { _scanCts?.Dispose(); _scanCts = null; }
    }

    private void RefreshScanList()
    {
        if (_scanSession == null) return;
        _lvScan.BeginUpdate();
        _lvScan.Items.Clear();
        int shown = 0;
        foreach (var (addr, value) in _scanSession.Candidates)
        {
            if (shown++ >= 5000) break;
            var it = new ListViewItem("0x" + addr.ToString("X")) { Tag = addr };
            it.SubItems.Add(_scanSession.FormatValue(value));
            var w = _identifier?.WhatIs(addr, value);
            it.SubItems.Add(w?.Text ?? "");
            if (w is { } wi) it.ForeColor = WhatIsColor(wi.Category);
            _lvScan.Items.Add(it);
        }
        _lvScan.EndUpdate();
        _filterScan?.Reset();
    }

    private void JumpFromScan()
    {
        if (_lvScan.SelectedItems.Count == 0) return;
        ulong addr = (ulong)_lvScan.SelectedItems[0].Tag!;
        string hex = "0x" + addr.ToString("X");
        _ptrTarget.Text = hex; // lo deja listo para escanear rutas de puntero
        _txtAddress.Text = hex;
        _txtSize.Text = "256";
        ReadHexAtAddress();
        ShowSection(_hexPage);
    }

    // ---------------- Entropia ----------------

    private async void ComputeEntropy()
    {
        if (_reader == null || _regions.Count == 0) { _status.Text = "Enumera regiones primero."; return; }
        var reader = _reader;
        var regions = _regions.ToList();
        _status.Text = "Calculando entropia (muestra de 64 KB/region)...";
        try
        {
            double[] vals = await Task.Run(() =>
            {
                var arr = new double[regions.Count];
                for (int i = 0; i < regions.Count; i++)
                {
                    int sample = (int)Math.Min(regions[i].RegionSize, (ulong)65536);
                    try { arr[i] = EntropyAnalyzer.Shannon(reader.ReadBytes(regions[i].BaseAddress, sample)); }
                    catch { arr[i] = -1; }
                }
                return arr;
            });

            for (int i = 0; i < _lvRegions.Items.Count && i < vals.Length; i++)
            {
                var it = _lvRegions.Items[i];
                if (it.SubItems.Count > 4)
                    it.SubItems[4].Text = vals[i] >= 0 ? vals[i].ToString("0.00") : "-";
                if (vals[i] >= 7.2) it.ForeColor = ThemeManager.Current.SeverityHigh; // posible empaquetado/cifrado
            }
            _status.Text = "Entropia calculada (rojo = >7.2, posible empaquetado/cifrado).";
        }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
    }

    // ---------------- Hilos ----------------

    private void ListThreads()
    {
        if (_reader == null) { _status.Text = "Abre un proceso primero."; return; }
        _lvThreads.BeginUpdate();
        _lvThreads.Items.Clear();
        try
        {
            var threads = ThreadInspector.Enumerate(_reader.ProcessId);
            foreach (var t in threads)
            {
                var it = new ListViewItem(t.Tid.ToString()) { Tag = t.StartAddress };
                it.SubItems.Add("0x" + t.StartAddress.ToString("X"));
                var mod = _scanner?.ResolveModuleOffset(t.StartAddress);
                string modText = mod != null ? $"{mod.Value.mod.Name}+0x{mod.Value.offset:X}" : "(dinamica)";
                if (mod == null && t.StartAddress != 0) it.ForeColor = ThemeManager.Current.SeverityHigh;
                it.SubItems.Add(modText);
                it.SubItems.Add(t.BasePriority.ToString());
                _lvThreads.Items.Add(it);
            }
            _status.Text = $"{threads.Count} hilos.";
        }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
        finally { _lvThreads.EndUpdate(); _filterThreads?.Reset(); }
    }

    private void JumpFromThread()
    {
        if (_reader == null || _lvThreads.SelectedItems.Count == 0) return;
        ulong addr = (ulong)_lvThreads.SelectedItems[0].Tag!;
        if (addr == 0) return;
        _txtAddress.Text = "0x" + addr.ToString("X");
        _txtSize.Text = "256";
        ReadHexAtAddress();
        ShowSection(_hexPage);
    }

    // ---------------- Desensamblado ----------------

    private void DoDisassemble()
    {
        if (_reader == null) { _status.Text = "Abre un proceso primero."; return; }
        if (!TryParseAddress(_disasmAddr.Text, out ulong addr)) { _status.Text = "Direccion invalida (hex)."; return; }
        if (!int.TryParse(_disasmCount.Text.Trim(), out int count) || count < 1) count = 40;
        count = Math.Min(count, 1000);
        int bitness = _reader.IsTargetWow64() ? 32 : 64;
        try
        {
            byte[] code = _reader.ReadBytes(addr, Math.Min(count * 16, 65536));
            _txtDisasm.Text = Disassembler.Disassemble(code, addr, bitness, count);
            _status.Text = $"Desensamblado desde 0x{addr:X} ({bitness} bits).";
        }
        catch (Win32Exception ex)
        {
            _txtDisasm.Text = string.Empty;
            _status.Text = ex.Message;
        }
    }

    // ---------------- Seguridad ----------------

    private async Task DoSecurityAnalysisAsync()
    {
        if (_reader == null) { _status.Text = "Abre un proceso primero."; return; }
        _lvSecurity.Items.Clear();
        _secCts = new CancellationTokenSource();
        var ct = _secCts.Token;
        var reader = _reader;
        var progress = new Progress<string>(m => _status.Text = m);
        try
        {
            var findings = await Task.Run(() => SecurityAnalyzer.Analyze(reader, progress, ct), ct);

            _lvSecurity.BeginUpdate();
            foreach (var f in findings)
            {
                var it = new ListViewItem(f.Severity) { Tag = f.Address };
                it.SubItems.Add(f.Category);
                it.SubItems.Add(f.Detail);
                if (f.Severity == "Alta") it.ForeColor = ThemeManager.Current.SeverityHigh;
                else if (f.Severity == "Media") it.ForeColor = ThemeManager.Current.SeverityMedium;
                _lvSecurity.Items.Add(it);
            }
            _lvSecurity.EndUpdate();
            _filterSecurity?.Reset();
            int alta = findings.Count(x => x.Severity == "Alta");
            _status.Text = $"{findings.Count} hallazgos ({alta} de severidad alta).";
        }
        catch (OperationCanceledException) { _status.Text = "Analisis cancelado."; }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
        finally { _secCts?.Dispose(); _secCts = null; }
    }

    private void JumpFromSecurity()
    {
        if (_reader == null || _lvSecurity.SelectedItems.Count == 0) return;
        ulong addr = (ulong)_lvSecurity.SelectedItems[0].Tag!;
        if (addr == 0) return;
        _txtAddress.Text = "0x" + addr.ToString("X");
        _txtSize.Text = "256";
        ReadHexAtAddress();
        ShowSection(_hexPage);
    }

    private void ExportSecurityCsv()
    {
        if (_lvSecurity.Items.Count == 0) { _status.Text = "No hay hallazgos que exportar."; return; }
        using var sfd = new SaveFileDialog
        {
            Title = "Guardar informe de seguridad",
            FileName = "seguridad.csv",
            Filter = "CSV (*.csv)|*.csv|Todos los archivos (*.*)|*.*"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("severidad,categoria,detalle");
            foreach (ListViewItem it in _lvSecurity.Items)
            {
                string det = it.SubItems[2].Text.Replace("\"", "\"\"");
                sb.AppendLine($"{it.Text},{it.SubItems[1].Text},\"{det}\"");
            }
            File.WriteAllText(sfd.FileName, sb.ToString());
            _status.Text = "Guardado en " + sfd.FileName;
        }
        catch (Exception ex) { _status.Text = "Error al guardar: " + ex.Message; }
    }

    // ---------------- Strings ----------------

    private async Task DoExtractStringsAsync()
    {
        if (_reader == null) { _status.Text = "Abre un proceso primero."; return; }
        if (!int.TryParse(_txtMinLen.Text.Trim(), out int minLen) || minLen < 1) minLen = 5;

        _lvStrings.Items.Clear();
        _stringsCts = new CancellationTokenSource();
        var ct = _stringsCts.Token;
        var reader = _reader;
        var progress = new Progress<string>(m => _status.Text = m);
        const int maxResults = 100000;
        try
        {
            var strings = await Task.Run(
                () => StringsExtractor.Extract(reader, minLen, maxResults, progress, ct), ct);

            _lvStrings.BeginUpdate();
            foreach (var s in strings)
            {
                var it = new ListViewItem("0x" + s.Address.ToString("X")) { Tag = s.Address };
                it.SubItems.Add(s.Encoding);
                it.SubItems.Add(s.Text.Length > 400 ? s.Text[..400] : s.Text);
                it.SubItems.Add(_identifier?.WhatIs(s.Address).Text ?? "");
                _lvStrings.Items.Add(it);
            }
            _lvStrings.EndUpdate();
            _filterStrings?.Reset();
            _status.Text = strings.Count >= maxResults
                ? $"Extraccion detenida en {maxResults:N0} cadenas."
                : $"{strings.Count:N0} cadenas extraidas.";
        }
        catch (OperationCanceledException) { _status.Text = "Extraccion cancelada."; }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
        finally { _stringsCts?.Dispose(); _stringsCts = null; }
    }

    private void JumpToString()
    {
        if (_reader == null || _lvStrings.SelectedItems.Count == 0) return;
        ulong addr = (ulong)_lvStrings.SelectedItems[0].Tag!;
        _txtAddress.Text = "0x" + addr.ToString("X");
        _txtSize.Text = "256";
        ReadHexAtAddress();
        ShowSection(_hexPage);
    }

    private void ExportStringsCsv()
    {
        if (_lvStrings.Items.Count == 0) { _status.Text = "No hay cadenas que exportar."; return; }
        using var sfd = new SaveFileDialog
        {
            Title = "Guardar strings",
            FileName = "strings.csv",
            Filter = "CSV (*.csv)|*.csv|Todos los archivos (*.*)|*.*"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("direccion,codificacion,texto");
            foreach (ListViewItem it in _lvStrings.Items)
            {
                string txt = it.SubItems[2].Text.Replace("\"", "\"\"");
                sb.AppendLine($"{it.Text},{it.SubItems[1].Text},\"{txt}\"");
            }
            File.WriteAllText(sfd.FileName, sb.ToString());
            _status.Text = "Guardado en " + sfd.FileName;
        }
        catch (Exception ex) { _status.Text = "Error al guardar: " + ex.Message; }
    }

    // ---------------- Minidump ----------------

    private async void WriteMinidump()
    {
        if (_reader == null) { _status.Text = "Abre un proceso primero."; return; }
        using var sfd = new SaveFileDialog
        {
            Title = "Guardar minidump (memoria completa)",
            FileName = $"pid{_reader.ProcessId}.dmp",
            Filter = "Minidump (*.dmp)|*.dmp|Todos los archivos (*.*)|*.*"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;

        var reader = _reader;
        string path = sfd.FileName;
        _status.Text = "Generando minidump (memoria completa)...";
        try
        {
            await Task.Run(() => reader.WriteMiniDump(path, fullMemory: true));
            var fi = new FileInfo(path);
            _status.Text = $"Minidump guardado: {FormatBytes((ulong)fi.Length)} en {path}";
        }
        catch (Exception ex)
        {
            _status.Text = "Error al generar minidump: " + ex.Message;
        }
    }

    // ---------------- Utilidades ----------------

    private void ShowElevationState()
    {
        bool elevated = false;
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            elevated = new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { /* ignore */ }

        if (elevated)
        {
            _lblAdmin.ForeColor = ThemeManager.Current.OkText;
            _lblAdmin.Text = "Ejecutando como Administrador.";
        }
        else
        {
            _lblAdmin.ForeColor = ThemeManager.Current.BadText;
            _lblAdmin.Text = "SIN privilegios de Administrador: la mayoria de procesos no se podran abrir.";
        }
    }

    private static bool TryParseAddress(string text, out ulong address)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address);
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] u = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes;
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{bytes} B" : $"{v:0.##} {u[i]}";
    }
}
