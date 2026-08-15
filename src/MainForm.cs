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
    private readonly ListView _lvProcesses;
    private readonly ListView _lvRegions;
    private readonly ListView _lvResults;
    private readonly TextBox _txtFilter;
    private readonly TextBox _txtAddress;
    private readonly TextBox _txtSize;
    private readonly TextBox _txtHex;
    private readonly TextBox _txtSearch;
    private readonly CheckBox _chkOnlyReadable;
    private readonly Label _lblProcess;
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
    private readonly System.Windows.Forms.Timer _refreshTimer;

    private ProcessMemoryReader? _reader;
    private List<MemoryRegion> _regions = new();
    private CancellationTokenSource? _searchCts;

    private static readonly Font Mono = new("Consolas", 9F);

    public MainForm()
    {
        Text = "MemReader - Lector de memoria de procesos (user-mode, solo lectura)";
        Width = 1180;
        Height = 760;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(960, 600);

        // ---------- Barra superior ----------
        var topBar = new Panel { Dock = DockStyle.Top, Height = 44, Padding = new Padding(8, 8, 8, 4) };
        var btnRefresh = new Button { Text = "Actualizar procesos", Left = 0, Top = 6, Width = 150, Anchor = AnchorStyles.Left | AnchorStyles.Top };
        btnRefresh.Click += (_, _) => LoadProcesses();

        var lblFilter = new Label { Text = "Filtro:", Left = 160, Top = 11, Width = 45, Anchor = AnchorStyles.Left | AnchorStyles.Top };
        _txtFilter = new TextBox { Left = 205, Top = 8, Width = 200, Anchor = AnchorStyles.Left | AnchorStyles.Top };
        _txtFilter.TextChanged += (_, _) => LoadProcesses();

        _lblAdmin = new Label { Left = 430, Top = 11, Width = 700, Anchor = AnchorStyles.Left | AnchorStyles.Top, ForeColor = Color.DarkRed };

        topBar.Controls.AddRange(new Control[] { btnRefresh, lblFilter, _txtFilter, _lblAdmin });

        // ---------- Split principal (izquierda: procesos / derecha: analisis) ----------
        var split1 = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };

        // ----- Panel izquierdo: procesos -----
        _lvProcesses = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false,
            HideSelection = false
        };
        _lvProcesses.Columns.Add("PID", 70);
        _lvProcesses.Columns.Add("Proceso", 230);
        _lvProcesses.DoubleClick += (_, _) => AnalyzeSelectedProcess();

        var btnAnalyze = new Button { Text = "Analizar proceso seleccionado", Dock = DockStyle.Bottom, Height = 34 };
        btnAnalyze.Click += (_, _) => AnalyzeSelectedProcess();

        var leftPanel = new Panel { Dock = DockStyle.Fill };
        leftPanel.Controls.Add(_lvProcesses);
        leftPanel.Controls.Add(btnAnalyze);
        split1.Panel1.Controls.Add(leftPanel);

        // ----- Panel derecho: regiones + visor/busqueda -----
        var split2 = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };

        // Regiones (arriba)
        _lblProcess = new Label { Dock = DockStyle.Top, Height = 24, Text = "Ningun proceso abierto.", Padding = new Padding(4, 4, 0, 0), Font = new Font("Segoe UI", 9F, FontStyle.Bold) };

        var regionsBar = new Panel { Dock = DockStyle.Top, Height = 32 };
        _chkOnlyReadable = new CheckBox { Text = "Solo regiones legibles", Checked = true, Left = 4, Top = 6, Width = 170 };
        _chkOnlyReadable.CheckedChanged += (_, _) => { if (_reader != null) EnumerateRegions(); };
        var btnDump = new Button { Text = "Volcar region a archivo...", Left = 180, Top = 3, Width = 190 };
        btnDump.Click += (_, _) => DumpSelectedRegion();
        var btnDumpAll = new Button { Text = "Volcar TODO a carpeta...", Left = 376, Top = 3, Width = 200 };
        btnDumpAll.Click += (_, _) => DumpAllRegions();
        var btnMinidump = new Button { Text = "Minidump (.dmp)...", Left = 584, Top = 3, Width = 150 };
        btnMinidump.Click += (_, _) => WriteMinidump();
        regionsBar.Controls.AddRange(new Control[] { _chkOnlyReadable, btnDump, btnDumpAll, btnMinidump });

        _lvRegions = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false,
            HideSelection = false
        };
        _lvRegions.Columns.Add("Direccion base", 160);
        _lvRegions.Columns.Add("Tamano", 90);
        _lvRegions.Columns.Add("Proteccion", 90);
        _lvRegions.Columns.Add("Tipo", 90);
        _lvRegions.SelectedIndexChanged += (_, _) => OnRegionSelected();

        var regionsHost = new Panel { Dock = DockStyle.Fill };
        regionsHost.Controls.Add(_lvRegions);
        regionsHost.Controls.Add(regionsBar);
        regionsHost.Controls.Add(_lblProcess);
        split2.Panel1.Controls.Add(regionsHost);

        // Pestanas (abajo): visor hex + busqueda + modulos
        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildHexTab());
        tabs.TabPages.Add(BuildSearchTab(out _txtSearch, out _lvResults, out _btnSearch));
        tabs.TabPages.Add(BuildModulesTab());
        tabs.TabPages.Add(BuildPointersTab());
        tabs.TabPages.Add(BuildStringsTab());
        split2.Panel2.Controls.Add(tabs);

        // Temporizador para el auto-refresco del visor hexadecimal.
        _refreshTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _refreshTimer.Tick += (_, _) => { if (_reader != null) ReadHexAtAddress(); };

        split1.Panel2.Controls.Add(split2);

        // ---------- Barra de estado ----------
        var statusStrip = new StatusStrip();
        _status = new ToolStripStatusLabel { Text = "Listo." };
        statusStrip.Items.Add(_status);

        // Los controles se agregan en orden: primero Fill, luego Top/Bottom.
        Controls.Add(split1);
        Controls.Add(statusStrip);
        Controls.Add(topBar);

        // Campos que se inicializan en los builders de pestanas.
        _txtAddress = _hexAddress!;
        _txtSize = _hexSize!;
        _txtHex = _hexView!;

        Load += (_, _) =>
        {
            // SplitterDistance se fija aqui, cuando los contenedores ya tienen
            // su tamano final, para evitar excepciones al arrancar.
            TrySetSplitter(split1, 340);
            TrySetSplitter(split2, 260);
            ShowElevationState();
            LoadProcesses();
        };
        FormClosing += (_, _) =>
        {
            _refreshTimer.Stop();
            _searchCts?.Cancel();
            _ptrCts?.Cancel();
            _stringsCts?.Cancel();
            _reader?.Dispose();
        };
    }

    // Referencias temporales usadas al construir las pestanas.
    private TextBox? _hexAddress;
    private TextBox? _hexSize;
    private TextBox? _hexView;

    private TabPage BuildHexTab()
    {
        var page = new TabPage("Visor hexadecimal");
        var bar = new Panel { Dock = DockStyle.Top, Height = 34 };

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
            BackColor = Color.FromArgb(30, 30, 30),
            ForeColor = Color.FromArgb(180, 220, 180)
        };
        interpPanel.Controls.Add(_txtInterp);
        interpPanel.Controls.Add(lblInterp);

        page.Controls.Add(_hexView);
        page.Controls.Add(interpPanel);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildSearchTab(out TextBox txtSearch, out ListView lvResults, out Button btnSearch)
    {
        var page = new TabPage("Buscar en memoria");
        var bar = new Panel { Dock = DockStyle.Top, Height = 34 };

        var lblType = new Label { Text = "Tipo:", Left = 4, Top = 9, Width = 38 };
        _cmbSearchType = new ComboBox
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

        lvResults = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        lvResults.Columns.Add("Direccion", 170);
        lvResults.Columns.Add("Tipo", 110);
        lvResults.Columns.Add("Valor", 400);
        var localResults = lvResults;
        lvResults.DoubleClick += (_, _) => JumpToResult(localResults);

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en un resultado para verlo en el visor hexadecimal.",
            ForeColor = Color.Gray,
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

        _lvModules = new ListView
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

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en un modulo para ir a su direccion base en el visor hexadecimal.",
            ForeColor = Color.Gray,
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvModules);
        page.Controls.Add(hint);
        return page;
    }

    private TabPage BuildPointersTab()
    {
        var page = new TabPage("Punteros");
        var bar = new Panel { Dock = DockStyle.Top, Height = 66 };

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

        _lvPointers = new ListView
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

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en una ruta para resolverla en vivo y saltar a la direccion final en el visor hex.",
            ForeColor = Color.Gray,
            Padding = new Padding(4, 2, 0, 0)
        };

        page.Controls.Add(_lvPointers);
        page.Controls.Add(hint);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildStringsTab()
    {
        var page = new TabPage("Strings");
        var bar = new Panel { Dock = DockStyle.Top, Height = 34 };

        var lbl = new Label { Text = "Long. min:", Left = 4, Top = 9, Width = 70 };
        _txtMinLen = new TextBox { Left = 76, Top = 6, Width = 50, Text = "5", Font = Mono };
        var btnGo = new Button { Text = "Extraer strings", Left = 134, Top = 4, Width = 130 };
        btnGo.Click += (_, _) => _ = DoExtractStringsAsync();
        var btnStop = new Button { Text = "Detener", Left = 270, Top = 4, Width = 80 };
        btnStop.Click += (_, _) => _stringsCts?.Cancel();
        var btnCsv = new Button { Text = "Exportar CSV...", Left = 356, Top = 4, Width = 120 };
        btnCsv.Click += (_, _) => ExportStringsCsv();

        bar.Controls.AddRange(new Control[] { lbl, _txtMinLen, btnGo, btnStop, btnCsv });

        _lvStrings = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _lvStrings.Columns.Add("Direccion", 160);
        _lvStrings.Columns.Add("Cod.", 70);
        _lvStrings.Columns.Add("Texto", 620);
        _lvStrings.DoubleClick += (_, _) => JumpToString();

        var hint = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 22,
            Text = "Doble clic en una cadena para verla en el visor hexadecimal.",
            ForeColor = Color.Gray,
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

        try
        {
            _reader?.Dispose();
            _reader = new ProcessMemoryReader(pid);
            _scanner = new PointerScanner(_reader);

            string arch = _reader.IsTargetWow64() ? "x86 (WOW64)" : "x64";
            string? path = _reader.GetProcessPath();
            _lblProcess.Text = $"Proceso: {name} (PID {pid})  |  {arch}"
                + (string.IsNullOrEmpty(path) ? "" : $"  |  {path}");

            EnumerateRegions();
            LoadModules();
            _txtHex.Text = string.Empty;
            _txtInterp.Text = string.Empty;
            _lvResults.Items.Clear();
            _lvPointers.Items.Clear();
            _lvStrings.Items.Clear();
        }
        catch (Win32Exception ex)
        {
            _reader = null;
            _scanner = null;
            _lblProcess.Text = "Ningun proceso abierto.";
            _lvRegions.Items.Clear();
            _lvModules.Items.Clear();
            _lvPointers.Items.Clear();
            _lvStrings.Items.Clear();
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
                _lvResults.Items.Add(item);
            }
            _lvResults.EndUpdate();
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
        if (_txtHex.Parent is TabPage page && page.Parent is TabControl tc)
            tc.SelectedTab = page;
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
        }
    }

    private void JumpToModule()
    {
        if (_reader == null || _lvModules.SelectedItems.Count == 0) return;
        ulong baseAddr = (ulong)_lvModules.SelectedItems[0].Tag!;
        _txtAddress.Text = "0x" + baseAddr.ToString("X");
        _txtSize.Text = "512";
        ReadHexAtAddress();
        if (_txtHex.Parent is TabPage page && page.Parent is TabControl tc)
            tc.SelectedTab = page;
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
        if (_chkAutoRefresh.Checked)
        {
            if (_reader == null)
            {
                _chkAutoRefresh.Checked = false;
                _status.Text = "Abre un proceso primero.";
                return;
            }
            _refreshTimer.Start();
        }
        else
        {
            _refreshTimer.Stop();
        }
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
        if (_txtHex.Parent is TabPage page && page.Parent is TabControl tc)
            tc.SelectedTab = page;
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
                _lvStrings.Items.Add(it);
            }
            _lvStrings.EndUpdate();
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
        if (_txtHex.Parent is TabPage page && page.Parent is TabControl tc)
            tc.SelectedTab = page;
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
            _lblAdmin.ForeColor = Color.DarkGreen;
            _lblAdmin.Text = "Ejecutando como Administrador.";
        }
        else
        {
            _lblAdmin.ForeColor = Color.DarkRed;
            _lblAdmin.Text = "SIN privilegios de Administrador: la mayoria de procesos no se podran abrir.";
        }
    }

    private static void TrySetSplitter(SplitContainer split, int distance)
    {
        try
        {
            int extent = split.Orientation == Orientation.Vertical ? split.Width : split.Height;
            int max = extent - split.Panel2MinSize - split.SplitterWidth;
            if (max > split.Panel1MinSize)
                split.SplitterDistance = Math.Clamp(distance, split.Panel1MinSize, max);
        }
        catch { /* si el tamano aun no permite fijarlo, se queda con el valor por defecto */ }
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
