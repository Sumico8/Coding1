using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;

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
        regionsBar.Controls.AddRange(new Control[] { _chkOnlyReadable, btnDump });

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

        // Pestanas (abajo): visor hex + busqueda
        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildHexTab());
        tabs.TabPages.Add(BuildSearchTab(out _txtSearch, out _lvResults, out _btnSearch));
        split2.Panel2.Controls.Add(tabs);

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
        FormClosing += (_, _) => { _searchCts?.Cancel(); _reader?.Dispose(); };
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
        _hexAddress = new TextBox { Left = 106, Top = 6, Width = 160, Font = Mono };
        var lblSize = new Label { Text = "Bytes:", Left = 276, Top = 9, Width = 45 };
        _hexSize = new TextBox { Left = 322, Top = 6, Width = 80, Text = "4096", Font = Mono };
        var btnRead = new Button { Text = "Leer", Left = 410, Top = 4, Width = 80 };
        btnRead.Click += (_, _) => ReadHexAtAddress();

        bar.Controls.AddRange(new Control[] { lblAddr, _hexAddress, lblSize, _hexSize, btnRead });

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

        page.Controls.Add(_hexView);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildSearchTab(out TextBox txtSearch, out ListView lvResults, out Button btnSearch)
    {
        var page = new TabPage("Buscar en memoria");
        var bar = new Panel { Dock = DockStyle.Top, Height = 34 };

        var lbl = new Label { Text = "Texto:", Left = 4, Top = 9, Width = 45 };
        txtSearch = new TextBox { Left = 50, Top = 6, Width = 320, Font = Mono };
        btnSearch = new Button { Text = "Buscar", Left = 378, Top = 4, Width = 90 };
        var localBtn = btnSearch;
        btnSearch.Click += (_, _) => ToggleSearch();

        bar.Controls.AddRange(new Control[] { lbl, txtSearch, localBtn });

        lvResults = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        lvResults.Columns.Add("Direccion", 170);
        lvResults.Columns.Add("Codificacion", 110);
        lvResults.Columns.Add("Coincidencia", 400);
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

        try
        {
            _reader?.Dispose();
            _reader = new ProcessMemoryReader(pid);
            _lblProcess.Text = $"Proceso abierto: {name} (PID {pid})";
            EnumerateRegions();
            _txtHex.Text = string.Empty;
            _lvResults.Items.Clear();
        }
        catch (Win32Exception ex)
        {
            _reader = null;
            _lblProcess.Text = "Ningun proceso abierto.";
            _lvRegions.Items.Clear();
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
            _status.Text = $"Leidos {data.Length} bytes desde 0x{address:X}.";
        }
        catch (Win32Exception ex)
        {
            _txtHex.Text = string.Empty;
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
            _status.Text = "Escribe el texto a buscar.";
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
                () => reader.SearchString(needle, maxHits, progress, ct), ct);

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
