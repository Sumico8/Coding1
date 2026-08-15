namespace MemReader;

/// <summary>
/// Filtro rapido para un ListView (que no tiene filtrado nativo). Guarda una copia
/// de los items reales y, al aplicar un texto, quita/reanade los MISMOS objetos
/// ListViewItem (Clear() solo los desvincula, no los destruye), de modo que se
/// preservan intactos el Tag, el ForeColor semantico y todos los subitems.
///
/// Uso: crear uno por ListView; llamar Reset() justo despues de cada carga de
/// datos (tras EndUpdate) y Apply(texto) desde el TextChanged de la caja de filtro.
/// </summary>
public sealed class ListViewFilter
{
    private readonly ListView _lv;
    private readonly List<ListViewItem> _all = new();

    public string Query { get; private set; } = string.Empty;

    public ListViewFilter(ListView lv) => _lv = lv;

    /// <summary>Toma una instantanea del contenido actual como conjunto completo.</summary>
    public void Reset()
    {
        _all.Clear();
        foreach (ListViewItem it in _lv.Items)
            _all.Add(it);
        // Reaplica el filtro vigente sobre el nuevo conjunto.
        if (!string.IsNullOrEmpty(Query))
            Apply(Query);
    }

    /// <summary>Muestra solo las filas cuyo texto (en cualquier columna) contenga la consulta.</summary>
    public void Apply(string query)
    {
        Query = query ?? string.Empty;
        _lv.BeginUpdate();
        try
        {
            _lv.Items.Clear();
            IEnumerable<ListViewItem> src = string.IsNullOrEmpty(Query)
                ? _all
                : _all.Where(Matches);
            _lv.Items.AddRange(src.ToArray());
        }
        finally
        {
            _lv.EndUpdate();
        }
    }

    private bool Matches(ListViewItem it)
    {
        foreach (ListViewItem.ListViewSubItem s in it.SubItems)
            if (s.Text.Contains(Query, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
