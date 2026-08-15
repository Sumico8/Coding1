namespace MemReader;

/// <summary>
/// Mantiene un conjunto de direcciones "congeladas": el timer reescribe su valor
/// fijado en cada tick para que no cambie en el proceso (estilo Cheat Engine).
/// Requiere el modo edicion (acceso de escritura).
/// </summary>
public sealed class FrozenValues
{
    private readonly Dictionary<ulong, byte[]> _frozen = new();

    public int Count => _frozen.Count;
    public bool IsFrozen(ulong addr) => _frozen.ContainsKey(addr);

    public void Freeze(ulong addr, byte[] value) => _frozen[addr] = (byte[])value.Clone();
    public void Unfreeze(ulong addr) => _frozen.Remove(addr);
    public void Clear() => _frozen.Clear();

    /// <summary>Reescribe todos los valores congelados (best-effort).</summary>
    public void Apply(ProcessMemoryReader reader)
    {
        if (_frozen.Count == 0 || !reader.CanWrite) return;
        foreach (var kv in _frozen)
        {
            try { reader.WriteBytes(kv.Key, kv.Value); }
            catch { /* pagina inaccesible: se ignora */ }
        }
    }
}
