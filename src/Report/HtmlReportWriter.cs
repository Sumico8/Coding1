using System.Text;

namespace MemReader;

/// <summary>
/// Genera un informe HTML autocontenido (CSS embebido, sin recursos externos)
/// a partir de un <see cref="TriageReport"/>. Pensado como entregable de un
/// triage: se abre en cualquier navegador sin dependencias.
/// </summary>
public static class HtmlReportWriter
{
    public static string Write(TriageReport r)
    {
        var sb = new StringBuilder(16 * 1024);
        sb.Append("<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.Append("<title>Informe MemReader - ").Append(E(r.ProcessName)).Append(" (PID ").Append(r.Pid).Append(")</title>");
        sb.Append("<style>").Append(Css).Append("</style></head><body>");

        // Cabecera.
        sb.Append("<header><h1>Informe de triage - MemReader</h1>");
        sb.Append("<div class=\"meta\">");
        Meta(sb, "Proceso", $"{E(r.ProcessName)} (PID {r.Pid})");
        Meta(sb, "Arquitectura", E(r.Architecture));
        if (!string.IsNullOrEmpty(r.Path)) Meta(sb, "Ruta", E(r.Path!));
        Meta(sb, "Analizador elevado", r.AnalyzerElevated ? "si" : "no");
        Meta(sb, "Generado (UTC)", E(r.GeneratedUtc));
        Meta(sb, "Version", E(r.Tool + " " + r.ToolVersion));
        sb.Append("</div></header>");

        // Tarjetas resumen.
        sb.Append("<section class=\"cards\">");
        Card(sb, "Regiones (commit)", r.RegionCount.ToString("N0"));
        Card(sb, "Memoria comprometida", FormatBytes(r.CommittedBytes));
        Card(sb, "Hallazgos alta sev.", r.HighSeverityCount.ToString(), r.HighSeverityCount > 0 ? "bad" : "ok");
        Card(sb, "Regiones alta entropia", r.HighEntropyRegions.Count.ToString(), r.HighEntropyRegions.Count > 0 ? "warn" : "ok");
        Card(sb, "Hilos sospechosos", r.SuspiciousThreads.Count.ToString(), r.SuspiciousThreads.Count > 0 ? "warn" : "ok");
        Card(sb, "Modulos", r.Modules.Count.ToString("N0"));
        if (r.Iocs.Count > 0) Card(sb, "IOCs", r.Iocs.Count.ToString("N0"), "warn");
        sb.Append("</section>");

        // Hallazgos de seguridad.
        sb.Append("<h2>Indicadores de seguridad</h2>");
        if (r.Findings.Count == 0)
        {
            sb.Append("<p class=\"empty\">Sin indicadores anomalos detectados.</p>");
        }
        else
        {
            sb.Append("<table><thead><tr><th>Severidad</th><th>Categoria</th><th>Detalle</th><th>Direccion</th></tr></thead><tbody>");
            foreach (var f in r.Findings)
            {
                string cls = f.Severity == "Alta" ? "sev-high" : f.Severity == "Media" ? "sev-med" : "sev-low";
                sb.Append("<tr><td class=\"").Append(cls).Append("\">").Append(E(f.Severity)).Append("</td><td>")
                  .Append(E(f.Category)).Append("</td><td>").Append(E(f.Detail)).Append("</td><td class=\"mono\">")
                  .Append(E(f.Address)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        // Regiones de alta entropia.
        sb.Append("<h2>Regiones de alta entropia (&ge; 7.2)</h2>");
        if (r.HighEntropyRegions.Count == 0)
            sb.Append("<p class=\"empty\">Ninguna region supera el umbral.</p>");
        else
        {
            sb.Append("<table><thead><tr><th>Direccion</th><th>Tamano</th><th>Proteccion</th><th>Tipo</th><th>Entropia</th></tr></thead><tbody>");
            foreach (var g in r.HighEntropyRegions)
                sb.Append("<tr><td class=\"mono\">").Append(E(g.Address)).Append("</td><td>").Append(E(g.Size))
                  .Append("</td><td class=\"mono\">").Append(E(g.Protect)).Append("</td><td>").Append(E(g.Type))
                  .Append("</td><td>").Append(g.Entropy.ToString("0.00")).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }

        // Hilos sospechosos.
        sb.Append("<h2>Hilos con inicio anomalo</h2>");
        if (r.SuspiciousThreads.Count == 0)
            sb.Append("<p class=\"empty\">Todos los hilos inician dentro de un modulo conocido.</p>");
        else
        {
            sb.Append("<table><thead><tr><th>TID</th><th>Direccion de inicio</th><th>Nota</th></tr></thead><tbody>");
            foreach (var t in r.SuspiciousThreads)
                sb.Append("<tr><td>").Append(t.Tid).Append("</td><td class=\"mono\">").Append(E(t.StartAddress))
                  .Append("</td><td>").Append(E(t.Note)).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }

        // IOCs (si los hay).
        if (r.Iocs.Count > 0)
        {
            sb.Append("<h2>Indicadores de compromiso (IOCs)</h2>");
            sb.Append("<table><thead><tr><th>Tipo</th><th>Valor</th><th>Direccion</th></tr></thead><tbody>");
            foreach (var i in r.Iocs)
                sb.Append("<tr><td>").Append(E(i.Type)).Append("</td><td class=\"mono\">").Append(E(i.Value))
                  .Append("</td><td class=\"mono\">").Append(E(i.Address)).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }

        // Modulos.
        sb.Append("<h2>Modulos cargados (").Append(r.Modules.Count).Append(")</h2>");
        if (r.Modules.Count == 0)
            sb.Append("<p class=\"empty\">No se pudieron enumerar modulos.</p>");
        else
        {
            sb.Append("<table><thead><tr><th>Modulo</th><th>Base</th><th>Tamano</th>");
            bool anyHash = r.Modules.Any(m => !string.IsNullOrEmpty(m.Sha256));
            if (anyHash) sb.Append("<th>SHA-256</th>");
            sb.Append("<th>Ruta</th></tr></thead><tbody>");
            foreach (var m in r.Modules)
            {
                sb.Append("<tr><td>").Append(E(m.Name)).Append("</td><td class=\"mono\">").Append(E(m.BaseAddress))
                  .Append("</td><td>").Append(E(m.Size)).Append("</td>");
                if (anyHash) sb.Append("<td class=\"mono small\">").Append(E(m.Sha256 ?? "")).Append("</td>");
                sb.Append("<td class=\"small\">").Append(E(m.Path ?? "")).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        // Notas.
        if (r.Notes.Count > 0)
        {
            sb.Append("<h2>Notas</h2><ul>");
            foreach (var n in r.Notes) sb.Append("<li>").Append(E(n)).Append("</li>");
            sb.Append("</ul>");
        }

        sb.Append("<footer>Informe generado por MemReader (solo lectura). Uselo unicamente sobre sistemas y procesos ")
          .Append("para los que tenga autorizacion. La deteccion de indicadores no confirma por si sola un compromiso.</footer>");

        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static void Meta(StringBuilder sb, string k, string v)
        => sb.Append("<div><span class=\"k\">").Append(E(k)).Append("</span><span class=\"v\">").Append(v).Append("</span></div>");

    private static void Card(StringBuilder sb, string label, string value, string tone = "")
    {
        sb.Append("<div class=\"card ").Append(tone).Append("\"><div class=\"num\">").Append(E(value))
          .Append("</div><div class=\"lbl\">").Append(E(label)).Append("</div></div>");
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] u = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes;
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{bytes} B" : $"{v:0.##} {u[i]}";
    }

    /// <summary>Escapa texto para insertarlo con seguridad en HTML.</summary>
    private static string E(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\'': sb.Append("&#39;"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    private const string Css = @"
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 0 0 3rem; font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.45;
  background: #0f1115; color: #e6e6e6; }
header { padding: 1.5rem 2rem; background: linear-gradient(135deg,#1b2330,#0f1115); border-bottom: 1px solid #2a2f3a; }
h1 { margin: 0 0 .75rem; font-size: 1.35rem; }
h2 { margin: 1.8rem 2rem .6rem; font-size: 1.05rem; border-left: 3px solid #4f8cff; padding-left: .6rem; }
.meta { display: flex; flex-wrap: wrap; gap: .35rem 2rem; font-size: .86rem; }
.meta .k { color: #8b93a7; margin-right: .4rem; }
.meta .v { color: #d7dbe6; }
.cards { display: flex; flex-wrap: wrap; gap: .8rem; padding: 1.2rem 2rem 0; }
.card { flex: 1 1 140px; background: #171b23; border: 1px solid #262c38; border-radius: 10px; padding: .8rem 1rem; }
.card .num { font-size: 1.5rem; font-weight: 700; }
.card .lbl { font-size: .76rem; color: #8b93a7; margin-top: .2rem; }
.card.ok .num { color: #57d38c; }
.card.warn .num { color: #e2b93b; }
.card.bad .num { color: #ff6b6b; }
table { width: calc(100% - 4rem); margin: .3rem 2rem; border-collapse: collapse; font-size: .85rem;
  background: #12151b; border: 1px solid #262c38; border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: .45rem .7rem; border-bottom: 1px solid #21262f; vertical-align: top; }
th { background: #1a1f29; color: #aab2c5; font-weight: 600; }
tr:last-child td { border-bottom: none; }
.mono { font-family: Consolas, 'Courier New', monospace; }
.small { font-size: .78rem; color: #aab2c5; word-break: break-all; }
.sev-high { color: #ff6b6b; font-weight: 700; }
.sev-med { color: #e2b93b; font-weight: 600; }
.sev-low { color: #8b93a7; }
.empty { margin: .3rem 2rem; color: #8b93a7; font-style: italic; }
footer { margin: 2.5rem 2rem 0; padding-top: 1rem; border-top: 1px solid #262c38; font-size: .78rem; color: #8b93a7; }
@media (prefers-color-scheme: light) {
  body { background: #f6f7f9; color: #1c2230; }
  header { background: linear-gradient(135deg,#eaf0fb,#f6f7f9); border-bottom-color: #dfe3ea; }
  .meta .k { color: #6b7280; } .meta .v { color: #263043; }
  .card { background: #fff; border-color: #e2e6ee; }
  .card .lbl, .small, .empty, footer, th { color: #5b6474; }
  table { background: #fff; border-color: #e2e6ee; }
  th { background: #eef1f6; } th, td { border-bottom-color: #eceef3; }
}
";
}
