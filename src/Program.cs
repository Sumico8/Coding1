using System.Security.Principal;

namespace MemReader;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // Manejo de errores global: si algo falla (incluido el constructor de la
        // ventana, que corre antes del bucle de mensajes) mostramos el error y lo
        // guardamos en un log, en vez de que la app "se cierre sola" en silencio.
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => ReportCrash(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => ReportCrash(e.ExceptionObject as Exception);

        try
        {
            ApplicationConfiguration.Initialize();
            ThemeManager.Load();

            if (!IsElevated())
            {
                MessageBox.Show(
                    "MemReader necesita ejecutarse como Administrador para poder leer la " +
                    "memoria de otros procesos (privilegio SeDebugPrivilege).\n\n" +
                    "Cierra la aplicacion y vuelve a abrirla con 'Ejecutar como administrador'.",
                    "Se requieren privilegios de Administrador",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                // No abortamos: la app se abre igualmente para poder inspeccionar
                // procesos accesibles, pero muchos fallaran al abrirse.
            }
            else
            {
                // Ya elevados: activamos SeDebugPrivilege para poder abrir procesos
                // de otros usuarios (sigue sin funcionar con procesos protegidos PPL).
                Privileges.EnableDebugPrivilege();
            }

            Application.Run(new MainForm());
        }
        catch (Exception ex)
        {
            ReportCrash(ex);
        }
    }

    /// <summary>Registra la excepcion en %APPDATA%\MemReader\crash.log y la muestra.</summary>
    private static void ReportCrash(Exception? ex)
    {
        string details = ex?.ToString() ?? "Error desconocido (sin detalles).";
        string path = "(no se pudo escribir el log)";
        try
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MemReader");
            Directory.CreateDirectory(dir);
            path = Path.Combine(dir, "crash.log");
            File.AppendAllText(path, $"===== {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====\n{details}\n\n");
        }
        catch { /* si no se puede escribir el log, seguimos mostrando el mensaje */ }

        try
        {
            MessageBox.Show(
                details + "\n\nGuardado en:\n" + path,
                "MemReader - error al iniciar",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch { /* sin UI disponible: nada mas que hacer */ }
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
