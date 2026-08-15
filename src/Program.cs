using System.Security.Principal;

namespace MemReader;

internal static class Program
{
    /// <summary>
    /// Punto de entrada. Sin argumentos abre la interfaz grafica de siempre.
    /// Con argumentos entra en el modo CLI headless (automatizacion/scripting),
    /// que sigue siendo estrictamente de solo lectura.
    /// </summary>
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0)
            return RunGui();

        return CliRunner.Run(args);
    }

    private static int RunGui()
    {
        ApplicationConfiguration.Initialize();

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
        return 0;
    }

    /// <summary>True si el proceso actual corre con privilegios de Administrador.</summary>
    internal static bool IsElevated()
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
