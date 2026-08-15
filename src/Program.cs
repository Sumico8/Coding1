using System.Security.Principal;

namespace MemReader;

internal static class Program
{
    [STAThread]
    private static void Main()
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
