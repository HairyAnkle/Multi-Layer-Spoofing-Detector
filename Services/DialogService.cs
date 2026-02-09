using System.Windows;
using Multi_Layer_Spoofing_Detector.Dialogs;

namespace Multi_Layer_Spoofing_Detector.Services
{
    public static class DialogService
    {
        public static void ShowInfo(Window owner, string title, string message)
        {
            ShowDialog(owner, title, message, NotificationDialogType.Info, NotificationDialogButtons.Ok);
        }

        public static void ShowSuccess(Window owner, string title, string message)
        {
            ShowDialog(owner, title, message, NotificationDialogType.Success, NotificationDialogButtons.Ok);
        }

        public static void ShowWarning(Window owner, string title, string message)
        {
            ShowDialog(owner, title, message, NotificationDialogType.Warning, NotificationDialogButtons.Ok);
        }

        public static void ShowError(Window owner, string title, string message)
        {
            ShowDialog(owner, title, message, NotificationDialogType.Error, NotificationDialogButtons.Ok);
        }

        public static bool ShowConfirm(Window owner, string title, string message)
        {
            return ShowDialog(owner, title, message, NotificationDialogType.Question, NotificationDialogButtons.YesNo);
        }

        private static bool ShowDialog(
            Window owner,
            string title,
            string message,
            NotificationDialogType type,
            NotificationDialogButtons buttons)
        {
            var dialog = new NotificationDialog(title, message, type, buttons)
            {
                Owner = owner
            };

            return dialog.ShowDialog() == true;
        }
    }
}
