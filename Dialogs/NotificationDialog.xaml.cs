using System.Windows;

namespace Multi_Layer_Spoofing_Detector.Dialogs
{
    public enum NotificationDialogType
    {
        Info,
        Warning,
        Error,
        Success,
        Question
    }

    public enum NotificationDialogButtons
    {
        Ok,
        YesNo
    }

    public partial class NotificationDialog : Window
    {
        public NotificationDialog(
            string title,
            string message,
            NotificationDialogType type,
            NotificationDialogButtons buttons)
        {
            InitializeComponent();

            TitleText.Text = title;
            MessageText.Text = message;
            IconText.Text = type switch
            {
                NotificationDialogType.Success => "✅",
                NotificationDialogType.Warning => "⚠️",
                NotificationDialogType.Error => "❌",
                NotificationDialogType.Question => "❓",
                _ => "ℹ️"
            };

            if (buttons == NotificationDialogButtons.YesNo)
            {
                PrimaryButton.Content = "Yes";
                SecondaryButton.Content = "No";
                SecondaryButton.Visibility = Visibility.Visible;
            }
            else
            {
                PrimaryButton.Content = "OK";
                SecondaryButton.Visibility = Visibility.Collapsed;
            }
        }

        private void PrimaryButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }

        private void SecondaryButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
}
