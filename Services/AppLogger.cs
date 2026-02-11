using System;
using System.IO;

namespace Multi_Layer_Spoofing_Detector.Services
{
    public static class AppLogger
    {
        private static readonly object Sync = new();

        public static void Info(string message) => Write("INFO", message);
        public static void Error(string message) => Write("ERROR", message);

        private static void Write(string level, string message)
        {
            try
            {
                string root = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "MLSD",
                    "logs");

                Directory.CreateDirectory(root);
                string filePath = Path.Combine(root, "app.log");

                string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}";
                lock (Sync)
                {
                    File.AppendAllText(filePath, line);
                }
            }
            catch
            {
                // Best effort logging only.
            }
        }
    }
}
