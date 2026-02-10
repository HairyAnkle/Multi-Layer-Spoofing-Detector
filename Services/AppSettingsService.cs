using System;
using System.IO;
using System.Text.Json;

namespace Multi_Layer_Spoofing_Detector.Services
{
    public static class AppSettingsService
    {
        private const string FileName = "appsettings.runtime.json";

        public static AppRuntimeSettings Load()
        {
            string path = GetSettingsPath();

            if (!File.Exists(path))
            {
                var defaults = new AppRuntimeSettings();
                Save(defaults);
                return defaults;
            }

            try
            {
                var json = File.ReadAllText(path);
                var settings = JsonSerializer.Deserialize<AppRuntimeSettings>(json);
                return settings ?? new AppRuntimeSettings();
            }
            catch
            {
                return new AppRuntimeSettings();
            }
        }

        public static void Save(AppRuntimeSettings settings)
        {
            string path = GetSettingsPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            File.WriteAllText(path, JsonSerializer.Serialize(settings, new JsonSerializerOptions
            {
                WriteIndented = true
            }));
        }

        private static string GetSettingsPath()
        {
            string appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "MLSD");

            return Path.Combine(appData, FileName);
        }
    }
}
