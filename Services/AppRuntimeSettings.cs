using System;

namespace Multi_Layer_Spoofing_Detector.Services
{
    public sealed class AppRuntimeSettings
    {
        public string MlDockerImage { get; set; } = "multi-layer-spoof-detector";
        public string CicFlowMeterImage { get; set; } = "cicflowmeter";
        public int AnalysisTimeoutMs { get; set; } = 900_000;
        public string DataRootDirectory { get; set; } = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MLSD");
        public bool AutoRunAfterUpload { get; set; } = false;
    }
}
