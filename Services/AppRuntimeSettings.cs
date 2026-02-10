using System;

namespace Multi_Layer_Spoofing_Detector.Services
{
    public sealed class AppRuntimeSettings
    {
        public string MlDockerImage { get; set; } = "multi-layer-spoof-detector";
        public string CicFlowMeterImage { get; set; } = "cicflowmeter";
        public int AnalysisTimeoutMs { get; set; } = 900_000;
        public int MaxPcapSizeMb { get; set; } = 500;
        public int MinAlertConfidence { get; set; } = 60;
        public int HighConfidenceThreshold { get; set; } = 85;
        public int MediumConfidenceThreshold { get; set; } = 60;
        public string DataRootDirectory { get; set; } = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MLSD");
        public bool AutoRunAfterUpload { get; set; } = false;
    }
}
