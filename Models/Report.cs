using System;

namespace Multi_Layer_Spoofing_Detector.Models
{
    public class Report
    {
        public string Name { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Status { get; set; } = "";
        public int ThreatsDetected { get; set; }
        public int PacketsAnalyzed { get; set; }
    }
}
