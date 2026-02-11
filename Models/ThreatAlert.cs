using System;

namespace Multi_Layer_Spoofing_Detector.Models
{
    public class ThreatAlert
    {
        public string Type { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Severity { get; set; } = "";
        public string IpAddress { get; set; } = "";
        public string AdditionalInfo { get; set; } = "";
    }
}
