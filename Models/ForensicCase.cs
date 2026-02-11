using System;

namespace Multi_Layer_Spoofing_Detector.Models
{
    public class ForensicCase
    {
        public string CaseId { get; set; } = "";
        public string PcapFile { get; set; } = "";
        public string PcapHash { get; set; } = "";
        public string NetworkStatus { get; set; } = "";
        public int PacketsAnalyzed { get; set; }
        public DateTime AnalysisTime { get; set; }
    }
}
