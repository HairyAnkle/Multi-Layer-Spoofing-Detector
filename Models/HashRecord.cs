using System;

namespace Multi_Layer_Spoofing_Detector.Models
{
    public class HashRecord
    {
        public string EvidenceType { get; set; } = "";
        public string HashValue { get; set; } = "";
        public string Algorithm { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }
}
