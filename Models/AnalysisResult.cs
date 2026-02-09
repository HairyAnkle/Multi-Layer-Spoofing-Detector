namespace Multi_Layer_Spoofing_Detector.Models
{
    public class AnalysisResult
    {
        public string Category { get; set; } = "";
        public string RiskLevel { get; set; } = "";
        public string Description { get; set; } = "";
        public string Details { get; set; } = "";
        public int Confidence { get; set; }
    }
}
