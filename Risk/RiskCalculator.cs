using System;
using System.Collections.Generic;
using System.Linq;
using Multi_Layer_Spoofing_Detector.Models;

namespace Multi_Layer_Spoofing_Detector.Risk
{
    public sealed class ReportRisk
    {
        public double Score { get; init; }
        public string Rating { get; init; } = "NONE";
        public List<string> SummaryBullets { get; init; } = new();
        public List<string> MitreItems { get; init; } = new();
    }

    public static class RiskCalculator
    {
        public static ReportRisk ComputeReportRisk(List<AnalysisResult> analysisResults)
        {
            if (analysisResults == null || analysisResults.Count == 0)
            {
                return new ReportRisk
                {
                    Score = 0.0,
                    Rating = "NONE",
                    SummaryBullets = new List<string> { "No findings detected from the analyzed PCAP." },
                    MitreItems = new List<string>()
                };
            }

            double finalScore = ComputeMaxScore(analysisResults);
            string rating = CvssRating(finalScore);
            var mitre = ComputeReportMitreMappings(analysisResults);

            var bullets = new List<string>
            {
                $"Highest observed risk derived from {analysisResults.Count} findings.",
                "CVSS-like score is confidence-weighted using ML confidence values.",
                $"Categories involved: {string.Join(", ", analysisResults.Select(x => x.Category).Distinct())}."
            };

            return new ReportRisk
            {
                Score = finalScore,
                Rating = rating,
                SummaryBullets = bullets,
                MitreItems = mitre
            };
        }

        public static (double Score, string Rating, List<string> MitreTechniques) ComputeUiRisk(
            List<AnalysisResult> analysisResults)
        {
            if (analysisResults == null || analysisResults.Count == 0)
            {
                return (0.0, "NONE", new List<string> { "No findings" });
            }

            double finalScore = ComputeMaxScore(analysisResults);
            string rating = CvssRating(finalScore);
            var mitre = ComputeUiMitreMappings(analysisResults);

            return (finalScore, rating, mitre);
        }

        private static double ComputeMaxScore(List<AnalysisResult> analysisResults)
        {
            double maxScore = 0.0;

            foreach (var result in analysisResults)
            {
                double baseScore = (result.RiskLevel ?? "").Trim() switch
                {
                    "High" => 9.3,
                    "Medium" => 6.5,
                    "Low" => 3.1,
                    _ => 0.0
                };

                double confFactor = Math.Clamp(result.Confidence / 100.0, 0.0, 1.0);
                double score = baseScore * confFactor;
                if (score > maxScore)
                {
                    maxScore = score;
                }
            }

            return Math.Round(maxScore, 1);
        }

        private static string CvssRating(double score)
        {
            if (score <= 0.0) return "NONE";
            if (score < 4.0) return "LOW";
            if (score < 7.0) return "MEDIUM";
            if (score < 9.0) return "HIGH";
            return "CRITICAL";
        }

        private static List<string> ComputeUiMitreMappings(List<AnalysisResult> analysisResults)
        {
            var mapped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var result in analysisResults)
            {
                var category = (result.Category ?? "").Trim().ToUpperInvariant();
                switch (category)
                {
                    case "ARP":
                        mapped.Add("T1557 – Adversary-in-the-Middle (ARP Spoofing)");
                        break;
                    case "DNS":
                        mapped.Add("T1568.002 – DNS Manipulation");
                        break;
                    case "IP":
                        mapped.Add("Network Traffic Manipulation (IP Spoofing Behavior)");
                        break;
                }
            }

            return mapped.Count == 0
                ? new List<string> { "No mapped techniques" }
                : mapped.ToList();
        }

        private static List<string> ComputeReportMitreMappings(List<AnalysisResult> analysisResults)
        {
            var mitre = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var result in analysisResults)
            {
                var category = (result.Category ?? "").Trim().ToUpperInvariant();
                switch (category)
                {
                    case "ARP":
                        mitre.Add("Adversary-in-the-Middle (network interception)");
                        break;
                    case "DNS":
                        mitre.Add("DNS manipulation / traffic redirection");
                        break;
                    case "IP":
                        mitre.Add("Network traffic manipulation (spoofed source identity)");
                        break;
                }
            }

            return mitre.ToList();
        }
    }
}
