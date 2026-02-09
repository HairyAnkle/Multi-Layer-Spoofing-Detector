using Microsoft.Win32;
using Multi_Layer_Spoofing_Detector.data;
using Multi_Layer_Spoofing_Detector.Models;
using Multi_Layer_Spoofing_Detector.Risk;
using Multi_Layer_Spoofing_Detector.Services;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace Multi_Layer_Spoofing_Detector
{
    public partial class MainWindow : Window
    {
        private DispatcherTimer _clockTimer;
        private string _currentPcapFilePath = "";

        private List<ThreatAlert> _threatAlerts = new List<ThreatAlert>();
        private List<AnalysisResult> _analysisResults = new List<AnalysisResult>();
        private List<Report> _reports = new List<Report>();

        private readonly ForensicsRepository _repo = new ForensicsRepository();
        private string? _currentCaseId;

        private string BaseReportDirectory =>
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "reports");

        private string HtmlReportDirectory =>
            System.IO.Path.Combine(BaseReportDirectory, "html");

        private string JsonReportDirectory =>
            System.IO.Path.Combine(BaseReportDirectory, "json");

        private string _currentNetworkStatus = "SECURE";
        private DateTime _lastAnalysisTime;

        private double _currentCvssScore = 0.0;
        private string _currentCvssRating = "NONE";
        private List<string> _currentMitreTechniques = new();

        private MLIntegration? _mlIntegration;
        private bool _isMlIntegrationReady;

        public MainWindow()
        {
            InitializeComponent();
            InitializeTimers();
            InitializeMLIntegration();
            UpdateDateTime();
        }

        #region ML Integration
        private void InitializeMLIntegration()
        {
            try
            {
                if (!DockerChecker.IsDockerInstalled(out string dockerError))
                {
                    throw new Exception(
                        "Docker is not installed.\n\nPlease install Docker Desktop."
                    );
                }

                if (!DockerChecker.IsDockerRunning(out dockerError))
                {
                    throw new Exception(
                        "Docker is installed but not running.\n\nPlease start Docker Desktop."
                    );
                }

                if (!DockerChecker.IsDockerImageAvailable("multi-layer-spoof-detector", out dockerError))
                {
                    throw new Exception(
                        "Spoof Detector Docker image not found.\n\n" +
                        "Run the following command inside the integration folder:\n\n" +
                        "docker build -t multi-layer-spoof-detector ."
                    );
                }

                if (!DockerChecker.IsCICFlowMeterImageAvailable(out dockerError))
                {
                    throw new Exception(
                        "CICFlowMeter Docker image not found.\n\n" +
                        "Please build or pull the CICFlowMeter image:\n\n" +
                        "docker build -t cicflowmeter ."
                    );
                }

                _mlIntegration = new MLIntegration();
                _isMlIntegrationReady = true;

                AnalysisModuleDetails.Text = "✓ Docker ML Engine ready";
                AnalysisModuleDetails.Foreground =
                    (SolidColorBrush)FindResource("SafeBrush");
            }
            catch (Exception ex)
            {
                _isMlIntegrationReady = false;
                AnalysisModuleDetails.Text = "✗ Environment check failed";
                AnalysisModuleDetails.Foreground =
                    (SolidColorBrush)FindResource("CriticalBrush");

                AnalyzeBtn.IsEnabled = false;

                DialogService.ShowError(
                    this,
                    "Environment Error",
                    ex.Message
                );
            }
        }

        #endregion

        #region Initialization
        private void InitializeTimers()
        {
            _clockTimer = new DispatcherTimer();
            _clockTimer.Interval = TimeSpan.FromSeconds(1);
            _clockTimer.Tick += ClockTimer_Tick;
            _clockTimer.Start();
        }
        private void UpdateDateTime()
        {
            if (DateTimeText != null)
            {
                DateTimeText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            }
        }

        #endregion

        #region Timer Events

        private void ClockTimer_Tick(object sender, EventArgs e)
        {
            if (DateTimeText != null)
            {
                DateTimeText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            }
        }

        #endregion

        #region Network Status Management

        private void UpdateNetworkStatus()
        {
            string statusIcon;
            SolidColorBrush statusColor;

            switch (_currentNetworkStatus)
            {
                case "CRITICAL":
                    statusIcon = "🚨";
                    statusColor = (SolidColorBrush)FindResource("CriticalBrush");
                    break;

                case "HIGH":
                    statusIcon = "⚠️";
                    statusColor = (SolidColorBrush)FindResource("CriticalBrush");
                    break;

                case "MEDIUM":
                    statusIcon = "⚠️";
                    statusColor = (SolidColorBrush)FindResource("WarningBrush");
                    break;

                case "LOW":
                    statusIcon = "🟡";
                    statusColor = (SolidColorBrush)FindResource("WarningBrush");
                    break;

                default:
                    statusIcon = "✅";
                    statusColor = (SolidColorBrush)FindResource("SafeBrush");
                    break;
            }

            NetworkStatusText.Text = "";
            NetworkStatusIcon.Text = "";
            NetworkStatusIndicator.Background = statusColor;

            CvssScoreText.Text = $"{_currentCvssScore:0.0}";

            MitreBullets.ItemsSource = _currentMitreTechniques ?? new List<string> { "No findings" };

            LastScanText.Text = $"Last scan: {_lastAnalysisTime:HH:mm:ss}";
        }

        #endregion        

        #region Button Event Handlers

        private void UploadPcapBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog
                {
                    Title = "Select PCAP File",
                    Filter = "PCAP files (*.pcap;*.pcapng)|*.pcap;*.pcapng",
                    Multiselect = false
                };

                if (openFileDialog.ShowDialog() != true)
                    return;

                string selectedPath = openFileDialog.FileName;
                string extension = System.IO.Path.GetExtension(selectedPath)?.ToLower();

                if (extension != ".pcap" && extension != ".pcapng")
                {
                    DialogService.ShowWarning(
                        this,
                        "Invalid File",
                        "Invalid file type selected.\n\nOnly PCAP (.pcap, .pcapng) files are allowed."
                    );

                    AnalyzeBtn.IsEnabled = false;
                    FileInfoPanel.Visibility = Visibility.Collapsed;

                    UploadModuleStatus.Text = "✗ Invalid file format";
                    UploadModuleStatus.Foreground = (SolidColorBrush)FindResource("CriticalBrush");

                    return;
                }

                _currentPcapFilePath = selectedPath;
                FileInfo fileInfo = new FileInfo(_currentPcapFilePath);

                FileInfoPanel.Visibility = Visibility.Visible;
                FileNameText.Text = System.IO.Path.GetFileName(_currentPcapFilePath);
                FileSizeText.Text = FormatFileSize(fileInfo.Length);

                FileStatusText.Text = "File uploaded - Ready for analysis";
                StatusIndicator.Fill = (SolidColorBrush)FindResource("SafeBrush");

                UploadModuleStatus.Text = "✓ PCAP file loaded successfully";
                UploadModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");

                AnalysisModuleStatus.Text = "✓ Ready to process packets";
                AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");
                AnalysisModuleDetails.Text = $"File: {System.IO.Path.GetFileName(_currentPcapFilePath)}";

                AnalyzeBtn.IsEnabled = true;

                DialogService.ShowSuccess(
                    this,
                    "File Upload",
                    "PCAP file uploaded successfully to File Upload."
                );
            }

            catch (Exception ex)
            {
                UploadModuleStatus.Text = "✗ Upload failed";
                UploadModuleStatus.Foreground = (SolidColorBrush)FindResource("CriticalBrush");

                AnalyzeBtn.IsEnabled = false;

                DialogService.ShowError(
                    this,
                    "Upload Error",
                    $"Error in File Upload Module:\n{ex.Message}"
                );
            }
        }


        private async void AnalyzeBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                AnalyzeBtn.IsEnabled = false;
                LoadingOverlay.Visibility = Visibility.Visible;

                LoadingProgressText.Text = "CICFlowMeter - Extracting flows...";
                await Task.Delay(500);

                var progress = new Progress<string>(message =>
                {
                    LoadingProgressText.Text = message;
                });

                if (!_isMlIntegrationReady || _mlIntegration == null)
                {
                    throw new InvalidOperationException(
                        "ML integration is not ready. Please verify Docker and required images."
                    );
                }

                var mlResult = await _mlIntegration.AnalyzePcapAsync(_currentPcapFilePath, progress);

                if (mlResult == null)
                {
                    throw new Exception("ML engine returned no result.");
                }

                if (mlResult.Status == "error")
                {
                    throw new Exception(mlResult.ErrorMessage);
                }

                LoadingProgressText.Text = "Hybrid ML Detection (RF + XGBoost)...";
                DetectionModuleStatus.Text = "Status: Processing Results";
                DetectionModuleStatus.Foreground = (SolidColorBrush)FindResource("PrimaryAccentBrush");

                ArpDetectionIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");
                await Task.Delay(800);

                DnsDetectionIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");
                await Task.Delay(800);

                IpDetectionIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");
                await Task.Delay(800);

                ConvertMLResultsToAppFormat(mlResult);

                ComputeRiskAndMitreFromFindings();

                _currentNetworkStatus = _currentCvssRating;

                _currentCaseId = $"SPOOF-{DateTime.Now:yyyyMMdd-HHmmss}";
                _lastAnalysisTime = DateTime.Now;

                string pcapHash = ComputeSHA256FromFile(_currentPcapFilePath);

                _repo.InsertAnalysisCase(
                    _currentCaseId,
                    System.IO.Path.GetFileName(_currentPcapFilePath),
                    pcapHash,
                    _currentNetworkStatus,
                     _reports[0].PacketsAnalyzed,
                    _threatAlerts,
                    _analysisResults,
                    pcapHash
                 );


                LoadingProgressText.Text = "Results Display - Preparing outputs...";
                await Task.Delay(1000);

                LoadingOverlay.Visibility = Visibility.Collapsed;

                FileStatusText.Text = "Analysis complete - Results available";
                StatusIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");

                AnalysisModuleStatus.Text = "✓ Packet analysis completed";
                AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");
                AnalysisModuleDetails.Text = "All features extracted successfully";

                DetectionModuleStatus.Text = "Status: Detection Complete";
                DetectionModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");

                ArpDetectionIndicator.Fill = (_analysisResults.Any(r => r.Category == "ARP" && r.RiskLevel != "Low")) ?
                    (SolidColorBrush)FindResource("CriticalBrush") : (SolidColorBrush)FindResource("SafeBrush");
                DnsDetectionIndicator.Fill = (_analysisResults.Any(r => r.Category == "DNS" && r.RiskLevel != "Low")) ?
                    (SolidColorBrush)FindResource("WarningBrush") : (SolidColorBrush)FindResource("SafeBrush");
                IpDetectionIndicator.Fill = (_analysisResults.Any(r => r.Category == "IP" && r.RiskLevel != "Low")) ?
                    (SolidColorBrush)FindResource("WarningBrush") : (SolidColorBrush)FindResource("SafeBrush");

                UpdateAlertsDisplay();

                UpdateNetworkStatus();
                UpdateAnalysisResultsDisplay();
                UpdateReportSummary();

                AnalyzeBtn.IsEnabled = true;

                DialogService.ShowSuccess(
                    this,
                    "Analysis Complete",
                    $"Multi-Layer Spoofing Detection Complete!\n\n" +
                    $"✓ File Upload: Success\n" +
                    $"✓ Packet Analysis: {_analysisResults.Count} findings\n" +
                    $"✓ Detection: {_threatAlerts.Count} threats identified\n" +
                    $"✓ Results Display: Ready\n\n" +
                    $"Results are now available in the Results Display."
                );
            }
            catch (Exception ex)
            {
                LoadingOverlay.Visibility = Visibility.Collapsed;
                AnalyzeBtn.IsEnabled = true;

                AnalysisModuleStatus.Text = "✗ Analysis failed";
                AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("CriticalBrush");

                DialogService.ShowError(
                    this,
                    "Analysis Error",
                    $"Error during analysis: {ex.Message}"
                );
            }
        }

        private void ConvertMLResultsToAppFormat(MLAnalysisResult mlResult)
        {
            _analysisResults.Clear();
            _threatAlerts.Clear();

            foreach (var threat in mlResult.Arp_Spoofing)
            {
                var result = new AnalysisResult
                {
                    Category = "ARP",
                    RiskLevel = threat.Confidence >= 85 ? "High" : (threat.Confidence >= 60 ? "Medium" : "Low"),
                    Description = "ARP Spoofing Detected by ML Model",
                    Details = threat.Details,
                    Confidence = (int)threat.Confidence
                };
                _analysisResults.Add(result);

                var alert = new ThreatAlert
                {
                    Type = threat.Type,
                    Description = $"ML Model detected {threat.Type}",
                    Timestamp = DateTime.Now,
                    Severity = result.RiskLevel == "High" ? "Critical" : "Warning",
                    IpAddress = threat.Src_Ip ?? "Unknown",
                    AdditionalInfo = $"{threat.Details} | Confidence: {threat.Confidence:F2}%"
                };
                _threatAlerts.Add(alert);
            }

            foreach (var threat in mlResult.Dns_Spoofing)
            {
                var result = new AnalysisResult
                {
                    Category = "DNS",
                    RiskLevel = threat.Confidence >= 85 ? "High" : (threat.Confidence >= 60 ? "Medium" : "Low"),
                    Description = "DNS Spoofing Detected by ML Model",
                    Details = threat.Details,
                    Confidence = (int)threat.Confidence
                };
                _analysisResults.Add(result);

                var alert = new ThreatAlert
                {
                    Type = threat.Type,
                    Description = $"ML Model detected {threat.Type}",
                    Timestamp = DateTime.Now,
                    Severity = result.RiskLevel == "High" ? "Critical" : "Warning",
                    IpAddress = threat.Src_Ip ?? "Unknown",
                    AdditionalInfo = $"{threat.Details} | Confidence: {threat.Confidence:F2}%"
                };
                _threatAlerts.Add(alert);
            }

            foreach (var threat in mlResult.Ip_Spoofing)
            {
                var result = new AnalysisResult
                {
                    Category = "IP",
                    RiskLevel = threat.Confidence >= 85 ? "High" : (threat.Confidence >= 60 ? "Medium" : "Low"),
                    Description = "IP Spoofing Detected by ML Model",
                    Details = threat.Details,
                    Confidence = (int)threat.Confidence
                };
                _analysisResults.Add(result);

                var alert = new ThreatAlert
                {
                    Type = threat.Type,
                    Description = $"ML Model detected {threat.Type}",
                    Timestamp = DateTime.Now,
                    Severity = result.RiskLevel == "High" ? "Critical" : "Warning",
                    IpAddress = threat.Src_Ip ?? "Unknown",
                    AdditionalInfo = $"{threat.Details} | Confidence: {threat.Confidence:F2}%"
                };
                _threatAlerts.Add(alert);
            }

            if (!_analysisResults.Any())
            {
                _analysisResults.Add(new AnalysisResult
                {
                    Category = "IP",
                    RiskLevel = "Low",
                    Description = "Normal Traffic Pattern",
                    Details = "ML Model: No spoofing attacks detected in analyzed packets",
                    Confidence = 99
                });

                _threatAlerts.Add(new ThreatAlert
                {
                    Type = "Analysis Complete",
                    Description = "ML Model analysis completed - No threats detected",
                    Timestamp = DateTime.Now,
                    Severity = "Safe",
                    IpAddress = "System",
                    AdditionalInfo = $"Total packets analyzed: {mlResult.Total_Packets}"
                });
            }

            GenerateNewReport(mlResult.Total_Packets);
        }

        private void GenerateNewReport(int packetsAnalyzed)
        {
            var newReport = new Report
            {
                Name = $"Report_{DateTime.Now:yyyy-MM-dd_HH-mm}",
                Timestamp = DateTime.Now,
                Status = "Complete",
                ThreatsDetected = _analysisResults.Count(r => r.RiskLevel == "High" || r.RiskLevel == "Medium"),
                PacketsAnalyzed = packetsAnalyzed
            };

            _reports.Insert(0, newReport);

            if (_reports.Count > 10)
            {
                _reports.RemoveRange(10, _reports.Count - 10);
            }

            UpdateReportSummary();
        }

        private void GenerateHtmlReportBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_currentCaseId))
                {
                    DialogService.ShowWarning(
                        this,
                        "No Case Available",
                        "No analysis case available.\n\nPlease analyze a PCAP first."
                    );
                    return;
                }

                EnsureReportDirectories();

                string fileName = $"ForensicReport_{DateTime.Now:yyyyMMdd_HHmmss}.html";
                string fullPath = System.IO.Path.Combine(HtmlReportDirectory, fileName);

                GenerateForensicReportHTML(fullPath);

                var shouldOpen = DialogService.ShowConfirm(
                    this,
                    "Report Generated",
                    $"Forensic HTML report generated successfully!\n\nLocation:\n{fullPath}\n\nOpen now?"
                );

                if (shouldOpen)
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = fullPath,
                        UseShellExecute = true
                    });
                }
            }
            catch (Exception ex)
            {
                DialogService.ShowError(
                    this,
                    "Export Error",
                    $"Error generating HTML report:\n{ex.Message}"
                );
            }
        }

        private void GenerateJsonReportBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_currentCaseId))
                {
                    DialogService.ShowWarning(
                        this,
                        "No Case Available",
                        "No analysis case available.\n\nPlease analyze a PCAP first."
                    );
                    return;
                }

                EnsureReportDirectories();

                string fileName = $"ForensicReport_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                string fullPath = System.IO.Path.Combine(JsonReportDirectory, fileName);

                GenerateForensicReportJSON(fullPath);

                DialogService.ShowSuccess(
                    this,
                    "Report Generated",
                    $"Forensic JSON report generated successfully!\n\nLocation:\n{fullPath}"
                );
            }
            catch (Exception ex)
            {
                DialogService.ShowError(
                    this,
                    "Export Error",
                    $"Error generating JSON report:\n{ex.Message}"
                );
            }
        }

        #endregion

        #region UI Update Methods

        private void UpdateReportSummary()
        {
            TotalThreatsText.Text = _threatAlerts.Count.ToString();
            CriticalAlertsText.Text = _threatAlerts.Count(a => a.Severity == "Critical").ToString();
            PacketsAnalyzedText.Text = _reports.Any() ? _reports[0].PacketsAnalyzed.ToString("N0") : "0";
        }

        private void UpdateAlertsDisplay()
        {
            AlertsPanel.Children.Clear();

            foreach (var alert in _threatAlerts)
            {
                var alertBorder = CreateAlertUI(alert);
                AlertsPanel.Children.Add(alertBorder);
            }
        }

        private Border CreateAlertUI(ThreatAlert alert)
        {
            string backgroundColor = alert.Severity switch
            {
                "Critical" => "#4A2C2A",
                "Warning" => "#4A3C2A",
                "Safe" => "#2A4A2A",
                _ => "#333344"
            };

            string borderColor = alert.Severity switch
            {
                "Critical" => "CriticalBrush",
                "Warning" => "WarningBrush",
                "Safe" => "SafeBrush",
                _ => "SubTextBrush"
            };

            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(backgroundColor)),
                BorderBrush = (SolidColorBrush)FindResource(borderColor),
                BorderThickness = new Thickness(2),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 4, 0, 0)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var ellipse = new Ellipse
            {
                Width = 12,
                Height = 12,
                Fill = (SolidColorBrush)FindResource(borderColor),
                Margin = new Thickness(0, 0, 8, 0)
            };
            Grid.SetColumn(ellipse, 0);

            var contentPanel = new StackPanel();
            var titleText = new TextBlock
            {
                Text = alert.Type,
                Style = (Style)FindResource("RegularTextStyle"),
                FontWeight = FontWeights.Bold
            };
            var descText = new TextBlock
            {
                Text = alert.Description,
                Style = (Style)FindResource("SubTextStyle")
            };
            var infoText = new TextBlock
            {
                Text = alert.AdditionalInfo,
                Style = (Style)FindResource("SubTextStyle")
            };

            contentPanel.Children.Add(titleText);
            contentPanel.Children.Add(descText);
            contentPanel.Children.Add(infoText);
            Grid.SetColumn(contentPanel, 1);

            var timeText = new TextBlock
            {
                Text = alert.Timestamp.ToString("HH:mm:ss"),
                Style = (Style)FindResource("SubTextStyle"),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(timeText, 2);

            grid.Children.Add(ellipse);
            grid.Children.Add(contentPanel);
            grid.Children.Add(timeText);
            border.Child = grid;

            return border;
        }

        private void UpdateAnalysisResultsDisplay()
        {
            ArpResultsPanel.Children.Clear();
            DnsResultsPanel.Children.Clear();
            IpResultsPanel.Children.Clear();

            foreach (var result in _analysisResults)
            {
                var resultUI = CreateAnalysisResultUI(result);

                switch (result.Category.ToUpper())
                {
                    case "ARP":
                        ArpResultsPanel.Children.Add(resultUI);
                        break;
                    case "DNS":
                        DnsResultsPanel.Children.Add(resultUI);
                        break;
                    case "IP":
                        IpResultsPanel.Children.Add(resultUI);
                        break;
                }
            }
        }
        private Border CreateAnalysisResultUI(AnalysisResult result)
        {
            string backgroundColor = result.RiskLevel switch
            {
                "High" => "#4A2C2A",
                "Medium" => "#4A3C2A",
                "Low" => "#2A4A2A",
                _ => "#333344"
            };

            string riskIcon = result.RiskLevel switch
            {
                "High" => "🔴",
                "Medium" => "🟡",
                "Low" => "🟢",
                _ => "⚪"
            };

            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(backgroundColor)),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 4, 0, 0)
            };

            var panel = new StackPanel();

            var titleText = new TextBlock
            {
                Text = $"{riskIcon} {result.RiskLevel} Risk - {result.Description}",
                Style = (Style)FindResource("RegularTextStyle"),
                FontWeight = FontWeights.Bold
            };

            var detailsText = new TextBlock
            {
                Text = result.Details,
                Style = (Style)FindResource("SubTextStyle")
            };

            var confidenceText = new TextBlock
            {
                Text = $"Confidence: {result.Confidence}%",
                Style = (Style)FindResource("SubTextStyle")
            };

            panel.Children.Add(titleText);
            panel.Children.Add(detailsText);
            panel.Children.Add(confidenceText);
            border.Child = panel;

            return border;
        }

        #endregion

        #region Forensic Report Generation

        private void GenerateForensicReportHTML(string filePath)
        {
            if (string.IsNullOrEmpty(_currentCaseId))
                throw new InvalidOperationException("No analysis case available.");

            var threatAlerts = _repo.GetThreatAlerts(_currentCaseId);
            var analysisResults = _repo.GetAnalysisResults(_currentCaseId);
            var caseMeta = _repo.GetCaseMetadata(_currentCaseId);
            var hashes = _repo.GetHashes(_currentCaseId);

            var risk = RiskCalculator.ComputeReportRisk(analysisResults);

            var reportDate = DateTime.Now;
            var investigator = Environment.UserName;

            int criticalCount = threatAlerts.Count(a => a.Severity == "Critical");
            int warningCount = threatAlerts.Count(a => a.Severity == "Warning");
            int totalPackets = caseMeta.PacketsAnalyzed;
            int avgConfidence = analysisResults.Any()
                ? (int)Math.Round(analysisResults.Average(r => r.Confidence))
                : 0;
            string riskClass = risk.Rating.ToLowerInvariant(); 

            string threatRows = threatAlerts.Any()
                ? string.Join("", threatAlerts.Select(alert => $@"
<tr>
    <td>{alert.Timestamp:yyyy-MM-dd HH:mm:ss}</td>
    <td><span class='badge sev-{HtmlSafe(alert.Severity.ToLower())}'>{HtmlSafe(alert.Severity)}</span></td>
    <td>{HtmlSafe(alert.Type)}</td>
    <td>{HtmlSafe(alert.IpAddress)}</td>
    <td>{HtmlSafe(alert.Description)}<br/><small>{HtmlSafe(alert.AdditionalInfo)}</small></td>
</tr>"))
                : "<tr><td colspan='5'>No threat alerts detected.</td></tr>";

            string hashSection = hashes.Any()
                ? "<table class='table'>" +
                  "<thead><tr><th>Evidence</th><th>Algorithm</th><th>Hash</th><th>Timestamp</th></tr></thead><tbody>" +
                  string.Join("", hashes.Select(h => $@"
<tr>
    <td>{HtmlSafe(h.EvidenceType)}</td>
    <td>{HtmlSafe(h.Algorithm)}</td>
    <td class='mono'>{HtmlSafe(h.HashValue)}</td>
    <td>{h.Timestamp:yyyy-MM-dd HH:mm:ss}</td>
</tr>")) +
                  "</tbody></table>"
                : "<p>No hash records found.</p>";

            string mitreBullets = risk.MitreItems.Any()
                ? "<ul>" + string.Join("", risk.MitreItems.Select(x => $"<li>{HtmlSafe(x)}</li>")) + "</ul>"
                : "<p>No mapped techniques.</p>";

            string html = $@"<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>Network Forensic Analysis Report</title>
<style>
body {{ font-family: Segoe UI; background:#f5f5f5; padding:20px; }}
.container {{ background:white; padding:40px; max-width:1200px; margin:auto; }}
.header {{ border-bottom:4px solid #00C9A7; margin-bottom:30px; }}

.cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:15px; }}
.card {{ padding:20px; border-left:4px solid #00C9A7; background:#f8f9fa; border-radius:10px; }}
.card.critical {{ border-color:#FF4757; }}
.card.warning {{ border-color:#FFA502; }}
.card.safe {{ border-color:#26DE81; }}

.badge {{ padding:4px 10px; color:white; border-radius:10px; font-size:12px; display:inline-block; }}
.sev-critical {{ background:#FF4757; }}
.sev-warning  {{ background:#FFA502; }}
.sev-safe     {{ background:#26DE81; }}

.cvss-critical {{ background:#FF4757; }}
.cvss-high     {{ background:#FF6B6B; }}
.cvss-medium   {{ background:#FFA502; }}
.cvss-low      {{ background:#26DE81; }}
.cvss-none     {{ background:#2ECC71; }}

.table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
.table th {{ background:#1E1E2E; color:white; padding:10px; text-align:left; }}
.table td {{ padding:10px; border-bottom:1px solid #ddd; vertical-align:top; }}

.riskbox {{ margin-top:18px; padding:16px; background:#f8f9fa; border-radius:12px; border-left:6px solid #00C9A7; }}
.riskTitle {{ font-size:20px; font-weight:700; margin:0; }}
.riskScore {{ font-size:16px; margin-top:8px; }}
.scoreBadge {{ font-weight:700; padding:4px 10px; border-radius:10px; color:white; }}
.mono {{ font-family: Consolas; font-size:12px; word-break:break-all; }}

.footer {{ margin-top:40px; text-align:center; color:#666; font-size:13px; }}
</style>
</head>
<body>
<div class='container'>

<div class='header'>
<h1>🛡️ Network Forensic Analysis Report</h1>
<p>AI-Based Multi-Layer Spoofing Detection System</p>
</div>

<table>
<tr><td><b>Case Number:</b></td><td>{HtmlSafe(caseMeta.CaseId)}</td></tr>
<tr><td><b>Investigator:</b></td><td>{HtmlSafe(investigator)}</td></tr>
<tr><td><b>Report Generated:</b></td><td>{reportDate:yyyy-MM-dd HH:mm:ss}</td></tr>
<tr><td><b>PCAP File:</b></td><td>{HtmlSafe(caseMeta.PcapFile)}</td></tr>
</table>

<div class='riskbox'>
  <p class='riskTitle'>System Risk (CVSS + MITRE)</p>
  <div class='riskScore'>
    <span class='badge cvss-{riskClass}'>{HtmlSafe(risk.Rating)}</span>
    &nbsp;
    <span class='scoreBadge cvss-{riskClass}'>Score: {risk.Score:0.0}</span>
  </div>
  <div style='margin-top:10px;'>
    <b>Summary</b>
    <ul>
      {string.Join("", risk.SummaryBullets.Select(b => $"<li>{HtmlSafe(b)}</li>"))}
    </ul>
  </div>
  <div style='margin-top:10px;'>
    <b>MITRE ATT&CK (mapped techniques)</b>
    {mitreBullets}
  </div>
</div>

<h2>Executive Summary</h2>
<div class='cards'>
  <div class='card critical'><b>Critical</b><br/>{criticalCount}</div>
  <div class='card warning'><b>Warning</b><br/>{warningCount}</div>
  <div class='card'><b>Flows</b><br/>{totalPackets:N0}</div>
  <div class='card safe'><b>Confidence</b><br/>{avgConfidence}%</div>
</div>

<h2>Detected Threat Alerts</h2>
<table class='table'>
<thead>
<tr>
  <th>Timestamp</th>
  <th>Severity</th>
  <th>Type</th>
  <th>Source IP</th>
  <th>Description</th>
</tr>
</thead>
<tbody>
{threatRows}
</tbody>
</table>

<h2>Chain of Custody (Hashes)</h2>
{hashSection}

<div class='footer'>
  <p><strong>AI-Based Multi-Layer Spoofing Detection System</strong></p>
  <p>Report ID: {HtmlSafe(caseMeta.CaseId)}</p>
  <p>Generated: {reportDate:yyyy-MM-dd HH:mm:ss}</p>
</div>

</div>
</body>
</html>";

            File.WriteAllText(filePath, html);
        }

        private void GenerateForensicReportJSON(string filePath)
        {
            if (string.IsNullOrEmpty(_currentCaseId))
                throw new InvalidOperationException("No analysis case available.");

            var threatAlerts = _repo.GetThreatAlerts(_currentCaseId);
            var analysisResults = _repo.GetAnalysisResults(_currentCaseId);
            var caseMeta = _repo.GetCaseMetadata(_currentCaseId);
            var hashes = _repo.GetHashes(_currentCaseId);

            var risk = RiskCalculator.ComputeReportRisk(analysisResults);

            var reportBody = new
            {
                ForensicReport = new
                {
                    Metadata = new
                    {
                        caseMeta.CaseId,
                        caseMeta.PcapFile,
                        Investigator = Environment.UserName,
                        Organization = "AI-Based Spoofing Detection System",
                        ReportGenerated = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        PacketsAnalyzed = caseMeta.PacketsAnalyzed,
                        PcapHash = caseMeta.PcapHash
                    },

                    SystemRisk = new
                    {
                        CvssScore = risk.Score,
                        CvssRating = risk.Rating,
                        Summary = risk.SummaryBullets,
                        MitreAttack = risk.MitreItems
                    },

                    ExecutiveSummary = new
                    {
                        TotalThreats = threatAlerts.Count,
                        CriticalThreats = threatAlerts.Count(a => a.Severity == "Critical"),
                        WarningThreats = threatAlerts.Count(a => a.Severity == "Warning"),
                        AverageConfidence = analysisResults.Any()
                            ? Math.Round(analysisResults.Average(r => r.Confidence), 2)
                            : 0
                    },

                    ThreatAlerts = threatAlerts.Select(a => new
                    {
                        Timestamp = a.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        a.Severity,
                        a.Type,
                        a.IpAddress,
                        a.Description,
                        a.AdditionalInfo
                    }).ToList(),

                    AnalysisResults = analysisResults.Select(r => new
                    {
                        r.Category,
                        r.RiskLevel,
                        r.Description,
                        r.Details,
                        r.Confidence
                    }).ToList(),

                    ChainOfCustody = hashes.Select(h => new
                    {
                        h.EvidenceType,
                        h.Algorithm,
                        h.HashValue,
                        Timestamp = h.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                    }).ToList()
                }
            };

            string jsonBody = JsonSerializer.Serialize(reportBody, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            string reportHash = ComputeSHA256(jsonBody);

            var finalJson = new
            {
                ReportHash = new
                {
                    Algorithm = "SHA-256",
                    Value = reportHash
                },
                Report = reportBody
            };

            File.WriteAllText(
                filePath,
                JsonSerializer.Serialize(finalJson, new JsonSerializerOptions { WriteIndented = true })
            );
        }

        #endregion

        #region Helper Methods

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }
        private static string ComputeSHA256(string content)
        {
            using var sha256 = SHA256.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(content);
            byte[] hash = sha256.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
        private static string ComputeSHA256FromFile(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            byte[] hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private void EnsureReportDirectories()
        {
            Directory.CreateDirectory(HtmlReportDirectory);
            Directory.CreateDirectory(JsonReportDirectory);
        }

        private void ComputeRiskAndMitreFromFindings()
        {
            var risk = RiskCalculator.ComputeUiRisk(_analysisResults);
            _currentCvssScore = risk.Score;
            _currentCvssRating = risk.Rating;
            _currentMitreTechniques = risk.MitreTechniques;
        }

        private static string HtmlSafe(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return System.Net.WebUtility.HtmlEncode(s);
        }

        #endregion

        #region Window Control Events

        private void TitleBar_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            try
            {
                if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed)
                {
                    this.DragMove();
                }
            }
            catch (InvalidOperationException)
            {
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        {
            if (this.WindowState == WindowState.Maximized)
            {
                this.WindowState = WindowState.Normal;
                MaximizeButton.ToolTip = "Maximize";
            }
            else
            {
                this.WindowState = WindowState.Maximized;
                MaximizeButton.ToolTip = "Restore";
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            var shouldClose = DialogService.ShowConfirm(
                this,
                "Confirm Exit",
                "Are you sure you want to exit the application?"
            );

            if (shouldClose)
            {
                this.Close();
            }
        }

        #endregion

        #region Window Events

        protected override void OnClosed(EventArgs e)
        {
            _clockTimer?.Stop();
            base.OnClosed(e);
        }

        #endregion

    }


}
