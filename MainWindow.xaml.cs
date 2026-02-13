using Microsoft.Win32;
using Multi_Layer_Spoofing_Detector.data;
using Multi_Layer_Spoofing_Detector.Models;
using Multi_Layer_Spoofing_Detector.Risk;
using Multi_Layer_Spoofing_Detector.Services;
using LiveCharts;
using LiveCharts.Wpf;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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
            System.IO.Path.Combine(_settings.DataRootDirectory, "reports");

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
        private readonly AppRuntimeSettings _settings;
        private bool _isDarkMode = true;
        private DateTime _captureStartTime = DateTime.Now;

        public MainWindow()
        {
            InitializeComponent();
            _settings = AppSettingsService.Load();
            _settings.AutoRunAfterUpload = false;
            AutoRunCheckBox.IsChecked = false;
            ApplyTheme(_isDarkMode);
            InitializeTimers();
            InitializeMLIntegration();
            LoadRecentCases();
            UpdateDateTime();
        }

        #region ML Integration
        private void InitializeMLIntegration()
        {
            try
            {
                var preflight = RunPreflightCheck();
                if (!preflight.Ok)
                    throw new Exception(preflight.Message);

                _mlIntegration = new MLIntegration(
                    _settings.MlDockerImage,
                    _settings.CicFlowMeterImage,
                    _settings.AnalysisTimeoutMs);
                _isMlIntegrationReady = true;

                AnalysisModuleDetails.Text = preflight.Message;
                AnalysisModuleDetails.Foreground =
                    (SolidColorBrush)FindResource("SafeBrush");
                OperationalStatusText.Text = "● Platform ready — no active analysis";
                AppLogger.Info("Environment preflight passed.");
            }
            catch (Exception ex)
            {
                _isMlIntegrationReady = false;
                AnalysisModuleDetails.Text = "✗ Environment check failed";
                AnalysisModuleDetails.Foreground =
                    (SolidColorBrush)FindResource("CriticalBrush");

                AnalyzeBtn.IsEnabled = false;
                OperationalStatusText.Text = "● Environment check failed";
                AnalysisModuleDetails.Text = ex.Message;
                AppLogger.Error($"Environment preflight failed: {ex.Message}");

                DialogService.ShowError(
                    this,
                    "Environment Error",
                    ex.Message
                );
            }
        }

        private (bool Ok, string Message) RunPreflightCheck()
        {
            var statuses = new List<string>();

            bool dockerInstalled = DockerChecker.IsDockerInstalled(out var dockerError);
            statuses.Add($"Docker Installed: {(dockerInstalled ? "PASS" : "FAIL")}");
            if (!dockerInstalled) return (false, string.Join("\n", statuses) + $"\n{dockerError}");

            bool dockerRunning = DockerChecker.IsDockerRunning(out dockerError);
            statuses.Add($"Docker Running: {(dockerRunning ? "PASS" : "FAIL")}");
            if (!dockerRunning) return (false, string.Join("\n", statuses) + $"\n{dockerError}");

            bool mlImage = DockerChecker.IsDockerImageAvailable(_settings.MlDockerImage, out dockerError);
            statuses.Add($"ML Image ({_settings.MlDockerImage}): {(mlImage ? "PASS" : "FAIL")}");
            if (!mlImage) return (false, string.Join("\n", statuses) + $"\n{dockerError}");

            bool cicImage = DockerChecker.IsDockerImageAvailable(_settings.CicFlowMeterImage, out dockerError);
            statuses.Add($"CICFlowMeter Image ({_settings.CicFlowMeterImage}): {(cicImage ? "PASS" : "FAIL")}");
            if (!cicImage) return (false, string.Join("\n", statuses) + $"\n{dockerError}");

            string dbDir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MLSD", "database");
            Directory.CreateDirectory(dbDir);
            statuses.Add("Database Path Writable: PASS");

            return (true, string.Join("\n", statuses));
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
            SolidColorBrush statusColor;
            if (_currentCvssScore >= 9.0)
            {
                statusColor = (SolidColorBrush)FindResource("CriticalBrush");
            }
            else if (_currentCvssScore >= 7.0)
            {
                statusColor = (SolidColorBrush)FindResource("WarningBrush");
            }
            else
            {
                statusColor = (SolidColorBrush)FindResource("SafeBrush");
            }

            NetworkStatusText.Text = $"{_currentCvssScore:0.0}";
            NetworkStatusIcon.Text = "●";
            NetworkStatusIndicator.Background = statusColor;

            CvssScoreText.Text = $"{_currentCvssScore:0.0}";
            CvssRatingText.Text = string.Empty;
            NetworkRiskBadge.Text = "● CVSS-based network risk index";

            MitreBullets.ItemsSource = _currentMitreTechniques ?? new List<string> { "No findings" };

            LastScanText.Text = _lastAnalysisTime == default ? "Last scan: —" : $"Last scan: {_lastAnalysisTime:HH:mm:ss}";
            UpdateCvssLevelIndicators();
        }

        private void UpdateCvssLevelIndicators()
        {
            SetCvssLevelOpacity("CvssLevelLow", _currentCvssScore > 0 ? 1.0 : 0.35);
            SetCvssLevelOpacity("CvssLevelMedium", _currentCvssScore >= 4.0 ? 1.0 : 0.35);
            SetCvssLevelOpacity("CvssLevelHigh", _currentCvssScore >= 7.0 ? 1.0 : 0.35);
            SetCvssLevelOpacity("CvssLevelCritical", _currentCvssScore >= 9.0 ? 1.0 : 0.35);
        }

        private void SetCvssLevelOpacity(string elementName, double opacity)
        {
            if (FindName(elementName) is Border levelBorder)
            {
                levelBorder.Opacity = opacity;
            }
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
                _captureStartTime = DateTime.Now;
                FileInfo fileInfo = new FileInfo(_currentPcapFilePath);

                long maxBytes = (long)_settings.MaxPcapSizeMb * 1024 * 1024;
                if (_settings.MaxPcapSizeMb > 0 && fileInfo.Length > maxBytes)
                {
                    DialogService.ShowWarning(
                        this,
                        "Large PCAP File",
                        $"Selected file is {FormatFileSize(fileInfo.Length)}.\n\n" +
                        $"Configured max file size is {_settings.MaxPcapSizeMb} MB to avoid UI stalls and timeout issues."
                    );

                    AnalyzeBtn.IsEnabled = false;
                    FileInfoPanel.Visibility = Visibility.Collapsed;
                    UploadModuleStatus.Text = "✗ File exceeds configured size limit";
                    UploadModuleStatus.Foreground = (SolidColorBrush)FindResource("CriticalBrush");
                    return;
                }

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

                ReportModuleStatus.Text = "⏸  PCAP uploaded. Run the pipeline to enable reports.";
                ReportModuleStatus.Foreground = (SolidColorBrush)FindResource("WarningBrush");

                DialogService.ShowSuccess(
                    this,
                    "File Upload",
                    "PCAP file uploaded successfully to File Upload."
                );

                AppLogger.Info($"PCAP uploaded: {_currentPcapFilePath}");

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
                AppLogger.Info($"Analysis started for file: {_currentPcapFilePath}");

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

                ArpDetectionIndicator.Fill = (SolidColorBrush)FindResource("ProtocolArpBrush");
                await Task.Delay(800);

                DnsDetectionIndicator.Fill = (SolidColorBrush)FindResource("ProtocolDnsBrush");
                await Task.Delay(800);

                IpDetectionIndicator.Fill = (SolidColorBrush)FindResource("ProtocolIpBrush");
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

                UpdateDetectionLayerStatus();
                UpdateAlertsDisplay();

                UpdateNetworkStatus();
                UpdateAnalysisResultsDisplay();
                UpdateReportSummary();
                ReportModuleStatus.Text = $"✓ Analysis run complete. Case: {_currentCaseId} | Findings: {_analysisResults.Count}";
                ReportModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");

                AnalyzeBtn.IsEnabled = true;

                AppLogger.Info($"Analysis completed. Findings: {_analysisResults.Count}, Alerts: {_threatAlerts.Count}");

                DialogService.ShowSuccess(
                    this,
                    "Analysis Complete",
                    $"Multi-Layer Spoofing Detection Complete!\n\n" +
                    $"✓ File Upload: Success\n" +
                    $"✓ Packet Analysis: {_analysisResults.Count} findings\n" +
                    $"✓ Detection: {_threatAlerts.Count} threats identified\n" +
                    $"✓ Results Display: Ready\n\n" +
                    $"Results are now available in the Results Display Module."
                );
            }
            catch (Exception ex)
            {
                LoadingOverlay.Visibility = Visibility.Collapsed;
                AnalyzeBtn.IsEnabled = true;

                AnalysisModuleStatus.Text = "✗ Analysis failed";
                AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("CriticalBrush");

                AppLogger.Error($"Analysis failed: {ex.Message}");

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
                if (threat.Confidence < _settings.MinAlertConfidence)
                {
                    continue;
                }

                var result = new AnalysisResult
                {
                    Category = "ARP",
                    RiskLevel = threat.Confidence >= _settings.HighConfidenceThreshold ? "High" : (threat.Confidence >= _settings.MediumConfidenceThreshold ? "Medium" : "Low"),
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
                    AdditionalInfo = $"Confidence={threat.Confidence:F2}% | Rule: confidence >= {_settings.MinAlertConfidence}%"
                };
                _threatAlerts.Add(alert);
            }

            foreach (var threat in mlResult.Dns_Spoofing)
            {
                if (threat.Confidence < _settings.MinAlertConfidence)
                {
                    continue;
                }

                var result = new AnalysisResult
                {
                    Category = "DNS",
                    RiskLevel = threat.Confidence >= _settings.HighConfidenceThreshold ? "High" : (threat.Confidence >= _settings.MediumConfidenceThreshold ? "Medium" : "Low"),
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
                    AdditionalInfo = $"Confidence={threat.Confidence:F2}% | Rule: confidence >= {_settings.MinAlertConfidence}%"
                };
                _threatAlerts.Add(alert);
            }

            foreach (var threat in mlResult.Ip_Spoofing)
            {
                if (threat.Confidence < _settings.MinAlertConfidence)
                {
                    continue;
                }

                var result = new AnalysisResult
                {
                    Category = "IP",
                    RiskLevel = threat.Confidence >= _settings.HighConfidenceThreshold ? "High" : (threat.Confidence >= _settings.MediumConfidenceThreshold ? "Medium" : "Low"),
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
                    AdditionalInfo = $"Confidence={threat.Confidence:F2}% | Rule: confidence >= {_settings.MinAlertConfidence}%"
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
                    AdditionalInfo = $"Total packets analyzed: {mlResult.Total_Packets} | No alert met threshold ({_settings.MinAlertConfidence}%)"
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

                AppLogger.Info($"HTML report generated: {fullPath}");

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

                AppLogger.Info($"JSON report generated: {fullPath}");

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

        private void RunPreflightCheckBtn_Click(object sender, RoutedEventArgs e)
        {
            var preflight = RunPreflightCheck();
            AnalysisModuleDetails.Text = preflight.Message;

            if (preflight.Ok)
            {
                _mlIntegration = new MLIntegration(
                    _settings.MlDockerImage,
                    _settings.CicFlowMeterImage,
                    _settings.AnalysisTimeoutMs);
                _isMlIntegrationReady = true;
                AnalyzeBtn.IsEnabled = true;
                OperationalStatusText.Text = "● Platform ready — no active analysis";
                DialogService.ShowSuccess(this, "Preflight Check", "Environment is ready.");
                AppLogger.Info("Manual preflight check passed.");
            }
            else
            {
                _isMlIntegrationReady = false;
                AnalyzeBtn.IsEnabled = false;
                OperationalStatusText.Text = "● Environment check failed";
                DialogService.ShowWarning(this, "Preflight Check", preflight.Message);
                AppLogger.Error($"Manual preflight check failed: {preflight.Message}");
            }
        }

        private void AutoRunCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            _settings.AutoRunAfterUpload = false;
            AutoRunCheckBox.IsChecked = false;
            AppSettingsService.Save(_settings);
            AppLogger.Info("Auto-run after upload is disabled; manual pipeline execution required.");
        }

        private void ThemeToggleButton_Click(object sender, RoutedEventArgs e)
        {
            _isDarkMode = !_isDarkMode;
            ApplyTheme(_isDarkMode);
        }

        private void ApplyTheme(bool darkMode)
        {
            var legendBg = (Color)ColorConverter.ConvertFromString(darkMode ? "#091628" : "#EAF2FB");
            var legendBorder = (Color)ColorConverter.ConvertFromString(darkMode ? "#1A3355" : "#B8CCE4");
            var contentBg = (Color)ColorConverter.ConvertFromString(darkMode ? "#00000000" : "#F7FBFF");

            LegendBarBorder.Background = new SolidColorBrush(legendBg);
            LegendBarBorder.BorderBrush = new SolidColorBrush(legendBorder);
            MainContentGrid.Background = new SolidColorBrush(contentBg);
            MainContentScrollViewer.Background = new SolidColorBrush(contentBg);

            ThemeToggleButton.Content = darkMode ? "☀ Light" : "🌙 Dark";
            AppLogger.Info($"Theme switched to {(darkMode ? "dark" : "light")} mode.");
        }

        private void ExportEvidenceBundleBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_currentCaseId))
                {
                    DialogService.ShowWarning(this, "No Case Available", "Analyze a PCAP first before exporting evidence bundle.");
                    return;
                }

                EnsureReportDirectories();

                string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string htmlPath = System.IO.Path.Combine(HtmlReportDirectory, $"ForensicReport_{stamp}.html");
                string jsonPath = System.IO.Path.Combine(JsonReportDirectory, $"ForensicReport_{stamp}.json");

                GenerateForensicReportHTML(htmlPath);
                GenerateForensicReportJSON(jsonPath);

                string bundleDir = System.IO.Path.Combine(BaseReportDirectory, "bundle");
                Directory.CreateDirectory(bundleDir);
                string zipPath = System.IO.Path.Combine(bundleDir, $"EvidenceBundle_{_currentCaseId}_{stamp}.zip");

                if (File.Exists(zipPath)) File.Delete(zipPath);
                using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);
                archive.CreateEntryFromFile(htmlPath, System.IO.Path.GetFileName(htmlPath));
                archive.CreateEntryFromFile(jsonPath, System.IO.Path.GetFileName(jsonPath));

                DialogService.ShowSuccess(this, "Evidence Bundle", $"Evidence bundle exported successfully.\n\nLocation:\n{zipPath}");
                AppLogger.Info($"Evidence bundle exported: {zipPath}");
            }
            catch (Exception ex)
            {
                DialogService.ShowError(this, "Export Error", $"Error creating evidence bundle:\n{ex.Message}");
                AppLogger.Error($"Evidence bundle export failed: {ex.Message}");
            }
        }

        private void OpenReportsFolderBtn_Click(object sender, RoutedEventArgs e)
        {
            EnsureReportDirectories();
            Process.Start(new ProcessStartInfo
            {
                FileName = BaseReportDirectory,
                UseShellExecute = true
            });
        }

        private void OpenLogsFolderBtn_Click(object sender, RoutedEventArgs e)
        {
            string logDir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "MLSD",
                "logs");
            Directory.CreateDirectory(logDir);

            Process.Start(new ProcessStartInfo
            {
                FileName = logDir,
                UseShellExecute = true
            });
        }

        private void RefreshRecentCasesBtn_Click(object sender, RoutedEventArgs e)
        {
            LoadRecentCases();
        }

        private void LoadRecentCases()
        {
            try
            {
                var recentCases = _repo.GetRecentCases(8);
                RecentCasesList.ItemsSource = recentCases
                    .Select(c => $"{c.AnalysisTime:yyyy-MM-dd HH:mm:ss} | {c.CaseId} | {c.PcapFile} | {c.NetworkStatus}")
                    .ToList();
            }
            catch (Exception ex)
            {
                AppLogger.Error($"Failed to load recent cases: {ex.Message}");
                RecentCasesList.ItemsSource = new List<string>
                {
                    "Unable to load recent cases."
                };
            }
        }

        #endregion

        #region UI Update Methods

        private void UpdateDetectionLayerStatus()
        {
            int arpFindings = _analysisResults.Count(r => r.Category == "ARP" && r.RiskLevel != "Low");
            int dnsFindings = _analysisResults.Count(r => r.Category == "DNS" && r.RiskLevel != "Low");
            int ipFindings = _analysisResults.Count(r => r.Category == "IP" && r.RiskLevel != "Low");

            ArpThreatCount.Text = arpFindings.ToString();
            DnsThreatCount.Text = dnsFindings.ToString();
            IpThreatCount.Text = ipFindings.ToString();

            ArpLayerStatus.Text = arpFindings > 0 ? "ANOMALY" : "NORMAL";
            DnsLayerStatus.Text = dnsFindings > 0 ? "ANOMALY" : "NORMAL";
            IpLayerStatus.Text = ipFindings > 0 ? "ANOMALY" : "NORMAL";

            ArpDetectionIndicator.Fill = arpFindings > 0
                ? (SolidColorBrush)FindResource("CriticalBrush")
                : (SolidColorBrush)FindResource("ProtocolArpBrush");
            DnsDetectionIndicator.Fill = dnsFindings > 0
                ? (SolidColorBrush)FindResource("CriticalBrush")
                : (SolidColorBrush)FindResource("ProtocolDnsBrush");
            IpDetectionIndicator.Fill = ipFindings > 0
                ? (SolidColorBrush)FindResource("CriticalBrush")
                : (SolidColorBrush)FindResource("ProtocolIpBrush");
        }

        private void UpdateReportSummary()
        {
            int packets = _reports.Any() ? _reports[0].PacketsAnalyzed : 0;
            int critical = _threatAlerts.Count(a => a.Severity == "Critical");
            int warnings = _threatAlerts.Count(a => a.Severity == "Warning");
            var elapsedSeconds = Math.Max(1, (_lastAnalysisTime == default ? 1 : (_lastAnalysisTime - _captureStartTime).TotalSeconds));
            var avgPktRate = packets / elapsedSeconds;

            TotalThreatsText.Text = $"{_threatAlerts.Count} threats detected";
            CriticalAlertsText.Text = critical.ToString();
            PacketsAnalyzedText.Text = packets.ToString("N0");
            PktRateText.Text = $"{avgPktRate:0.#} pkt/s avg";

            InsightsText.Text =
                $"Current CVSS score: {_currentCvssScore:0.0}. " +
                $"Detected alerts: {critical} critical, {warnings} warning. " +
                "Action: prioritize high-confidence anomalies and export evidence bundle for documentation.";

            UpdateAnalyticsVisuals(packets, avgPktRate, critical, warnings);
        }

        private void UpdateAnalyticsVisuals(int packets, double avgPktRate, int critical, int warnings)
        {
            int arpAnomalies = _analysisResults.Count(r => r.Category.Equals("ARP", StringComparison.OrdinalIgnoreCase) && r.RiskLevel != "Low");
            int dnsAnomalies = _analysisResults.Count(r => r.Category.Equals("DNS", StringComparison.OrdinalIgnoreCase) && r.RiskLevel != "Low");
            int ipAnomalies = _analysisResults.Count(r => r.Category.Equals("IP", StringComparison.OrdinalIgnoreCase) && r.RiskLevel != "Low");

            var uniqueIps = _threatAlerts.Select(a => a.IpAddress).Where(ip => !string.IsNullOrWhiteSpace(ip) && ip != "System").Distinct().Count();
            var captureMinutes = Math.Max(1, (_lastAnalysisTime == default ? 1 : (_lastAnalysisTime - _captureStartTime).TotalMinutes));

            StatAvgPktRate.Text = avgPktRate.ToString("0.#");
            StatUniqueIPs.Text = uniqueIps.ToString("N0");
            StatArpAnomalies.Text = arpAnomalies.ToString();
            StatDnsAnomalies.Text = dnsAnomalies.ToString();
            StatIpAnomalies.Text = ipAnomalies.ToString();
            StatCaptureMins.Text = captureMinutes.ToString("0");

            ThreatTimelineChart.Series = new SeriesCollection
            {
                new LineSeries
                {
                    Title = "Total",
                    Values = new ChartValues<int> { Math.Max(0, packets / 5), Math.Max(0, packets / 4), Math.Max(0, packets / 3), Math.Max(0, packets / 2), packets },
                    Stroke = (SolidColorBrush)FindResource("InfoBrush"),
                    Fill = Brushes.Transparent,
                    PointGeometry = null
                },
                new LineSeries
                {
                    Title = "Flagged",
                    Values = new ChartValues<int> { Math.Max(0, (critical + warnings) / 5), Math.Max(0, (critical + warnings) / 4), Math.Max(0, (critical + warnings) / 3), Math.Max(0, (critical + warnings) / 2), critical + warnings },
                    Stroke = (SolidColorBrush)FindResource("CritBrush"),
                    Fill = Brushes.Transparent,
                    PointGeometry = null
                }
            };
            TimelineAxisX.Labels = new[] { "-4", "-3", "-2", "-1", "now" };

            int arpTotal = _analysisResults.Count(r => r.Category == "ARP");
            int dnsTotal = _analysisResults.Count(r => r.Category == "DNS");
            int ipTotal = _analysisResults.Count(r => r.Category == "IP");
            int protocolTotal = Math.Max(1, arpTotal + dnsTotal + ipTotal);

            ArpPctText.Text = $"{(arpTotal * 100.0 / protocolTotal):0.#}%";
            DnsPctText.Text = $"{(dnsTotal * 100.0 / protocolTotal):0.#}%";
            IpPctText.Text = $"{(ipTotal * 100.0 / protocolTotal):0.#}%";

            ProtocolPieChart.Series = new SeriesCollection
            {
                new PieSeries { Title = "ARP", Values = new ChartValues<double> { Math.Max(0, arpTotal) }, Fill = (SolidColorBrush)FindResource("ArpBrush"), DataLabels = false },
                new PieSeries { Title = "DNS", Values = new ChartValues<double> { Math.Max(0, dnsTotal) }, Fill = (SolidColorBrush)FindResource("DnsBrush"), DataLabels = false },
                new PieSeries { Title = "IP", Values = new ChartValues<double> { Math.Max(0, ipTotal) }, Fill = (SolidColorBrush)FindResource("IpBrush"), DataLabels = false }
            };

            PacketFlowChart.Series = new SeriesCollection
            {
                new ColumnSeries { Title = "ARP", Values = new ChartValues<int> { arpAnomalies }, Fill = (SolidColorBrush)FindResource("ArpBrush") },
                new ColumnSeries { Title = "DNS", Values = new ChartValues<int> { dnsAnomalies }, Fill = (SolidColorBrush)FindResource("DnsBrush") },
                new ColumnSeries { Title = "IP", Values = new ChartValues<int> { ipAnomalies }, Fill = (SolidColorBrush)FindResource("IpBrush") }
            };

            var av = Math.Min(10, _currentCvssScore * 0.9);
            var ac = Math.Min(10, 10 - (_currentCvssScore * 0.5));
            var imp = Math.Min(10, _currentCvssScore);
            var exp = Math.Min(10, _currentCvssScore * 0.8);

            CvssAvText.Text = av.ToString("0.0");
            CvssAcText.Text = ac.ToString("0.0");
            CvssImpText.Text = imp.ToString("0.0");
            CvssExpText.Text = exp.ToString("0.0");

            CvssAvBar.Width = av * 12;
            CvssAcBar.Width = ac * 12;
            CvssImpBar.Width = imp * 12;
            CvssExpBar.Width = exp * 12;
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
            string borderColor = alert.Severity switch
            {
                "Critical" => "CriticalBrush",
                "Warning" => "WarningBrush",
                "Safe" => "SafeBrush",
                _ => "SubTextBrush"
            };

            var border = new Border
            {
                Background = (SolidColorBrush)FindResource("BgBase"),
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
            contentPanel.Children.Add(titleText);
            contentPanel.Children.Add(descText);

            var explainability = new Expander
            {
                Header = "Explainability",
                Margin = new Thickness(0, 4, 0, 0),
                Foreground = (SolidColorBrush)FindResource("TextBrush")
            };

            var explainabilityText = new TextBlock
            {
                Text = alert.AdditionalInfo,
                Style = (Style)FindResource("SubTextStyle"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0)
            };

            explainability.Content = explainabilityText;
            contentPanel.Children.Add(explainability);
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
            string riskIcon = result.RiskLevel switch
            {
                "High" => "🔴",
                "Medium" => "🟡",
                "Low" => "🟢",
                _ => "⚪"
            };

            double cvScore = result.RiskLevel switch
            {
                "High" => 9.3,
                "Medium" => 6.5,
                "Low" => 3.1,
                _ => 0.0
            };
            cvScore = Math.Round(cvScore * Math.Clamp(result.Confidence / 100.0, 0.0, 1.0), 1);

            var border = new Border
            {
                Background = (SolidColorBrush)FindResource("BgBase"),
                BorderBrush = result.RiskLevel == "High"
                    ? (SolidColorBrush)FindResource("CriticalBrush")
                    : result.RiskLevel == "Medium"
                        ? (SolidColorBrush)FindResource("WarningBrush")
                        : (SolidColorBrush)FindResource("SafeBrush"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 4, 0, 0)
            };

            var panel = new StackPanel();

            var titleText = new TextBlock
            {
                Text = $"{riskIcon} CV Score {cvScore:0.0} - {result.Description}",
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
                Text = $"Model confidence: {result.Confidence}%",
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

            double AlertCvss(ThreatAlert a) => a.Severity == "Critical" ? 9.2 : (a.Severity == "Warning" ? 6.4 : 2.8);

            string threatRows = threatAlerts.Any()
                ? string.Join("", threatAlerts.Select(alert => $@"
<tr>
    <td>{alert.Timestamp:yyyy-MM-dd HH:mm:ss}</td>
    <td>{AlertCvss(alert):0.0}</td>
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
  <p class='riskTitle'>System Risk (CVSS Score)</p>
  <div class='riskScore'>
    <span class='scoreBadge cvss-{riskClass}'>CVSS Score: {risk.Score:0.0}</span>
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
  <div class='card'><b>CVSS Score</b><br/>{risk.Score:0.0}</div>
  <div class='card'><b>Total Threats</b><br/>{threatAlerts.Count}</div>
  <div class='card'><b>Flows</b><br/>{totalPackets:N0}</div>
  <div class='card safe'><b>Confidence</b><br/>{avgConfidence}%</div>
</div>
<p><b>CVSS Rating Legend:</b> Low 0.1-3.9 | Medium 4.0-6.9 | High 7.0-8.9 | Critical 9.0-10.0</p>

<h2>Detected Threat Alerts</h2>
<table class='table'>
<thead>
<tr>
  <th>Timestamp</th>
  <th>CVSS Score</th>
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
                        CvssRatingLegend = "Low 0.1-3.9 | Medium 4.0-6.9 | High 7.0-8.9 | Critical 9.0-10.0",
                        Summary = risk.SummaryBullets,
                        MitreAttack = risk.MitreItems
                    },

                    ExecutiveSummary = new
                    {
                        CvssScore = risk.Score,
                        TotalThreats = threatAlerts.Count,
                        TotalFlows = caseMeta.PacketsAnalyzed,
                        CvssRatingLegend = "Low 0.1-3.9 | Medium 4.0-6.9 | High 7.0-8.9 | Critical 9.0-10.0",
                        AverageConfidence = analysisResults.Any()
                            ? Math.Round(analysisResults.Average(r => r.Confidence), 2)
                            : 0
                    },

                    ThreatAlerts = threatAlerts.Select(a => new
                    {
                        Timestamp = a.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        CvssScore = a.Severity == "Critical" ? 9.2 : (a.Severity == "Warning" ? 6.4 : 2.8),
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
                AppLogger.Info("Application closing by user confirmation.");
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
