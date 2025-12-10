using Microsoft.Win32;
using System.IO;
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

        // Data structures for simulations
        private List<ThreatAlert> _threatAlerts = new List<ThreatAlert>();
        private List<AnalysisResult> _analysisResults = new List<AnalysisResult>();
        private List<Report> _reports = new List<Report>();
        private Random _random = new Random();

        // Network status tracking
        private string _currentNetworkStatus = "SECURE";
        private DateTime _lastThreatTime = DateTime.MinValue;

        public MainWindow()
        {
            InitializeComponent();
            InitializeTimers();
            InitializeSimulationData();
            UpdateDateTime();
            PopulateInitialData();
        }

        #region Data Models
        public class ThreatAlert
        {
            public string Type { get; set; }
            public string Description { get; set; }
            public DateTime Timestamp { get; set; }
            public string Severity { get; set; } // Critical, Warning, Safe
            public string IpAddress { get; set; }
            public string AdditionalInfo { get; set; }
        }

        public class AnalysisResult
        {
            public string Category { get; set; } // ARP, DNS, IP
            public string RiskLevel { get; set; } // High, Medium, Low
            public string Description { get; set; }
            public string Details { get; set; }
            public int Confidence { get; set; }
        }

        public class Report
        {
            public string Name { get; set; }
            public DateTime Timestamp { get; set; }
            public string Status { get; set; }
            public int ThreatsDetected { get; set; }
            public int PacketsAnalyzed { get; set; }
        }
        #endregion

        #region Initialization
        private void InitializeTimers()
        {
            // Timer for updating date/time display
            _clockTimer = new DispatcherTimer();
            _clockTimer.Interval = TimeSpan.FromSeconds(1);
            _clockTimer.Tick += ClockTimer_Tick;
            _clockTimer.Start();
        }

        private void InitializeSimulationData()
        {
            // Initialize with some sample analysis results
            _analysisResults.AddRange(new[]
            {
                new AnalysisResult
                {
                    Category = "ARP",
                    RiskLevel = "High",
                    Description = "MAC Address Conflict Detected",
                    Details = "IP: 192.168.1.100 | MAC: AA:BB:CC:DD:EE:FF",
                    Confidence = 95
                },
                new AnalysisResult
                {
                    Category = "ARP",
                    RiskLevel = "Medium",
                    Description = "Unusual ARP Frequency",
                    Details = "IP: 192.168.1.50 | MAC: 11:22:33:44:55:66",
                    Confidence = 72
                },
                new AnalysisResult
                {
                    Category = "DNS",
                    RiskLevel = "Medium",
                    Description = "DNS Response Anomaly",
                    Details = "Domain: suspicious-site.com | Redirected IP: 10.0.0.1",
                    Confidence = 68
                },
                new AnalysisResult
                {
                    Category = "IP",
                    RiskLevel = "Low",
                    Description = "Normal Traffic Pattern",
                    Details = "No IP spoofing detected in current session",
                    Confidence = 99
                }
            });

            // Initialize with sample reports
            _reports.AddRange(new[]
            {
                new Report
                {
                    Name = $"Report_{DateTime.Now.ToString("yyyy-MM-dd_HH-mm")}",
                    Timestamp = DateTime.Now.AddMinutes(-30),
                    Status = "Complete",
                    ThreatsDetected = 3,
                    PacketsAnalyzed = 1247
                },
                new Report
                {
                    Name = $"Report_{DateTime.Now.AddHours(-1).ToString("yyyy-MM-dd_HH-mm")}",
                    Timestamp = DateTime.Now.AddHours(-1),
                    Status = "Complete",
                    ThreatsDetected = 1,
                    PacketsAnalyzed = 892
                },
                new Report
                {
                    Name = $"Report_{DateTime.Now.AddHours(-2).ToString("yyyy-MM-dd_HH-mm")}",
                    Timestamp = DateTime.Now.AddHours(-2),
                    Status = "Complete",
                    ThreatsDetected = 0,
                    PacketsAnalyzed = 654
                }
            });
        }

        private void PopulateInitialData()
        {
            // Start with clean slate - no initial data
            // Module starts in ready state
            UpdateAnalysisResultsDisplay();
            UpdateNetworkStatus();
        }

        private void UpdateDateTime()
        {
            // Initial date/time update
            if (DateTimeText != null)
            {
                DateTimeText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            }
        }
        #endregion

        #region Timer Events
        private void ClockTimer_Tick(object sender, EventArgs e)
        {
            // Update the date/time display in real-time
            if (DateTimeText != null)
            {
                DateTimeText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            }

            // Update network status periodically (every minute)
            if (DateTime.Now.Second == 0)
            {
                UpdateNetworkStatus();
            }
        }
        #endregion

        #region Network Status Management
        private void UpdateNetworkStatus()
        {
            var criticalThreats = _threatAlerts.Count(a => a.Severity == "Critical" && a.Timestamp > DateTime.Now.AddMinutes(-5));
            var warningThreats = _threatAlerts.Count(a => a.Severity == "Warning" && a.Timestamp > DateTime.Now.AddMinutes(-5));
            var recentThreats = _threatAlerts.Count(a => a.Timestamp > DateTime.Now.AddMinutes(-2));

            string newStatus;
            string statusIcon;
            string statusDescription;
            SolidColorBrush statusColor;

            if (criticalThreats > 0)
            {
                newStatus = "CRITICAL";
                statusIcon = "🚨";
                statusDescription = $"{criticalThreats} critical threat(s) active";
                statusColor = (SolidColorBrush)FindResource("CriticalBrush");
            }
            else if (warningThreats > 1)
            {
                newStatus = "WARNING";
                statusIcon = "⚠️";
                statusDescription = $"{warningThreats} warnings detected";
                statusColor = (SolidColorBrush)FindResource("WarningBrush");
            }
            else if (recentThreats > 0)
            {
                newStatus = "MONITORING";
                statusIcon = "🔍";
                statusDescription = "Monitoring recent activity";
                statusColor = (SolidColorBrush)FindResource("SecondaryAccentBrush");
            }
            else
            {
                newStatus = "SECURE";
                statusIcon = "✅";
                statusDescription = "No threats detected";
                statusColor = (SolidColorBrush)FindResource("SafeBrush");
            }

            // Update UI elements
            NetworkStatusText.Text = newStatus;
            NetworkStatusIcon.Text = statusIcon;
            NetworkStatusDescription.Text = statusDescription;
            NetworkStatusIndicator.Background = statusColor;

            // Update last scan time
            LastScanText.Text = $"Last scan: {DateTime.Now:HH:mm:ss}";

            _currentNetworkStatus = newStatus;
            if (recentThreats > 0 || criticalThreats > 0 || warningThreats > 0)
            {
                _lastThreatTime = DateTime.Now;
            }
        }
        #endregion

        #region Simulation Methods
        private void GenerateAlertsFromAnalysis()
        {
            // Clear existing alerts
            _threatAlerts.Clear();

            // Generate alerts based on the analysis results
            foreach (var result in _analysisResults)
            {
                // Only create alerts for Medium and High risk results
                if (result.RiskLevel == "High" || result.RiskLevel == "Medium")
                {
                    var alert = new ThreatAlert
                    {
                        Type = result.Description,
                        Description = $"{result.Category} {result.Description.ToLower()} detected",
                        Timestamp = DateTime.Now.AddSeconds(-_random.Next(1, 30)), // Slight time variation
                        Severity = result.RiskLevel == "High" ? "Critical" : "Warning",
                        IpAddress = ExtractIPFromDetails(result.Details),
                        AdditionalInfo = $"{result.Details} | Confidence: {result.Confidence}%"
                    };

                    _threatAlerts.Add(alert);
                }
            }

            // If no high/medium risks, add a safe status alert
            if (!_threatAlerts.Any())
            {
                var safeAlert = new ThreatAlert
                {
                    Type = "Network Scan Complete",
                    Description = "Analysis completed with no critical threats detected",
                    Timestamp = DateTime.Now,
                    Severity = "Safe",
                    IpAddress = "System",
                    AdditionalInfo = "Network security status: Normal"
                };

                _threatAlerts.Add(safeAlert);
            }

            // Sort by severity (Critical first, then Warning, then Safe)
            _threatAlerts = _threatAlerts.OrderByDescending(a => a.Severity == "Critical" ? 3 :
                                                              a.Severity == "Warning" ? 2 : 1)
                                       .ThenByDescending(a => a.Timestamp)
                                       .ToList();
        }

        private string ExtractIPFromDetails(string details)
        {
            // Extract IP address from details string, or return a default
            if (details.Contains("IP:"))
            {
                var parts = details.Split('|');
                foreach (var part in parts)
                {
                    if (part.Trim().StartsWith("IP:"))
                    {
                        return part.Trim().Substring(3).Trim();
                    }
                }
            }

            // Return a random IP if not found
            return GenerateRandomIP();
        }

        private string GenerateAlertDescription(string alertType, string ipAddress)
        {
            return alertType switch
            {
                "ARP Spoofing" => $"Suspicious ARP responses detected from {ipAddress}",
                "DNS Spoofing" => $"Suspicious DNS responses from {ipAddress}",
                "IP Spoofing" => $"Potential IP spoofing detected from {ipAddress}",
                "Unusual Traffic Pattern" => $"Abnormal network behavior from {ipAddress}",
                "Port Scanning" => $"Port scanning activity detected from {ipAddress}",
                "MAC Address Conflict" => $"MAC address conflict involving {ipAddress}",
                _ => $"Network anomaly detected from {ipAddress}"
            };
        }

        private string GenerateAdditionalInfo(string alertType, string ipAddress)
        {
            return alertType switch
            {
                "ARP Spoofing" => $"MAC: {GenerateRandomMAC()} | Confidence: {_random.Next(70, 99)}%",
                "DNS Spoofing" => $"Domain: {GenerateRandomDomain()} | Confidence: {_random.Next(60, 95)}%",
                "IP Spoofing" => $"Original IP: {GenerateRandomIP()} | Confidence: {_random.Next(75, 98)}%",
                "Port Scanning" => $"Ports: {_random.Next(1, 65535)}-{_random.Next(1, 65535)} | Confidence: {_random.Next(80, 99)}%",
                _ => $"Packets: {_random.Next(10, 500)} | Confidence: {_random.Next(60, 99)}%"
            };
        }

        private string GenerateRandomMAC()
        {
            return string.Join(":", Enumerable.Range(0, 6)
                .Select(x => _random.Next(0, 256).ToString("X2")));
        }

        private string GenerateRandomIP()
        {
            return $"{_random.Next(192, 194)}.{_random.Next(168, 170)}.{_random.Next(1, 3)}.{_random.Next(1, 255)}";
        }

        private string GenerateRandomDomain()
        {
            string[] domains = { "suspicious-site.com", "fake-bank.net", "malware-host.org", "phishing-site.com", "trojan-server.net" };
            return domains[_random.Next(domains.Length)];
        }
        #endregion

        #region Button Event Handlers
        private void UploadPcapBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // MODULE 1: File Upload Module
                OpenFileDialog openFileDialog = new OpenFileDialog
                {
                    Title = "Select PCAP File - File Upload Module",
                    Filter = "PCAP files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*",
                    FilterIndex = 1,
                    Multiselect = false
                };

                if (openFileDialog.ShowDialog() == true)
                {
                    _currentPcapFilePath = openFileDialog.FileName;
                    FileInfo fileInfo = new FileInfo(_currentPcapFilePath);

                    // Show file info panel
                    FileInfoPanel.Visibility = Visibility.Visible;

                    // Update file information
                    FileNameText.Text = System.IO.Path.GetFileName(_currentPcapFilePath);
                    FileStatusText.Text = "File uploaded - Ready for analysis";
                    StatusIndicator.Fill = (SolidColorBrush)FindResource("SafeBrush");
                    FileSizeText.Text = FormatFileSize(fileInfo.Length);

                    // Update module statuses
                    UploadModuleStatus.Text = "✓ PCAP file loaded successfully";
                    UploadModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");

                    AnalysisModuleStatus.Text = "✓ Ready to process packets";
                    AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");
                    AnalysisModuleDetails.Text = $"File: {System.IO.Path.GetFileName(_currentPcapFilePath)}";

                    // Enable analyze button
                    AnalyzeBtn.IsEnabled = true;

                    MessageBox.Show("PCAP file uploaded successfully to File Upload Module!",
                        "File Upload Module", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                UploadModuleStatus.Text = "✗ Upload failed";
                UploadModuleStatus.Foreground = (SolidColorBrush)FindResource("CriticalBrush");

                MessageBox.Show($"Error in File Upload Module: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void AnalyzeBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Disable analyze button and show loading overlay
                AnalyzeBtn.IsEnabled = false;
                LoadingOverlay.Visibility = Visibility.Visible;

                // MODULE 2: Packet Analysis Module
                LoadingProgressText.Text = "MODULE 2: Packet Analysis - Parsing packets...";
                await Task.Delay(1500);

                LoadingProgressText.Text = "Extracting features using Python (Scapy, PyShark)...";
                AnalysisModuleStatus.Text = "⚙ Processing packets...";
                AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("SecondaryAccentBrush");
                await Task.Delay(2000);

                LoadingProgressText.Text = "Transforming raw packet data to structured info...";
                await Task.Delay(1500);

                // MODULE 3: Detection Module
                LoadingProgressText.Text = "MODULE 3: Detection - Running AI model...";
                DetectionModuleStatus.Text = "Status: AI Model Running";
                DetectionModuleStatus.Foreground = (SolidColorBrush)FindResource("PrimaryAccentBrush");

                // Activate detection indicators
                ArpDetectionIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");
                await Task.Delay(1200);

                LoadingProgressText.Text = "Detecting ARP spoofing...";
                await Task.Delay(1000);

                DnsDetectionIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");
                LoadingProgressText.Text = "Detecting DNS spoofing...";
                await Task.Delay(1000);

                IpDetectionIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");
                LoadingProgressText.Text = "Detecting IP spoofing...";
                await Task.Delay(1000);

                LoadingProgressText.Text = "Computing threat confidence scores...";
                await Task.Delay(1500);

                // Generate analysis results
                GenerateAnalysisResults();

                // Generate alerts based on analysis
                GenerateAlertsFromAnalysis();

                // Generate a new report
                GenerateNewReport();

                // MODULE 4: Results Display Module
                LoadingProgressText.Text = "MODULE 4: Results Display - Preparing outputs...";
                await Task.Delay(1000);

                // Analysis complete - hide loading overlay
                LoadingOverlay.Visibility = Visibility.Collapsed;

                // Update file status
                FileStatusText.Text = "Analysis complete - Results available";
                StatusIndicator.Fill = (SolidColorBrush)FindResource("PrimaryAccentBrush");

                // Update module statuses
                AnalysisModuleStatus.Text = "✓ Packet analysis completed";
                AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");
                AnalysisModuleDetails.Text = "All features extracted successfully";

                DetectionModuleStatus.Text = "Status: Detection Complete";
                DetectionModuleStatus.Foreground = (SolidColorBrush)FindResource("SafeBrush");

                // Update detection indicators
                ArpDetectionIndicator.Fill = (_analysisResults.Any(r => r.Category == "ARP" && r.RiskLevel != "Low")) ?
                    (SolidColorBrush)FindResource("CriticalBrush") : (SolidColorBrush)FindResource("SafeBrush");
                DnsDetectionIndicator.Fill = (_analysisResults.Any(r => r.Category == "DNS" && r.RiskLevel != "Low")) ?
                    (SolidColorBrush)FindResource("WarningBrush") : (SolidColorBrush)FindResource("SafeBrush");
                IpDetectionIndicator.Fill = (_analysisResults.Any(r => r.Category == "IP" && r.RiskLevel != "Low")) ?
                    (SolidColorBrush)FindResource("WarningBrush") : (SolidColorBrush)FindResource("SafeBrush");

                // Update all displays
                UpdateAlertsDisplay();
                UpdateAnalysisResultsDisplay();
                UpdateReportSummary();
                UpdateNetworkStatus();

                // Re-enable analyze button
                AnalyzeBtn.IsEnabled = true;

                // Show results
                MessageBox.Show($"Multi-Layer Spoofing Detection Complete!\n\n" +
                    $"✓ File Upload Module: Success\n" +
                    $"✓ Packet Analysis Module: {_analysisResults.Count} findings\n" +
                    $"✓ Detection Module: {_threatAlerts.Count} threats identified\n" +
                    $"✓ Results Display Module: Ready\n\n" +
                    $"Results are now available in the Results Display Module.",
                    "Analysis Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                LoadingOverlay.Visibility = Visibility.Collapsed;
                AnalyzeBtn.IsEnabled = true;

                AnalysisModuleStatus.Text = "✗ Analysis failed";
                AnalysisModuleStatus.Foreground = (SolidColorBrush)FindResource("CriticalBrush");

                MessageBox.Show($"Error during analysis: {ex.Message}", "Analysis Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateReportSummary()
        {
            // Update summary statistics in Report Generation Module
            TotalThreatsText.Text = _threatAlerts.Count.ToString();
            CriticalAlertsText.Text = _threatAlerts.Count(a => a.Severity == "Critical").ToString();
            PacketsAnalyzedText.Text = _reports.Any() ? _reports[0].PacketsAnalyzed.ToString("N0") : "0";
        }

        private void GenerateAnalysisResults()
        {
            // Clear existing results
            _analysisResults.Clear();

            // Generate random analysis results
            string[] arpThreats = { "MAC Address Spoofing", "ARP Cache Poisoning", "Gratuitous ARP Attack", "ARP Request Flooding" };
            string[] dnsThreats = { "DNS Cache Poisoning", "DNS Hijacking", "DNS Tunneling", "Domain Spoofing" };
            string[] ipThreats = { "IP Address Spoofing", "Source Route Spoofing", "Blind Spoofing", "Non-Blind Spoofing" };

            // Generate ARP results
            for (int i = 0; i < _random.Next(1, 4); i++)
            {
                _analysisResults.Add(new AnalysisResult
                {
                    Category = "ARP",
                    RiskLevel = GetRandomRiskLevel(),
                    Description = arpThreats[_random.Next(arpThreats.Length)],
                    Details = $"IP: {GenerateRandomIP()} | MAC: {GenerateRandomMAC()}",
                    Confidence = _random.Next(60, 99)
                });
            }

            // Generate DNS results
            for (int i = 0; i < _random.Next(1, 3); i++)
            {
                _analysisResults.Add(new AnalysisResult
                {
                    Category = "DNS",
                    RiskLevel = GetRandomRiskLevel(),
                    Description = dnsThreats[_random.Next(dnsThreats.Length)],
                    Details = $"Domain: {GenerateRandomDomain()} | Redirected IP: {GenerateRandomIP()}",
                    Confidence = _random.Next(65, 95)
                });
            }

            // Generate IP results
            for (int i = 0; i < _random.Next(0, 3); i++)
            {
                _analysisResults.Add(new AnalysisResult
                {
                    Category = "IP",
                    RiskLevel = GetRandomRiskLevel(),
                    Description = ipThreats[_random.Next(ipThreats.Length)],
                    Details = $"Source IP: {GenerateRandomIP()} | Target: {GenerateRandomIP()}",
                    Confidence = _random.Next(70, 98)
                });
            }

            // Always add at least one "safe" result if no threats found
            if (!_analysisResults.Any())
            {
                _analysisResults.Add(new AnalysisResult
                {
                    Category = "IP",
                    RiskLevel = "Low",
                    Description = "Normal Traffic Pattern",
                    Details = "No spoofing attacks detected in analyzed packets",
                    Confidence = 99
                });
            }
        }

        private string GetRandomRiskLevel()
        {
            string[] levels = { "High", "Medium", "Low" };
            int[] weights = { 20, 40, 40 }; // 20% High, 40% Medium, 40% Low

            int rand = _random.Next(100);
            if (rand < weights[0]) return levels[0];
            if (rand < weights[0] + weights[1]) return levels[1];
            return levels[2];
        }

        private void GenerateNewReport()
        {
            var newReport = new Report
            {
                Name = $"Report_{DateTime.Now:yyyy-MM-dd_HH-mm}",
                Timestamp = DateTime.Now,
                Status = "Complete",
                ThreatsDetected = _analysisResults.Count(r => r.RiskLevel == "High" || r.RiskLevel == "Medium"),
                PacketsAnalyzed = _random.Next(500, 2000)
            };

            _reports.Insert(0, newReport); // Add to beginning

            // Keep only last 10 reports
            if (_reports.Count > 10)
            {
                _reports.RemoveRange(10, _reports.Count - 10);
            }

            // Update report summary display
            UpdateReportSummary();
        }

        private void OpenFolderBtn_Click(object sender, RoutedEventArgs e)
        {
            OpenCaptureFolder();
        }

        private void ExportCsvBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog
                {
                    Title = "Generate Forensic Report (HTML)",
                    Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*",
                    DefaultExt = "html",
                    FileName = $"ForensicReport_{DateTime.Now:yyyyMMdd_HHmmss}.html"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    GenerateForensicReportHTML(saveFileDialog.FileName);

                    // Ask if user wants to open the report
                    var result = MessageBox.Show($"Forensic report generated successfully!\n\nLocation: {saveFileDialog.FileName}\n\nWould you like to open the report now?",
                        "Report Generated", MessageBoxButton.YesNo, MessageBoxImage.Information);

                    if (result == MessageBoxResult.Yes)
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = saveFileDialog.FileName,
                            UseShellExecute = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error generating HTML report: {ex.Message}", "Export Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportJsonBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog
                {
                    Title = "Generate Forensic Report (JSON)",
                    Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
                    DefaultExt = "json",
                    FileName = $"ForensicReport_{DateTime.Now:yyyyMMdd_HHmmss}.json"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    GenerateForensicReportJSON(saveFileDialog.FileName);

                    MessageBox.Show($"Forensic report generated successfully!\n\nLocation: {saveFileDialog.FileName}",
                        "Report Generated", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error generating JSON report: {ex.Message}", "Export Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region UI Update Methods
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
            // Determine colors based on severity
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

            // Status indicator
            var ellipse = new Ellipse
            {
                Width = 12,
                Height = 12,
                Fill = (SolidColorBrush)FindResource(borderColor),
                Margin = new Thickness(0, 0, 8, 0)
            };
            Grid.SetColumn(ellipse, 0);

            // Content
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

            // Timestamp
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

        private void UpdateReportsDisplay()
        {
            // Reports display removed - now using summary statistics only
            // Report generation happens on-demand via buttons
        }

        private Border CreateReportUI(Report report)
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#333344")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 4, 0, 0)
            };

            var panel = new StackPanel();

            var nameText = new TextBlock
            {
                Text = report.Name,
                Style = (Style)FindResource("RegularTextStyle"),
                FontWeight = FontWeights.Bold
            };

            var statusText = new TextBlock
            {
                Text = $"Status: {report.Status}",
                Style = (Style)FindResource("SubTextStyle")
            };

            var threatsText = new TextBlock
            {
                Text = $"Threats: {report.ThreatsDetected} detected",
                Style = (Style)FindResource("SubTextStyle")
            };

            var packetsText = new TextBlock
            {
                Text = $"Packets: {report.PacketsAnalyzed:N0} analyzed",
                Style = (Style)FindResource("SubTextStyle")
            };

            var timestampText = new TextBlock
            {
                Text = $"Generated: {report.Timestamp:yyyy-MM-dd HH:mm:ss}",
                Style = (Style)FindResource("SubTextStyle")
            };

            panel.Children.Add(nameText);
            panel.Children.Add(statusText);
            panel.Children.Add(threatsText);
            panel.Children.Add(packetsText);
            panel.Children.Add(timestampText);
            border.Child = panel;

            return border;
        }
        #endregion

        #region Forensic Report Generation
        private void GenerateForensicReportHTML(string filePath)
        {
            var reportDate = DateTime.Now;
            var caseInfo = new
            {
                CaseNumber = $"SPOOF-{reportDate:yyyyMMdd-HHmmss}",
                Investigator = Environment.UserName,
                Organization = "AI-Based Spoofing Detection System",
                ReportDate = reportDate.ToString("yyyy-MM-dd HH:mm:ss")
            };

            var html = $@"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Network Forensic Analysis Report - {caseInfo.CaseNumber}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f5f5; 
            padding: 20px;
            color: #333;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{ 
            border-bottom: 4px solid #00C9A7; 
            padding-bottom: 20px; 
            margin-bottom: 30px;
        }}
        .header h1 {{ 
            color: #1E1E2E; 
            font-size: 28px; 
            margin-bottom: 10px;
        }}
        .header .subtitle {{ 
            color: #666; 
            font-size: 16px;
        }}
        .case-info {{ 
            background: #f8f9fa; 
            padding: 20px; 
            border-left: 4px solid #00C9A7; 
            margin-bottom: 30px;
        }}
        .case-info table {{ 
            width: 100%; 
            border-collapse: collapse;
        }}
        .case-info td {{ 
            padding: 8px; 
            border-bottom: 1px solid #e0e0e0;
        }}
        .case-info td:first-child {{ 
            font-weight: bold; 
            width: 200px; 
            color: #555;
        }}
        .section {{ 
            margin-bottom: 40px;
        }}
        .section-title {{ 
            color: #1E1E2E; 
            font-size: 22px; 
            margin-bottom: 15px; 
            padding-bottom: 10px; 
            border-bottom: 2px solid #e0e0e0;
        }}
        .summary-cards {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px;
        }}
        .card {{ 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            border-left: 4px solid #00C9A7;
        }}
        .card.critical {{ border-left-color: #FF4757; }}
        .card.warning {{ border-left-color: #FFA502; }}
        .card.safe {{ border-left-color: #26DE81; }}
        .card-title {{ 
            color: #666; 
            font-size: 14px; 
            margin-bottom: 10px;
        }}
        .card-value {{ 
            font-size: 32px; 
            font-weight: bold; 
            color: #1E1E2E;
        }}
        .threat-table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 15px;
        }}
        .threat-table th {{ 
            background: #1E1E2E; 
            color: white; 
            padding: 12px; 
            text-align: left; 
            font-weight: 600;
        }}
        .threat-table td {{ 
            padding: 12px; 
            border-bottom: 1px solid #e0e0e0;
        }}
        .threat-table tr:hover {{ 
            background: #f8f9fa;
        }}
        .severity-badge {{ 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 12px; 
            font-size: 12px; 
            font-weight: bold; 
            color: white;
        }}
        .severity-critical {{ background: #FF4757; }}
        .severity-warning {{ background: #FFA502; }}
        .severity-safe {{ background: #26DE81; }}
        .risk-high {{ background: #FF4757; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; }}
        .risk-medium {{ background: #FFA502; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; }}
        .risk-low {{ background: #26DE81; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; }}
        .footer {{ 
            margin-top: 50px; 
            padding-top: 20px; 
            border-top: 2px solid #e0e0e0; 
            text-align: center; 
            color: #666; 
            font-size: 14px;
        }}
        .metadata {{ 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 8px; 
            font-size: 14px; 
            color: #666;
        }}
        .finding {{ 
            background: white; 
            border: 1px solid #e0e0e0; 
            padding: 15px; 
            margin-bottom: 15px; 
            border-radius: 8px;
        }}
        .finding-title {{ 
            font-weight: bold; 
            color: #1E1E2E; 
            margin-bottom: 8px;
        }}
        .finding-details {{ 
            color: #666; 
            font-size: 14px; 
            line-height: 1.6;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <!-- Header -->
        <div class='header'>
            <h1>🛡️ Network Forensic Analysis Report</h1>
            <div class='subtitle'>AI-Based Multi-Layer Spoofing Detection and Prevention System</div>
        </div>

        <!-- Case Information -->
        <div class='case-info'>
            <table>
                <tr><td>Case Number:</td><td>{caseInfo.CaseNumber}</td></tr>
                <tr><td>Investigator:</td><td>{caseInfo.Investigator}</td></tr>
                <tr><td>Organization:</td><td>{caseInfo.Organization}</td></tr>
                <tr><td>Report Generated:</td><td>{caseInfo.ReportDate}</td></tr>
                <tr><td>Analysis System:</td><td>AI-Based Spoofing Detection System v1.0</td></tr>
                <tr><td>Network Status:</td><td><span class='severity-badge severity-{(_currentNetworkStatus == "CRITICAL" ? "critical" : _currentNetworkStatus == "WARNING" ? "warning" : "safe")}'>{_currentNetworkStatus}</span></td></tr>
            </table>
        </div>

        <!-- Executive Summary -->
        <div class='section'>
            <h2 class='section-title'>Executive Summary</h2>
            <div class='summary-cards'>
                <div class='card critical'>
                    <div class='card-title'>Critical Threats</div>
                    <div class='card-value'>{_threatAlerts.Count(a => a.Severity == "Critical")}</div>
                </div>
                <div class='card warning'>
                    <div class='card-title'>Warning Threats</div>
                    <div class='card-value'>{_threatAlerts.Count(a => a.Severity == "Warning")}</div>
                </div>
                <div class='card'>
                    <div class='card-title'>Total Packets Analyzed</div>
                    <div class='card-value'>{(_reports.Any() ? _reports[0].PacketsAnalyzed : 0):N0}</div>
                </div>
                <div class='card safe'>
                    <div class='card-title'>Analysis Confidence</div>
                    <div class='card-value'>{(_analysisResults.Any() ? Math.Round(_analysisResults.Average(r => r.Confidence)) : 0)}%</div>
                </div>
            </div>
            <div class='metadata'>
                <strong>Analysis Summary:</strong> This forensic report documents the network traffic analysis performed on {reportDate:yyyy-MM-dd} at {reportDate:HH:mm:ss}. 
                The AI-based detection system analyzed {(_reports.Any() ? _reports[0].PacketsAnalyzed : 0):N0} network packets and identified {_threatAlerts.Count} potential security incidents requiring investigation.
            </div>
        </div>

        <!-- Threat Alerts -->
        <div class='section'>
            <h2 class='section-title'>Detected Threat Alerts</h2>
            {(_threatAlerts.Any() ? $@"
            <table class='threat-table'>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Threat Type</th>
                        <th>Source IP</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {string.Join("", _threatAlerts.Select(alert => $@"
                    <tr>
                        <td>{alert.Timestamp:yyyy-MM-dd HH:mm:ss}</td>
                        <td><span class='severity-badge severity-{alert.Severity.ToLower()}'>{alert.Severity}</span></td>
                        <td>{alert.Type}</td>
                        <td>{alert.IpAddress}</td>
                        <td>{alert.Description}<br/><small style='color: #999;'>{alert.AdditionalInfo}</small></td>
                    </tr>
                    "))}
                </tbody>
            </table>
            " : "<p style='color: #666; padding: 20px; background: #f8f9fa; border-radius: 8px;'>No threat alerts detected during this analysis session.</p>")}
        </div>

        <!-- Detailed Findings -->
        <div class='section'>
            <h2 class='section-title'>Detailed Analysis Findings</h2>
            
            <h3 style='color: #1E1E2E; margin: 20px 0 10px 0; font-size: 18px;'>ARP Spoofing Analysis</h3>
            {(GetAnalysisResultsByCategory("ARP").Any() ? string.Join("", GetAnalysisResultsByCategory("ARP").Select(result => $@"
            <div class='finding'>
                <div class='finding-title'>
                    <span class='risk-{result.RiskLevel.ToLower()}'>{result.RiskLevel.ToUpper()} RISK</span>
                    {result.Description}
                </div>
                <div class='finding-details'>
                    <strong>Details:</strong> {result.Details}<br/>
                    <strong>Detection Confidence:</strong> {result.Confidence}%<br/>
                    <strong>Analysis Method:</strong> AI-based pattern recognition and anomaly detection
                </div>
            </div>
            ")) : "<p style='color: #666; font-style: italic;'>No ARP spoofing threats detected.</p>")}

            <h3 style='color: #1E1E2E; margin: 20px 0 10px 0; font-size: 18px;'>DNS Spoofing Analysis</h3>
            {(GetAnalysisResultsByCategory("DNS").Any() ? string.Join("", GetAnalysisResultsByCategory("DNS").Select(result => $@"
            <div class='finding'>
                <div class='finding-title'>
                    <span class='risk-{result.RiskLevel.ToLower()}'>{result.RiskLevel.ToUpper()} RISK</span>
                    {result.Description}
                </div>
                <div class='finding-details'>
                    <strong>Details:</strong> {result.Details}<br/>
                    <strong>Detection Confidence:</strong> {result.Confidence}%<br/>
                    <strong>Analysis Method:</strong> DNS query pattern analysis and response validation
                </div>
            </div>
            ")) : "<p style='color: #666; font-style: italic;'>No DNS spoofing threats detected.</p>")}

            <h3 style='color: #1E1E2E; margin: 20px 0 10px 0; font-size: 18px;'>IP Spoofing Analysis</h3>
            {(GetAnalysisResultsByCategory("IP").Any() ? string.Join("", GetAnalysisResultsByCategory("IP").Select(result => $@"
            <div class='finding'>
                <div class='finding-title'>
                    <span class='risk-{result.RiskLevel.ToLower()}'>{result.RiskLevel.ToUpper()} RISK</span>
                    {result.Description}
                </div>
                <div class='finding-details'>
                    <strong>Details:</strong> {result.Details}<br/>
                    <strong>Detection Confidence:</strong> {result.Confidence}%<br/>
                    <strong>Analysis Method:</strong> IP header validation and source verification
                </div>
            </div>
            ")) : "<p style='color: #666; font-style: italic;'>No IP spoofing threats detected.</p>")}
        </div>

        <!-- Recommendations -->
        <div class='section'>
            <h2 class='section-title'>Recommendations</h2>
            <div class='finding'>
                <div class='finding-details'>
                    {GenerateRecommendations()}
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class='footer'>
            <p><strong>AI-Based Multi-Layer Spoofing Detection and Prevention System</strong></p>
            <p>This report was automatically generated by the forensic analysis system.</p>
            <p>Report ID: {caseInfo.CaseNumber} | Generated: {caseInfo.ReportDate}</p>
        </div>
    </div>
</body>
</html>";

            File.WriteAllText(filePath, html);
        }

        private void GenerateForensicReportJSON(string filePath)
        {
            var reportData = new
            {
                ForensicReport = new
                {
                    CaseInformation = new
                    {
                        CaseNumber = $"SPOOF-{DateTime.Now:yyyyMMdd-HHmmss}",
                        Investigator = Environment.UserName,
                        Organization = "AI-Based Spoofing Detection System",
                        ReportDate = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        AnalysisSystem = "AI-Based Spoofing Detection System v1.0",
                        NetworkStatus = _currentNetworkStatus
                    },
                    ExecutiveSummary = new
                    {
                        TotalThreats = _threatAlerts.Count,
                        CriticalThreats = _threatAlerts.Count(a => a.Severity == "Critical"),
                        WarningThreats = _threatAlerts.Count(a => a.Severity == "Warning"),
                        SafeAlerts = _threatAlerts.Count(a => a.Severity == "Safe"),
                        TotalPacketsAnalyzed = _reports.Any() ? _reports[0].PacketsAnalyzed : 0,
                        AverageConfidence = _analysisResults.Any() ? Math.Round(_analysisResults.Average(r => r.Confidence), 2) : 0
                    },
                    ThreatAlerts = _threatAlerts.Select(alert => new
                    {
                        alert.Timestamp,
                        alert.Severity,
                        alert.Type,
                        alert.IpAddress,
                        alert.Description,
                        alert.AdditionalInfo
                    }).ToList(),
                    DetailedFindings = new
                    {
                        ARPSpoofing = GetAnalysisResultsByCategory("ARP").Select(r => new
                        {
                            r.RiskLevel,
                            r.Description,
                            r.Details,
                            r.Confidence,
                            AnalysisMethod = "AI-based pattern recognition and anomaly detection"
                        }).ToList(),
                        DNSSpoofing = GetAnalysisResultsByCategory("DNS").Select(r => new
                        {
                            r.RiskLevel,
                            r.Description,
                            r.Details,
                            r.Confidence,
                            AnalysisMethod = "DNS query pattern analysis and response validation"
                        }).ToList(),
                        IPSpoofing = GetAnalysisResultsByCategory("IP").Select(r => new
                        {
                            r.RiskLevel,
                            r.Description,
                            r.Details,
                            r.Confidence,
                            AnalysisMethod = "IP header validation and source verification"
                        }).ToList()
                    },
                    Recommendations = GenerateRecommendationsJSON(),
                    ReportMetadata = new
                    {
                        GeneratedBy = "AI-Based Spoofing Detection System",
                        ReportFormat = "JSON",
                        ReportVersion = "1.0",
                        ExportDate = DateTime.Now
                    }
                }
            };

            string json = System.Text.Json.JsonSerializer.Serialize(reportData, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(filePath, json);
        }

        private List<AnalysisResult> GetAnalysisResultsByCategory(string category)
        {
            return _analysisResults.Where(r => r.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        private string GenerateRecommendations()
        {
            var criticalCount = _threatAlerts.Count(a => a.Severity == "Critical");
            var warningCount = _threatAlerts.Count(a => a.Severity == "Warning");

            var recommendations = new List<string>();

            if (criticalCount > 0)
            {
                recommendations.Add("• <strong>IMMEDIATE ACTION REQUIRED:</strong> Critical threats detected. Isolate affected systems and conduct thorough investigation.");
                recommendations.Add("• Review ARP tables on all network devices for unauthorized entries.");
                recommendations.Add("• Implement static ARP entries for critical infrastructure.");
                recommendations.Add("• Enable port security on network switches.");
            }

            if (warningCount > 0)
            {
                recommendations.Add("• <strong>WARNING:</strong> Suspicious activity detected. Monitor network traffic closely.");
                recommendations.Add("• Review DNS server logs for anomalous queries.");
                recommendations.Add("• Consider implementing DNSSEC for DNS integrity.");
                recommendations.Add("• Enable network segmentation to limit attack surface.");
            }

            if (criticalCount == 0 && warningCount == 0)
            {
                recommendations.Add("• Continue regular network monitoring and analysis.");
                recommendations.Add("• Maintain current security configurations.");
                recommendations.Add("• Schedule periodic security audits.");
                recommendations.Add("• Keep AI detection models updated with latest threat intelligence.");
            }

            recommendations.Add("• Document all findings and maintain audit trail.");
            recommendations.Add("• Train personnel on spoofing attack recognition and response procedures.");

            return string.Join("<br/>", recommendations);
        }

        private List<string> GenerateRecommendationsJSON()
        {
            var criticalCount = _threatAlerts.Count(a => a.Severity == "Critical");
            var warningCount = _threatAlerts.Count(a => a.Severity == "Warning");

            var recommendations = new List<string>();

            if (criticalCount > 0)
            {
                recommendations.Add("IMMEDIATE ACTION REQUIRED: Critical threats detected. Isolate affected systems and conduct thorough investigation.");
                recommendations.Add("Review ARP tables on all network devices for unauthorized entries.");
                recommendations.Add("Implement static ARP entries for critical infrastructure.");
                recommendations.Add("Enable port security on network switches.");
            }

            if (warningCount > 0)
            {
                recommendations.Add("WARNING: Suspicious activity detected. Monitor network traffic closely.");
                recommendations.Add("Review DNS server logs for anomalous queries.");
                recommendations.Add("Consider implementing DNSSEC for DNS integrity.");
                recommendations.Add("Enable network segmentation to limit attack surface.");
            }

            if (criticalCount == 0 && warningCount == 0)
            {
                recommendations.Add("Continue regular network monitoring and analysis.");
                recommendations.Add("Maintain current security configurations.");
                recommendations.Add("Schedule periodic security audits.");
                recommendations.Add("Keep AI detection models updated with latest threat intelligence.");
            }

            recommendations.Add("Document all findings and maintain audit trail.");
            recommendations.Add("Train personnel on spoofing attack recognition and response procedures.");

            return recommendations;
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

        private void CreatePlaceholderPcapFile(string filePath)
        {
            // Method kept for potential future use but not currently needed
        }

        private void OpenCaptureFolder()
        {
            // Method kept for potential future use but not currently needed
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
                // Handle exception when trying to drag during certain operations
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
                // Update maximize button tooltip
                MaximizeButton.ToolTip = "Maximize";
            }
            else
            {
                this.WindowState = WindowState.Maximized;
                // Update maximize button tooltip
                MaximizeButton.ToolTip = "Restore";
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            // Optional: Show confirmation dialog before closing
            var result = MessageBox.Show("Are you sure you want to exit the application?",
                "Confirm Exit", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                this.Close();
            }
        }

        // Handle double-click on title bar to maximize/restore
        private void TitleBar_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            MaximizeButton_Click(sender, null);
        }
        #endregion

        #region Window Events
        protected override void OnClosed(EventArgs e)
        {
            // Clean up timers
            _clockTimer?.Stop();

            base.OnClosed(e);
        }
        #endregion

        #region Production Implementation Notes
        /*
         * For production implementation, you would need to:
         * 
         * 1. PACKET CAPTURE:
         *    - Install SharpPcap NuGet package: Install-Package SharpPcap
         *    - Implement actual packet capture using LibPcap/WinPcap
         *    - Handle network interface selection
         *    - Implement proper packet filtering
         * 
         * 2. AI ANALYSIS:
         *    - Install ML.NET NuGet package: Install-Package Microsoft.ML
         *    - Load trained models for spoofing detection
         *    - Implement feature extraction from packets
         *    - Process packets through AI models
         * 
         * 3. FILE HANDLING:
         *    - Use PacketDotNet for parsing PCAP files: Install-Package PacketDotNet
         *    - Implement proper error handling for corrupted files
         *    - Add support for different PCAP formats
         * 
         * 4. DATABASE INTEGRATION:
         *    - Store analysis results in database (SQLite/SQL Server)
         *    - Implement report generation
         *    - Add historical data tracking
         * 
         * 5. REAL-TIME ALERTS:
         *    - Implement notification system
         *    - Add email/SMS alert functionality
         *    - Create alert severity levels
         * 
         * 6. REQUIRED NUGET PACKAGES:
         *    - SharpPcap (for packet capture)
         *    - PacketDotNet (for packet parsing)
         *    - Microsoft.ML (for AI models)
         *    - System.Text.Json (already included in .NET Core 3.0+)
         */
        #endregion
    }


}