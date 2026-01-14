using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using static Multi_Layer_Spoofing_Detector.MainWindow;

namespace Multi_Layer_Spoofing_Detector.data
{
    public class ForensicsRepository
    {
        private readonly string _connectionString;

        public ForensicsRepository()
        {
            string dbDir = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "database"
            );

            if (!Directory.Exists(dbDir))
                Directory.CreateDirectory(dbDir);

            string dbPath = Path.Combine(dbDir, "forensics.db");

            _connectionString = $"Data Source={dbPath};Version=3;";

            InitializeDatabase();
        }

        // DATABASE INITIALIZATION
        private void InitializeDatabase()
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            using var cmd = new SQLiteCommand(conn);

            cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS Cases (
                CaseId TEXT PRIMARY KEY,
                PcapFile TEXT,
                PcapHash TEXT,
                NetworkStatus TEXT,
                PacketsAnalyzed INTEGER,
                AnalysisTime TEXT
            );

            CREATE TABLE IF NOT EXISTS ThreatAlerts (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                CaseId TEXT,
                Timestamp TEXT,
                Severity TEXT,
                Type TEXT,
                IpAddress TEXT,
                Description TEXT,
                AdditionalInfo TEXT
            );

            CREATE TABLE IF NOT EXISTS AnalysisResults (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                CaseId TEXT,
                Category TEXT,
                RiskLevel TEXT,
                Description TEXT,
                Details TEXT,
                Confidence REAL
            );

            CREATE TABLE IF NOT EXISTS Hashes (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                CaseId TEXT,
                EvidenceType TEXT,
                HashValue TEXT,
                Algorithm TEXT,
                Timestamp TEXT
            );
            ";

            cmd.ExecuteNonQuery();
        }

        // CASE METADATA
        public void InsertCase(
            string caseId,
            string pcapFile,
            string pcapHash,
            string networkStatus,
            int packetsAnalyzed)
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            using var cmd = new SQLiteCommand(@"
                INSERT INTO Cases (
                    CaseId, PcapFile, PcapHash,
                    NetworkStatus, PacketsAnalyzed, AnalysisTime
                )
                VALUES (
                    @caseId, @pcapFile, @pcapHash,
                    @networkStatus, @packets, @time
                );
            ", conn);

            cmd.Parameters.AddWithValue("@caseId", caseId);
            cmd.Parameters.AddWithValue("@pcapFile", pcapFile);
            cmd.Parameters.AddWithValue("@pcapHash", pcapHash);
            cmd.Parameters.AddWithValue("@networkStatus", networkStatus);
            cmd.Parameters.AddWithValue("@packets", packetsAnalyzed);
            cmd.Parameters.AddWithValue("@time", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

            cmd.ExecuteNonQuery();
        }

        public ForensicCase GetCaseMetadata(string caseId)
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            using var cmd = new SQLiteCommand(@"
                SELECT CaseId, PcapFile, PcapHash,
                       NetworkStatus, PacketsAnalyzed, AnalysisTime
                FROM Cases
                WHERE CaseId = @caseId
                LIMIT 1;
            ", conn);

            cmd.Parameters.AddWithValue("@caseId", caseId);

            using var reader = cmd.ExecuteReader();

            if (!reader.Read())
                throw new Exception($"Case not found: {caseId}");

            return new ForensicCase
            {
                CaseId = reader.GetString(0),
                PcapFile = reader.GetString(1),
                PcapHash = reader.GetString(2),
                NetworkStatus = reader.GetString(3),
                PacketsAnalyzed = reader.GetInt32(4),
                AnalysisTime = DateTime.Parse(reader.GetString(5))
            };
        }

        // THREAT ALERTS
        public void InsertThreatAlerts(string caseId, List<ThreatAlert> alerts)
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            foreach (var alert in alerts)
            {
                using var cmd = new SQLiteCommand(@"
                    INSERT INTO ThreatAlerts
                    (CaseId, Timestamp, Severity, Type, IpAddress, Description, AdditionalInfo)
                    VALUES
                    (@caseId, @time, @severity, @type, @ip, @desc, @info);
                ", conn);

                cmd.Parameters.AddWithValue("@caseId", caseId);
                cmd.Parameters.AddWithValue("@time", alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.Parameters.AddWithValue("@severity", alert.Severity);
                cmd.Parameters.AddWithValue("@type", alert.Type);
                cmd.Parameters.AddWithValue("@ip", alert.IpAddress);
                cmd.Parameters.AddWithValue("@desc", alert.Description);
                cmd.Parameters.AddWithValue("@info", alert.AdditionalInfo);

                cmd.ExecuteNonQuery();
            }
        }

        // ANALYSIS RESULTS
        public void InsertAnalysisResults(string caseId, List<AnalysisResult> results)
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            foreach (var r in results)
            {
                using var cmd = new SQLiteCommand(@"
                    INSERT INTO AnalysisResults
                    (CaseId, Category, RiskLevel, Description, Details, Confidence)
                    VALUES
                    (@caseId, @cat, @risk, @desc, @details, @conf);
                ", conn);

                cmd.Parameters.AddWithValue("@caseId", caseId);
                cmd.Parameters.AddWithValue("@cat", r.Category);
                cmd.Parameters.AddWithValue("@risk", r.RiskLevel);
                cmd.Parameters.AddWithValue("@desc", r.Description);
                cmd.Parameters.AddWithValue("@details", r.Details);
                cmd.Parameters.AddWithValue("@conf", r.Confidence);

                cmd.ExecuteNonQuery();
            }
        }

        // HASH / CHAIN OF CUSTODY
        public void InsertHash(string caseId, string evidenceType, string hashValue)
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            using var cmd = new SQLiteCommand(@"
                INSERT INTO Hashes
                (CaseId, EvidenceType, HashValue, Algorithm, Timestamp)
                VALUES
                (@caseId, @type, @hash, 'SHA-256', @time);
            ", conn);

            cmd.Parameters.AddWithValue("@caseId", caseId);
            cmd.Parameters.AddWithValue("@type", evidenceType);
            cmd.Parameters.AddWithValue("@hash", hashValue);
            cmd.Parameters.AddWithValue("@time", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

            cmd.ExecuteNonQuery();
        }

        public List<ThreatAlert> GetThreatAlerts(string caseId)
        {
            var alerts = new List<ThreatAlert>();

            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            using var cmd = new SQLiteCommand(@"
                SELECT Timestamp, Severity, Type, IpAddress, Description, AdditionalInfo
                FROM ThreatAlerts
                WHERE CaseId = @caseId
                ORDER BY Timestamp ASC;
            ", conn);

            cmd.Parameters.AddWithValue("@caseId", caseId);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                alerts.Add(new ThreatAlert
                {
                    Timestamp = DateTime.Parse(reader.GetString(0)),
                    Severity = reader.GetString(1),
                    Type = reader.GetString(2),
                    IpAddress = reader.GetString(3),
                    Description = reader.GetString(4),
                    AdditionalInfo = reader.GetString(5)
                });
            }

            return alerts;
        }

        public List<AnalysisResult> GetAnalysisResults(string caseId)
        {
            var results = new List<AnalysisResult>();

            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();

            using var cmd = new SQLiteCommand(@"
                SELECT Category, RiskLevel, Description, Details, Confidence
                FROM AnalysisResults
                WHERE CaseId = @caseId;
            ", conn);

            cmd.Parameters.AddWithValue("@caseId", caseId);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(new AnalysisResult
                {
                    Category = reader.GetString(0),
                    RiskLevel = reader.GetString(1),
                    Description = reader.GetString(2),
                    Details = reader.GetString(3),
                    Confidence = (int)reader.GetDouble(4)
                });
            }

            return results;
        }

        public List<(string EvidenceType, string HashValue, string Algorithm, DateTime Timestamp)>
            GetHashes(string caseId)
                {
                    var hashes = new List<(string, string, string, DateTime)>();

                    using var conn = new SQLiteConnection(_connectionString);
                    conn.Open();

                    using var cmd = new SQLiteCommand(@"
                SELECT EvidenceType, HashValue, Algorithm, Timestamp
                FROM Hashes
                WHERE CaseId = @caseId;
            ", conn);

            cmd.Parameters.AddWithValue("@caseId", caseId);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                hashes.Add((
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    DateTime.Parse(reader.GetString(3))
                ));
            }

            return hashes;
        }



    }

    #region forensic_case model
    public class ForensicCase
    {
        public string CaseId { get; set; }
        public string PcapFile { get; set; }
        public string PcapHash { get; set; }
        public string NetworkStatus { get; set; }
        public int PacketsAnalyzed { get; set; }
        public DateTime AnalysisTime { get; set; }
    }

    #endregion
}
