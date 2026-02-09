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
    CaseId TEXT NOT NULL,
    Timestamp TEXT,
    Severity TEXT,
    Type TEXT,
    IpAddress TEXT,
    Description TEXT,
    AdditionalInfo TEXT,
    FOREIGN KEY (CaseId) REFERENCES Cases(CaseId)
);

CREATE TABLE IF NOT EXISTS AnalysisResults (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId TEXT NOT NULL,
    Category TEXT,
    RiskLevel TEXT,
    Description TEXT,
    Details TEXT,
    Confidence REAL,
    FOREIGN KEY (CaseId) REFERENCES Cases(CaseId)
);

CREATE TABLE IF NOT EXISTS Hashes (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId TEXT NOT NULL,
    EvidenceType TEXT,
    HashValue TEXT,
    Algorithm TEXT,
    Timestamp TEXT,
    FOREIGN KEY (CaseId) REFERENCES Cases(CaseId)
);
