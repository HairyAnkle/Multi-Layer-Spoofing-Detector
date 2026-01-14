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
    SourceIP TEXT,
    Description TEXT,
    FOREIGN KEY (CaseId) REFERENCES Cases(CaseId)
);

CREATE TABLE IF NOT EXISTS AnalysisResults (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId TEXT,
    Category TEXT,
    RiskLevel TEXT,
    Description TEXT,
    Details TEXT,
    Confidence REAL,
    FOREIGN KEY (CaseId) REFERENCES Cases(CaseId)
);

CREATE TABLE IF NOT EXISTS IntegrityHashes (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId TEXT,
    ArtifactType TEXT,
    HashAlgorithm TEXT,
    HashValue TEXT,
    GeneratedAt TEXT,
    FOREIGN KEY (CaseId) REFERENCES Cases(CaseId)
);
