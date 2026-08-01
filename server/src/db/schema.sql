-- Enterprise SOC Assessment Platform Schema definition

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Analyst',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(48),
    os_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'Active',
    installed_software JSONB DEFAULT '[]'::jsonb,
    running_services JSONB DEFAULT '[]'::jsonb,
    owner VARCHAR(100) DEFAULT 'SOC Operations',
    tags JSONB DEFAULT '[]'::jsonb,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS imported_findings (
    id SERIAL PRIMARY KEY,
    source_tool VARCHAR(100) NOT NULL,
    cve_id VARCHAR(50),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    cvss_score NUMERIC(3, 1) DEFAULT 0.0,
    affected_resource VARCHAR(255) NOT NULL,
    description TEXT,
    evidence TEXT,
    mitigation TEXT,
    raw_data JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_logs (
    id SERIAL PRIMARY KEY,
    log_source VARCHAR(100) NOT NULL,
    event_id VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(50) DEFAULT 'Informational',
    summary TEXT NOT NULL,
    user_name VARCHAR(100),
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    mitre_technique VARCHAR(50),
    details JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    report_title VARCHAR(255) NOT NULL,
    classification VARCHAR(100) DEFAULT 'CONFIDENTIAL / CISO AUDIT',
    risk_score INT DEFAULT 90,
    summary TEXT,
    mitre_mappings JSONB DEFAULT '[]'::jsonb,
    recommendations JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS network_flows (
    id VARCHAR(100) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_type VARCHAR(50) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    src_port INT NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    dest_port INT NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    bytes BIGINT NOT NULL,
    packets INT NOT NULL,
    duration_ms INT DEFAULT 0,
    flags VARCHAR(50),
    direction VARCHAR(20) DEFAULT 'INBOUND',
    vlan_id INT DEFAULT 1,
    geo_country VARCHAR(10) DEFAULT 'US',
    anomaly_flag BOOLEAN DEFAULT FALSE,
    risk_score INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pcap_sessions (
    id VARCHAR(100) PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    total_packets INT NOT NULL,
    duration_sec INT NOT NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    protocol_distribution JSONB DEFAULT '[]'::jsonb,
    dns_queries JSONB DEFAULT '[]'::jsonb,
    http_sessions JSONB DEFAULT '[]'::jsonb,
    tls_handshakes JSONB DEFAULT '[]'::jsonb,
    flagged_threats JSONB DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS discovery_jobs (
    id VARCHAR(100) PRIMARY KEY,
    target_cidr VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    scan_speed VARCHAR(50) DEFAULT 'Normal',
    discovered_count INT DEFAULT 0,
    scheduled_interval_min INT DEFAULT 0,
    last_run TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    next_run TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS siem_events (
    id VARCHAR(100) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_category VARCHAR(50) NOT NULL,
    host_name VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    event_id VARCHAR(100) NOT NULL,
    mitre_technique VARCHAR(100),
    summary TEXT NOT NULL,
    dedup_hash VARCHAR(64),
    dedup_count INT DEFAULT 1,
    raw_details JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS unified_security_events (
    id VARCHAR(100) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    collector VARCHAR(50) NOT NULL,
    vendor VARCHAR(100) NOT NULL,
    product VARCHAR(100) NOT NULL,
    host VARCHAR(255) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    raw TEXT NOT NULL,
    normalized JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_unified_events_collector ON unified_security_events(collector);
CREATE INDEX IF NOT EXISTS idx_unified_events_severity ON unified_security_events(severity);
CREATE INDEX IF NOT EXISTS idx_unified_events_vendor ON unified_security_events(vendor);
CREATE INDEX IF NOT EXISTS idx_unified_events_timestamp ON unified_security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_unified_events_host ON unified_security_events(host);

CREATE TABLE IF NOT EXISTS collector_metrics (
    id SERIAL PRIMARY KEY,
    collector_name VARCHAR(100) NOT NULL,
    collector_type VARCHAR(50) NOT NULL,
    state VARCHAR(50) NOT NULL,
    events_per_sec INT DEFAULT 0,
    dropped_packets_total INT DEFAULT 0,
    parser_errors_total INT DEFAULT 0,
    average_latency_ms INT DEFAULT 0,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


