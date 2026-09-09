-- NKAT AI Full Supabase / PostgreSQL Schema

-- Run this in Supabase -> SQL Editor -> New query -> Run


CREATE TABLE organizations (
	id SERIAL NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id)
);

CREATE TABLE posts (
	id SERIAL NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	tag VARCHAR(100), 
	tag_color VARCHAR(50), 
	author VARCHAR(100), 
	read_time VARCHAR(50), 
	image_url TEXT, 
	video_url TEXT, 
	snippet TEXT NOT NULL, 
	content TEXT, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id)
);

CREATE TABLE assessments (
	id SERIAL NOT NULL, 
	organization_id INTEGER, 
	name VARCHAR(255) NOT NULL, 
	title VARCHAR(255), 
	target_url VARCHAR(255), 
	target_scope TEXT, 
	repository_path VARCHAR(255), 
	status VARCHAR(50) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE SET NULL
);

CREATE TABLE domain_targets (
	id SERIAL NOT NULL, 
	organization_id INTEGER NOT NULL, 
	domain VARCHAR(255) NOT NULL, 
	target_url VARCHAR(255), 
	verification_token VARCHAR(255) NOT NULL, 
	verification_method VARCHAR(50) NOT NULL, 
	status VARCHAR(50) NOT NULL, 
	target_status VARCHAR(50) NOT NULL, 
	target_type VARCHAR(100), 
	allowed_hosts TEXT, 
	allowed_ports TEXT, 
	allowed_paths TEXT, 
	auth_method VARCHAR(100), 
	scan_profile VARCHAR(100), 
	owner VARCHAR(255), 
	approval_timestamp TIMESTAMP WITH TIME ZONE, 
	approval_expiration TIMESTAMP WITH TIME ZONE, 
	scope_restrictions TEXT, 
	verified_at TIMESTAMP WITH TIME ZONE, 
	last_error TEXT, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_org_domain UNIQUE (organization_id, domain), 
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE
);

CREATE TABLE users (
	id SERIAL NOT NULL, 
	organization_id INTEGER NOT NULL, 
	username VARCHAR(150) NOT NULL, 
	email VARCHAR(255), 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(50) NOT NULL, 
	is_email_verified BOOLEAN NOT NULL, 
	email_verification_token VARCHAR(255), 
	email_verification_code VARCHAR(10), 
	email_verification_sent_at TIMESTAMP WITH TIME ZONE, 
	email_verification_expires_at TIMESTAMP WITH TIME ZONE, 
	auth_provider VARCHAR(50) NOT NULL, 
	google_sub VARCHAR(255), 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE
);

CREATE TABLE domain_audit_logs (
	id SERIAL NOT NULL, 
	user_id INTEGER, 
	domain VARCHAR(255) NOT NULL, 
	method VARCHAR(50) NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	result VARCHAR(50) NOT NULL, 
	details TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE platform_activity_logs (
	id SERIAL NOT NULL, 
	user_id INTEGER, 
	username VARCHAR(100), 
	action_type VARCHAR(100) NOT NULL, 
	target_resource VARCHAR(255), 
	ip_address VARCHAR(50), 
	details TEXT, 
	timestamp TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE scans (
	id SERIAL NOT NULL, 
	organization_id INTEGER, 
	assessment_id INTEGER, 
	target VARCHAR(255) NOT NULL, 
	status VARCHAR(50) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE SET NULL, 
	FOREIGN KEY(assessment_id) REFERENCES assessments (id) ON DELETE SET NULL
);

CREATE TABLE subdomains (
	id SERIAL NOT NULL, 
	scan_id INTEGER NOT NULL, 
	hostname VARCHAR(255) NOT NULL, 
	ip_address VARCHAR(100), 
	is_api_endpoint BOOLEAN, 
	discovered_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE findings (
	id SERIAL NOT NULL, 
	subdomain_id INTEGER NOT NULL, 
	assessment_id INTEGER, 
	check_name VARCHAR(255) NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	evidence TEXT, 
	recommendation TEXT, 
	config_snippet TEXT, 
	status VARCHAR(50) NOT NULL, 
	ml_confidence FLOAT, 
	ml_predicted_label INTEGER, 
	approved_at TIMESTAMP WITH TIME ZONE, 
	approved_by VARCHAR(255), 
	review_deadline TIMESTAMP WITH TIME ZONE, 
	previous_state TEXT, 
	owasp_category VARCHAR(255), 
	cwe_id VARCHAR(50), 
	is_in_cisa_kev BOOLEAN, 
	epss_score FLOAT, 
	epss_percentile FLOAT, 
	is_api_endpoint BOOLEAN, 
	priority_tier VARCHAR(50), 
	contextual_risk_score FLOAT, 
	risk_acceptance_reason TEXT, 
	vulnerability_type VARCHAR(255), 
	detection_method VARCHAR(100), 
	request_evidence TEXT, 
	response_evidence TEXT, 
	code_evidence TEXT, 
	verification_scan_id INTEGER, 
	before_evidence TEXT, 
	after_evidence TEXT, 
	reverified_at TIMESTAMP WITH TIME ZONE, 
	sla_deadline TIMESTAMP WITH TIME ZONE, 
	is_sla_breached BOOLEAN, 
	historical_context_note TEXT, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_subdomain_check_evidence UNIQUE (subdomain_id, check_name, evidence), 
	FOREIGN KEY(subdomain_id) REFERENCES subdomains (id) ON DELETE CASCADE, 
	FOREIGN KEY(assessment_id) REFERENCES assessments (id) ON DELETE SET NULL
);

CREATE TABLE audit_logs (
	id SERIAL NOT NULL, 
	finding_id INTEGER, 
	scan_id INTEGER, 
	subdomain_id INTEGER, 
	action VARCHAR(50) NOT NULL, 
	actor VARCHAR(50) NOT NULL, 
	actor_name VARCHAR(255), 
	timestamp TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE, 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
	FOREIGN KEY(subdomain_id) REFERENCES subdomains (id) ON DELETE CASCADE
);

CREATE TABLE feedback_labels (
	id SERIAL NOT NULL, 
	finding_id INTEGER NOT NULL, 
	features_snapshot TEXT NOT NULL, 
	human_label VARCHAR(50) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE TABLE in_app_notifications (
	id SERIAL NOT NULL, 
	organization_id INTEGER NOT NULL, 
	domain_id INTEGER, 
	scan_id INTEGER, 
	finding_id INTEGER, 
	title VARCHAR(255) NOT NULL, 
	message TEXT NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	is_read BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE, 
	FOREIGN KEY(domain_id) REFERENCES domain_targets (id) ON DELETE CASCADE, 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE TABLE remediations (
	id SERIAL NOT NULL, 
	finding_id INTEGER NOT NULL, 
	repository VARCHAR(255), 
	branch VARCHAR(255), 
	base_commit VARCHAR(255), 
	applied_commit VARCHAR(255), 
	rollback_commit VARCHAR(255), 
	patch TEXT, 
	root_cause TEXT, 
	affected_file VARCHAR(255), 
	affected_function VARCHAR(255), 
	vulnerable_line INTEGER, 
	patch_strategy TEXT, 
	status VARCHAR(50) NOT NULL, 
	confidence FLOAT NOT NULL, 
	validation_status TEXT, 
	approval_status VARCHAR(50) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

-- Seed Default Organization
INSERT INTO organizations (id, name, created_at)
VALUES (1, 'Default Organization', now())
ON CONFLICT (id) DO NOTHING;

-- Seed Default Admin User (username: admin | password: admin_secret_2026)
INSERT INTO users (organization_id, username, email, password_hash, role, is_email_verified, auth_provider, created_at)
VALUES (1, 'admin', 'analyst@nkat.ai', '$2b$12$FSHf3y3ElBJNItDQLgg/tebn0wfQp6FireJzV/qblrfMEqadfT2oq', 'admin', true, 'local', now())
ON CONFLICT DO NOTHING;