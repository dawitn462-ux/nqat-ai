"""
Advanced AI Threat Correlation & Attack Path Graph Engine
---------------------------------------------------------
Constructs directed acyclic graph (DAG) attack chain models, correlates compound vulnerabilities,
and calculates composite threat vector risk scores (0-100) for security scan findings.

Graph Structure:
- Nodes: Assets (Target, Subdomain), Findings (Vulnerabilities), Impact Nodes (Exfiltration, Takeover, Exposure).
- Edges: Directed attack relationships ('exposes', 'enables', 'escalates_to').
"""

import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.models import Scan, Subdomain, Finding

logger = logging.getLogger("nkat.threat_correlation")

SEVERITY_WEIGHTS = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 4.0,
    "INFO": 1.0,
}

ATTACK_VECTOR_PATTERNS = [
    {
        "pattern_name": "Full Infrastructure Compromise via Exposure & SQLi",
        "required_checks": ["Exposed Git Repository", "SQL Injection"],
        "severity": "CRITICAL",
        "description": "Exposed source code combined with SQL Injection allows database extraction and server takeover.",
        "impact_node": "Full System & Data Exfiltration Takeover"
    },
    {
        "pattern_name": "Account Takeover via Authentication Bypass & Session Leak",
        "required_checks": ["SQL Injection Login Auth Bypass", "Security Headers Audit"],
        "severity": "CRITICAL",
        "description": "Auth bypass combined with missing session protection enables widespread user impersonation.",
        "impact_node": "Mass Account Takeover & Session Hijacking"
    },
    {
        "pattern_name": "Information Leak & Perimeter Reconnaissance Chain",
        "required_checks": ["Exposed Git Repository", "Information Disclosure"],
        "severity": "HIGH",
        "description": "Source disclosure combined with directory indexing exposes internal endpoint architecture.",
        "impact_node": "Unrestricted Architectural Reconnaissance"
    }
]


def compute_attack_path_graph(db: Session, scan_id: int) -> Dict[str, Any]:
    """
    Builds attack path graph nodes, directed edges, compound threat chains,
    and composite threat vector score for a scan_id.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {
            "scan_id": scan_id,
            "composite_threat_score": 0.0,
            "threat_level": "LOW",
            "nodes": [],
            "edges": [],
            "attack_chains": []
        }

    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan_id).all()
    findings = (
        db.query(Finding)
        .join(Subdomain, Finding.subdomain_id == Subdomain.id)
        .filter(Subdomain.scan_id == scan_id)
        .all()
    )

    nodes = []
    edges = []
    attack_chains = []

    # 1. Target Root Node
    root_node_id = f"target_{scan.id}"
    nodes.append({
        "id": root_node_id,
        "type": "TargetAsset",
        "label": scan.target,
        "severity": "INFO",
        "details": {"scan_id": scan.id, "status": scan.status}
    })

    sub_id_map = {}
    finding_names = set()

    # 2. Subdomain Nodes & Edges
    for sub in subdomains:
        s_node_id = f"sub_{sub.id}"
        sub_id_map[sub.id] = s_node_id
        nodes.append({
            "id": s_node_id,
            "type": "SubdomainAsset",
            "label": sub.hostname,
            "severity": "INFO",
            "details": {"ip_address": sub.ip_address}
        })
        edges.append({
            "source": root_node_id,
            "target": s_node_id,
            "relationship": "exposes_subdomain"
        })

    # 3. Finding Nodes & Edges
    raw_score = 0.0
    for f in findings:
        finding_names.add(f.check_name)
        f_node_id = f"finding_{f.id}"
        nodes.append({
            "id": f_node_id,
            "type": "VulnerabilityNode",
            "label": f.check_name,
            "severity": f.severity,
            "details": {
                "finding_id": f.id,
                "owasp_category": f.owasp_category,
                "cwe_id": f.cwe_id,
                "status": f.status
            }
        })
        parent_sub_id = sub_id_map.get(f.subdomain_id, root_node_id)
        edges.append({
            "source": parent_sub_id,
            "target": f_node_id,
            "relationship": "contains_vulnerability"
        })

        raw_score += SEVERITY_WEIGHTS.get(f.severity.upper(), 5.0)

    # 4. Detect Compound Attack Paths
    for pattern in ATTACK_VECTOR_PATTERNS:
        match_count = sum(1 for req in pattern["required_checks"] if any(req.lower() in fn.lower() for fn in finding_names))
        if match_count >= len(pattern["required_checks"]):
            impact_id = f"impact_{pattern['pattern_name'].replace(' ', '_').lower()}"
            nodes.append({
                "id": impact_id,
                "type": "AttackImpactNode",
                "label": pattern["impact_node"],
                "severity": pattern["severity"],
                "details": {"description": pattern["description"]}
            })

            # Link matching findings to impact node
            for f in findings:
                if any(req.lower() in f.check_name.lower() for req in pattern["required_checks"]):
                    edges.append({
                        "source": f"finding_{f.id}",
                        "target": impact_id,
                        "relationship": "enables_compound_exploit"
                    })

            attack_chains.append({
                "chain_name": pattern["pattern_name"],
                "severity": pattern["severity"],
                "impact": pattern["impact_node"],
                "description": pattern["description"]
            })
            raw_score += 25.0  # Compound threat multiplier

    # Normalize Composite Threat Score (0 - 100 cap)
    composite_threat_score = round(min(100.0, raw_score), 1)

    if composite_threat_score >= 80.0:
        threat_level = "CRITICAL"
    elif composite_threat_score >= 50.0:
        threat_level = "HIGH"
    elif composite_threat_score >= 25.0:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return {
        "scan_id": scan_id,
        "target": scan.target,
        "composite_threat_score": composite_threat_score,
        "threat_level": threat_level,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": nodes,
        "edges": edges,
        "attack_chains": attack_chains
    }
