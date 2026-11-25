import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Network,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
  FileText,
  Layers,
  RefreshCw
} from 'lucide-react';
import NetworkTopology from './NetworkTopology';

export default function App() {
  const [activeTab, setActiveTab] = useState('simulator');
  const [backendOnline, setBackendOnline] = useState(false);
  const [topologyLoading, setTopologyLoading] = useState(true);
  const [apiError, setApiError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [simulationError, setSimulationError] = useState(null);

  // Data states loaded exclusively from FastAPI endpoints
  const [segments, setSegments] = useState([]);
  const [resources, setResources] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [guardrails, setGuardrails] = useState([]);

  // Shared Connection Form State (synced between Simulator & Interactive Topology)
  const [sourceSegment, setSourceSegment] = useState('seg-hr');
  const [destinationResource, setDestinationResource] = useState('res-fin-db');
  const [port, setPort] = useState(5432);
  const [protocol, setProtocol] = useState('TCP');

  // Proposed Rule State
  const [hasProposedRule, setHasProposedRule] = useState(true);
  const [proposedRuleName, setProposedRuleName] = useState('Allow HR to Finance Database Direct');
  const [proposedRuleAction, setProposedRuleAction] = useState('ALLOW');
  const [proposedRulePriority, setProposedRulePriority] = useState(15);

  // Simulation & Topology Connectivity Results (calculated by Python policy engine)
  const [simulationResult, setSimulationResult] = useState(null);
  const [connectivityResult, setConnectivityResult] = useState(null);
  const [connectivityLoading, setConnectivityLoading] = useState(false);
  const [connectivityError, setConnectivityError] = useState(null);
  const [policyViewMode, setPolicyViewMode] = useState('baseline');

  const fetchAllBackendData = useCallback(async () => {
    setTopologyLoading(true);
    setApiError(null);
    try {
      const healthRes = await fetch('/api/health');
      if (!healthRes.ok) {
        throw new Error('Backend health check failed.');
      }

      const [topoRes, policiesRes, guardrailsRes] = await Promise.all([
        fetch('/api/network-topology'),
        fetch('/api/policies/current'),
        fetch('/api/security-guardrails')
      ]);

      if (!topoRes.ok || !policiesRes.ok || !guardrailsRes.ok) {
        throw new Error('Failed to load network topology or policy data from FastAPI.');
      }

      const topoData = await topoRes.json();
      const policiesData = await policiesRes.json();
      const guardrailsData = await guardrailsRes.json();

      const loadedSegments = topoData.segments || [];
      const loadedResources = topoData.resources || [];

      setSegments(loadedSegments);
      setResources(loadedResources);
      setPolicies(policiesData);
      setGuardrails(guardrailsData);
      setBackendOnline(true);

      if (loadedSegments.length > 0 && !loadedSegments.some((s) => s.id === sourceSegment)) {
        setSourceSegment(loadedSegments[0].id);
      }
      if (loadedResources.length > 0 && !loadedResources.some((r) => r.id === destinationResource)) {
        setDestinationResource(loadedResources[0].id);
        setPort(loadedResources[0].port);
        setProtocol(loadedResources[0].protocol || 'TCP');
      }
    } catch (err) {
      setBackendOnline(false);
      setApiError(
        err instanceof Error
          ? `${err.message} Start FastAPI with uvicorn on http://127.0.0.1:8000.`
          : 'Unable to reach FastAPI backend at http://127.0.0.1:8000.'
      );
    } finally {
      setTopologyLoading(false);
    }
  }, [sourceSegment, destinationResource]);

  useEffect(() => {
    fetchAllBackendData();
  }, []);

  const buildRequestPayload = useCallback(() => {
    const parsedPort = parseInt(port, 10);
    const parsedPriority = parseInt(proposedRulePriority, 10);

    return {
      source_segment: sourceSegment,
      destination_resource: destinationResource,
      port: Number.isNaN(parsedPort) ? 0 : parsedPort,
      protocol: (protocol || 'TCP').toUpperCase(),
      proposed_rule: hasProposedRule
        ? {
            id: 'RULE-PROPOSED-001',
            name: proposedRuleName || 'Proposed Policy Rule',
            source_segment: sourceSegment,
            destination_resource: destinationResource,
            port: Number.isNaN(parsedPort) ? 0 : parsedPort,
            protocol: (protocol || 'TCP').toUpperCase(),
            action: proposedRuleAction,
            priority: Number.isNaN(parsedPriority) ? 15 : parsedPriority,
            description: 'User-defined proposed rule simulated via NetImpact'
          }
        : null
    };
  }, [
    sourceSegment,
    destinationResource,
    port,
    protocol,
    hasProposedRule,
    proposedRuleName,
    proposedRuleAction,
    proposedRulePriority
  ]);

  const evaluateConnectivity = useCallback(async () => {
    if (!backendOnline || segments.length === 0 || resources.length === 0) {
      return;
    }

    const parsedPort = parseInt(port, 10);
    if (Number.isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setConnectivityError('Please enter a valid port number between 1 and 65535.');
      return;
    }

    setConnectivityLoading(true);
    setConnectivityError(null);

    try {
      const response = await fetch('/api/connectivity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildRequestPayload())
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || 'Connectivity evaluation failed.');
      }

      const data = await response.json();
      setConnectivityResult(data);
    } catch (err) {
      setConnectivityError(
        err instanceof Error ? err.message : 'Unable to evaluate connectivity via FastAPI.'
      );
    } finally {
      setConnectivityLoading(false);
    }
  }, [backendOnline, segments.length, resources.length, port, buildRequestPayload]);

  // Automatically re-evaluate topology connectivity via Python backend when inputs change
  useEffect(() => {
    if (!backendOnline || segments.length === 0 || resources.length === 0) {
      return;
    }
    const timer = setTimeout(() => {
      evaluateConnectivity();
    }, 180);
    return () => clearTimeout(timer);
  }, [backendOnline, segments.length, resources.length, evaluateConnectivity]);

  // Keep policyViewMode valid if proposed rule is toggled off
  useEffect(() => {
    if (!hasProposedRule && policyViewMode === 'proposed') {
      setPolicyViewMode('baseline');
    }
  }, [hasProposedRule, policyViewMode]);

  const handleSelectDestinationResource = (resourceId) => {
    setDestinationResource(resourceId);
    const selected = resources.find((item) => item.id === resourceId);
    if (selected) {
      setPort(selected.port);
      if (selected.protocol) {
        setProtocol(selected.protocol);
      }
    }
  };

  // Preset Handlers
  const loadScenario = (type) => {
    if (type === 'risky-hr') {
      setSourceSegment('seg-hr');
      setDestinationResource('res-fin-db');
      setPort(5432);
      setProtocol('TCP');
      setHasProposedRule(true);
      setProposedRuleName('Allow HR to Finance DB directly');
      setProposedRuleAction('ALLOW');
      setProposedRulePriority(15);
    } else if (type === 'safe-finance') {
      setSourceSegment('seg-finance');
      setDestinationResource('res-fin-db');
      setPort(5432);
      setProtocol('TCP');
      setHasProposedRule(false);
    } else if (type === 'denied-jumpbox') {
      setSourceSegment('seg-hr');
      setDestinationResource('res-it-jumpbox');
      setPort(22);
      setProtocol('TCP');
      setHasProposedRule(false);
    } else if (type === 'safe-portal') {
      setSourceSegment('seg-hr');
      setDestinationResource('res-fin-web');
      setPort(443);
      setProtocol('TCP');
      setHasProposedRule(false);
    }
  };

  // Run Simulation strictly via FastAPI policy engine
  const handleSimulate = async () => {
    const parsedPort = parseInt(port, 10);
    if (Number.isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setSimulationError('Please enter a valid port number between 1 and 65535.');
      return;
    }

    setLoading(true);
    setSimulationError(null);

    try {
      const response = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildRequestPayload())
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || 'Policy simulation request failed.');
      }

      const data = await response.json();
      setSimulationResult(data);
      setConnectivityResult(data);
      setBackendOnline(true);
      if (hasProposedRule) {
        setPolicyViewMode('proposed');
      }
    } catch (err) {
      setBackendOnline(false);
      setSimulationError(
        err instanceof Error
          ? `${err.message} Make sure the FastAPI backend is running on port 8000.`
          : 'Could not reach the FastAPI policy engine.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-layout">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo-icon">
            <Shield size={22} />
          </div>
          <div className="logo-text">
            <h1>NetImpact</h1>
            <p>Policy Risk Platform</p>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button
            className={`nav-item ${activeTab === 'simulator' ? 'active' : ''}`}
            onClick={() => setActiveTab('simulator')}
          >
            <Play size={18} />
            <span>Policy Simulator</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'topology' ? 'active' : ''}`}
            onClick={() => setActiveTab('topology')}
          >
            <Network size={18} />
            <span>Network Topology</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'guardrails' ? 'active' : ''}`}
            onClick={() => setActiveTab('guardrails')}
          >
            <ShieldAlert size={18} />
            <span>Security Guardrails</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'policies' ? 'active' : ''}`}
            onClick={() => setActiveTab('policies')}
          >
            <FileText size={18} />
            <span>Active Policies</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="status-badge">
            <span className={`status-dot ${backendOnline ? '' : 'offline'}`}></span>
            <span>{backendOnline ? 'FastAPI Connected' : 'FastAPI Offline'}</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        <header className="content-header">
          <div className="header-title">
            <h2>
              {activeTab === 'simulator' && 'Network Access Simulation & Impact Analysis'}
              {activeTab === 'topology' && 'Interactive Network Topology & Connectivity Analysis'}
              {activeTab === 'guardrails' && 'Predefined Security Guardrails'}
              {activeTab === 'policies' && 'Current Baseline Firewall Policies'}
            </h2>
            <p>
              {activeTab === 'simulator' && 'Evaluate proposed firewall rules and detect security policy violations before deployment.'}
              {activeTab === 'topology' && 'Visualize segments, critical assets, firewall boundaries, and live policy connectivity.'}
              {activeTab === 'guardrails' && 'Hard isolation boundaries enforced independently from firewall rules.'}
              {activeTab === 'policies' && 'Current active allow and default-deny access control rules.'}
            </p>
          </div>

          <div className="header-badges">
            <span className="badge badge-warning">Milestone 2</span>
            <span className="badge badge-allowed">FastAPI + React</span>
          </div>
        </header>

        <div className="content-body">
          {/* TAB 1: POLICY SIMULATOR */}
          {activeTab === 'simulator' && (
            <div>
              {!backendOnline && (
                <div className="offline-banner" role="alert">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <AlertTriangle size={22} color="#fbbf24" />
                    <div>
                      <strong>FastAPI Backend Disconnected</strong>
                      <p style={{ fontSize: '0.86rem', color: '#fde68a', marginTop: '2px' }}>
                        {apiError || 'Start FastAPI on port 8000 to load segments and evaluate firewall policies.'}
                      </p>
                    </div>
                  </div>
                  <button className="btn-preset" onClick={fetchAllBackendData}>
                    <RefreshCw size={15} />
                    <span>Retry Connection</span>
                  </button>
                </div>
              )}

              {/* Presets Bar */}
              <div className="presets-bar">
                <div className="presets-label">Quick Demonstration Presets:</div>
                <div className="preset-buttons">
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('risky-hr')}
                  >
                    <AlertTriangle size={15} color="#ef4444" />
                    <span>🚨 Test Risky HR → Finance DB Rule</span>
                  </button>
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('safe-finance')}
                  >
                    <CheckCircle2 size={15} color="#10b981" />
                    <span>✅ Test Permitted Finance → Finance DB</span>
                  </button>
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('denied-jumpbox')}
                  >
                    <XCircle size={15} color="#9ca3af" />
                    <span>⛔ Test Denied HR → IT Jumpbox</span>
                  </button>
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('safe-portal')}
                  >
                    <CheckCircle2 size={15} color="#3b82f6" />
                    <span>🌐 Test Safe Corporate Web Portal</span>
                  </button>
                </div>
              </div>

              {/* Simulation Input Card */}
              <div className="card">
                <h3 className="card-title">
                  <Network size={20} color="#3b82f6" />
                  <span>1. Configure Proposed Connection</span>
                </h3>

                <div className="simulator-grid">
                  <div className="form-group">
                    <label>Source Network Segment:</label>
                    <select
                      className="form-control"
                      value={sourceSegment}
                      onChange={(e) => setSourceSegment(e.target.value)}
                      disabled={segments.length === 0}
                    >
                      {segments.length === 0 ? (
                        <option value="">Loading segments from API...</option>
                      ) : (
                        segments.map((seg) => (
                          <option key={seg.id} value={seg.id}>
                            {seg.name} ({seg.cidr})
                          </option>
                        ))
                      )}
                    </select>
                  </div>

                  <div className="form-group">
                    <label>Destination Target Resource:</label>
                    <select
                      className="form-control"
                      value={destinationResource}
                      onChange={(e) => handleSelectDestinationResource(e.target.value)}
                      disabled={resources.length === 0}
                    >
                      {resources.length === 0 ? (
                        <option value="">Loading resources from API...</option>
                      ) : (
                        resources.map((res) => (
                          <option key={res.id} value={res.id}>
                            {res.name} ({res.ip}) {res.is_critical ? '⭐ [CRITICAL]' : ''}
                          </option>
                        ))
                      )}
                    </select>
                  </div>

                  <div className="form-group">
                    <label>Port Number:</label>
                    <input
                      type="number"
                      className="form-control"
                      value={port}
                      onChange={(e) => setPort(e.target.value)}
                    />
                  </div>

                  <div className="form-group">
                    <label>Protocol:</label>
                    <select
                      className="form-control"
                      value={protocol}
                      onChange={(e) => setProtocol(e.target.value)}
                    >
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                    </select>
                  </div>
                </div>

                {/* Proposed Rule Configuration Box */}
                <div className="proposed-rule-box">
                  <div
                    className="rule-header-toggle"
                    onClick={() => setHasProposedRule(!hasProposedRule)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <input
                        type="checkbox"
                        checked={hasProposedRule}
                        onChange={(e) => setHasProposedRule(e.target.checked)}
                        style={{ cursor: 'pointer', width: '16px', height: '16px' }}
                      />
                      <strong style={{ fontSize: '0.95rem' }}>Simulate a Proposed Rule Change</strong>
                    </div>
                    <span style={{ fontSize: '0.8rem', color: '#9ca3af' }}>
                      {hasProposedRule ? 'Evaluating with proposed rule' : 'Testing baseline policy only'}
                    </span>
                  </div>

                  {hasProposedRule && (
                    <div className="simulator-grid" style={{ marginTop: '16px', marginBottom: 0 }}>
                      <div className="form-group">
                        <label>Proposed Rule Label:</label>
                        <input
                          type="text"
                          className="form-control"
                          value={proposedRuleName}
                          onChange={(e) => setProposedRuleName(e.target.value)}
                          placeholder="e.g. Allow HR DB Direct Access"
                        />
                      </div>

                      <div className="form-group">
                        <label>Action:</label>
                        <select
                          className="form-control"
                          value={proposedRuleAction}
                          onChange={(e) => setProposedRuleAction(e.target.value)}
                        >
                          <option value="ALLOW">ALLOW</option>
                          <option value="DENY">DENY</option>
                        </select>
                      </div>

                      <div className="form-group">
                        <label>Priority (Lower = Higher precedence):</label>
                        <input
                          type="number"
                          className="form-control"
                          value={proposedRulePriority}
                          onChange={(e) => setProposedRulePriority(e.target.value)}
                          min="1"
                          max="998"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <div className="simulator-actions-row">
                  <button
                    className="btn-simulate"
                    onClick={handleSimulate}
                    disabled={loading || !backendOnline || segments.length === 0 || resources.length === 0}
                  >
                    <Play size={18} />
                    <span>{loading ? 'Evaluating Policies...' : 'Run Security Impact Simulation'}</span>
                  </button>

                  <button
                    type="button"
                    className="btn-preset"
                    onClick={() => {
                      if (hasProposedRule) {
                        setPolicyViewMode('proposed');
                      }
                      setActiveTab('topology');
                    }}
                  >
                    <Network size={16} color="#60a5fa" />
                    <span>View Path in Network Topology</span>
                  </button>
                </div>

                {simulationError && (
                  <div className="error-callout" role="alert">
                    <AlertTriangle size={18} color="#f87171" />
                    <span>{simulationError}</span>
                  </div>
                )}
              </div>

              {/* SIMULATION RESULTS VIEW */}
              {simulationResult && (
                <div>
                  {/* Critical Security Risk Banner */}
                  {simulationResult.risk_detected ? (
                    <div className="risk-banner">
                      <div className="risk-banner-header">
                        <ShieldAlert size={28} color="#ef4444" />
                        <h3>CRITICAL SECURITY VIOLATION FLAGGED</h3>
                      </div>
                      <p style={{ color: '#fecaca', fontSize: '0.95rem', marginBottom: '14px' }}>
                        The proposed change introduces a direct policy breach against enterprise security boundaries.
                        <strong> This change must not be deployed.</strong>
                      </p>

                      {simulationResult.violations.map((violation, idx) => (
                        <div key={idx} className="violation-item">
                          <div className="violation-title">
                            ⚠️ Guardrail {violation.guardrail_id}: {violation.name} [{violation.severity}]
                          </div>
                          <div className="violation-desc">
                            {violation.description}
                          </div>
                          <div className="violation-rationale">
                            <strong>Compliance Impact:</strong> {violation.rationale}
                          </div>
                        </div>
                      ))}

                      <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(0,0,0,0.4)', borderRadius: '6px' }}>
                        <span style={{ fontWeight: '600', color: '#f87171' }}>Platform Recommendation: </span>
                        <span style={{ color: '#ffffff' }}>{simulationResult.recommendation}</span>
                      </div>
                    </div>
                  ) : (
                    <div className="safe-banner">
                      <ShieldCheck size={28} color="#10b981" />
                      <div>
                        <strong style={{ color: '#34d399', fontSize: '1.05rem', display: 'block' }}>
                          No Security Violations Detected
                        </strong>
                        <span style={{ color: '#d1fae5', fontSize: '0.88rem' }}>
                          {simulationResult.recommendation}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Before vs. After Side-by-Side Comparison */}
                  <div className="card" style={{ marginTop: '24px' }}>
                    <div className="comparison-card-top">
                      <h3 className="card-title" style={{ margin: 0 }}>
                        <Layers size={20} color="#3b82f6" />
                        <span>Before vs. After Policy Impact Analysis</span>
                      </h3>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                        <span className={`badge ${
                          simulationResult.change_type === 'ACCESS_GRANTED'
                            ? (simulationResult.risk_detected ? 'badge-critical' : 'badge-allowed')
                            : (simulationResult.change_type === 'ACCESS_REVOKED' ? 'badge-denied' : 'badge-warning')
                        }`}>
                          Delta: {simulationResult.change_type}
                        </span>
                        <button
                          type="button"
                          className="btn-preset"
                          onClick={() => {
                            setPolicyViewMode(hasProposedRule ? 'proposed' : 'baseline');
                            setActiveTab('topology');
                          }}
                        >
                          <Network size={14} color="#60a5fa" />
                          <span>Inspect in Topology</span>
                        </button>
                      </div>
                    </div>

                    <div className="comparison-container">
                      {/* Before Card */}
                      <div className={`comparison-card ${simulationResult.current_evaluation.status === 'ALLOWED' ? 'allowed' : 'denied'}`}>
                        <div className="comparison-header">
                          <h4>BEFORE (Current Baseline)</h4>
                          <span className={`badge ${simulationResult.current_evaluation.status === 'ALLOWED' ? 'badge-allowed' : 'badge-denied'}`}>
                            {simulationResult.current_evaluation.status === 'ALLOWED' ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                            {simulationResult.current_evaluation.status}
                          </span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Matched Policy:</span>
                          <span className="meta-value">{simulationResult.current_evaluation.matched_rule_name}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Rule Priority:</span>
                          <span className="meta-value">Priority {simulationResult.current_evaluation.matched_rule_priority}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Explanation:</span>
                          <span style={{ fontSize: '0.84rem', color: '#9ca3af' }}>
                            {simulationResult.current_evaluation.explanation}
                          </span>
                        </div>
                      </div>

                      {/* After Card */}
                      <div className={`comparison-card ${
                        simulationResult.risk_detected
                          ? 'denied'
                          : (simulationResult.proposed_evaluation.status === 'ALLOWED' ? 'allowed' : 'denied')
                      }`}>
                        <div className="comparison-header">
                          <h4>AFTER (Proposed Policy)</h4>
                          <span className={`badge ${
                            simulationResult.risk_detected
                              ? 'badge-critical'
                              : (simulationResult.proposed_evaluation.status === 'ALLOWED' ? 'badge-allowed' : 'badge-denied')
                          }`}>
                            {simulationResult.risk_detected ? (
                              <>
                                <AlertTriangle size={13} />
                                CRITICAL RISK
                              </>
                            ) : (
                              simulationResult.proposed_evaluation.status === 'ALLOWED' ? (
                                <><CheckCircle2 size={13} /> ALLOWED</>
                              ) : (
                                <><XCircle size={13} /> DENIED</>
                              )
                            )}
                          </span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Active Rule:</span>
                          <span className="meta-value">{simulationResult.proposed_evaluation.matched_rule_name}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Rule Priority:</span>
                          <span className="meta-value">Priority {simulationResult.proposed_evaluation.matched_rule_priority}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Security Evaluation:</span>
                          <span style={{ fontSize: '0.84rem', color: simulationResult.risk_detected ? '#fca5a5' : '#9ca3af' }}>
                            {simulationResult.risk_detected
                              ? `Traffic is allowed by the proposed rule, but rejected by Independent Security Guardrail ${simulationResult.violations.map((v) => v.guardrail_id).join(', ')}.`
                              : simulationResult.proposed_evaluation.explanation
                            }
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: INTERACTIVE NETWORK TOPOLOGY */}
          {activeTab === 'topology' && (
            <NetworkTopology
              segments={segments}
              resources={resources}
              backendOnline={backendOnline}
              topologyLoading={topologyLoading}
              apiError={apiError}
              onRetryConnection={fetchAllBackendData}
              sourceSegment={sourceSegment}
              onSelectSourceSegment={setSourceSegment}
              destinationResource={destinationResource}
              onSelectDestinationResource={handleSelectDestinationResource}
              port={port}
              onChangePort={setPort}
              protocol={protocol}
              onChangeProtocol={setProtocol}
              hasProposedRule={hasProposedRule}
              proposedRuleName={proposedRuleName}
              proposedRuleAction={proposedRuleAction}
              proposedRulePriority={proposedRulePriority}
              policyViewMode={policyViewMode}
              onChangePolicyViewMode={setPolicyViewMode}
              connectivityResult={connectivityResult}
              connectivityLoading={connectivityLoading}
              connectivityError={connectivityError}
              onRefreshConnectivity={evaluateConnectivity}
              onOpenSimulator={() => setActiveTab('simulator')}
            />
          )}

          {/* TAB 3: SECURITY GUARDRAILS */}
          {activeTab === 'guardrails' && (
            <div className="card">
              <h3 className="card-title">
                <ShieldAlert size={20} color="#ef4444" />
                <span>Enterprise Security Guardrails & Hard Boundaries</span>
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '0.9rem', marginBottom: '20px' }}>
                Guardrails represent absolute compliance and security constraints. Even if an engineer writes an
                <code style={{ color: '#60a5fa', margin: '0 4px' }}>ALLOW</code> firewall rule,
                NetImpact intercepts and blocks it if it breaches these guardrails.
              </p>

              <div className="table-responsive">
                <table className="custom-table">
                  <thead>
                    <tr>
                      <th>Guardrail ID</th>
                      <th>Name</th>
                      <th>Forbidden Source</th>
                      <th>Protected Destination</th>
                      <th>Severity</th>
                      <th>Regulatory Rationale</th>
                    </tr>
                  </thead>
                  <tbody>
                    {guardrails.map((g) => (
                      <tr key={g.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: '#60a5fa' }}>{g.id}</td>
                        <td><strong>{g.name}</strong></td>
                        <td><code>{g.forbidden_source}</code></td>
                        <td><code>{g.forbidden_destination}</code></td>
                        <td>
                          <span className={`badge ${g.severity === 'CRITICAL' ? 'badge-critical' : 'badge-warning'}`}>
                            {g.severity}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.82rem', color: '#9ca3af' }}>{g.rationale}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: ACTIVE BASELINE POLICIES */}
          {activeTab === 'policies' && (
            <div className="card">
              <h3 className="card-title">
                <FileText size={20} color="#3b82f6" />
                <span>Current Active Firewall Policies</span>
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '0.9rem', marginBottom: '20px' }}>
                Rules are evaluated in ascending priority order (lowest number first). The first rule that matches a packet
                dictates the action. Unmatched traffic falls through to Rule 999 (Default Deny).
              </p>

              <div className="table-responsive">
                <table className="custom-table">
                  <thead>
                    <tr>
                      <th>Priority</th>
                      <th>Rule ID</th>
                      <th>Rule Label</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {policies.map((p) => (
                      <tr key={p.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: '#93c5fd' }}>
                          #{p.priority}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{p.id}</td>
                        <td><strong>{p.name}</strong></td>
                        <td><code>{p.source_segment}</code></td>
                        <td><code>{p.destination_resource}</code></td>
                        <td>{p.port !== null ? p.port : 'ANY'}</td>
                        <td>{p.protocol}</td>
                        <td>
                          <span className={`badge ${p.action === 'ALLOW' ? 'badge-allowed' : 'badge-denied'}`}>
                            {p.action}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
