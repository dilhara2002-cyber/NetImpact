import React from 'react';
import {
  Network,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Database,
  Play,
  RefreshCw,
  ArrowRight,
  Info
} from 'lucide-react';

function truncateText(text, maxLength) {
  if (!text) return '';
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

export default function NetworkTopology({
  segments,
  resources,
  backendOnline,
  topologyLoading,
  apiError,
  onRetryConnection,
  sourceSegment,
  onSelectSourceSegment,
  destinationResource,
  onSelectDestinationResource,
  port,
  onChangePort,
  protocol,
  onChangeProtocol,
  hasProposedRule,
  proposedRuleName,
  proposedRuleAction,
  proposedRulePriority,
  policyViewMode,
  onChangePolicyViewMode,
  connectivityResult,
  connectivityLoading,
  connectivityError,
  onRefreshConnectivity,
  onOpenSimulator
}) {
  const selectedSegmentObj = segments.find((s) => s.id === sourceSegment) || null;
  const selectedResourceObj = resources.find((r) => r.id === destinationResource) || null;

  const isProposedMode = policyViewMode === 'proposed' && hasProposedRule;
  const activeEval = connectivityResult
    ? isProposedMode
      ? connectivityResult.proposed_evaluation
      : connectivityResult.current_evaluation
    : null;

  const isAllowed = activeEval?.status === 'ALLOWED';
  const hasGuardrailRisk =
    Boolean(connectivityResult?.risk_detected) && isProposedMode && isAllowed;

  // Compute responsive SVG node coordinates dynamically from FastAPI data
  const svgWidth = 960;
  const nodeHeight = 96;
  const rowGap = 24;
  const topPadding = 48;
  const bottomPadding = 32;
  const maxNodes = Math.max(segments.length, resources.length, 1);
  const svgHeight = Math.max(
    410,
    topPadding + maxNodes * nodeHeight + Math.max(0, maxNodes - 1) * rowGap + bottomPadding
  );

  const getNodeY = (index, count) => {
    const totalGroupHeight = count * nodeHeight + Math.max(0, count - 1) * rowGap;
    const availableHeight = svgHeight - topPadding - bottomPadding;
    const startY = topPadding + Math.max(0, (availableHeight - totalGroupHeight) / 2);
    return startY + index * (nodeHeight + rowGap);
  };

  const leftX = 24;
  const leftW = 250;
  const centerW = 200;
  const centerX = (svgWidth - centerW) / 2;
  const centerH = 176;
  const centerY = (svgHeight - centerH) / 2 + 8;
  const rightX = svgWidth - 274;
  const rightW = 250;

  const selectedSegIndex = segments.findIndex((s) => s.id === sourceSegment);
  const selectedResIndex = resources.findIndex((r) => r.id === destinationResource);

  const sourceAnchor =
    selectedSegIndex >= 0
      ? {
          x: leftX + leftW,
          y: getNodeY(selectedSegIndex, segments.length) + nodeHeight / 2
        }
      : null;

  const firewallLeftAnchor = { x: centerX, y: centerY + centerH / 2 };
  const firewallRightAnchor = { x: centerX + centerW, y: centerY + centerH / 2 };

  const destAnchor =
    selectedResIndex >= 0
      ? {
          x: rightX,
          y: getNodeY(selectedResIndex, resources.length) + nodeHeight / 2
        }
      : null;

  const activeStrokeColor = !activeEval
    ? '#60a5fa'
    : isAllowed
      ? '#10b981'
      : '#ef4444';

  const statusTextLabel = !activeEval
    ? 'CHECKING...'
    : isAllowed
      ? 'ALLOWED'
      : 'DENIED';

  return (
    <div>
      {!backendOnline && (
        <div className="offline-banner" role="alert">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <AlertTriangle size={22} color="#fbbf24" />
            <div>
              <strong>FastAPI Backend Disconnected</strong>
              <p style={{ fontSize: '0.86rem', color: '#fde68a', marginTop: '2px' }}>
                {apiError ||
                  'Start the FastAPI backend on port 8000 so NetImpact can load live network segments and run the Python policy engine.'}
              </p>
            </div>
          </div>
          <button className="btn-preset" onClick={onRetryConnection}>
            <RefreshCw size={15} />
            <span>Retry Connection</span>
          </button>
        </div>
      )}

      {/* Interactive Connection Controls */}
      <div className="card">
        <div className="topology-controls-header">
          <h3 className="card-title" style={{ marginBottom: 0 }}>
            <Network size={20} color="#3b82f6" />
            <span>Interactive Connectivity Analyzer</span>
          </h3>

          <div className="policy-mode-toggle" role="group" aria-label="Policy evaluation mode">
            <button
              type="button"
              className={`mode-btn ${policyViewMode === 'baseline' ? 'active' : ''}`}
              onClick={() => onChangePolicyViewMode('baseline')}
            >
              Current Baseline (Before)
            </button>
            <button
              type="button"
              className={`mode-btn ${policyViewMode === 'proposed' ? 'active' : ''}`}
              onClick={() => onChangePolicyViewMode('proposed')}
              disabled={!hasProposedRule}
              title={
                hasProposedRule
                  ? 'Inspect proposed rule impact on topology'
                  : 'Enable a proposed rule in the Policy Simulator to compare Before/After'
              }
            >
              Proposed Policy (After)
              {hasProposedRule && <span className="mode-dot" aria-hidden="true" />}
            </button>
          </div>
        </div>

        <p className="topology-subtitle">
          Click any source network segment and destination asset on the map—or choose them below—to evaluate live connectivity through the Python policy engine.
        </p>

        <div className="simulator-grid" style={{ marginBottom: '16px' }}>
          <div className="form-group">
            <label htmlFor="topo-source-select">Source Segment:</label>
            <select
              id="topo-source-select"
              className="form-control"
              value={sourceSegment}
              onChange={(e) => onSelectSourceSegment(e.target.value)}
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
            <label htmlFor="topo-dest-select">Destination Resource:</label>
            <select
              id="topo-dest-select"
              className="form-control"
              value={destinationResource}
              onChange={(e) => onSelectDestinationResource(e.target.value)}
              disabled={resources.length === 0}
            >
              {resources.length === 0 ? (
                <option value="">Loading resources from API...</option>
              ) : (
                resources.map((res) => (
                  <option key={res.id} value={res.id}>
                    {res.name} ({res.ip}) {res.is_critical ? '[CRITICAL]' : ''}
                  </option>
                ))
              )}
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="topo-port-input">Destination Port:</label>
            <input
              id="topo-port-input"
              type="number"
              min="1"
              max="65535"
              className="form-control"
              value={port}
              onChange={(e) => onChangePort(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label htmlFor="topo-protocol-select">Protocol:</label>
            <select
              id="topo-protocol-select"
              className="form-control"
              value={protocol}
              onChange={(e) => onChangeProtocol(e.target.value)}
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
            </select>
          </div>
        </div>

        <div className="topology-action-bar">
          <div className="topology-legend" aria-label="Topology color and status legend">
            <span className="legend-item">
              <CheckCircle2 size={15} color="#10b981" />
              <span>Green Path = ALLOWED</span>
            </span>
            <span className="legend-item">
              <XCircle size={15} color="#ef4444" />
              <span>Red Path = DENIED</span>
            </span>
            <span className="legend-item">
              <ShieldAlert size={15} color="#f59e0b" />
              <span>Critical Asset / Guardrail Boundary</span>
            </span>
          </div>

          <div className="topology-buttons">
            <button
              type="button"
              className="btn-preset"
              onClick={onRefreshConnectivity}
              disabled={!backendOnline || connectivityLoading}
            >
              <RefreshCw size={15} />
              <span>{connectivityLoading ? 'Evaluating...' : 'Re-evaluate Path'}</span>
            </button>
            <button
              type="button"
              className="btn-preset btn-preset-primary"
              onClick={onOpenSimulator}
            >
              <Play size={15} />
              <span>
                {hasProposedRule ? 'Edit Proposed Rule in Simulator' : 'Simulate Rule Change'}
              </span>
            </button>
          </div>
        </div>

        {/* Interactive Topology Diagram */}
        <div className="topology-canvas-wrapper">
          {topologyLoading && segments.length === 0 ? (
            <div className="topology-empty-state">
              Loading network segments and assets from FastAPI...
            </div>
          ) : segments.length === 0 || resources.length === 0 ? (
            <div className="topology-empty-state">
              No topology data available. Ensure FastAPI is running at{' '}
              <code>http://127.0.0.1:8000</code> and click Retry Connection.
            </div>
          ) : (
            <svg
              className="topology-svg"
              viewBox={`0 0 ${svgWidth} ${svgHeight}`}
              role="img"
              aria-label={`Interactive network topology diagram showing ${selectedSegmentObj?.name || sourceSegment} to ${selectedResourceObj?.name || destinationResource} status ${statusTextLabel}`}
            >
              <defs>
                <marker
                  id="arrow-allowed"
                  viewBox="0 0 10 10"
                  refX="8"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
                </marker>
                <marker
                  id="arrow-denied"
                  viewBox="0 0 10 10"
                  refX="8"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
                </marker>
                <marker
                  id="arrow-neutral"
                  viewBox="0 0 10 10"
                  refX="8"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#60a5fa" />
                </marker>
              </defs>

              {/* Column Headings */}
              <text x={leftX} y={24} className="svg-column-heading">
                1. SOURCE NETWORK SEGMENTS
              </text>
              <text
                x={centerX + centerW / 2}
                y={24}
                textAnchor="middle"
                className="svg-column-heading"
              >
                2. LOGICAL FIREWALL BOUNDARY
              </text>
              <text x={rightX} y={24} className="svg-column-heading">
                3. DESTINATION RESOURCES & ASSETS
              </text>

              {/* Vertical Security Boundary Line */}
              <line
                x1={centerX + centerW / 2}
                y1={36}
                x2={centerX + centerW / 2}
                y2={svgHeight - 16}
                stroke="#334155"
                strokeWidth="2"
                strokeDasharray="6 6"
              />

              {/* Subtle inactive baseline topology links */}
              {segments.map((seg, idx) => {
                const y = getNodeY(idx, segments.length) + nodeHeight / 2;
                return (
                  <path
                    key={`bg-seg-${seg.id}`}
                    d={`M ${leftX + leftW} ${y} C ${leftX + leftW + 45} ${y}, ${centerX - 45} ${centerY + centerH / 2}, ${centerX} ${centerY + centerH / 2}`}
                    fill="none"
                    stroke="#263244"
                    strokeWidth="1.5"
                    strokeDasharray="4 4"
                  />
                );
              })}
              {resources.map((res, idx) => {
                const y = getNodeY(idx, resources.length) + nodeHeight / 2;
                return (
                  <path
                    key={`bg-res-${res.id}`}
                    d={`M ${centerX + centerW} ${centerY + centerH / 2} C ${centerX + centerW + 45} ${centerY + centerH / 2}, ${rightX - 45} ${y}, ${rightX} ${y}`}
                    fill="none"
                    stroke="#263244"
                    strokeWidth="1.5"
                    strokeDasharray="4 4"
                  />
                );
              })}

              {/* Active Evaluated Connection Path */}
              {sourceAnchor && destAnchor && (
                <g>
                  <path
                    d={`M ${sourceAnchor.x} ${sourceAnchor.y} C ${sourceAnchor.x + 55} ${sourceAnchor.y}, ${firewallLeftAnchor.x - 55} ${firewallLeftAnchor.y}, ${firewallLeftAnchor.x} ${firewallLeftAnchor.y}`}
                    fill="none"
                    stroke={activeStrokeColor}
                    strokeWidth="3.5"
                    strokeDasharray={isAllowed ? undefined : '7 5'}
                  />
                  <path
                    d={`M ${firewallRightAnchor.x} ${firewallRightAnchor.y} C ${firewallRightAnchor.x + 55} ${firewallRightAnchor.y}, ${destAnchor.x - 55} ${destAnchor.y}, ${destAnchor.x - 4} ${destAnchor.y}`}
                    fill="none"
                    stroke={activeStrokeColor}
                    strokeWidth="3.5"
                    strokeDasharray={isAllowed ? undefined : '7 5'}
                    markerEnd={
                      !activeEval
                        ? 'url(#arrow-neutral)'
                        : isAllowed
                          ? 'url(#arrow-allowed)'
                          : 'url(#arrow-denied)'
                    }
                  />

                  {/* Accessible path status label pill */}
                  <g
                    transform={`translate(${centerX + centerW / 2}, ${centerY - 22})`}
                  >
                    <rect
                      x="-96"
                      y="-14"
                      width="192"
                      height="26"
                      rx="13"
                      fill={
                        !activeEval
                          ? '#1e293b'
                          : isAllowed
                            ? '#064e3b'
                            : '#7f1d1d'
                      }
                      stroke={activeStrokeColor}
                      strokeWidth="1.5"
                    />
                    <text
                      x="0"
                      y="3"
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize="11.5"
                      fontWeight="700"
                      fontFamily="Inter, sans-serif"
                    >
                      {`${statusTextLabel} • ${protocol.toUpperCase()}/${port || '?'}`}
                    </text>
                  </g>
                </g>
              )}

              {/* Source Segment Nodes */}
              {segments.map((seg, idx) => {
                const y = getNodeY(idx, segments.length);
                const isSelected = seg.id === sourceSegment;
                return (
                  <g
                    key={seg.id}
                    className="svg-interactive-node"
                    role="button"
                    tabIndex={0}
                    aria-pressed={isSelected}
                    aria-label={`Select source segment ${seg.name} (${seg.cidr})`}
                    onClick={() => onSelectSourceSegment(seg.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectSourceSegment(seg.id);
                      }
                    }}
                  >
                    <title>{`${seg.name} (${seg.cidr}) — ${seg.security_zone}`}</title>
                    <rect
                      x={leftX}
                      y={y}
                      width={leftW}
                      height={nodeHeight}
                      rx="12"
                      fill={isSelected ? '#172554' : '#1f2937'}
                      stroke={isSelected ? '#3b82f6' : '#374151'}
                      strokeWidth={isSelected ? '2.5' : '1.5'}
                    />
                    <text
                      x={leftX + 14}
                      y={y + 26}
                      fill="#f9fafb"
                      fontSize="13.5"
                      fontWeight="700"
                      fontFamily="Inter, sans-serif"
                    >
                      {truncateText(seg.name, 25)}
                    </text>
                    <rect
                      x={leftX + 14}
                      y={y + 38}
                      width="116"
                      height="22"
                      rx="6"
                      fill="rgba(59, 130, 246, 0.2)"
                    />
                    <text
                      x={leftX + 22}
                      y={y + 53}
                      fill="#93c5fd"
                      fontSize="11.5"
                      fontWeight="600"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {seg.cidr}
                    </text>
                    <text
                      x={leftX + 14}
                      y={y + 79}
                      fill="#9ca3af"
                      fontSize="11"
                      fontFamily="Inter, sans-serif"
                    >
                      {`Zone: ${truncateText(seg.security_zone, 24)}`}
                    </text>
                    {isSelected && (
                      <g transform={`translate(${leftX + leftW - 76}, ${y + 38})`}>
                        <rect
                          x="0"
                          y="0"
                          width="64"
                          height="22"
                          rx="11"
                          fill="#2563eb"
                        />
                        <text
                          x="32"
                          y="15"
                          textAnchor="middle"
                          fill="#ffffff"
                          fontSize="10"
                          fontWeight="700"
                          fontFamily="Inter, sans-serif"
                        >
                          SOURCE
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}

              {/* Center Logical Firewall / Policy Engine Boundary */}
              <g>
                <rect
                  x={centerX}
                  y={centerY}
                  width={centerW}
                  height={centerH}
                  rx="14"
                  fill="#0f172a"
                  stroke={
                    hasGuardrailRisk
                      ? '#f59e0b'
                      : activeEval
                        ? activeStrokeColor
                        : '#475569'
                  }
                  strokeWidth="2.5"
                />
                <text
                  x={centerX + centerW / 2}
                  y={centerY + 28}
                  textAnchor="middle"
                  fill="#f8fafc"
                  fontSize="13"
                  fontWeight="800"
                  fontFamily="Inter, sans-serif"
                >
                  LOGICAL FIREWALL
                </text>
                <text
                  x={centerX + centerW / 2}
                  y={centerY + 46}
                  textAnchor="middle"
                  fill="#94a3b8"
                  fontSize="11"
                  fontFamily="Inter, sans-serif"
                >
                  {isProposedMode ? 'Proposed Policy Mode' : 'Baseline Policy Mode'}
                </text>

                {/* Status Pill inside Firewall */}
                <rect
                  x={centerX + 24}
                  y={centerY + 60}
                  width={centerW - 48}
                  height="30"
                  rx="8"
                  fill={
                    !activeEval
                      ? '#1e293b'
                      : isAllowed
                        ? 'rgba(16, 185, 129, 0.2)'
                        : 'rgba(239, 68, 68, 0.2)'
                  }
                  stroke={activeStrokeColor}
                  strokeWidth="1.2"
                />
                <text
                  x={centerX + centerW / 2}
                  y={centerY + 79}
                  textAnchor="middle"
                  fill={!activeEval ? '#cbd5e1' : isAllowed ? '#34d399' : '#fca5a5'}
                  fontSize="12.5"
                  fontWeight="800"
                  fontFamily="Inter, sans-serif"
                >
                  {activeEval
                    ? isAllowed
                      ? '✓ ALLOWED'
                      : '✕ DENIED'
                    : 'AWAITING API'}
                </text>

                <text
                  x={centerX + centerW / 2}
                  y={centerY + 112}
                  textAnchor="middle"
                  fill="#cbd5e1"
                  fontSize="11"
                  fontFamily="JetBrains Mono, monospace"
                >
                  {activeEval
                    ? `${activeEval.matched_rule_id} (Prio ${activeEval.matched_rule_priority})`
                    : 'No evaluation yet'}
                </text>

                <text
                  x={centerX + centerW / 2}
                  y={centerY + 132}
                  textAnchor="middle"
                  fill={
                    hasGuardrailRisk
                      ? '#fbbf24'
                      : activeEval?.is_default_deny
                        ? '#fca5a5'
                        : '#94a3b8'
                  }
                  fontSize="10.5"
                  fontWeight={hasGuardrailRisk ? '700' : '500'}
                  fontFamily="Inter, sans-serif"
                >
                  {hasGuardrailRisk
                    ? '⚠ GUARDRAIL VIOLATION'
                    : activeEval?.is_default_deny
                      ? 'Default-Deny Enforced'
                      : 'Security Boundary Active'}
                </text>

                {connectivityResult && hasProposedRule && (
                  <text
                    x={centerX + centerW / 2}
                    y={centerY + 154}
                    textAnchor="middle"
                    fill="#93c5fd"
                    fontSize="10"
                    fontWeight="600"
                    fontFamily="Inter, sans-serif"
                  >
                    {`Delta: ${connectivityResult.change_type}`}
                  </text>
                )}
              </g>

              {/* Destination Resource Nodes */}
              {resources.map((res, idx) => {
                const y = getNodeY(idx, resources.length);
                const isSelected = res.id === destinationResource;
                const borderColor = isSelected
                  ? activeEval
                    ? activeStrokeColor
                    : '#3b82f6'
                  : res.is_critical
                    ? 'rgba(239, 68, 68, 0.65)'
                    : '#374151';

                return (
                  <g
                    key={res.id}
                    className="svg-interactive-node"
                    role="button"
                    tabIndex={0}
                    aria-pressed={isSelected}
                    aria-label={`Select destination resource ${res.name} (${res.ip}:${res.port})`}
                    onClick={() => onSelectDestinationResource(res.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectDestinationResource(res.id);
                      }
                    }}
                  >
                    <title>{`${res.name} (${res.ip}:${res.port}/${res.protocol}) — ${res.description}`}</title>
                    <rect
                      x={rightX}
                      y={y}
                      width={rightW}
                      height={nodeHeight}
                      rx="12"
                      fill={isSelected ? '#172554' : '#1f2937'}
                      stroke={borderColor}
                      strokeWidth={isSelected ? '2.5' : '1.5'}
                    />
                    <text
                      x={rightX + 14}
                      y={y + 26}
                      fill="#f9fafb"
                      fontSize="13.5"
                      fontWeight="700"
                      fontFamily="Inter, sans-serif"
                    >
                      {truncateText(res.name, 25)}
                    </text>

                    <rect
                      x={rightX + 14}
                      y={y + 38}
                      width="144"
                      height="22"
                      rx="6"
                      fill="rgba(59, 130, 246, 0.2)"
                    />
                    <text
                      x={rightX + 22}
                      y={y + 53}
                      fill="#93c5fd"
                      fontSize="11.5"
                      fontWeight="600"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {`${res.ip}:${res.port} ${res.protocol}`}
                    </text>

                    <text
                      x={rightX + 14}
                      y={y + 79}
                      fill="#9ca3af"
                      fontSize="11"
                      fontFamily="Inter, sans-serif"
                    >
                      {`Segment: ${res.segment_id}`}
                    </text>

                    {res.is_critical && (
                      <g transform={`translate(${rightX + rightW - 88}, ${y + 64})`}>
                        <rect
                          x="0"
                          y="0"
                          width="76"
                          height="20"
                          rx="10"
                          fill="rgba(239, 68, 68, 0.25)"
                          stroke="#ef4444"
                          strokeWidth="1"
                        />
                        <text
                          x="38"
                          y="13.5"
                          textAnchor="middle"
                          fill="#fca5a5"
                          fontSize="9.5"
                          fontWeight="700"
                          fontFamily="Inter, sans-serif"
                        >
                          CRITICAL
                        </text>
                      </g>
                    )}

                    {isSelected && (
                      <g transform={`translate(${rightX + rightW - 76}, ${y + 38})`}>
                        <rect
                          x="0"
                          y="0"
                          width="64"
                          height="22"
                          rx="11"
                          fill={activeEval ? activeStrokeColor : '#2563eb'}
                        />
                        <text
                          x="32"
                          y="15"
                          textAnchor="middle"
                          fill="#ffffff"
                          fontSize="10"
                          fontWeight="700"
                          fontFamily="Inter, sans-serif"
                        >
                          TARGET
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}
            </svg>
          )}
        </div>

        {connectivityError && (
          <div className="error-callout" role="alert">
            <AlertTriangle size={18} color="#f87171" />
            <span>{connectivityError}</span>
          </div>
        )}
      </div>

      {/* Evaluated Connectivity Verdict & Policy Details */}
      {connectivityResult && activeEval && (
        <div className="card">
          <div className="topology-controls-header" style={{ marginBottom: '16px' }}>
            <h3 className="card-title" style={{ marginBottom: 0 }}>
              <Shield size={20} color="#3b82f6" />
              <span>
                Connectivity Analysis Result (
                {isProposedMode ? 'Proposed Policy State' : 'Current Baseline State'})
              </span>
            </h3>

            <span
              className={`badge ${
                hasGuardrailRisk
                  ? 'badge-critical'
                  : isAllowed
                    ? 'badge-allowed'
                    : 'badge-denied'
              }`}
            >
              {isAllowed ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
              <span>
                {activeEval.status}
                {hasGuardrailRisk ? ' (GUARDRAIL VIOLATION)' : ''}
              </span>
            </span>
          </div>

          <div className="connectivity-summary-grid">
            <div className="meta-box">
              <span className="meta-label">Source Subnet</span>
              <span className="meta-value">{connectivityResult.source_cidr}</span>
              <span className="meta-subtext">{connectivityResult.source_segment_name}</span>
            </div>

            <div className="meta-box">
              <span className="meta-label">Destination IP & Target</span>
              <span className="meta-value">{connectivityResult.destination_ip}</span>
              <span className="meta-subtext">
                {connectivityResult.destination_resource_name}
                {connectivityResult.is_critical_target ? ' • Critical Asset' : ''}
              </span>
            </div>

            <div className="meta-box">
              <span className="meta-label">Protocol & Port</span>
              <span className="meta-value">
                {connectivityResult.protocol} / Port {connectivityResult.port}
              </span>
              <span className="meta-subtext">Evaluated by Python Policy Engine</span>
            </div>

            <div className="meta-box">
              <span className="meta-label">Matched Rule & Priority</span>
              <span className="meta-value">
                {activeEval.matched_rule_id} (Priority {activeEval.matched_rule_priority})
              </span>
              <span className="meta-subtext">{activeEval.matched_rule_name}</span>
            </div>
          </div>

          <div className="rule-reasoning-box">
            <div className="rule-reasoning-header">
              <Info size={16} color="#60a5fa" />
              <strong>Policy Evaluation Reasoning</strong>
            </div>
            <p className="rule-reasoning-text">{activeEval.explanation}</p>
            {activeEval.matched_rule_description && (
              <p className="rule-reasoning-subtext">
                Rule Description: {activeEval.matched_rule_description}
              </p>
            )}

            {activeEval.is_default_deny && activeEval.default_deny_reason && (
              <div className="default-deny-callout">
                <strong>Default-Deny Reasoning:</strong> {activeEval.default_deny_reason}
              </div>
            )}
          </div>

          {/* Before vs After Simulation Link */}
          <div className="topology-sim-link-box">
            <div className="topology-sim-link-header">
              <div>
                <strong>Before vs. After Policy Simulation Connection</strong>
                <p style={{ fontSize: '0.84rem', color: '#9ca3af', marginTop: '4px' }}>
                  {hasProposedRule
                    ? `Active proposed rule: "${proposedRuleName}" (${proposedRuleAction}, Priority ${proposedRulePriority})`
                    : 'No proposed rule is currently active. Enable one in the Policy Simulator to test how a change alters this path.'}
                </p>
              </div>
              <button
                type="button"
                className="btn-preset btn-preset-primary"
                onClick={onOpenSimulator}
              >
                <span>Open Full Before / After Analysis</span>
                <ArrowRight size={15} />
              </button>
            </div>

            <div className="mini-delta-grid">
              <div
                className={`mini-delta-card ${
                  connectivityResult.current_evaluation.status === 'ALLOWED'
                    ? 'allowed'
                    : 'denied'
                }`}
              >
                <span className="meta-label">BEFORE (Current Baseline)</span>
                <div className="mini-delta-status">
                  <span
                    className={`badge ${
                      connectivityResult.current_evaluation.status === 'ALLOWED'
                        ? 'badge-allowed'
                        : 'badge-denied'
                    }`}
                  >
                    {connectivityResult.current_evaluation.status === 'ALLOWED' ? (
                      <CheckCircle2 size={13} />
                    ) : (
                      <XCircle size={13} />
                    )}
                    {connectivityResult.current_evaluation.status}
                  </span>
                  <span className="meta-value">
                    {connectivityResult.current_evaluation.matched_rule_id} (Prio{' '}
                    {connectivityResult.current_evaluation.matched_rule_priority})
                  </span>
                </div>
              </div>

              <div
                className={`mini-delta-card ${
                  connectivityResult.risk_detected
                    ? 'denied'
                    : connectivityResult.proposed_evaluation.status === 'ALLOWED'
                      ? 'allowed'
                      : 'denied'
                }`}
              >
                <span className="meta-label">AFTER (Proposed Policy)</span>
                <div className="mini-delta-status">
                  <span
                    className={`badge ${
                      connectivityResult.risk_detected
                        ? 'badge-critical'
                        : connectivityResult.proposed_evaluation.status === 'ALLOWED'
                          ? 'badge-allowed'
                          : 'badge-denied'
                    }`}
                  >
                    {connectivityResult.risk_detected ? (
                      <>
                        <ShieldAlert size={13} />
                        CRITICAL RISK ({connectivityResult.proposed_evaluation.status})
                      </>
                    ) : connectivityResult.proposed_evaluation.status === 'ALLOWED' ? (
                      <>
                        <CheckCircle2 size={13} />
                        ALLOWED
                      </>
                    ) : (
                      <>
                        <XCircle size={13} />
                        DENIED
                      </>
                    )}
                  </span>
                  <span className="meta-value">
                    {connectivityResult.proposed_evaluation.matched_rule_id} (Prio{' '}
                    {connectivityResult.proposed_evaluation.matched_rule_priority})
                  </span>
                </div>
              </div>
            </div>

            {connectivityResult.risk_detected && connectivityResult.violations.length > 0 && (
              <div className="violation-item" style={{ marginTop: '14px' }}>
                <div className="violation-title">
                  Guardrail Breach: {connectivityResult.violations[0].guardrail_id} —{' '}
                  {connectivityResult.violations[0].name} [
                  {connectivityResult.violations[0].severity}]
                </div>
                <div className="violation-desc">
                  {connectivityResult.recommendation}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Segment & Asset Inventory Cards loaded from FastAPI */}
      <div className="card">
        <h3 className="card-title">
          <Network size={20} color="#3b82f6" />
          <span>Configured Network Segments (from FastAPI)</span>
        </h3>

        <div className="topology-grid">
          {segments.map((seg) => {
            const isSelected = seg.id === sourceSegment;
            return (
              <button
                type="button"
                key={seg.id}
                className={`segment-card segment-card-interactive ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelectSourceSegment(seg.id)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                  <strong style={{ fontSize: '1rem' }}>{seg.name}</strong>
                  <span className="segment-badge">{seg.cidr}</span>
                </div>
                <div style={{ fontSize: '0.8rem', color: '#60a5fa' }}>
                  Zone: {seg.security_zone}
                </div>
                <p style={{ fontSize: '0.85rem', color: '#9ca3af', textAlign: 'left' }}>
                  {seg.description}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      <div className="card">
        <h3 className="card-title">
          <Database size={20} color="#3b82f6" />
          <span>Destination Resources & Critical Assets (from FastAPI)</span>
        </h3>

        <div className="topology-grid">
          {resources.map((res) => {
            const isSelected = res.id === destinationResource;
            return (
              <button
                type="button"
                key={res.id}
                className={`segment-card segment-card-interactive ${isSelected ? 'selected' : ''}`}
                style={res.is_critical && !isSelected ? { borderColor: 'rgba(239, 68, 68, 0.7)' } : {}}
                onClick={() => onSelectDestinationResource(res.id)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', gap: '8px' }}>
                  <strong style={{ fontSize: '1rem', textAlign: 'left' }}>{res.name}</strong>
                  {res.is_critical && (
                    <span className="badge badge-critical">Critical Asset</span>
                  )}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#93c5fd' }}>
                  {res.ip} : {res.port} ({res.protocol}) • Segment: {res.segment_id}
                </div>
                <p style={{ fontSize: '0.85rem', color: '#9ca3af', textAlign: 'left' }}>
                  {res.description}
                </p>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
