import React, { useEffect, useRef, useState } from 'react';
import { CI_RUN, REPO, RELEASE, SCENARIOS, SOURCE, SOURCE_COMMIT } from './data/scenarios';
import type { Scenario } from './data/scenarios';
import { isRecord, requestJson, text, validateAnalysis, validateRecovery, validateReplay } from './api';
import type { JsonRecord } from './api';

type Mode = 'fixture' | 'live';
type Tab = 'verifier' | 'architecture' | 'benchmark';
type Health = 'checking' | 'available' | 'unavailable';
type Busy = 'analysis' | 'recovery' | null;
interface RunResult { source: Mode; data: JsonRecord }
const STAGES = ['Signing', 'Loss branch', 'Recovery branch', 'Replay check'];
const TABS: { id: Tab; label: string }[] = [
  { id: 'verifier', label: 'Verification playground' },
  { id: 'architecture', label: 'Mathematical model' },
  { id: 'benchmark', label: 'Evidence & citations' },
];

function Shield() {
  return <svg viewBox="0 0 32 38" fill="none" aria-hidden="true"><path d="M16 2 29 7v12c0 8-7 14-13 17C10 33 3 27 3 19V7L16 2Z" stroke="currentColor" strokeWidth="1.7" /><path d="m9 19 5 5 10-13" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}
function External({ href, children }: { href: string; children: React.ReactNode }) {
  return <a href={href} target="_blank" rel="noopener noreferrer">{children}<span aria-hidden="true"> ↗</span></a>;
}
function RawDetails({ title, data }: { title: string; data: JsonRecord }) {
  return <details className="raw-details"><summary>{title}</summary><pre>{JSON.stringify(data, null, 2)}</pre></details>;
}
function Hero() {
  return <section className="hero"><div className="wrap hero-grid">
    <div><div className="eyebrow">Ethereum capability verification / Interactive dashboard</div>
      <h1>A signature can<br />move nothing.<br /><em>And risk everything.</em></h1>
      <p className="hero-copy">Inspect the capability. Follow the modeled loss path. Check recovery on a separate state branch — with bundled fixtures or your existing local engine.</p>
      <div className="actions"><a className="btn btn-primary" href="#workspace">Open the dashboard <span aria-hidden="true">↗</span></a><a className="btn btn-secondary" href="/judge-demo.html">Judge walkthrough</a></div>
      <div className="hero-footnote">Hackathon prototype · No wallet connection · Local test scenarios</div>
    </div>
    <div className="visual" aria-label="Fixture illustration: loss and recovery start on separate branches, before funds are lost.">
      <div className="visual-head"><h2>Same signature. Different futures.</h2><span className="badge">Fixture example</span></div>
      <div className="mini-node"><div className="node-label"><span><span className="node-icon" aria-hidden="true">↗</span>Off-chain signing</span><span className="mono small">Step 0</span></div><div className="node-value">0.00 <span>immediate balance change</span></div></div>
      <div className="branch-line">↓ &nbsp; TWO SEPARATE LOCAL-STATE BRANCHES &nbsp; ↓</div>
      <div className="branch-pair"><div className="branch-box"><div className="b-label">Without recovery</div><strong>10,000</strong><p>test USDC loss in the<br />modeled fixture</p></div><div className="branch-box good"><div className="b-label">Recovery first</div><strong>0.00</strong><p>test USDC loss on<br />the known-trace check</p></div></div>
      <p className="visual-note">Illustration from bundled fixtures, not the current run. Recovery is evaluated before loss on a separate initial-state branch; it does not refund stolen assets.</p>
    </div>
  </div></section>;
}
function Snapshot() {
  return <section className="snapshot" aria-label="Published benchmark results"><div className="wrap">
    <div className="snapshot-head"><span>REPOSITORY-REPORTED BENCHMARK · v1.0.13 RELEASE CONTEXT</span><External href={`${SOURCE}/testdata/AEGIS_USENIX_EVALUATION.md`}>Read results and methodology</External></div>
    <div className="stats">{[
      ['58', 'USENIX-derived cases'], ['51 / 58', 'Executable loss witnesses'],
      ['51 / 51', 'Clean-state witness replays'], ['51 / 51', 'Known-trace neutralizations'],
    ].map(([value, label]) => <div className="stat" key={label}><strong>{value}</strong><p>{label}</p></div>)}</div>
  </div></section>;
}
function Scope() {
  return <section id="scope" className="scope"><div className="wrap scope-grid">
    <div><div className="eyebrow">03 / Know the boundary</div><h2>A concrete loss witness.<br />Not a universal safety promise.</h2></div>
    <div><p><strong>Bounded verification.</strong> The repository describes supported actions, a search depth up to three, and a primary tracked ERC-20 token. No modeled loss found does not establish global safety.</p>
    <p><strong>State-specific recovery.</strong> A known-trace replay check concerns the tested state and trace. It does not refund assets already lost, cover every future path, or guarantee live transaction ordering.</p>
    <p><strong>Separate evidence sources.</strong> Fixture values are bundled examples. Local-engine results are displayed only from the returned API evidence. Unknown, incomplete, or failed responses are not replaced with successful fixture outcomes. <External href={`${SOURCE}/engine/src/search/explorer.ts`}>Inspect engine scope and limitations</External></p></div>
  </div></section>;
}
function Evidence() {
  return <div className="view-content">
    <div className="view-heading"><div className="eyebrow">Source-backed, not a moving claim</div><h3>Evidence you can inspect.</h3><p>These are published repository results for the pinned release, not measurements performed by this dashboard session.</p></div>
    <div className="evidence-grid">
      <article className="evidence-box"><h3>Four published CI jobs.</h3><p>GitHub Actions run {CI_RUN} was reported successful for the source commit. The new frontend changes are not covered by that historical run.</p><ul className="checks">{['Foundry Solidity Tests','React Frontend Build','USENIX 58-Case Executable Benchmark','TypeScript Reachability Engine Kill Tests'].map(name => <li key={name}><span>{name}</span><span className="passed">Passed at source</span></li>)}</ul><External href={`${REPO}/actions/runs/${CI_RUN}`}>Inspect the original CI run</External></article>
      <article className="evidence-box"><h3>A pinned presentation baseline.</h3><p>The release, source revision, and historical CI form the evidence reference for both pages.</p><dl className="release-dl"><div><dt>Release</dt><dd><External href={`${REPO}/releases/tag/${RELEASE}`}>{RELEASE}</External></dd></div><div><dt>Source SHA</dt><dd className="mono">{SOURCE_COMMIT}</dd></div><div><dt>Review</dt><dd>26 September 2026</dd></div><div><dt>Frontend status</dt><dd>Restyled dashboard; separate UI verification is required for this revision.</dd></div></dl></article>
    </div>
    <article className="evidence-box evidence-method"><h3>Read the inclusion criteria before the headline.</h3><p>58 denotes the repository's USENIX-derived chain-address inclusion set. 51/58 is its reported executable witness yield; 51/51 replay and neutralization results are conditional on that discovered-witness subset. They are not detection accuracy for arbitrary wallets.</p><div className="reference-links"><External href={`${SOURCE}/testdata/AEGIS_USENIX_EVALUATION.md`}>Evaluation methodology</External><External href={`${SOURCE}/README.md`}>Architecture and limitations</External><External href={`${SOURCE}/SUBMISSION_EVIDENCE.md`}>Submission evidence</External></div></article>
  </div>;
}
function Architecture() {
  return <div className="view-content">
    <div className="view-heading"><div className="eyebrow">The verification contract</div><h3>Follow the state, not just the signature.</h3><p>Finding a concrete loss witness and establishing universal safety are different claims.</p></div>
    <div className="model-grid">
      <article className="evidence-box"><span className="card-index">01 / The signing moment</span><h3>No immediate change is not a guarantee.</h3><p>A detached authorization can change no balance when signed while still enabling a later loss-producing path.</p><div className="formula">SimulateCurrentExecution(c, s₀)<br /><span>⇏ SafeFutureCapability(c, s₀)</span></div></article>
      <article className="evidence-box"><span className="card-index">02 / The search boundary</span><h3>Search the supported action space.</h3><p>The repository's bounded explorer examines modeled transitions up to depth k ≤ 3. Unmodeled actions, deeper paths, or untracked assets remain outside this claim.</p><div className="formula">Found witness π:<br /><span>L(s₀, Tπ(s₀)) &gt; 0</span></div></article>
      <article className="evidence-box"><span className="card-index">03 / The separate branch</span><h3>Check prevention, not reimbursement.</h3><p>Recovery is tested on a separate copy of the initial state. A previously discovered trace is checked again after the recovery action.</p><div className="formula">Known-trace neutralization:<br /><span>L(sR, Tπ(sR)) = 0</span></div></article>
      <article className="evidence-box"><span className="card-index">04 / The output contract</span><h3>Unknown stays unknown.</h3><p><code>NO_MODELED_LOSS</code> is not global safety. <code>UNMODELED</code>, invalid responses, and infrastructure failures must not become green success states.</p><div className="formula">No witness found<br /><span>≠ every future path is safe</span></div></article>
    </div>
    <div className="branch-note">The local recovery API also returns a bounded portfolio re-search result. The dashboard displays that separately from the known-trace replay; neither is a guarantee against unmodeled capabilities.</div>
    <External href={`${SOURCE}/README.md`}>Read the full repository formulation</External>
  </div>;
}

export function App() {
  const urlParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
  const initialScenario = urlParams?.get('scenario');
  const validScenarioId = SCENARIOS.some(s => s.id === initialScenario) ? initialScenario! : SCENARIOS[0].id;
  const initialTab = urlParams?.get('tab') as Tab;
  const validTab: Tab = (initialTab === 'architecture' || initialTab === 'benchmark') ? initialTab : 'verifier';
  const initialStage = urlParams?.has('stage') ? Math.min(3, Math.max(0, parseInt(urlParams.get('stage')!) || 0)) : 0;

  const [selectedId, setSelectedId] = useState(validScenarioId);
  const [tab, setTab] = useState<Tab>(validTab);
  const [mode, setMode] = useState<Mode>('fixture');
  const [health, setHealth] = useState<Health>('checking');
  const [healthRefresh, setHealthRefresh] = useState(0);
  const [stage, setStage] = useState(initialStage);
  const [busy, setBusy] = useState<Busy>(null);
  const [result, setResult] = useState<RunResult | null>(null);
  const [receipt, setReceipt] = useState<JsonRecord | null>(null);
  const [replay, setReplay] = useState<JsonRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Async results are tied to a generation, preventing an old scenario from
  // replacing the current view after reset, mode change, or scenario selection.
  const generation = useRef(0);
  const pending = useRef<AbortController | null>(null);
  const busyRef = useRef(false);
  const scenario = SCENARIOS.find(item => item.id === selectedId) ?? SCENARIOS[0];

  useEffect(() => {
    const controller = new AbortController();
    let disposed = false;
    const timer = window.setTimeout(() => controller.abort(), 5000);
    setHealth('checking');
    requestJson('/api/health', controller.signal)
      .then(data => { if (!disposed && !controller.signal.aborted) setHealth(data.status === 'ok' || data.status === 'OK' ? 'available' : 'unavailable'); })
      .catch(() => { if (!disposed) setHealth('unavailable'); })
      .finally(() => window.clearTimeout(timer));
    return () => { disposed = true; window.clearTimeout(timer); controller.abort(); };
  }, [healthRefresh]);
  useEffect(() => () => { generation.current++; pending.current?.abort(); }, []);

  const reset = () => {
    generation.current++;
    pending.current?.abort(); pending.current = null; busyRef.current = false;
    setBusy(null); setStage(0); setResult(null); setReceipt(null); setReplay(null); setError(null);
  };
  const changeScenario = (id: string) => { if (id !== selectedId) { reset(); setSelectedId(id); } };
  const changeMode = (next: Mode) => { if (next !== mode) { reset(); setMode(next); } };
  const runOperation = async (kind: Exclude<Busy, null>, work: (signal: AbortSignal, current: () => boolean) => Promise<void>) => {
    if (busyRef.current) return;
    busyRef.current = true;
    const id = ++generation.current;
    pending.current?.abort();
    const controller = new AbortController(); pending.current = controller;
    setBusy(kind); setError(null);
    const current = () => generation.current === id && !controller.signal.aborted;
    const timeout = window.setTimeout(() => controller.abort(), kind === 'analysis' ? 45000 : 120000);
    try { await work(controller.signal, current); }
    catch (cause) {
      if (generation.current === id) {
        setError(controller.signal.aborted
          ? 'The local request timed out. Its outcome is unknown; no fixture success was substituted. Start a fresh analysis before retrying recovery.'
          : cause instanceof Error ? cause.message : 'Local engine request failed. No live outcome was accepted.');
      }
    } finally {
      window.clearTimeout(timeout);
      if (generation.current === id) { busyRef.current = false; pending.current = null; setBusy(null); }
    }
  };
  const runAnalysis = async () => {
    if (mode === 'fixture') { setStage(1); setResult({ source: 'fixture', data: { status: 'FOUND_LOSS' } }); return; }
    await runOperation('analysis', async (signal, current) => {
      setResult(null); setReceipt(null); setReplay(null);
      const data = validateAnalysis(await requestJson('/api/analyze', signal, { scenarioId: selectedId }));
      if (current()) { setResult({ source: 'live', data }); setHealth('available'); setStage(1); }
    });
  };
  const runRecovery = async () => {
    if (mode === 'fixture') { setStage(3); return; }
    if (result?.source !== 'live' || result.data.status !== 'FOUND_LOSS' || receipt) return;
    const runId = text(result.data.runId, '');
    if (!runId) return;
    await runOperation('recovery', async (signal, current) => {
      const recovered = validateRecovery(await requestJson('/api/recover', signal, { runId }), runId);
      if (!current()) return;
      setReceipt(recovered);
      const checked = validateReplay(await requestJson('/api/replay', signal, { runId }), runId);
      if (current()) { setReplay(checked); setStage(3); }
    });
  };

  const foundLoss = mode === 'fixture' || result?.data.status === 'FOUND_LOSS';
  const ce = result?.source === 'live' && isRecord(result.data.counterexample) ? result.data.counterexample : null;
  const loss = ce && isRecord(ce.loss) ? ce.loss : null;
  const plan = result?.source === 'live' && isRecord(result.data.recoveryPlan) ? result.data.recoveryPlan : null;
  const portfolio = receipt && isRecord(receipt.postRecoveryExplore) ? receipt.postRecoveryExplore : null;
  const canStage = (index: number) => mode === 'fixture' || index === 0 ||
    (index === 1 && !!result) || (index === 2 && !!result && foundLoss) || (index === 3 && !!replay);
  const next = () => {
    if (busy) return;
    if (stage === 0) { if (result) setStage(1); else void runAnalysis(); }
    else if (stage === 1 && foundLoss) setStage(2);
    else if (stage === 2) { if (replay) setStage(3); else void runRecovery(); }
    else reset();
  };
  const nextLabel = busy === 'analysis' ? 'Running local verifier…' : busy === 'recovery' ? 'Checking recovery & replay…' :
    stage === 0 ? mode === 'fixture' ? 'View fixture loss →' : result ? 'View analysis result →' : 'Run local verifier →' :
    stage === 1 ? foundLoss ? 'View recovery branch →' : 'Start a new analysis ↺' :
    stage === 2 ? mode === 'fixture' ? 'View recorded check →' : replay ? 'View replay result →' : 'Execute recovery & verify replay →' : 'Start again ↺';
  const nextDisabled = !!busy || (mode === 'live' && stage === 2 && !replay && (!!receipt || !!error || !plan));
  const fixtureText = [scenario.signing, scenario.lossDescription, scenario.recovery, scenario.replay][stage];
  const status = text(result?.data.status, 'Not run');
  const liveTitles: Record<string, string> = {
    FOUND_LOSS: 'The engine returned a loss witness.', NO_MODELED_LOSS: 'No modeled loss found within the bound.',
    UNMODELED: 'The engine cannot model this result.', INVALID_CAPABILITY: 'The capability was not accepted.',
    PROSPECTIVE_RISK: 'The engine reported prospective risk.',
  };
  const stageTitle = stage === 0 ? 'Nothing moves when you sign.' :
    stage === 1 ? mode === 'fixture' ? 'A later path can produce loss.' : liveTitles[status] ?? 'Analysis result unavailable.' :
    stage === 2 ? 'Test recovery on a separate branch.' : mode === 'fixture' ? 'Check the known trace again.' :
    replay?.mitigated === true ? 'The engine reports zero known-trace loss.' : 'The replay still reports tracked loss.';
  const liveText = stage === 0 ? 'Run the existing local engine against the selected bundled scenario. The fixture details below describe the scenario, not a fresh observation of your wallet.' :
    stage === 1 ? status === 'FOUND_LOSS' ? 'The metrics below come from this API response, not from the illustrative 10,000-USDC fixture. Inspect the response for the complete returned evidence.' : text(result?.data.reason, 'This status does not establish global safety. Recovery is unavailable unless the engine returns a complete loss witness.') :
    stage === 2 ? text(plan?.description, 'Review the engine-generated recovery plan. The existing local backend executes the recovery and known-trace check; this page does not connect to a wallet.') : text(replay?.message, 'No replay result has been accepted.');
  const branchNote = stage === 0 ? 'Initial fixture state. No immediate balance change is not a safety guarantee about later use of the authorization.' :
    stage === 1 ? 'Loss branch only. The recovery branch starts again from the original pre-loss state; it is not a refund.' :
    stage === 2 ? 'Separate initial-state branch, before loss. Cancelling or leaving the view does not roll back a backend operation already sent.' :
    'Known-trace check on the recovered branch. Other paths, assets, and live ordering risks remain outside this claim.';
  const metric = mode === 'fixture' ? ['0.00', '10,000.00', '10,000.00', '0.00'][stage] :
    stage === 0 ? '—' : stage === 1 && loss ? text(loss.formatted) : stage === 3 && replay ? text(replay.assetsLost) : '—';
  const metricLabel = mode === 'fixture' ? ['Immediate balance change', 'Modeled loss in the fixture', 'Starting balance on the clean branch', 'Loss on the recorded replay check'][stage] :
    stage === 0 ? 'Live verification not run' : stage === 1 ? loss ? 'Engine-reported tracked loss' : 'No loss metric returned' : stage === 2 ? 'Recovery plan — not executed here yet' : 'Engine-reported replay loss';
  const metricUnit = mode === 'fixture' ? 'test USDC · bundled fixture' : stage === 3 ? 'raw token units · exact API value' : loss && stage === 1 ? `${text(loss.symbol)} · local API response` : 'Not a measured zero';
  const tone = stage === 1 && foundLoss || stage === 3 && mode === 'live' && replay?.mitigated === false ? 'loss' : mode === 'live' && stage === 1 ? 'unknown' : 'neutral';
  const phase = mode === 'fixture' ? ['Initial fixture', 'Fixture loss', 'Separate branch', 'Recorded check'][stage] :
    stage === 0 ? 'Local mode' : stage === 1 ? status : stage === 2 ? 'Plan review' : 'API replay';

  return <>
    <a className="skip" href="#workspace">Skip to dashboard</a>
    <header className="topbar"><div className="wrap nav">
      <a className="brand" href="#main" aria-label="Aegis7702 home"><Shield />Aegis<span>7702</span></a>
      <nav aria-label="Main navigation"><a href="#workspace" className="nav-dashboard" aria-current="page">Dashboard</a><a href="/judge-demo.html" className="nav-demo">Judge demo</a><a href="#scope" className="nav-secondary">Scope</a><a className="nav-repo" href={REPO} target="_blank" rel="noopener noreferrer">GitHub ↗</a></nav>
    </div></header>
    <main id="main"><Hero /><Snapshot />
      <section id="workspace" className="section"><div className="wrap">
        <div className="section-head"><div><div className="eyebrow">01 / Main interactive dashboard</div><h2>Inspect. Verify. Check recovery.</h2></div><p>The same visual language as the judge demo, with the controls and evidence needed to inspect each result.</p></div>
        <div className="workspace-tabs" role="tablist" aria-label="Dashboard views">{TABS.map((item, index) => <button key={item.id} id={`tab-${item.id}`} type="button" role="tab" aria-selected={tab === item.id} aria-controls={`panel-${item.id}`} tabIndex={tab === item.id ? 0 : -1} onClick={() => setTab(item.id)} onKeyDown={event => {
          const nextIndex = event.key === 'ArrowRight' ? (index + 1) % TABS.length : event.key === 'ArrowLeft' ? (index + TABS.length - 1) % TABS.length : event.key === 'Home' ? 0 : event.key === 'End' ? TABS.length - 1 : -1;
          if (nextIndex >= 0) { event.preventDefault(); setTab(TABS[nextIndex].id); document.getElementById(`tab-${TABS[nextIndex].id}`)?.focus(); }
        }}>{item.label}</button>)}</div>
        <div className="demo-shell app-shell" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
          {tab === 'verifier' ? <>
            <div className="demo-toolbar"><div><div className="mode">{mode === 'fixture' ? 'Fixture walkthrough · no live execution' : 'Local engine · API-backed results'}</div><p className="mode-note">{mode === 'fixture' ? 'Bundled examples are never presented as this session’s live results.' : 'Uses only the existing local scenario endpoints. No wallet connection.'}</p></div><div className="engine-health"><span className={`health-dot ${health}`} aria-hidden="true" /><span>{health === 'checking' ? 'Checking local API…' : health === 'available' ? 'Local API available' : 'Local API unavailable'}</span><button type="button" aria-label="Recheck local engine connection" onClick={() => setHealthRefresh(value => value + 1)} disabled={health === 'checking'}>↻</button></div></div>
            <div className="controls-row"><div className="segmented" role="group" aria-label="Execution mode"><button type="button" aria-pressed={mode === 'fixture'} onClick={() => changeMode('fixture')}>Fixture walkthrough</button><button type="button" aria-pressed={mode === 'live'} onClick={() => changeMode('live')}>Local engine</button></div><span className="control-hint">{mode === 'fixture' ? 'Offline presentation values' : 'Explicit execution on your local backend'}</span></div>
            <div className="scenario-group" role="group" aria-label="Test scenario">{SCENARIOS.map(item => <button type="button" key={item.id} className="scenario-btn" aria-pressed={selectedId === item.id} onClick={() => changeScenario(item.id)}><span>{item.name}</span><small>{item.protocol}</small></button>)}</div>
            {mode === 'live' && health === 'unavailable' && <div className="notice notice-warning"><strong>Local API not detected.</strong> The selected mode remains live. Start your engine and recheck the connection, or explicitly select the fixture walkthrough. Failed requests will not fall back to successful fixtures.</div>}
            {error && <div className="notice notice-error" role="alert"><strong>Live operation not verified.</strong><span>{error}</span><button type="button" onClick={reset} className="text-button">Reset local view</button></div>}
            <div className="demo-grid">
              <div className="demo-story"><div className="demo-caption">{scenario.name} / {mode === 'fixture' ? 'Recorded illustration' : 'Local test environment'}</div><h3>{stageTitle}</h3><p>{mode === 'fixture' ? fixtureText : liveText}</p>
                <div className="steps" role="group" aria-label="Verification stages">{STAGES.map((label, index) => <button key={label} type="button" className={`step ${index < stage ? 'past' : ''}`} aria-current={stage === index ? 'step' : undefined} disabled={!!busy || !canStage(index)} onClick={() => setStage(index)}><b>0{index + 1}</b>{label}</button>)}</div>
                <div className="branch-note">{branchNote}</div>
                <div className="demo-buttons"><button type="button" className="btn btn-secondary" disabled={stage === 0 || !!busy} onClick={() => setStage(value => value - 1)}>← Back</button><button type="button" className="btn btn-primary" onClick={next} disabled={nextDisabled}>{nextLabel}</button><button type="button" className="btn btn-reset" onClick={reset}>{busy ? 'Cancel / reset view' : 'Reset'}</button></div>
                {mode === 'live' && stage === 2 && receipt && !replay && <p className="inline-caution">Recovery was submitted, but no complete replay result was accepted. Reset and start a fresh analysis; do not infer success.</p>}
                {mode === 'live' && stage === 2 && !plan && <p className="inline-caution">The engine did not return a recovery plan. No recovery request can be sent from this view.</p>}
              </div>
              <aside className="evidence-card" data-tone={tone} aria-label="Current result evidence"><div className="card-top"><span>{mode === 'fixture' ? 'Fixture evidence' : 'Session evidence'}</span><span className="phase-badge">{phase.replaceAll('_', ' ')}</span></div><div className="metric-label">{metricLabel}</div><div className="metric-number" data-testid="current-metric">{metric}</div><div className="metric-unit">{metricUnit}</div>
                <div className="result-title">{stage === 0 ? mode === 'fixture' ? 'No execution at the signing moment' : 'Waiting for explicit verification' : stage === 1 ? mode === 'fixture' ? `${scenario.trace.length}-step recorded loss path` : status : stage === 2 ? mode === 'fixture' ? scenario.strategy : text(plan?.strategy, 'Recovery plan unavailable') : mode === 'fixture' ? 'Fixture outcome: 10,000 test USDC preserved' : replay?.mitigated === true ? 'API reports known-trace neutralization' : 'API reports remaining tracked loss'}</div>
                <p className="result-note">{mode === 'fixture' ? 'This is a displayed fixture outcome, not a new verifier execution. Starting balance: 10,000 test USDC.' : stage === 3 ? `Final tracked balance: ${text(replay?.finalVictimBalance)}. Replay disposition: ${replay?.reverted === true ? 'reported blocked or reverted' : replay?.reverted === false ? 'no revert reported' : 'not returned'}.` : 'Metrics and status are taken only from the accepted local API response. Missing values remain unknown.'}</p>
                {mode === 'live' && result && <div className="run-id mono">Run: {text(result.data.runId)}</div>}
                <a className="source-link" href={`${SOURCE}/app/src/App.tsx`} target="_blank" rel="noopener noreferrer">{mode === 'fixture' ? 'Source fixture definitions ↗' : 'Original dashboard API integration ↗'}</a>
              </aside>
            </div>
            <div className="inspection-area"><div className="inspection-grid">
              <CapabilityPanel scenario={scenario} />
              <section className="detail-card"><div className="detail-card-head"><span className="eyebrow">{mode === 'fixture' ? 'Recorded path' : 'Returned evidence'}</span><span className="badge">{mode === 'fixture' ? 'Fixture only' : result ? 'API result' : 'Not run'}</span></div><h3>{mode === 'fixture' ? 'Trace and branch context' : 'Local analysis evidence'}</h3>
                {mode === 'fixture' ? <><ol className="trace-list">{scenario.trace.map((item, index) => <li key={item.title}><span className="trace-number">0{index + 1}</span><div><h4>{item.title}</h4><p>{item.description}</p><span className="trace-balance mono">{item.balance}</span></div></li>)}</ol><p className="detail-note">Illustrative loss branch. The recovery check uses a separate pre-loss state.</p></> : result ? <><dl className="release-dl"><div><dt>Status</dt><dd>{status}</dd></div><div><dt>Depth</dt><dd>{ce ? text(ce.depth) : 'No witness returned'}</dd></div><div><dt>Tracked loss</dt><dd>{loss ? `${text(loss.formatted)} ${text(loss.symbol)}` : 'Not returned'}</dd></div></dl>{ce && Array.isArray(ce.trace) && <ol className="trace-list">{ce.trace.map((item, index) => <li key={index}><span className="trace-number">0{index + 1}</span><div><h4>{isRecord(item) ? text(item.id, text(item.actionId, 'Returned action')) : 'Returned action'}</h4><p>{isRecord(item) ? text(item.description, 'Details are available in the raw API response.') : 'Inspect the API response.'}</p></div></li>)}</ol>}<RawDetails title="Inspect analysis response" data={result.data} /></> : <div className="empty-state"><span aria-hidden="true">◎</span><p>No local analysis has run.</p><small>The dashboard will not use the fixture's loss or trace as live evidence.</small></div>}
              </section>
            </div>
            {receipt && <section className="detail-card receipt-card"><div className="detail-card-head"><span className="eyebrow">Local recovery receipt</span><span className="badge">{text(receipt.status)}</span></div><h3>Recovery and replay are separate checks.</h3><dl className="release-dl"><div><dt>Transaction</dt><dd className="mono">{text(receipt.txHash)}</dd></div><div><dt>Gas used</dt><dd>{text(receipt.gasUsed)}</dd></div><div><dt>Portfolio check</dt><dd>{text(portfolio?.status, 'Not returned — not verified')}</dd></div><div><dt>Known trace</dt><dd>{!replay ? 'No accepted replay result' : replay.mitigated === true ? 'API reports zero tracked loss' : 'API reports remaining tracked loss'}</dd></div></dl>{portfolio?.verified !== true && <div className="notice notice-warning">The post-recovery portfolio check is not verified. A successful known-trace replay must not be presented as complete recovery.</div>}<RawDetails title="Inspect recovery response" data={receipt} />{replay && <RawDetails title="Inspect replay response" data={replay} />}</section>}
            </div>
            <div className="demo-disclaimer">{mode === 'fixture' ? 'Fixture mode: no analysis, recovery, or replay request is sent. A separate read-only health check detects whether the local API is available.' : 'Local mode: existing /api/analyze, /api/recover, and /api/replay endpoints only. Results are backend reports, not an independent security certification.'}</div>
          </> : tab === 'architecture' ? <Architecture /> : <Evidence />}
        </div>
        <div className="dashboard-footnote"><span>Same source baseline. Clearly separated evidence.</span><a href="/judge-demo.html#walkthrough">Open the presentation walkthrough ↗</a></div>
      </div></section><Scope />
    </main>
    <footer><div className="wrap footer-row"><span>Aegis7702 · Interactive dashboard & local verification UI</span><span>Prepared for Dr. Lew Kai Liang · Source snapshot: v1.0.13</span></div></footer>
    <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{scenario.name}. {mode === 'fixture' ? 'Fixture mode' : 'Local engine mode'}. Stage {stage + 1} of 4: {STAGES[stage]}. {busy ? nextLabel : stageTitle}</div>
  </>;
}
function CapabilityPanel({ scenario }: { scenario: Scenario }) {
  return <section className="detail-card"><div className="detail-card-head"><span className="eyebrow">Capability inspection</span><span className="badge">Fixture metadata</span></div><h3>{scenario.capabilityLabel}</h3><p className="detail-note">Reference values from the bundled scenario, not a live wallet observation. Engine-generated addresses and signatures may differ; inspect the API response for that run.</p><dl className="capability-fields">{Object.entries(scenario.fields).map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="mono">{value}</dd></div>)}</dl></section>;
}
export default App;
