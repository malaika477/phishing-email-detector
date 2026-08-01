import { useState, useRef } from 'react'

const SAMPLE_EMAIL = `From: PayPal Security <support@paypa1-verify.com>
Subject: URGENT!! Your Account Will Be Suspended

Dear Customer,

We have detected UNUSUAL ACTIVITY on your account. You must verify your identity immediately or your account will be suspended within 24 hours.

Click here to confirm your password and avoid suspension: http://bit.ly/paypal-verify-acct

Failure to comply will result in permanent account closure.

Thank you,
PayPal Security Team!!!`

const SCAN_STEPS = [
  'Initializing scan environment',
  'Parsing headers and sender metadata',
  'Cross-referencing sender against known brands',
  'Extracting and resolving links',
  'Scanning body for coercive language patterns',
  'Calculating composite risk score',
]

function prefersReducedMotion() {
  return typeof window !== 'undefined' &&
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function severityColor(score) {
  if (score < 25) return '#00d9a3'
  if (score < 55) return '#ffb020'
  return '#ff4557'
}

function severityClass(sev) {
  if (sev === 'high') return 'finding high'
  if (sev === 'low') return 'finding low'
  return 'finding med'
}

function RadarRing({ score, phase }) {
  const size = 220
  const stroke = 14
  const r = (size - stroke) / 2
  const circumference = 2 * Math.PI * r
  const pct = phase === 'done' ? score / 100 : 0
  const offset = circumference * (1 - pct)
  const color = severityColor(score)

  return (
    <div className="radar-wrap">
      {phase === 'scanning' && <div className="radar-beacon" />}
      <svg width={size} height={size} className="radar-svg">
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none" stroke="#1b2330" strokeWidth={stroke}
        />
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className="radar-progress"
        />
      </svg>
      <div className="radar-center">
        {phase === 'idle' && <div className="radar-standby">STANDBY</div>}
        {phase === 'scanning' && <div className="radar-standby scanning">SCANNING</div>}
        {phase === 'done' && (
          <>
            <div className="radar-score" style={{ color }}>{score}</div>
            <div className="radar-unit">RISK / 100</div>
          </>
        )}
      </div>
    </div>
  )
}
const API_URL = import.meta.env.VITE_API_URL || ''
export default function App() {
  const [email, setEmail] = useState('')
  const [phase, setPhase] = useState('idle') // idle | scanning | done
  const [logLines, setLogLines] = useState([])
  const [result, setResult] = useState(null)
  const [revealedFindings, setRevealedFindings] = useState([])
  const [error, setError] = useState('')
  const runId = useRef(0)

  async function handleAnalyze() {
    if (!email.trim() || phase === 'scanning') return
    setError('')
    setResult(null)
    setRevealedFindings([])
    setLogLines([])
    setPhase('scanning')
    const myRun = ++runId.current

    let data
    try {
      const res = await fetch('${API_URL}/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      if (!res.ok) throw new Error('Analysis failed')
      data = await res.json()
    } catch (err) {
      if (runId.current !== myRun) return
      setError('Could not reach the analysis backend. Is the Flask server running on port 5000?')
      setPhase('idle')
      return
    }

    const reduced = prefersReducedMotion()

    if (reduced) {
      setResult(data)
      setRevealedFindings(data.findings)
      setPhase('done')
      return
    }

    // Play out the scan sequence
    for (const step of SCAN_STEPS) {
      if (runId.current !== myRun) return
      setLogLines((prev) => [...prev, { text: step, type: 'step' }])
      await delay(260)
    }

    if (data.findings.length > 0) {
      setLogLines((prev) => [...prev, {
        text: `${data.findings.length} flag${data.findings.length > 1 ? 's' : ''} detected`,
        type: 'alert',
      }])
      await delay(200)
      for (const f of data.findings) {
        if (runId.current !== myRun) return
        setLogLines((prev) => [...prev, { text: `[${f.tag}] +${f.weight}`, type: f.severity }])
        setRevealedFindings((prev) => [...prev, f])
        await delay(220)
      }
    } else {
      setLogLines((prev) => [...prev, { text: 'No red flags matched', type: 'safe' }])
      await delay(200)
    }

    setLogLines((prev) => [...prev, { text: 'Scan complete', type: 'done' }])
    await delay(150)
    if (runId.current !== myRun) return
    setResult(data)
    setPhase('done')
  }

  function loadSample() {
    setEmail(SAMPLE_EMAIL)
    setResult(null)
    setPhase('idle')
    setLogLines([])
    setRevealedFindings([])
  }

  const verdictClass = result
    ? result.score < 25 ? 'tag-safe' : result.score < 55 ? 'tag-warn' : 'tag-danger'
    : ''

  return (
    <div className="wrap">
      <header>
        <div className="brand">
          <span className="dot" />
          <h1>Phishing Email Detector</h1>
        </div>
        <div className="status-pill">
          <span className="status-blip" /> SCANNER ONLINE
        </div>
      </header>

      <div className="grid">
        <div className="panel input-panel">
          <h2>Email Content</h2>
          <textarea
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Paste the full email here — including the From: address and Subject line if you have them — then click Analyze."
          />
          <div className="row-between">
            <button className="sample-btn" onClick={loadSample}>
              Load a sample phishing email
            </button>
            <button
              className="analyze-btn"
              onClick={handleAnalyze}
              disabled={phase === 'scanning'}
            >
              {phase === 'scanning' ? 'Scanning…' : 'Analyze Email'}
            </button>
          </div>
          {error && <p className="error-text">{error}</p>}
        </div>

        <div className="panel result-panel">
          <h2>Live Scan</h2>

          <RadarRing score={result ? result.score : 0} phase={phase} />

          {phase === 'done' && result && (
            <div className="verdict-stamp">
              <span className={`verdict-tag ${verdictClass}`}>{result.verdict}</span>
            </div>
          )}

          <div className="console">
            {phase === 'idle' && logLines.length === 0 && (
              <div className="empty-state">
                <span className="glyph">&gt;_</span>
                Awaiting input. Paste an email and click Analyze to begin the scan.
              </div>
            )}
            {logLines.map((line, i) => (
              <div key={i} className={`log-line log-${line.type}`}>
                <span className="log-caret">›</span> {line.text}
              </div>
            ))}
            {phase === 'scanning' && <div className="log-cursor" />}
          </div>

          {phase === 'done' && (
            <div className="findings">
              {revealedFindings.length === 0 ? (
                <div className="empty-state">
                  No red flags detected by the rule set. Still, always verify unexpected requests independently.
                </div>
              ) : (
                revealedFindings.map((f, i) => (
                  <div key={i} className={`${severityClass(f.severity)} finding-in`} style={{ animationDelay: `${i * 60}ms` }}>
                    <div className="finding-head">
                      <span>{f.tag}</span>
                      <span className="finding-weight">+{f.weight}</span>
                    </div>
                    <div className="finding-detail">{f.detail}</div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>

      <footer>Educational tool. Rule-based heuristics only — always verify suspicious emails through official channels.</footer>
    </div>
  )
}