import { useState } from "react";
import { analyzeThreat, type AnalysisResult } from "./analyzer";
import "./App.css";

const scamExample = `Dear SBI customer, your account will be blocked today.
Complete KYC immediately at https://sbi-secure-update.xyz
and verify your OTP.`;

const safeExample = `Hi Tanvi, the college workshop starts tomorrow at 10 AM.
Please reach Lab 2 fifteen minutes early.`;

function App() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const analyze = () => {
    if (!input.trim()) return;
    setResult(analyzeThreat(input));
  };

  const riskColor = (score: number) => {
    if (score >= 80) return "#ff4757";
    if (score >= 60) return "#ff8c42";
    if (score >= 30) return "#f6c344";
    return "#2ed573";
  };

  const dnaItems =
    result &&
    [
      ["Urgency", result.scamDNA.urgency],
      ["Fear", result.scamDNA.fear],
      ["Impersonation", result.scamDNA.impersonation],
      ["Credential bait", result.scamDNA.credentials],
      ["URL manipulation", result.scamDNA.urlRisk],
    ];

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="shield">K</div>

          <div>
            <h1>KAVACH AI</h1>
            <p>Explainable On-Device Scam Intelligence</p>
          </div>
        </div>

        <div className="privacy-badge">
          <span className="privacy-dot" />
          LOCAL PRIVACY MODE
          <strong>0 bytes uploaded</strong>
        </div>
      </header>

      <main>
        <section className="hero">
          <div className="hero-copy">
            <span className="eyebrow">DETECT THE THREAT · DECODE THE DECEPTION</span>

            <h2>
              Understand <span>how</span> a scam is trying to manipulate you.
            </h2>

            <p>
              KAVACH analyzes suspicious messages and URLs directly in your
              browser and explains the evidence behind its decision.
            </p>
          </div>

          <div className="offline-card">
            <span>●</span>
            <div>
              <strong>On-device core analysis</strong>
              <small>No cloud API required</small>
            </div>
          </div>
        </section>

        <section className="scanner-card">
          <div className="scanner-heading">
            <div>
              <span className="section-label">THREAT SCANNER</span>
              <h3>Paste a suspicious message or URL</h3>
            </div>

            <span className="browser-label">RUNS IN THIS BROWSER</span>
          </div>

          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="Example: Your bank account will be blocked. Verify KYC immediately at..."
          />

          <div className="scanner-actions">
            <div className="examples">
              <button
                className="secondary"
                onClick={() => {
                  setInput(scamExample);
                  setResult(null);
                }}
              >
                Load scam example
              </button>

              <button
                className="secondary"
                onClick={() => {
                  setInput(safeExample);
                  setResult(null);
                }}
              >
                Load safe example
              </button>
            </div>

            <button className="analyze-button" onClick={analyze}>
              Analyze Threat →
            </button>
          </div>
        </section>

        {result && (
          <section className="results">
            <div className="result-summary">
              <div
                className="score-ring"
                style={{
                  background: `conic-gradient(${riskColor(
                    result.score
                  )} ${result.score * 3.6}deg, #1c2838 0deg)`,
                }}
              >
                <div className="score-inner">
                  <strong>{result.score}</strong>
                  <span>/100</span>
                </div>
              </div>

              <div className="summary-copy">
                <span
                  className="risk-level"
                  style={{ color: riskColor(result.score) }}
                >
                  {result.level} RISK
                </span>

                <h3>{result.category}</h3>

                <p>
                  KAVACH found {result.signals.length} suspicious signal
                  {result.signals.length === 1 ? "" : "s"} in this content.
                </p>
              </div>
            </div>

            <div className="grid two-columns">
              <div className="panel">
                <div className="panel-title">
                  <span>🧬</span>
                  <div>
                    <h3>Scam DNA</h3>
                    <p>Behavioural fingerprint of this message</p>
                  </div>
                </div>

                <div className="dna-list">
                  {dnaItems?.map(([name, value]) => (
                    <div className="dna-item" key={name}>
                      <div className="dna-row">
                        <span>{name}</span>
                        <strong>{value}%</strong>
                      </div>

                      <div className="bar">
                        <div
                          className="bar-fill"
                          style={{
                            width: `${value}%`,
                            backgroundColor: riskColor(Number(value)),
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel">
                <div className="panel-title">
                  <span>🔬</span>
                  <div>
                    <h3>Risk X-Ray</h3>
                    <p>Exactly what contributed to the score</p>
                  </div>
                </div>

                <div className="signal-list">
                  {result.signals.length === 0 ? (
                    <p className="muted">No major suspicious signals found.</p>
                  ) : (
                    result.signals.map((signal) => (
                      <div className="signal-row" key={signal.id}>
                        <div>
                          <strong>{signal.label}</strong>
                          <small>{signal.reason}</small>
                        </div>

                        <span>+{signal.points}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {result.claimedBrand && result.observedDomain && (
              <div className="panel trust-panel">
                <div className="panel-title">
                  <span>🕵️</span>
                  <div>
                    <h3>Trust Gap</h3>
                    <p>Claimed identity versus actual destination</p>
                  </div>
                </div>

                <div className="trust-flow">
                  <div className="trust-box">
                    <span>CLAIMED IDENTITY</span>
                    <strong>{result.claimedBrand}</strong>
                  </div>

                  <div className="trust-arrow">
                    <span>≠</span>
                    <small>
                      Trust Gap {result.trustGap ?? 0}%
                    </small>
                  </div>

                  <div className="trust-box danger">
                    <span>OBSERVED DOMAIN</span>
                    <strong>{result.observedDomain}</strong>
                  </div>
                </div>

                {result.expectedDomain && (
                  <p className="expected-domain">
                    Expected trusted domain: <strong>{result.expectedDomain}</strong>
                  </p>
                )}
              </div>
            )}

            <div className="grid two-columns">
              <div className="panel">
                <div className="panel-title">
                  <span>🕸️</span>
                  <div>
                    <h3>Deception Chain</h3>
                    <p>How the scam may attempt to influence the victim</p>
                  </div>
                </div>

                <div className="chain">
                  {result.deceptionChain.map((step, index) => (
                    <div className="chain-step" key={`${step}-${index}`}>
                      <span>{index + 1}</span>
                      <p>{step}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel action-panel">
                <div className="panel-title">
                  <span>🛡️</span>
                  <div>
                    <h3>Safe Next Action</h3>
                    <p>What the user should do now</p>
                  </div>
                </div>

                <div className="actions-list">
                  {result.actions.map((action) => (
                    <div className="action" key={action}>
                      <span>✓</span>
                      <p>{action}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        )}

        <footer>
          <strong>KAVACH AI · VAYU FORGE</strong>
          <span>
            Prototype risk assessment is heuristic and should complement,
            not replace, trusted security verification.
          </span>
        </footer>
      </main>
    </div>
  );
}

export default App;