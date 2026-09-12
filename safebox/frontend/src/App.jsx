import { useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Code2,
  FileCode2,
  FileUp,
  Loader2,
  Play,
  Shield,
  Upload,
} from "lucide-react";

const API_URL = "http://127.0.0.1:8000";
const MAX_FILE_SIZE = 100 * 1024;
const ACCEPTED_EXTENSIONS = [".py", ".js", ".txt", ".ts", ".jsx", ".tsx", ".json", ".md", ".sh"];

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  return `${(bytes / 1024).toFixed(1)} KB`;
}

function App() {
  const [mode, setMode] = useState("code");
  const [code, setCode] = useState('print("Hello SafeBox!")');
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef(null);

  const switchMode = (nextMode) => {
    setMode(nextMode);
    setResult(null);
    setError("");
    setLoading(false);
  };

  const handleApiError = (err) => {
    setResult(null);
    setError(
      err.message
        ? `Unable to reach the SafeBox backend: ${err.message}`
        : "Unable to reach the SafeBox backend. Confirm it is running on port 8000."
    );
  };

  const applyResponse = async (response) => {
    let data;

    try {
      data = await response.json();
    } catch {
      setResult(null);
      setError("The backend returned an unexpected response.");
      return;
    }

    if (data.status === "error" && !data.analysis) {
      setResult(null);
      setError(data.error || data.output || "Analysis failed.");
      return;
    }

    setError("");
    setResult(data);
  };

  const runSandbox = async () => {
    setLoading(true);
    setResult(null);
    setError("");

    try {
      const response = await fetch(`${API_URL}/execute`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code }),
      });

      await applyResponse(response);
    } catch (err) {
      handleApiError(err);
    } finally {
      setLoading(false);
    }
  };

  const setSelectedFile = (selected) => {
    if (!selected) {
      return;
    }

    if (selected.size > MAX_FILE_SIZE) {
      setFile(null);
      setError("File is too large. Maximum size is 100 KB.");
      return;
    }

    setError("");
    setResult(null);
    setFile(selected);
  };

  const analyzeFile = async () => {
    if (!file) {
      setError("No file selected. Choose a file to analyze.");
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      setError("File is too large. Maximum size is 100 KB.");
      return;
    }

    setLoading(true);
    setResult(null);
    setError("");

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_URL}/analyze-file`, {
        method: "POST",
        body: formData,
      });

      await applyResponse(response);
    } catch (err) {
      handleApiError(err);
    } finally {
      setLoading(false);
    }
  };

  const onDrop = (event) => {
    event.preventDefault();
    setDragActive(false);
    const dropped = event.dataTransfer.files?.[0];
    setSelectedFile(dropped);
  };

  const risk = result?.analysis?.risk || "LOW";
  const events = result?.analysis?.events || [];
  const analyzedFileName = result?.file?.name;

  const riskClass = {
    LOW: "risk-low",
    MEDIUM: "risk-medium",
    HIGH: "risk-high",
  }[risk];

  return (
    <div className="app">
      <header>
        <div className="brand">
          <div className="shield">
            <Shield size={22} />
          </div>

          <div>
            <h1>SafeBox</h1>
            <p>Secure Code Execution & Malware Behavior Analysis</p>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot"></span>
          Sandbox Engine Online
        </div>
      </header>

      <main>
        <div className="mode-selector" role="tablist" aria-label="Analysis mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "code"}
            className={mode === "code" ? "mode-button active" : "mode-button"}
            onClick={() => switchMode("code")}
          >
            <Code2 size={18} />
            CODE
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "file"}
            className={mode === "file" ? "mode-button active" : "mode-button"}
            onClick={() => switchMode("file")}
          >
            <FileUp size={18} />
            FILE
          </button>
        </div>

        {mode === "code" ? (
          <section className="card">
            <div className="section-header">
              <div>
                <h2>Untrusted Code</h2>
                <p>Execute potentially unsafe code inside an isolated environment.</p>
              </div>

              <span className="badge">PYTHON</span>
            </div>

            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              spellCheck="false"
            />

            <div className="actions">
              <button
                className="run-button"
                onClick={runSandbox}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <Loader2 size={16} className="spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Play size={16} />
                    Run in Sandbox
                  </>
                )}
              </button>

              <button
                className="sample-button"
                onClick={() =>
                  setCode(`import socket

s = socket.socket()
s.connect(("example.com", 80))`)
                }
              >
                Load Threat Test
              </button>
            </div>
          </section>
        ) : (
          <section className="card">
            <div className="section-header">
              <div>
                <h2>Untrusted File</h2>
                <p>Upload a text or code file and analyze it inside the sandbox.</p>
              </div>

              <span className="badge">UPLOAD</span>
            </div>

            <div
              className={dragActive ? "dropzone active" : "dropzone"}
              onDragOver={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={(event) => {
                event.preventDefault();
                setDragActive(false);
              }}
              onDrop={onDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload size={28} />
              <strong>Drop a file here</strong>
              <p>or click to choose .py, .js, .txt, and other text/code files</p>
              <p className="dropzone-limit">Maximum size 100 KB</p>
            </div>

            <input
              ref={fileInputRef}
              type="file"
              className="file-input"
              accept={ACCEPTED_EXTENSIONS.join(",")}
              onChange={(event) => {
                setSelectedFile(event.target.files?.[0]);
                event.target.value = "";
              }}
            />

            {file && (
              <div className="file-meta">
                <FileCode2 size={18} />
                <div>
                  <strong>{file.name}</strong>
                  <span>{formatBytes(file.size)}</span>
                </div>
              </div>
            )}

            <div className="actions">
              <button
                className="run-button"
                onClick={analyzeFile}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <Loader2 size={16} className="spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <FileUp size={16} />
                    Analyze File
                  </>
                )}
              </button>

              <button
                className="sample-button"
                type="button"
                onClick={() => fileInputRef.current?.click()}
              >
                Choose File
              </button>
            </div>
          </section>
        )}

        {error && (
          <section className="card error-card">
            <AlertTriangle size={18} />
            <div>
              <strong>Analysis could not run</strong>
              <p>{error}</p>
            </div>
          </section>
        )}

        {result && (
          <>
            <section className="risk-card">
              <div>
                <p className="eyebrow">SECURITY ASSESSMENT</p>

                <h2>Behavior Analysis</h2>

                <p className="muted">
                  SafeBox monitored the program while it executed inside the
                  sandbox.
                </p>

                {mode === "file" && analyzedFileName && (
                  <p className="analyzed-file">
                    Analyzed file: <strong>{analyzedFileName}</strong>
                  </p>
                )}
              </div>

              <div className={`risk-indicator ${riskClass}`}>
                <span>{risk}</span>
                <small>RISK</small>
              </div>
            </section>

            <section className="metrics">
              <div className="metric">
                <span>Sandbox</span>
                <strong>
                  {result.security?.sandboxed ? "Protected" : "Unknown"}
                </strong>
              </div>

              <div className="metric">
                <span>Network</span>
                <strong>{result.security?.network || "Unknown"}</strong>
              </div>

              <div className="metric">
                <span>Memory Limit</span>
                <strong>{result.security?.memory_limit || "N/A"}</strong>
              </div>

              <div className="metric">
                <span>Process Limit</span>
                <strong>{result.security?.process_limit || "N/A"}</strong>
              </div>
            </section>

            <section className="card">
              <div className="section-header">
                <div>
                  <h2>Execution Result</h2>
                  <p>Program output captured by SafeBox.</p>
                </div>

                <span
                  className={
                    result.status === "completed"
                      ? "success-badge"
                      : "danger-badge"
                  }
                >
                  {result.status}
                </span>
              </div>

              <pre className="terminal">
                {result.output || "No output produced."}
              </pre>
            </section>

            <section className="card">
              <div className="section-header">
                <div>
                  <h2>Security Events</h2>
                  <p>Suspicious behavior detected during execution.</p>
                </div>

                <span className="event-count">
                  {events.length} events
                </span>
              </div>

              {events.length === 0 ? (
                <div className="empty-events">
                  <div>
                    <CheckCircle2 size={20} />
                  </div>
                  <strong>No suspicious behavior detected</strong>
                  <p>
                    The program completed without triggering monitored
                    security events.
                  </p>
                </div>
              ) : (
                <div className="timeline">
                  {events.map((event, index) => (
                    <div className="event" key={`${event.type}-${index}`}>
                      <div className="event-icon">
                        <AlertTriangle size={16} />
                      </div>

                      <div>
                        <strong>{event.message}</strong>
                        <span>{event.type}</span>
                      </div>

                      <small>
                        #{String(index + 1).padStart(2, "0")}
                      </small>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </>
        )}
      </main>

      <footer>
        <span>SafeBox</span>
        <span>•</span>
        <span>Defense & Sandboxing</span>
        <span>•</span>
        <span>Untrusted execution environment</span>
      </footer>
    </div>
  );
}

export default App;
