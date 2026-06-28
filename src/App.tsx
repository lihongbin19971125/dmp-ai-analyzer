import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import DropZone from "./components/DropZone";
import OptionsPanel from "./components/OptionsPanel";
import ResultView from "./components/ResultView";

export interface AnalyzeResult {
  context_json: string;
  ai_analysis: string;
  report_md: string;
  report_html: string;
  success: boolean;
  error?: string;
}

function App() {
  const [dmpPath, setDmpPath] = useState<string>("");
  const [exeDir, setExeDir] = useState("");
  const [symbolPaths, setSymbolPaths] = useState("");
  const [provider, setProvider] = useState("deepseek");
  const [apiKey, setApiKey] = useState("");
  const [jsonOnly, setJsonOnly] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    if (!dmpPath) return;

    setAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const symbolPathsList: string[] = symbolPaths
        .split(";")
        .map((s) => s.trim())
        .filter(Boolean);

      const r: AnalyzeResult = await invoke("analyze_dmp", {
        path: dmpPath,
        exeDir: exeDir || null,
        symbolPaths: symbolPathsList,
        provider: provider || "deepseek",
        apiKey: apiKey || null,
        model: null,
        timeoutSecs: 120,
        jsonOnly: jsonOnly,
      });

      setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>DMP AI Analyzer</h1>
        <p>AI-powered Windows crash dump analysis</p>
      </header>

      <main className="app-main">
        <div className="left-panel">
          <DropZone onFileSelected={setDmpPath} selectedPath={dmpPath} />
          <OptionsPanel
            exeDir={exeDir}
            onExeDirChange={setExeDir}
            symbolPaths={symbolPaths}
            onSymbolPathsChange={setSymbolPaths}
            provider={provider}
            onProviderChange={setProvider}
            apiKey={apiKey}
            onApiKeyChange={setApiKey}
            jsonOnly={jsonOnly}
            onJsonOnlyChange={setJsonOnly}
          />
          <button
            className="analyze-btn"
            onClick={handleAnalyze}
            disabled={!dmpPath || analyzing}
          >
            {analyzing ? "Analyzing..." : "Analyze"}
          </button>
        </div>

        <div className="right-panel">
          {analyzing && <div className="progress">Analyzing dump file...</div>}
          {error && <div className="error-box">Error: {error}</div>}
          {result && <ResultView result={result} />}
          {!result && !analyzing && !error && (
            <div className="placeholder">
              Drop a .dmp file to begin analysis
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
