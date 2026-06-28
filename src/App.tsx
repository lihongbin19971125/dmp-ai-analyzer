import { useState, useEffect, useCallback } from "react";
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

interface UserSettings {
  exe_dir: string;
  symbol_paths: string;
  provider: string;
  api_key: string;
  json_only: boolean;
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
  const [loaded, setLoaded] = useState(false);

  // Load settings on startup
  useEffect(() => {
    async function load() {
      try {
        const s: UserSettings = await invoke("load_settings");
        if (s.exe_dir) setExeDir(s.exe_dir);
        if (s.symbol_paths) setSymbolPaths(s.symbol_paths);
        if (s.provider) setProvider(s.provider);
        if (s.api_key) setApiKey(s.api_key);
        setJsonOnly(s.json_only);
      } catch {
        // First run, no settings file — use defaults
      }
      setLoaded(true);
    }
    load();
  }, []);

  // Auto-save settings whenever any option changes
  const save = useCallback(async (settings: UserSettings) => {
    if (!loaded) return;
    try {
      await invoke("save_settings", { settings });
    } catch {
      // Ignore save errors
    }
  }, [loaded]);

  const updateExeDir = (v: string) => {
    setExeDir(v);
    save({ exe_dir: v, symbol_paths: symbolPaths, provider, api_key: apiKey, json_only: jsonOnly });
  };
  const updateSymbolPaths = (v: string) => {
    setSymbolPaths(v);
    save({ exe_dir: exeDir, symbol_paths: v, provider, api_key: apiKey, json_only: jsonOnly });
  };
  const updateProvider = (v: string) => {
    setProvider(v);
    save({ exe_dir: exeDir, symbol_paths: symbolPaths, provider: v, api_key: apiKey, json_only: jsonOnly });
  };
  const updateApiKey = (v: string) => {
    setApiKey(v);
    save({ exe_dir: exeDir, symbol_paths: symbolPaths, provider, api_key: v, json_only: jsonOnly });
  };
  const updateJsonOnly = (v: boolean) => {
    setJsonOnly(v);
    save({ exe_dir: exeDir, symbol_paths: symbolPaths, provider, api_key: apiKey, json_only: v });
  };

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
            onExeDirChange={updateExeDir}
            symbolPaths={symbolPaths}
            onSymbolPathsChange={updateSymbolPaths}
            provider={provider}
            onProviderChange={updateProvider}
            apiKey={apiKey}
            onApiKeyChange={updateApiKey}
            jsonOnly={jsonOnly}
            onJsonOnlyChange={updateJsonOnly}
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
