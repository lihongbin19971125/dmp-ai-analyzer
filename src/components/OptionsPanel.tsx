interface OptionsPanelProps {
  exeDir: string;
  onExeDirChange: (v: string) => void;
  symbolPaths: string;
  onSymbolPathsChange: (v: string) => void;
  provider: string;
  onProviderChange: (v: string) => void;
  apiKey: string;
  onApiKeyChange: (v: string) => void;
  jsonOnly: boolean;
  onJsonOnlyChange: (v: boolean) => void;
}

export default function OptionsPanel({
  exeDir, onExeDirChange,
  symbolPaths, onSymbolPathsChange,
  provider, onProviderChange,
  apiKey, onApiKeyChange,
  jsonOnly, onJsonOnlyChange,
}: OptionsPanelProps) {
  return (
    <div className="options-panel">
      <h3>Options</h3>

      <label>
        EXE Directory:
        <input
          type="text"
          value={exeDir}
          onChange={(e) => onExeDirChange(e.target.value)}
          placeholder="C:\Program Files\MyApp"
        />
      </label>

      <label>
        Symbol Paths (; separated):
        <input
          type="text"
          value={symbolPaths}
          onChange={(e) => onSymbolPathsChange(e.target.value)}
          placeholder="D:\Symbols;\\server\pdbs"
        />
      </label>

      <label>
        AI Provider:
        <select value={provider} onChange={(e) => onProviderChange(e.target.value)}>
          <option value="deepseek">DeepSeek</option>
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic</option>
        </select>
      </label>

      <label>
        API Key:
        <input
          type="password"
          value={apiKey}
          onChange={(e) => onApiKeyChange(e.target.value)}
          placeholder="sk-... (or set env var)"
        />
      </label>

      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={jsonOnly}
          onChange={(e) => onJsonOnlyChange(e.target.checked)}
        />
        JSON only (skip AI analysis)
      </label>
    </div>
  );
}
