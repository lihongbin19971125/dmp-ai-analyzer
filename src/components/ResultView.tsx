import type { AnalyzeResult } from "../App";

export default function ResultView({ result }: { result: AnalyzeResult }) {
  return (
    <div className="result-view">
      <h2>Analysis Result</h2>

      {result.success === false && (
        <div className="error-box">Error: {result.error || "Unknown error"}</div>
      )}

      {result.ai_analysis && (
        <section>
          <h3>AI Analysis</h3>
          <div className="analysis-content markdown-body">
            <pre>{result.ai_analysis}</pre>
          </div>
        </section>
      )}

      {result.context_json && (
        <details>
          <summary>Context JSON</summary>
          <pre className="json-content">
            {(() => {
              try {
                return JSON.stringify(JSON.parse(result.context_json), null, 2);
              } catch {
                return result.context_json;
              }
            })()}
          </pre>
        </details>
      )}

      {result.report_md && (
        <details>
          <summary>Full Report (Markdown)</summary>
          <pre className="report-content">{result.report_md}</pre>
        </details>
      )}
    </div>
  );
}
