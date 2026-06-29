import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { AnalyzeResult } from "../App";

export default function ResultView({ result }: { result: AnalyzeResult }) {
  return (
    <div className="result-view">
      <h2>分析结果</h2>

      {result.success === false && (
        <div className="error-box">错误: {result.error || "Unknown error"}</div>
      )}

      {result.ai_analysis && (
        <section>
          <h3>AI 分析</h3>
          <div className="markdown-body">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {result.ai_analysis}
            </ReactMarkdown>
          </div>
        </section>
      )}

      {result.report_md && (
        <details>
          <summary>完整报告 (Markdown)</summary>
          <div className="markdown-body">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {result.report_md}
            </ReactMarkdown>
          </div>
        </details>
      )}

      {result.context_json && (
        <details>
          <summary>原始 JSON</summary>
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
    </div>
  );
}
