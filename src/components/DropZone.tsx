import { useState, useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

interface DropZoneProps {
  onFileSelected: (path: string) => void;
  selectedPath: string;
}

export default function DropZone({ onFileSelected, selectedPath }: DropZoneProps) {
  const [dragOver, setDragOver] = useState(false);

  // Tauri drag-drop listener
  useEffect(() => {
    const unlisten = getCurrentWindow().onDragDropEvent((event) => {
      if (event.payload.type === "over") {
        setDragOver(true);
      } else if (event.payload.type === "leave") {
        setDragOver(false);
      } else if (event.payload.type === "drop") {
        setDragOver(false);
        const paths = event.payload.paths;
        if (paths.length > 0) {
          // Filter to .dmp files, take the first one
          const dmp = paths.find(
            (p) =>
              p.toLowerCase().endsWith(".dmp") ||
              p.toLowerCase().endsWith(".mdmp") ||
              p.toLowerCase().endsWith(".hdmp"),
          );
          if (dmp) {
            onFileSelected(dmp);
          } else {
            // Not a .dmp file, still show the path
            onFileSelected(paths[0]);
          }
        }
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [onFileSelected]);

  return (
    <div className={`drop-zone ${dragOver ? "drag-over" : ""}`}>
      <div className="drop-area">
        <span className="drop-icon">📁</span>
        <span className="drop-text">
          {dragOver ? "释放以加载文件" : "拖拽 .dmp 文件到此处"}
        </span>
        <span className="drop-hint">或手动输入路径</span>
      </div>
      <input
        type="text"
        className="file-input"
        placeholder="D:\\path\\to\\crash.dmp"
        value={selectedPath}
        onChange={(e) => onFileSelected(e.target.value)}
      />
    </div>
  );
}
