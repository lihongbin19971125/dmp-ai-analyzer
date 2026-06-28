interface DropZoneProps {
  onFileSelected: (path: string) => void;
  selectedPath: string;
}

export default function DropZone({ onFileSelected, selectedPath }: DropZoneProps) {
  return (
    <div className="drop-zone">
      <label className="drop-label">
        <span className="drop-icon">📁</span>
        <span>DMP File</span>
      </label>
      <input
        type="text"
        className="file-input"
        placeholder="Drag .dmp file here or type path..."
        value={selectedPath}
        onChange={(e) => onFileSelected(e.target.value)}
      />
    </div>
  );
}
