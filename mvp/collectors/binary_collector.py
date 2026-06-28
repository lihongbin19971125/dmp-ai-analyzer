"""Binary file information collector.

When --exe-dir is provided, this collector matches the modules listed in
the DMP against actual files on disk.  It searches:
1. The EXE directory (--exe-dir, with subdirectory walk)
2. DMP-recorded paths (e.g. C:\\Windows\\System32\\ntdll.dll)
3. Common Windows system directories (System32, SysWOW64)
4. Tries .exe / .dll / .sys / .ocx / .cpl extensions when missing

For each found file it extracts:
- PE version (VS_FIXEDFILEINFO) and description
- SHA-256 hash of the first 64 KB
- Debug-info presence
- Version comparison (DMP record vs disk) flagging mismatches
"""

import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path

from ..context import AnalysisContext, BinaryInfo
from .base import BaseCollector


class BinaryCollector(BaseCollector):
    """Collect binary file metadata from disk with enhanced path resolution."""

    name = "binary_collector"

    # Modules that are almost certainly DLLs (never EXEs) – for STEM <-> ext
    # resolution when the DMP records a bare name.
    _KNOWN_DLL_PREFIXES = (
        "ntdll", "kernel32", "kernelbase", "user32", "gdi32", "gdi32full",
        "combase", "ole32", "oleaut32", "advapi32", "sechost", "rpcrt4",
        "bcrypt", "bcryptprimitives", "cryptbase", "win32u", "imm32",
        "msctf", "uxtheme", "dwmapi", "msvcrt", "ucrtbase", "ucrtbased",
        "vcruntime", "msvcp", "concrt", "version", "psapi",
        "kernel_appcore", "wow64cpu", "wow64win",
        "textinputframework", "textshaping", "coreuicomponents",
        "coremessaging", "oleacc", "wintypes", "dbghelp", "dbgcore",
        "symsrv", "srcsrv",
    )

    _PE_EXTENSIONS = (".exe", ".dll", ".sys", ".ocx", ".cpl")

    def __init__(self, recent_threshold_hours: int = 48):
        self.recent_threshold = recent_threshold_hours

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_applicable(self, ctx: AnalysisContext) -> bool:
        return bool(ctx.exe_dir) and Path(ctx.exe_dir).is_dir()

    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        exe_dir = Path(ctx.exe_dir).resolve()
        info = BinaryInfo()
        print(f"  [{self.name}] 扫描二进制文件: {exe_dir}")

        # Build a fast-lookup index for the EXE directory
        file_index: dict[str, Path] = {}
        for root, _, files in os.walk(exe_dir):
            for f in files:
                file_index[f.lower()] = Path(root) / f

        now = datetime.now()
        threshold = now - timedelta(hours=self.recent_threshold)

        found_count = 0
        mismatch_count = 0

        for mod in ctx.dmp.modules:
            disk_path = self._resolve_module_path(
                module_name=mod.name,
                dmp_path=mod.path,
                exe_dir=exe_dir,
                file_index=file_index,
            )

            if disk_path is None:
                info.modules_missing.append(mod.name)
                continue

            # Extract metadata
            meta = self._extract_pe_metadata(disk_path)
            meta["dmp_name"] = mod.name

            # Version comparison
            vcmp = self._compare_versions(
                dmp_version=mod.version,
                disk_version=meta.get("version"),
            )
            meta["version_match"] = vcmp["match"]
            meta["version_mismatch"] = vcmp["mismatch"]
            if vcmp["mismatch"]:
                meta["dmp_version"] = vcmp.get("dmp_version", "")
                meta["disk_version"] = vcmp.get("disk_version", "")
                mismatch_count += 1

            info.modules_found.append(meta)
            found_count += 1

            # Recently modified?
            try:
                mtime = datetime.fromtimestamp(disk_path.stat().st_mtime)
                if mtime > threshold:
                    info.recently_modified_files.append(
                        f"{mod.name} (modified {mtime.isoformat()})"
                    )
            except OSError:
                pass

        # Main EXE version – first .exe in the found list
        for found in info.modules_found:
            dn = found.get("dmp_name", "").lower()
            if dn.endswith(".exe") or (Path(dn).suffix == "" and not dn.startswith(self._KNOWN_DLL_PREFIXES)):
                info.main_exe_version = found.get("version")
                break

        ctx.binaries = info
        msg = f"  [{self.name}] 找到 {found_count} 个模块, 缺失 {len(info.modules_missing)} 个"
        if mismatch_count:
            msg += f", {mismatch_count} 个版本不匹配"
        print(msg)
        return ctx

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _resolve_module_path(
        self,
        module_name: str,
        dmp_path: str,
        exe_dir: Path,
        file_index: dict[str, Path],
    ) -> Path | None:
        """Find a module file on disk using multi-source search.

        Search order:
        1. EXE directory index (fast lookup)
        2. EXE directory (stem + extension guesses)
        3. DMP-recorded path (as-is, then filename-only in EXE dir)
        4. Common Windows system directories
        """
        mod_low = module_name.lower()
        mod_stem = Path(module_name).stem.lower()

        # 1. Exact name in EXE index
        if mod_low in file_index:
            return file_index[mod_low]

        # 2. Stem + known PE extensions in EXE index
        for ext in self._PE_EXTENSIONS:
            key = mod_stem + ext
            if key in file_index:
                return file_index[key]

        # 3. Walk EXE dir for stem match
        for root, _, files in os.walk(exe_dir):
            for f in files:
                fl = f.lower()
                if fl == mod_low or Path(fl).stem == mod_stem:
                    return Path(root) / f

        # 4. DMP-recorded path
        if dmp_path:
            dp = Path(dmp_path)
            if dp.is_file():
                return dp
            # Just the filename, look in EXE dir
            candidate = exe_dir / dp.name
            if candidate.is_file():
                return candidate

        # 5. Common Windows system paths
        for sys_dir in self._build_search_paths(module_name, dmp_path, exe_dir):
            p = Path(sys_dir)
            if p.is_file():
                return p

        return None

    def _build_search_paths(
        self,
        module_name: str,
        dmp_path: str,
        exe_dir: Path | str,
    ) -> list[str]:
        """Build an ordered list of candidate disk paths for a module."""
        candidates = []
        fname = Path(module_name).name if "." in module_name else module_name
        if not fname:
            return candidates

        # Add extension if missing
        if "." not in fname:
            # Guess extension from module name pattern
            if fname.lower().startswith(self._KNOWN_DLL_PREFIXES):
                fname += ".dll"
            else:
                fname += ".exe"
                candidates.append(str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / fname))

        # Windows system directories
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        for sub in ("System32", "SysWOW64"):
            candidates.append(str(Path(windir) / sub / fname))

        # EXE directory
        candidates.append(str(Path(exe_dir) / fname))

        return candidates

    # ------------------------------------------------------------------
    # Version comparison
    # ------------------------------------------------------------------

    def _compare_versions(
        self,
        dmp_version: str | None,
        disk_version: str | None,
    ) -> dict:
        """Compare DMP-recorded version against disk file version.

        Returns:
            dict with keys: match (bool|None), mismatch (bool),
            dmp_version, disk_version
        """
        result = {
            "match": None,
            "mismatch": False,
            "dmp_version": dmp_version or "",
            "disk_version": disk_version or "",
        }
        if dmp_version and disk_version:
            # Normalize: strip leading/trailing junk, compare first 4 parts
            dmp_parts = dmp_version.strip().split(".")[:4]
            disk_parts = disk_version.strip().split(".")[:4]
            result["match"] = dmp_parts == disk_parts
            result["mismatch"] = dmp_parts != disk_parts
        return result

    # ------------------------------------------------------------------
    # File hash
    # ------------------------------------------------------------------

    def _compute_hash(self, path: Path) -> str | None:
        """SHA-256 of the first 64 KB — enough for binary identity."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                h.update(f.read(65536))
            return h.hexdigest()
        except OSError:
            return None

    # ------------------------------------------------------------------
    # PE metadata extraction
    # ------------------------------------------------------------------

    def _extract_pe_metadata(self, path: Path) -> dict:
        """Extract metadata from a PE file on disk.

        Returns a dict with: path, size, version, sha256, has_debug_info,
        description, product_version, machine (x86/x64).
        """
        info: dict = {
            "path": str(path),
            "size": 0,
            "version": None,
            "sha256": None,
            "has_debug_info": False,
            "description": None,
            "product_version": None,
            "machine": None,
        }

        # File size (always available when file exists)
        try:
            info["size"] = path.stat().st_size
        except OSError:
            return info  # can't even stat — bail

        # Hash
        info["sha256"] = self._compute_hash(path)

        # PE parsing
        try:
            import pefile
            pe = pefile.PE(str(path), fast_load=True)
            # fast_load skips resource parsing; parse resources for version
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])

            # Machine type
            mach = pe.FILE_HEADER.Machine
            info["machine"] = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(mach, f"0x{mach:04X}")

            # VS_FIXEDFILEINFO (file version) — may be a list
            vs_list = getattr(pe, "VS_FIXEDFILEINFO", None)
            if vs_list:
                if isinstance(vs_list, list) and vs_list:
                    vs = vs_list[0]
                else:
                    vs = vs_list
                if vs:
                    info["version"] = (
                        f"{vs.FileVersionMS >> 16}.{vs.FileVersionMS & 0xFFFF}."
                        f"{vs.FileVersionLS >> 16}.{vs.FileVersionLS & 0xFFFF}"
                    )

            # StringFileInfo — may be nested list-of-lists
            fi = getattr(pe, "FileInfo", None)
            if fi:
                entries = fi
                # pefile sometimes wraps in extra lists
                while isinstance(entries, list) and entries:
                    if hasattr(entries[0], "StringTable"):
                        break
                    entries = entries[0]
                if isinstance(entries, list):
                    for entry in entries:
                        for st in getattr(entry, "StringTable", []):
                            for k, v in st.entries.items():
                                if k == "FileDescription":
                                    info["description"] = v
                                elif k == "ProductVersion":
                                    info["product_version"] = v

            # Debug directory
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                for entry in pe.DIRECTORY_ENTRY_DEBUG:
                    if entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                        info["has_debug_info"] = True
                        break

            pe.close()
        except ImportError:
            pass
        except Exception:
            pass

        return info
