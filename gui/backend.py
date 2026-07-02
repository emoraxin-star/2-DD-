from fastapi import FastAPI, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pathlib import Path
import json
import os
import mmap
from typing import Optional, List
import mimetypes

app = FastAPI(title="LiberTea RE Browser")

PROJECT_ROOT = Path(__file__).parent.parent

# Data directories
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"
DOCS_DIR = PROJECT_ROOT / "docs"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
BUILD_SCRIPTS_DIR = PROJECT_ROOT / "build_scripts"
RESWEEP_DIR = PROJECT_ROOT / "resweep"
ROOT_FILES = PROJECT_ROOT

mimetypes.add_type('text/plain', '.txt')
mimetypes.add_type('application/json', '.json')
mimetypes.add_type('application/octet-stream', '.bin')
mimetypes.add_type('application/octet-stream', '.dll')


@app.get("/")
async def root():
    return FileResponse(PROJECT_ROOT / "gui" / "index.html")


@app.get("/api/files")
async def list_files(path: str = ""):
    target = PROJECT_ROOT / path
    if not target.exists() or not target.is_relative_to(PROJECT_ROOT):
        raise HTTPException(404, "Not found")
    
    items = []
    for item in sorted(target.iterdir()):
        try:
            rel = item.relative_to(PROJECT_ROOT)
            stat = item.stat()
            items.append({
                "name": item.name,
                "path": str(rel),
                "is_dir": item.is_dir(),
                "size": stat.st_size,
                "modified": stat.st_mtime,
            })
        except:
            pass
    return {"items": items, "path": path}


@app.get("/api/file")
async def read_file(path: str, offset: int = 0, limit: int = 5000):
    target = PROJECT_ROOT / path
    if not target.exists() or not target.is_relative_to(PROJECT_ROOT):
        raise HTTPException(404, "Not found")
    
    if target.suffix in ['.bin', '.dll']:
        # Binary file - return hex dump
        with open(target, 'rb') as f:
            f.seek(offset)
            data = f.read(limit)
        hex_lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f"{offset + i:08x}  {hex_str:<48}  {ascii_str}")
        return {"content": '\n'.join(hex_lines), "is_binary": True, "offset": offset, "size": target.stat().st_size}
    
    # Text file
    with open(target, 'r', encoding='utf-8', errors='replace') as f:
        f.seek(offset)
        content = f.read(limit)
    return {"content": content, "is_binary": False, "offset": offset, "size": target.stat().st_size}


@app.get("/api/search")
async def search_files(q: str = Query(..., min_length=1), path: str = "", limit: int = 50):
    target = PROJECT_ROOT / path if path else PROJECT_ROOT
    if not target.exists() or not target.is_relative_to(PROJECT_ROOT):
        raise HTTPException(404, "Not found")
    
    results = []
    q_lower = q.lower()
    
    for file_path in target.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix in ['.bin', '.dll', '.vsidx', '.sqlite', '.wsuo']:
            continue
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    if q_lower in line.lower():
                        rel = file_path.relative_to(PROJECT_ROOT)
                        results.append({
                            "file": str(rel),
                            "line": i,
                            "content": line.strip()[:200],
                        })
                        if len(results) >= limit:
                            break
                if len(results) >= limit:
                    break
        except:
            pass
    return {"results": results, "query": q}


@app.get("/api/strings")
async def get_strings(
    file: str = "all_strings.txt",
    query: str = "",
    offset: int = 0,
    limit: int = 100,
    encoding: str = "utf-8"
):
    files_map = {
        "all_strings.txt": DATA_DIR / "all_strings.txt",
        "all_strings_raw.txt": DATA_DIR / "all_strings_raw.txt",
        "strings_utf16le.txt": DATA_DIR / "strings_utf16le.txt",
        "agentE_all_strings.txt": DATA_DIR / "agentE_all_strings.txt",
        "agentE_full_strings_sorted.txt": DATA_DIR / "agentE_full_strings_sorted.txt",
        "extracted_ascii.txt": LOGS_DIR / "extracted_ascii.txt",
        "extracted_utf16le.txt": LOGS_DIR / "extracted_utf16le.txt",
    }
    
    target = files_map.get(file, DATA_DIR / file)
    if not target.exists():
        raise HTTPException(404, "File not found")
    
    results = []
    with open(target, 'r', encoding=encoding, errors='ignore') as f:
        for i, line in enumerate(f):
            if i < offset:
                continue
            if query and query.lower() not in line.lower():
                continue
            results.append({"line": i, "content": line.rstrip()})
            if len(results) >= limit:
                break
    
    total_lines = sum(1 for _ in open(target, 'r', encoding=encoding, errors='ignore'))
    return {"strings": results, "total": total_lines, "offset": offset, "limit": limit}


@app.get("/api/patterns")
async def get_patterns(
    module: str = "",
    hook_type: str = "",
    query: str = "",
    offset: int = 0,
    limit: int = 100
):
    patterns_file = DATA_DIR / "patterns_extracted.json"
    if not patterns_file.exists():
        raise HTTPException(404, "Patterns file not found")
    
    with open(patterns_file, 'r') as f:
        data = json.load(f)
    
    patterns = data.get("patterns", [])
    
    if module:
        patterns = [p for p in patterns if module.lower() in p.get("module", "").lower()]
    if hook_type:
        patterns = [p for p in patterns if hook_type.lower() in p.get("hook_type", "").lower()]
    if query:
        q = query.lower()
        patterns = [p for p in patterns if q in p.get("pattern", "").lower() or q in p.get("description", "").lower() or q in p.get("module", "").lower()]
    
    total = len(patterns)
    results = patterns[offset:offset+limit]
    return {"patterns": results, "total": total, "offset": offset, "limit": limit}


@app.get("/api/patterns/stats")
async def get_pattern_stats():
    patterns_file = DATA_DIR / "patterns_extracted.json"
    if not patterns_file.exists():
        raise HTTPException(404, "Patterns file not found")
    
    with open(patterns_file, 'r') as f:
        data = json.load(f)
    
    patterns = data.get("patterns", [])
    modules = {}
    hook_types = {}
    for p in patterns:
        mod = p.get("module", "unknown")
        ht = p.get("hook_type", "unknown")
        modules[mod] = modules.get(mod, 0) + 1
        hook_types[ht] = hook_types.get(ht, 0) + 1
    
    return {"total": len(patterns), "modules": modules, "hook_types": hook_types}


@app.get("/api/docs")
async def list_docs(category: str = ""):
    docs = []
    for cat_dir in sorted(DOCS_DIR.iterdir()):
        if not cat_dir.is_dir():
            continue
        if category and category not in cat_dir.name:
            continue
        for doc in sorted(cat_dir.rglob("*.txt")):
            rel = doc.relative_to(PROJECT_ROOT)
            docs.append({
                "name": doc.name,
                "path": str(rel),
                "category": cat_dir.name,
                "size": doc.stat().st_size,
            })
    return {"docs": docs}


@app.get("/api/logs")
async def list_logs():
    logs = []
    for log in sorted(LOGS_DIR.glob("*.txt")):
        rel = log.relative_to(PROJECT_ROOT)
        logs.append({
            "name": log.name,
            "path": str(rel),
            "size": log.stat().st_size,
        })
    return {"logs": logs}


@app.get("/api/scripts")
async def list_scripts():
    scripts = []
    for script_dir in [SCRIPTS_DIR, BUILD_SCRIPTS_DIR, RESWEEP_DIR]:
        if script_dir.exists():
            for script in sorted(script_dir.rglob("*.py")):
                rel = script.relative_to(PROJECT_ROOT)
                scripts.append({
                    "name": script.name,
                    "path": str(rel),
                    "size": script.stat().st_size,
                })
            for script in sorted(script_dir.rglob("*.ps1")):
                rel = script.relative_to(PROJECT_ROOT)
                scripts.append({
                    "name": script.name,
                    "path": str(rel),
                    "size": script.stat().st_size,
                })
    return {"scripts": scripts}


@app.get("/api/root-files")
async def list_root_files():
    files = []
    for f in sorted(PROJECT_ROOT.iterdir()):
        if f.is_file() and not f.name.startswith('.'):
            rel = f.relative_to(PROJECT_ROOT)
            files.append({
                "name": f.name,
                "path": str(rel),
                "size": f.stat().st_size,
            })
    return {"files": files}


@app.get("/api/binary/hex")
async def get_hex_dump(path: str, offset: int = 0, length: int = 512):
    target = PROJECT_ROOT / path
    if not target.exists() or not target.is_relative_to(PROJECT_ROOT):
        raise HTTPException(404, "Not found")
    
    with open(target, 'rb') as f:
        f.seek(offset)
        data = f.read(length)
    
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_part:<48}  {ascii_part}")
    
    return {
        "lines": lines,
        "offset": offset,
        "length": len(data),
        "total_size": target.stat().st_size,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)