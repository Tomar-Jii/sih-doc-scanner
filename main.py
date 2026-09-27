import os
import hashlib
from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from blockchain import ledger
import ai_engine

app = FastAPI(title="SIH26188 - AI Document Scanner API")
templates = Jinja2Templates(directory="templates")

def get_file_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})

@app.post("/scan/")
async def scan_document(file: UploadFile = File(...)):
    os.makedirs("uploads", exist_ok=True)
    file_location = f"uploads/{file.filename}"
    
    file_bytes = await file.read()
    with open(file_location, "wb") as f:
        f.write(file_bytes)
        
    doc_hash = get_file_hash(file_bytes)
    
    # Run the 4 SIH Modules
    analysis_results = ai_engine.run_all_modules(file_location)
    
    # Log to Blockchain
    new_block = ledger.add_document_record(
        doc_hash=doc_hash, 
        status=analysis_results['final_status']
    )
    
    if os.path.exists(file_location):
        os.remove(file_location)
        
    return {
        "filename": file.filename,
        "document_hash": doc_hash,
        "analysis": analysis_results,
        "blockchain_receipt": {
            "block_index": new_block['index'],
            "timestamp": new_block['timestamp'],
            "previous_hash": new_block['previous_hash']
        }
    }

@app.get("/ledger/")
async def view_blockchain():
    return {"chain": ledger.chain, "length": len(ledger.chain)}
