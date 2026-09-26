import os
import hashlib
from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Import our custom modules
from blockchain import ledger
import ai_engine

app = FastAPI(title="SIH26188 - AI Document Scanner API")

# Template engine for Frontend
templates = Jinja2Templates(directory="templates")

def get_file_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    # Fixed TemplateResponse syntax for latest FastAPI versions
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})

@app.post("/scan/")
async def scan_document(file: UploadFile = File(...)):
    # Create uploads directory if it doesn't exist
    os.makedirs("uploads", exist_ok=True)
    file_location = f"uploads/{file.filename}"
    
    # Save file temporarily
    file_bytes = await file.read()
    with open(file_location, "wb") as f:
        f.write(file_bytes)
        
    # 1. Cryptographic Hash of the document
    doc_hash = get_file_hash(file_bytes)
    
    # 2. Run AI Forensics & OCR
    analysis_results = ai_engine.analyze_document(file_location)
    
    # 3. Securely Log to Blockchain Ledger
    new_block = ledger.add_document_record(
        doc_hash=doc_hash, 
        status=analysis_results['status']
    )
    
    # Clean up file from server to save space (Security Best Practice)
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
    # An endpoint for Judges to verify the immutable ledger
    return {"chain": ledger.chain, "length": len(ledger.chain)}
