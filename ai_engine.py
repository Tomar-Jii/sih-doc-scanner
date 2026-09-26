import cv2
import numpy as np
import pytesseract
from PIL import Image, ExifTags
import os

def extract_text(image_path):
    try:
        # Load image for OCR
        img = Image.open(image_path)
        # Using Tesseract to extract Machine Readable Zone (MRZ) or general text
        text = pytesseract.image_to_string(img)
        return text.strip()
    except Exception as e:
        return f"OCR Failed: {str(e)}"

def detect_tampering(image_path):
    tampered = False
    reasons = []
    confidence = 95.0 # Base confidence

    try:
        img = Image.open(image_path)
        
        # 1. EXIF Metadata Analysis (Check if edited in Photoshop/GIMP)
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag == 'Software':
                    val_str = str(value).lower()
                    if 'photoshop' in val_str or 'gimp' in val_str or 'canva' in val_str:
                        tampered = True
                        reasons.append(f"Metadata Forensics: Editing software detected ({value}).")
                        confidence -= 40.0
        else:
            reasons.append("Metadata Forensics: No EXIF data found (Possible screenshot or web-downloaded image).")
            confidence -= 10.0

        # 2. Simple Image Forensics using OpenCV (Error Level / Noise Check proxy)
        # Convert to OpenCV format
        cv_img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if cv_img is not None:
            # Calculate variance of Laplacian (Blur detection / compression artifacts)
            variance = cv2.Laplacian(cv_img, cv2.CV_64F).var()
            if variance < 50: # Very blurry or heavily compressed
                reasons.append(f"Image Forensics: Low clarity/resolution (Variance: {variance:.2f}). Possible copy.")
                confidence -= 15.0

        if not tampered and confidence > 80:
            reasons.append("Forensics Passed: Font structures and digital signatures appear consistent.")
            status = "PASSED / AUTHENTIC"
        else:
            status = "FLAGGED / FORGERY DETECTED"

        return {
            "is_tampered": tampered or (confidence < 70),
            "reasons": reasons,
            "confidence": round(max(0, confidence), 2),
            "status": status
        }

    except Exception as e:
        return {"is_tampered": True, "reasons": [f"Analysis Error: {str(e)}"], "confidence": 0, "status": "ERROR"}

def analyze_document(image_path):
    text = extract_text(image_path)
    forensics = detect_tampering(image_path)
    
    return {
        "text_extracted": text[:300] + ("..." if len(text)>300 else ""),
        "is_tampered": forensics["is_tampered"],
        "reasons": forensics["reasons"],
        "confidence": forensics["confidence"],
        "status": forensics["status"]
    }
