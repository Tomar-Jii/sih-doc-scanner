import cv2
import numpy as np
import pytesseract
from PIL import Image, ExifTags
import re

def run_all_modules(image_path):
    results = {"modules": {}, "risk_score": 0, "final_status": ""}
    risk_points = 0
    
    try:
        img = Image.open(image_path)
        cv_img = cv2.imread(image_path)
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    except:
        return {"risk_score": 100, "final_status": "CRITICAL RISK / UNREADABLE", "modules": {}}

    # === 1. PRE-PROCESSING FOR REAL OCR ===
    # Resize aur Adaptive Thresholding se text clear karna
    gray = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
    
    try:
        raw_text = pytesseract.image_to_string(thresh)
        text_upper = raw_text.upper()
        lines = [line.strip() for line in raw_text.split('\n') if len(line.strip()) > 2]
    except:
        raw_text = ""
        text_upper = ""
        lines = []

    # === 2. FACE DETECTION ===
    faces_detected = 0
    try:
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(50, 50))
        faces_detected = len(faces)
    except:
        pass

    # === 3. STRICT GATEWAY (Anti-Screenshot Logic) ===
    has_keywords = bool(re.search(r'(GOVERNMENT|INDIA|REPUBLIC|INCOME|TAX|ELECTION|PAN|AADHAAR|DOB|DATE|NAME|FATHER)', text_upper))
    has_mrz = bool(re.search(r'[PVI]<[A-Z]{3}', text_upper))
    
    # Agar image mein na toh text lines hain, na face, aur na hi ID wale keywords -> REJECT
    if len(lines) < 2 or (faces_detected == 0 and not has_keywords and not has_mrz):
        results["modules"]["ocr"] = {"status": "Blocked", "data": {"ERROR": "INVALID ID OR RANDOM SCREENSHOT DETECTED", "TEXT_LINES_READ": str(len(lines))}}
        results["modules"]["validation"] = {"status": "Critical", "details": "No official ID characteristics found."}
        results["modules"]["tampering"] = {"status": "Skipped", "details": ["Analysis aborted."]}
        results["modules"]["face"] = {"status": "Failed", "details": f"{faces_detected} faces found."}
        results["risk_score"] = 100
        results["final_status"] = "CRITICAL RISK / NOT A DOCUMENT"
        return results

    # === 4. REAL DATA EXTRACTION ===
    extracted_name = "NOT DETECTED"
    extracted_id = "NOT DETECTED"
    extracted_dob = "NOT DETECTED"

    # Aadhaar (XXXX XXXX XXXX), PAN (ABCDE1234F), Passport (A1234567)
    aadhaar_match = re.search(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', raw_text)
    pan_match = re.search(r'\b[A-Z]{5}\d{4}[A-Z]{1}\b', text_upper)
    passport_match = re.search(r'\b[A-Z][0-9]{7}\b', text_upper)

    if aadhaar_match: extracted_id = aadhaar_match.group(0)
    elif pan_match: extracted_id = pan_match.group(0)
    elif passport_match: extracted_id = passport_match.group(0)

    dob_match = re.search(r'\b\d{2}[/\-]\d{2}[/\-]\d{4}\b', raw_text)
    if dob_match:
        extracted_dob = dob_match.group(0)
    elif re.search(r'(DOB|YOB|BIRTH).*?(\d{4})', text_upper):
        extracted_dob = re.search(r'(DOB|YOB|BIRTH).*?(\d{4})', text_upper).group(2)

    # Smart Name Extractor (Avoid govt headers)
    garbage_words = ['GOVERNMENT', 'INDIA', 'INCOME', 'TAX', 'DEPARTMENT', 'ELECTION', 'COMMISSION', 'FATHER', 'NAME', 'DOB', 'SIGNATURE']
    for line in lines:
        upper_line = line.upper()
        if re.match(r'^[A-Z\s\.]{5,25}$', upper_line) and not any(gw in upper_line for gw in garbage_words):
            extracted_name = line
            break

    results["modules"]["ocr"] = {
        "status": "Success",
        "data": {
            "DETECTED_NAME": extracted_name,
            "DETECTED_ID_NO": extracted_id,
            "DETECTED_DOB": extracted_dob,
            "TEXT_LINES_READ": str(len(lines))
        }
    }

    # === 5. VALIDATION PENALTY ===
    if extracted_id == "NOT DETECTED":
        risk_points += 40
        val_status = "Flagged"
        val_details = "Critical Data Missing: ID Number."
    else:
        val_status = "Passed"
        val_details = f"Verified ID Format: {extracted_id}"
        
    if extracted_name == "NOT DETECTED" or extracted_dob == "NOT DETECTED":
        risk_points += 20
        
    results["modules"]["validation"] = {"status": val_status, "details": val_details}

    # === 6. FORENSICS ===
    tampered = False
    try:
        exif = img._getexif()
        if exif:
            for tag_id, val in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag == 'Software' and any(sw in str(val).lower() for sw in ['photoshop', 'gimp']):
                    tampered = True
                    risk_points += 40
    except:
        pass

    results["modules"]["tampering"] = {
        "status": "Flagged" if tampered else "Clean",
        "details": ["Software editing detected in EXIF data."] if tampered else ["No metadata tampering detected."]
    }

    # === 7. FACE PENALTY ===
    if faces_detected >= 1:
        results["modules"]["face"] = {"status": "Verified", "details": f"{faces_detected} human face(s) detected."}
    else:
        results["modules"]["face"] = {"status": "Flagged", "details": "0 faces found. Verification failed."}
        risk_points += 30

    # === 8. FINAL RISK SCORE TIER ===
    results["risk_score"] = min(100, risk_points)
    
    if results["risk_score"] >= 60:
        results["final_status"] = "HIGH RISK / FORGERY SUSPECTED"
    elif results["risk_score"] >= 30:
        results["final_status"] = "MEDIUM RISK / MANUAL REVIEW"
    else:
        results["final_status"] = "CLEAN / AUTHENTIC DOCUMENT"

    return results
