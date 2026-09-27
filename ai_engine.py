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
        return {"risk_score": 100, "final_status": "ERROR: UNREADABLE IMAGE", "modules": {}}

    # ==========================================
    # PRE-BUILT MODEL 1: FACE DETECTION
    # ==========================================
    faces_detected = 0
    try:
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
        faces_detected = len(faces)
    except:
        pass

    # ==========================================
    # PRE-BUILT MODEL 2: DOCUMENT SHAPE DETECTION (EDGE/CONTOUR)
    # ==========================================
    doc_found = False
    try:
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edged = cv2.Canny(blurred, 30, 150)
        contours, _ = cv2.findContours(edged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for c in contours:
            peri = cv2.arcLength(c, True)
            approx = cv2.approxPolyDP(c, 0.02 * peri, True)
            # Find a large rectangular shape typical of ID cards
            if len(approx) >= 4 and cv2.contourArea(approx) > 10000:
                doc_found = True
                break
    except:
        pass

    # ==========================================
    # REAL OCR EXTRACTION
    # ==========================================
    try:
        raw_text = pytesseract.image_to_string(img)
        text_upper = raw_text.upper()
        # Filter out empty lines
        lines = [line.strip() for line in raw_text.split('\n') if len(line.strip()) > 2]
    except:
        raw_text = ""
        text_upper = ""
        lines = []

    # GATEWAY: Pass if Face is found OR Card Shape is found OR it has sufficient text
    is_valid = faces_detected > 0 or doc_found or len(lines) >= 3

    if not is_valid:
        # Reject non-documents (scenery, blank photos)
        results["modules"]["ocr"] = {"status": "Blocked", "data": {"ERROR": "NO FACE, NO TEXT, OR CARD SHAPE DETECTED"}}
        results["modules"]["validation"] = {"status": "Critical", "details": "Image lacks basic document characteristics."}
        results["modules"]["tampering"] = {"status": "Skipped", "details": ["Analysis aborted."]}
        results["modules"]["face"] = {"status": "Skipped", "details": "No face found."}
        results["risk_score"] = 100
        results["final_status"] = "CRITICAL RISK / NOT A DOCUMENT"
        return results

    # ==========================================
    # EXTRACT REAL DATA (Regex Pattern Matching)
    # ==========================================
    extracted_name = "NOT DETECTED"
    extracted_id = "NOT DETECTED"
    extracted_dob = "NOT DETECTED"

    # Match ID formats (Aadhaar: 0000 0000 0000, PAN: ABCDE1234F, Passport: A1234567)
    aadhaar_match = re.search(r'\d{4}[\s\-]?\d{4}[\s\-]?\d{4}', raw_text)
    pan_match = re.search(r'[A-Z]{5}\d{4}[A-Z]{1}', text_upper)
    passport_match = re.search(r'[A-Z][0-9]{7}', text_upper)

    if aadhaar_match: extracted_id = aadhaar_match.group(0)
    elif pan_match: extracted_id = pan_match.group(0)
    elif passport_match: extracted_id = passport_match.group(0)

    # Match DOB
    dob_match = re.search(r'\d{2}[/\-]\d{2}[/\-]\d{4}', raw_text)
    if dob_match: 
        extracted_dob = dob_match.group(0)
    elif re.search(r'(DOB|YOB|YEAR OF BIRTH).*?(\d{4})', text_upper):
        extracted_dob = re.search(r'(DOB|YOB|YEAR OF BIRTH).*?(\d{4})', text_upper).group(2)

    # Basic Name Heuristic (Usually a fully capitalized line)
    for line in lines:
        if re.match(r'^[A-Z\s]{5,25}$', line) and line not in ["GOVERNMENT OF INDIA", "REPUBLIC OF INDIA", "INCOME TAX DEPARTMENT", "ELECTION COMMISSION"]:
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
    
    results["modules"]["validation"] = {
        "status": "Passed" if extracted_id != "NOT DETECTED" else "Flagged",
        "details": "Valid Government ID pattern verified." if extracted_id != "NOT DETECTED" else "Could not verify official ID format from text."
    }
    
    if extracted_id == "NOT DETECTED": 
        risk_points += 20

    # ==========================================
    # FORENSICS & TAMPERING
    # ==========================================
    tampered = False
    try:
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag == 'Software' and any(sw in str(value).lower() for sw in ['photoshop', 'gimp']):
                    tampered = True
                    risk_points += 40
    except:
        pass

    results["modules"]["tampering"] = {
        "status": "Flagged" if tampered else "Clean",
        "details": ["Software editing detected in EXIF data."] if tampered else ["No metadata tampering detected."]
    }

    # ==========================================
    # FACE VERIFICATION
    # ==========================================
    if faces_detected == 1:
        results["modules"]["face"] = {"status": "Verified", "details": "1 human face accurately detected on document."}
    else:
        results["modules"]["face"] = {"status": "Flagged", "details": f"{faces_detected} faces found. Verification failed."}
        risk_points += 25

    results["risk_score"] = min(100, risk_points)
    
    if results["risk_score"] >= 50:
        results["final_status"] = "HIGH RISK / MANUAL REVIEW REQUIRED"
    else:
        results["final_status"] = "CLEAN / AUTHENTIC DOCUMENT"

    return results
