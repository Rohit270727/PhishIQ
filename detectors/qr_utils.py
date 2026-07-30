import cv2

def decode_qr_from_image(image_path):
    img = cv2.imread(image_path)
    if img is None:
        return None, "Could not read the uploaded image. Try a clearer photo or a different file."

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)

    if not data:
        return None, "No QR code detected in this image."

    return data.strip(), None
