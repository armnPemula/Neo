
import threading
import base64
import logging

logger = logging.getLogger(__name__)

_payload_lock = threading.Lock()
uploaded_payload_data = None
uploaded_payload_filename = None

def validate_base64_payload(data):
    try:
        base64.b64decode(data.encode('utf-8'))
        return True
    except Exception:
        logger.error("Invalid base64 payload data")
        return False

def set_uploaded_payload(data, filename):
    global uploaded_payload_data, uploaded_payload_filename

    if not data or not filename:
        logger.error("Invalid payload data or filename provided")
        return False

    if not validate_base64_payload(data):
        logger.error("Invalid base64 payload provided")
        return False

    if len(data.encode('utf-8')) > 50 * 1024 * 1024:
        logger.error("Payload exceeds maximum allowed size of 50MB")
        return False

    with _payload_lock:
        if uploaded_payload_data is not None:
            logger.info(f"Replacing previous payload {uploaded_payload_filename}")

        uploaded_payload_data = data
        uploaded_payload_filename = filename
        logger.info(f"Payload {filename} set in storage ({len(data)} base64 characters)")
        return True

def get_uploaded_payload():
    global uploaded_payload_data, uploaded_payload_filename
    with _payload_lock:
        return uploaded_payload_data, uploaded_payload_filename

def clear_uploaded_payload():
    global uploaded_payload_data, uploaded_payload_filename
    with _payload_lock:
        if uploaded_payload_data is not None:
            logger.info(f"Payload {uploaded_payload_filename} cleared from storage")
        uploaded_payload_data = None
        uploaded_payload_filename = None
