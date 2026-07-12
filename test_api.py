import urllib.request
import urllib.parse
import json
import time
import sys

BASE_URL = "http://localhost:5000"

def test_upload_and_download():
    print("Testing standard upload and download...")
    
    # Prepare multipart form data manually (to avoid extra dependencies)
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    
    # Mock data
    file_content = b"EncryptedPayloadBytesHere12345"
    metadata_enc = "EncryptedMetadataStringExample"
    expiry = "300"
    self_destruct = "false"
    
    # Build body
    body = []
    
    # Metadata field
    body.append(f"--{boundary}".encode('utf-8'))
    body.append('Content-Disposition: form-data; name="metadata"'.encode('utf-8'))
    body.append(''.encode('utf-8'))
    body.append(metadata_enc.encode('utf-8'))
    
    # Expiry field
    body.append(f"--{boundary}".encode('utf-8'))
    body.append('Content-Disposition: form-data; name="expiry"'.encode('utf-8'))
    body.append(''.encode('utf-8'))
    body.append(expiry.encode('utf-8'))
    
    # Self-destruct field
    body.append(f"--{boundary}".encode('utf-8'))
    body.append('Content-Disposition: form-data; name="self_destruct"'.encode('utf-8'))
    body.append(''.encode('utf-8'))
    body.append(self_destruct.encode('utf-8'))
    
    # File field
    body.append(f"--{boundary}".encode('utf-8'))
    body.append('Content-Disposition: form-data; name="file"; filename="payload.enc"'.encode('utf-8'))
    body.append('Content-Type: application/octet-stream'.encode('utf-8'))
    body.append(''.encode('utf-8'))
    body.append(file_content)
    
    body.append(f"--{boundary}--".encode('utf-8'))
    body.append(''.encode('utf-8'))
    
    payload = b"\r\n".join(body)
    
    # Request
    req = urllib.request.Request(f"{BASE_URL}/api/upload", data=payload)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    
    try:
        with urllib.request.urlopen(req) as res:
            response_data = json.loads(res.read().decode('utf-8'))
            file_id = response_data.get("fileId")
            print(f" -> File uploaded successfully. Assigned ID: {file_id}")
            assert file_id is not None
    except Exception as e:
        print(f" -> Upload failed: {e}")
        return False

    # Get Metadata
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/metadata/{file_id}") as res:
            meta = json.loads(res.read().decode('utf-8'))
            print(" -> Metadata fetched correctly.")
            assert meta["metadata_enc"] == metadata_enc
            assert meta["size"] == len(file_content)
            assert meta["self_destruct"] is False
    except Exception as e:
        print(f" -> Get metadata failed: {e}")
        return False

    # Download payload
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/download/{file_id}") as res:
            downloaded_bytes = res.read()
            print(" -> Payload downloaded correctly.")
            assert downloaded_bytes == file_content
    except Exception as e:
        print(f" -> Download failed: {e}")
        return False

    print("Standard upload/download test passed!\n")
    return True


def test_self_destruct():
    print("Testing self-destruct functionality...")
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    file_content = b"SelfDestructDataTest"
    metadata_enc = "EncryptedMetadataForSelfDestruct"
    expiry = "300"
    self_destruct = "true"  # ENABLE SELF-DESTRUCT
    
    body = [
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="metadata"'.encode('utf-8'),
        ''.encode('utf-8'),
        metadata_enc.encode('utf-8'),
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="expiry"'.encode('utf-8'),
        ''.encode('utf-8'),
        expiry.encode('utf-8'),
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="self_destruct"'.encode('utf-8'),
        ''.encode('utf-8'),
        self_destruct.encode('utf-8'),
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="file"; filename="payload.enc"'.encode('utf-8'),
        'Content-Type: application/octet-stream'.encode('utf-8'),
        ''.encode('utf-8'),
        file_content,
        f"--{boundary}--".encode('utf-8'),
        ''.encode('utf-8')
    ]
    payload = b"\r\n".join(body)
    
    req = urllib.request.Request(f"{BASE_URL}/api/upload", data=payload)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    
    try:
        with urllib.request.urlopen(req) as res:
            file_id = json.loads(res.read().decode('utf-8'))["fileId"]
            print(f" -> Self-destruct file uploaded. ID: {file_id}")
    except Exception as e:
        print(f" -> Upload failed: {e}")
        return False

    # Download 1: Should work
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/download/{file_id}") as res:
            downloaded = res.read()
            assert downloaded == file_content
            print(" -> First download succeeded.")
    except Exception as e:
        print(f" -> First download failed: {e}")
        return False

    # Wait a moment for file deletion to execute on the server thread
    time.sleep(1.5)

    # Download 2: Should fail (404)
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/download/{file_id}") as res:
            res.read()
            print(" -> Error: Second download succeeded but file should have self-destructed!")
            return False
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(" -> Second download returned 404 (Correct: file self-destructed).")
        else:
            print(f" -> Unexpected HTTP code on second download: {e.code}")
            return False
    except Exception as e:
        print(f" -> Unexpected error on second download: {e}")
        return False

    print("Self-destruct test passed!\n")
    return True


def test_file_expiry():
    print("Testing file expiration...")
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    file_content = b"TemporaryEphemeralFileBytes"
    metadata_enc = "Metadata"
    expiry = "2"  # Expires in 2 seconds
    self_destruct = "false"
    
    body = [
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="metadata"'.encode('utf-8'),
        ''.encode('utf-8'),
        metadata_enc.encode('utf-8'),
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="expiry"'.encode('utf-8'),
        ''.encode('utf-8'),
        expiry.encode('utf-8'),
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="self_destruct"'.encode('utf-8'),
        ''.encode('utf-8'),
        self_destruct.encode('utf-8'),
        f"--{boundary}".encode('utf-8'),
        'Content-Disposition: form-data; name="file"; filename="payload.enc"'.encode('utf-8'),
        'Content-Type: application/octet-stream'.encode('utf-8'),
        ''.encode('utf-8'),
        file_content,
        f"--{boundary}--".encode('utf-8'),
        ''.encode('utf-8')
    ]
    payload = b"\r\n".join(body)
    
    req = urllib.request.Request(f"{BASE_URL}/api/upload", data=payload)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    
    try:
        with urllib.request.urlopen(req) as res:
            file_id = json.loads(res.read().decode('utf-8'))["fileId"]
            print(f" -> Ephemeral file uploaded. ID: {file_id}. Waiting 4 seconds for expiration...")
    except Exception as e:
        print(f" -> Upload failed: {e}")
        return False

    # Wait 4 seconds for expiry daemon or request-time expiry check to trigger
    time.sleep(4)

    # Attempt to download
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/download/{file_id}") as res:
            res.read()
            print(" -> Error: Download succeeded but file should have expired!")
            return False
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(" -> Download returned 404 (Correct: file expired and was purged).")
        else:
            print(f" -> Unexpected HTTP code on expired download: {e.code}")
            return False
    except Exception as e:
        print(f" -> Unexpected error on expired download: {e}")
        return False

    print("File expiration test passed!\n")
    return True


if __name__ == "__main__":
    time.sleep(1)  # Ensure server is fully running
    success = True
    success = success and test_upload_and_download()
    success = success and test_self_destruct()
    success = success and test_file_expiry()
    
    if success:
        print("ALL API ENDPOINT TESTS COMPLETED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED!")
        sys.exit(1)
