import os
import time
import json
import uuid
import shutil
import threading
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS

app = Flask(__name__, static_folder='public', static_url_path='')
CORS(app)

# Limit uploads to 100MB
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Background thread for periodic cleanup of expired files
def cleanup_loop():
    while True:
        try:
            now = time.time()
            if os.path.exists(UPLOAD_FOLDER):
                for file_id in os.listdir(UPLOAD_FOLDER):
                    folder_path = os.path.join(UPLOAD_FOLDER, file_id)
                    if os.path.isdir(folder_path):
                        meta_path = os.path.join(folder_path, 'meta.json')
                        if os.path.exists(meta_path):
                            try:
                                with open(meta_path, 'r') as f:
                                    meta = json.load(f)
                                upload_time = meta.get('upload_time', 0)
                                expiry_duration = meta.get('expiry', 0)
                                # 0 means infinite/no-expiry (or check if expired)
                                if expiry_duration > 0 and now > (upload_time + expiry_duration):
                                    print(f"[Cleanup] Deleting expired file: {file_id}")
                                    shutil.rmtree(folder_path, ignore_errors=True)
                            except Exception as e:
                                print(f"[Cleanup] Error reading meta for {file_id}: {e}")
                                shutil.rmtree(folder_path, ignore_errors=True)
                        else:
                            # Folder has no metadata, clean it up
                            shutil.rmtree(folder_path, ignore_errors=True)
        except Exception as e:
            print(f"[Cleanup] Error during cleanup: {e}")
        time.sleep(30)  # Check every 30 seconds

# Start the cleanup thread as a daemon so it exits with the main process
cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
cleanup_thread.start()


@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)


@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        # Check if the parts are present
        if 'file' not in request.files or 'metadata' not in request.form:
            return jsonify({"error": "Missing file or metadata"}), 400
        
        file = request.files['file']
        metadata_str = request.form['metadata']  # Encrypted metadata string
        expiry = int(request.form.get('expiry', 3600))  # Default 1 hour
        self_destruct = request.form.get('self_destruct', 'false').lower() == 'true'
        
        file_id = uuid.uuid4().hex
        file_dir = os.path.join(UPLOAD_FOLDER, file_id)
        os.makedirs(file_dir, exist_ok=True)
        
        # Save the encrypted payload
        payload_path = os.path.join(file_dir, 'payload.enc')
        file.save(payload_path)
        
        # Get file size
        file_size = os.path.getsize(payload_path)
        
        # Save the metadata and properties
        meta_data = {
            "file_id": file_id,
            "metadata_enc": metadata_str,
            "size": file_size,
            "upload_time": time.time(),
            "expiry": expiry,
            "self_destruct": self_destruct
        }
        
        with open(os.path.join(file_dir, 'meta.json'), 'w') as f:
            json.dump(meta_data, f)
            
        print(f"[Upload] File uploaded successfully: ID={file_id}, SelfDestruct={self_destruct}, Expiry={expiry}s")
        return jsonify({"fileId": file_id}), 200

    except Exception as e:
        print(f"[Upload Error]: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/metadata/<file_id>', methods=['GET'])
def get_metadata(file_id):
    file_dir = os.path.join(UPLOAD_FOLDER, file_id)
    meta_path = os.path.join(file_dir, 'meta.json')
    
    if not os.path.exists(meta_path):
        return jsonify({"error": "File not found or expired"}), 404
        
    try:
        with open(meta_path, 'r') as f:
            meta = json.load(f)
            
        # Double check expiry before returning
        now = time.time()
        expiry_duration = meta.get('expiry', 0)
        upload_time = meta.get('upload_time', 0)
        
        if expiry_duration > 0 and now > (upload_time + expiry_duration):
            shutil.rmtree(file_dir, ignore_errors=True)
            return jsonify({"error": "File not found or expired"}), 404
            
        return jsonify({
            "fileId": meta["file_id"],
            "metadata_enc": meta["metadata_enc"],
            "size": meta["size"],
            "self_destruct": meta["self_destruct"],
            "expiry": meta["expiry"],
            "upload_time": meta["upload_time"]
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    file_dir = os.path.join(UPLOAD_FOLDER, file_id)
    payload_path = os.path.join(file_dir, 'payload.enc')
    meta_path = os.path.join(file_dir, 'meta.json')
    
    if not os.path.exists(payload_path) or not os.path.exists(meta_path):
        return jsonify({"error": "File not found or expired"}), 404
        
    try:
        with open(meta_path, 'r') as f:
            meta = json.load(f)
            
        # Double check expiry
        now = time.time()
        expiry_duration = meta.get('expiry', 0)
        upload_time = meta.get('upload_time', 0)
        
        if expiry_duration > 0 and now > (upload_time + expiry_duration):
            shutil.rmtree(file_dir, ignore_errors=True)
            return jsonify({"error": "File not found or expired"}), 404
            
        self_destruct = meta.get('self_destruct', False)
        
        # Generator to stream the file and then delete if self_destruct is enabled
        def generate_file_stream():
            try:
                with open(payload_path, 'rb') as f:
                    while True:
                        chunk = f.read(65536)  # 64KB chunks
                        if not chunk:
                            break
                        yield chunk
            finally:
                if self_destruct:
                    print(f"[Self-Destruct] Deleting file path: {file_id}")
                    # Give a split second delay for OS file lock release, then remove the folder
                    def delayed_delete():
                        time.sleep(1)
                        shutil.rmtree(file_dir, ignore_errors=True)
                    threading.Thread(target=delayed_delete).start()
                    
        response = Response(generate_file_stream(), content_type='application/octet-stream')
        response.headers['Content-Length'] = os.path.getsize(payload_path)
        response.headers['Content-Disposition'] = f'attachment; filename="{file_id}.enc"'
        return response
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("--------------------------------------------------")
    print("  Secure File Sharing Server Running at:")
    print("  http://localhost:5000")
    print("--------------------------------------------------")
    app.run(host='0.0.0.0', port=5000, debug=False)
