import os
import json
import uuid
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, abort
from werkzeug.utils import secure_filename

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('scanner.log'), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['YARA_RULES'] = os.path.join(os.path.dirname(__file__), 'yara_rules', 'universal_malware.yar')
app.config['VIRUSTOTAL_API_KEY'] = os.environ.get('VIRUSTOTAL_API_KEY', '')
app.config['SECRET_KEY'] = os.urandom(24)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

import sys
sys.path.insert(0, os.path.dirname(__file__))

from utils.file_analyzer import (
    get_file_info, extract_pdf_metadata,
    detect_javascript, extract_embedded_files,
    analyze_pe, analyze_office, analyze_archive,
    analyze_script, analyze_image, analyze_generic,
    scan_with_yara, calculate_risk_score,
)
from utils.virustotal import check_hash, upload_file as vt_upload

ALLOWED_EXTENSIONS = {
    'pdf', 'exe', 'dll', 'sys', 'elf', 'so', 'dmg',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf',
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'jar', 'apk',
    'py', 'js', 'vbs', 'ps1', 'bat', 'cmd', 'sh', 'php', 'rb', 'pl', 'hta', 'wsf',
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'tif', 'tiff', 'bmp',
    'html', 'htm', 'xml', 'json', 'csv', 'txt', 'log',
    'iso', 'img', 'lnk', 'url', 'eml', 'msg',
}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def cleanup_old_files():
    import time
    folder = app.config['UPLOAD_FOLDER']
    now = time.time()
    for fname in os.listdir(folder):
        fpath = os.path.join(folder, fname)
        try:
            if os.path.isfile(fpath) and (now - os.path.getmtime(fpath)) > 3600:
                os.remove(fpath)
        except Exception:
            pass


def run_type_specific_analysis(file_path, file_type):
    cat = file_type.get('type_category', 'unknown')
    ext = file_type.get('extension', '')
    if cat == 'pdf':
        return {
            'analyzer': 'PDF',
            'metadata': extract_pdf_metadata(file_path),
            'javascript': detect_javascript(file_path),
            'embedded_files': extract_embedded_files(file_path),
        }
    elif cat == 'exe':
        return {'analyzer': 'PE Executable', 'pe_analysis': analyze_pe(file_path)}
    elif cat == 'elf':
        return {'analyzer': 'ELF Binary', 'pe_analysis': analyze_pe(file_path)}
    elif cat == 'office':
        return {'analyzer': 'Office Document', 'office_analysis': analyze_office(file_path, ext)}
    elif cat == 'archive':
        return {'analyzer': 'Archive', 'archive_analysis': analyze_archive(file_path, ext)}
    elif cat == 'script':
        return {'analyzer': 'Script', 'script_analysis': analyze_script(file_path, ext)}
    elif cat == 'image':
        return {'analyzer': 'Image', 'image_analysis': analyze_image(file_path, ext)}
    else:
        return {'analyzer': 'Generic', 'generic_analysis': analyze_generic(file_path)}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def scan_file():
    cleanup_old_files()
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    vt_api_key = request.form.get('vt_api_key', app.config['VIRUSTOTAL_API_KEY'])
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not supported.'}), 400

    original_filename = secure_filename(file.filename)
    scan_id = str(uuid.uuid4())
    unique_filename = f'{scan_id}_{original_filename}'
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    try:
        file.save(file_path)
        logger.info(f'Uploaded: {original_filename} (scan_id={scan_id})')

        file_info = get_file_info(file_path, original_filename)
        file_info['scan_id'] = scan_id
        file_type = file_info['file_type']

        yara_results = scan_with_yara(file_path, app.config['YARA_RULES'])
        type_analysis = run_type_specific_analysis(file_path, file_type)
        generic = analyze_generic(file_path)

        vt_results = {'available': False, 'message': 'VirusTotal API key not configured'}
        if vt_api_key:
            sha256 = file_info['hashes']['sha256']
            vt_results = check_hash(sha256, vt_api_key)
            if not vt_results.get('found') and vt_results.get('available'):
                vt_results = vt_upload(file_path, vt_api_key)

        primary_analysis = next(
            (v for k, v in type_analysis.items() if isinstance(v, dict) and k != 'analyzer'),
            generic
        )
        risk = calculate_risk_score(yara_results, primary_analysis, file_type.get('type_category', 'unknown'))

        report = {
            'scan_id': scan_id,
            'scan_time': datetime.now().isoformat(),
            'file_info': file_info,
            'risk': risk,
            'yara_results': yara_results,
            'type_analysis': type_analysis,
            'generic_analysis': generic,
            'virustotal': vt_results,
        }

        report_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{scan_id}_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f'Scan complete: {scan_id} | {risk["level"]} ({risk["score"]})')
        return jsonify(report)

    except Exception as e:
        logger.error(f'Scan error ({scan_id}): {e}')
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/api/report/<scan_id>')
def download_report(scan_id):
    if not all(c in '0123456789abcdef-' for c in scan_id):
        abort(400)
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{scan_id}_report.json')
    if not os.path.exists(report_path):
        abort(404)
    return send_file(report_path, mimetype='application/json', as_attachment=True,
                     download_name=f'scan_report_{scan_id[:8]}.json')


@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum 100MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
