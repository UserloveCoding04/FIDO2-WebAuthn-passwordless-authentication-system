import os
import json
from flask import Flask, session, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from webauthn import generate_registration_options, generate_authentication_options, verify_authentication_response, verify_registration_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor
)
from webauthn.helpers import options_to_json, base64url_to_bytes

# khoi tao flask app
app = Flask(__name__, static_folder='.', static_url_path='')

#cau hinh bi mat cho session
app.config['SECRET_KEY'] = os.urandom(32)

#ten website
RP_NAME = "Lab FIDO2"
RP_ID = "localhost"
ORIGIN = "http://localhost:5000"

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123456@localhost/fido2'
app.config['SECRET_KEY'] = os.urandom(32)
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_handle = db.Column(db.LargeBinary(64), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    credentials = db.relationship('Credential', backref='user', lazy=True)

class Credential(db.Model):
    __tablename__ = 'credentials'
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.LargeBinary(255), unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary(255), nullable=False)
    sign_count = db.Column(db.Integer, default=0, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

#ĐĂNG KÝ
@app.route('/register/start', methods=['POST'])
def register_start():
    username = request.json.get('username')
    email = request.json.get('email')
    if not username or not email:
        return jsonify({"error": "Nhập đủ thông tin"}), 400
    #Kiểm tra user tồn tại
    existing_user = User.query.filter_by(username=username, email=email).first()
    if existing_user:
        return jsonify({"error": "Tài khoản đã tồn tại"}), 400
    #Tạo user mới và lưu csdl
    user_handle = os.urandom(32)
    new_user = User(
        user_handle=user_handle,
        username=username,
        email=email,
        display_name=username
    )
    db.session.add(new_user)
    db.session.commit()

    #tạo option đăng ký
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=new_user.user_handle,
        user_name=new_user.username,
        user_display_name=new_user.display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        )   
    )

    #lưu challenge và username vào session
    session['challenge'] = options.challenge
    session['username_for_registration'] = new_user.username

    #gửi options về JS
    return jsonify(json.loads(options_to_json(options)))

@app.route('/register/finish', methods=['POST'])
def register_finish():
    #lấy user và challenge từ sesion
    username = session.get('username_for_registration')
    challenge = session.get('challenge')
    user = User.query.filter_by(username=username).first()

    if not all([username, challenge, user]):
        return jsonify({"error": "Session không hợp lệ"}), 400
    registration_response = request.json
    #kiểm tra dữ liệu đăng ký
    try:
        credential = verify_registration_response(
            credential=registration_response,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )
    except Exception as e:
        return jsonify({"error": f"Xác thực thất bại: {e}"}), 400
    
    #kiểm tra xem khóa đã tồn tại chưa
    existing_cred = Credential.query.filter_by(credential_id=credential.credential_id).first()
    if existing_cred:
        return jsonify({"error": "Khóa này đã được đăng ký"}), 400
    
    #lưu khóa vào csdl
    new_cred = Credential(
        credential_id=credential.credential_id,
        public_key=credential.credential_public_key,
        sign_count=credential.sign_count,
        user_id=user.id
    )

    db.session.add(new_cred)
    db.session.commit()

    #xóa session
    session.pop('challenge', None)
    session.pop('username_for_registration', None)

    return jsonify({"success": f"Đã đăng ký khóa cho user {username}"})

#ĐĂNG NHẬP
@app.route('/login/start', methods=['POST'])
def login_start():
    username = request.json.get('username')
    email = request.json.get('email')

    #tìm user trong csdl
    user = User.query.filter_by(username=username, email=email).first()
    if not user:
        return jsonify({"error": "User không tìm thấy"}), 400
    
    #lấy các khóa user đã đăng ký từ csdl 
    allowed_credentials = [
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in user.credentials
    ]

    if not allowed_credentials:
        return jsonify({"error": "User chưa đăng ký khóa nào"}), 400
    
    #tạo options đăng nhập
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allowed_credentials,
        user_verification=UserVerificationRequirement.REQUIRED
    )

    #lưu challenge và username vào session
    session['challenge'] = options.challenge
    session['username_for_login'] = username
    session['email_for_login'] = email

    return jsonify(json.loads(options_to_json(options)))

@app.route('/login/finish', methods=['POST'])
def login_finish():
    username = session.get('username_for_login')
    challenge = session.get('challenge')
    user = User.query.filter_by(username=username).first()

    if not all ([username, challenge, user]):
        return jsonify({"error": "Session không hợp lệ"}), 400
    
    login_response = request.json
    cred_id_bytes = base64url_to_bytes(login_response["id"])

    #tìm đúng khóa mà user đang dùng
    credential_to_check = Credential.query.filter_by(
        user_id=user.id,
        credential_id=cred_id_bytes
    ).first()

    if not credential_to_check:
        return jsonify({"error": "Không tìm thấy khóa này cho user"}), 404
    
    #KIỂM TRA CHỮ KÝ
    try:
        verification = verify_authentication_response(
            credential=login_response,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=credential_to_check.public_key,
            credential_current_sign_count=credential_to_check.sign_count
        )
    except Exception as e:
        return jsonify({"error": f"Xác thực thất bại: {e}"}), 400
    
    #update sign count
    credential_to_check.sign_count = verification.new_sign_count
    db.session.commit()

    session['username_logged_in'] = username

    session.pop('challenge', None)
    session.pop('username_for_login', None)

    return jsonify({"success": True, "username": username})

@app.route('/home')
def home():
    username = session.get('username_logged_in') or session.get('username_for_login') or None
    if not username:
        return redirect(url_for('index'))
    return render_template("homepage.html", username=username)

@app.route('/logout')
def logout():
    session.pop('challenge', None)
    session.pop('username_for_login', None)
    session.pop('username_for_registration', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)