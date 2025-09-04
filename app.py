from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime
import jwt
from functools import wraps
import requests
import eventlet

eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')

# Handle both SQLite and PostgreSQL database URLs
database_url = os.environ.get('DATABASE_URL', 'sqlite:///civi_connect.db')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='citizen')
    department = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Issue(db.Model):
    __tablename__ = 'issues'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    issue_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='reported')
    priority = db.Column(db.String(10), default='medium')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float)
    address = db.Column(db.String(255))
    image_url = db.Column(db.String(255))
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

class IssueUpdate(db.Model):
    __tablename__ = 'issue_updates'
    id = db.Column(db.Integer, primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issues.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    update_text = db.Column(db.Text)
    status_change = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Utility functions
def get_address_from_coordinates(lat, lng):
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lng}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('display_name', 'Location not found')
    except:
        pass
    return f"Lat: {lat:.6f}, Lng: {lng:.6f}"

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    user = User(
        name=data.get('name'),
        email=data.get('email'),
        password_hash=generate_password_hash(data.get('password'))
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    
    if user and check_password_hash(user.password_hash, data.get('password')):
        token = jwt.encode({
            'user_id': user.id,
            'email': user.email,
            'role': user.role
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department
            }
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin-login', methods=['POST'])
def admin_login():
    data = request.get_json()
    
    # Simple admin verification - in production, use proper admin credentials
    if data.get('admin_id') == 'admin123' and data.get('code') == 'secure2024':
        # Create or get admin user
        admin_user = User.query.filter_by(email='admin@city.gov').first()
        if not admin_user:
            admin_user = User(
                name='Administrator',
                email='admin@city.gov',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                department=data.get('department')
            )
            db.session.add(admin_user)
            db.session.commit()
        
        token = jwt.encode({
            'user_id': admin_user.id,
            'email': admin_user.email,
            'role': admin_user.role
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': admin_user.id,
                'name': admin_user.name,
                'email': admin_user.email,
                'role': admin_user.role,
                'department': admin_user.department
            }
        })
    
    return jsonify({'error': 'Invalid admin credentials'}), 401

@app.route('/api/issues', methods=['GET'])
def get_issues():
    user_id = request.args.get('user_id')
    status = request.args.get('status')
    search = request.args.get('search')
    
    query = Issue.query
    
    if user_id:
        query = query.filter_by(reported_by=user_id)
    if status:
        query = query.filter_by(status=status)
    if search:
        query = query.filter(Issue.title.contains(search) | Issue.description.contains(search))
    
    issues = query.order_by(Issue.created_at.desc()).all()
    
    issues_data = []
    for issue in issues:
        issues_data.append({
            'id': issue.id,
            'title': issue.title,
            'description': issue.description,
            'issue_type': issue.issue_type,
            'status': issue.status,
            'priority': issue.priority,
            'latitude': issue.latitude,
            'longitude': issue.longitude,
            'address': issue.address,
            'image_url': issue.image_url,
            'reported_by': issue.reported_by,
            'created_at': issue.created_at.isoformat(),
            'updated_at': issue.updated_at.isoformat()
        })
    
    return jsonify({
        'issues': issues_data,
        'total': len(issues_data)
    })

@app.route('/api/issues', methods=['POST'])
@token_required
def create_issue(current_user):
    try:
        title = request.form.get('title')
        description = request.form.get('description')
        issue_type = request.form.get('issue_type')
        latitude = float(request.form.get('latitude'))
        longitude = float(request.form.get('longitude'))
        accuracy = request.form.get('accuracy')
        
        # Handle image upload
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_url = f'/uploads/{filename}'
        
        # Get address from coordinates
        address = get_address_from_coordinates(latitude, longitude)
        
        issue = Issue(
            title=title,
            description=description,
            issue_type=issue_type,
            latitude=latitude,
            longitude=longitude,
            accuracy=float(accuracy) if accuracy else None,
            address=address,
            image_url=image_url,
            reported_by=current_user.id
        )
        
        db.session.add(issue)
        db.session.commit()
        
        # Emit real-time update
        socketio.emit('new_issue', {
            'issue_id': issue.id,
            'title': issue.title,
            'type': issue.issue_type,
            'location': address
        }, room='admin')
        
        return jsonify({
            'message': 'Issue created successfully',
            'issue_id': issue.id
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/issues/<int:issue_id>', methods=['PUT'])
@token_required
def update_issue(current_user, issue_id):
    issue = Issue.query.get_or_404(issue_id)
    data = request.get_json()
    
    # Only admin or issue reporter can update
    if current_user.role != 'admin' and issue.reported_by != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    old_status = issue.status
    new_status = data.get('status', issue.status)
    
    issue.status = new_status
    issue.priority = data.get('priority', issue.priority)
    
    if new_status == 'resolved' and old_status != 'resolved':
        issue.resolved_at = datetime.utcnow()
    
    if current_user.role == 'admin' and 'assigned_to' in data:
        issue.assigned_to = data['assigned_to']
    
    # Create update record
    if old_status != new_status:
        update = IssueUpdate(
            issue_id=issue.id,
            user_id=current_user.id,
            update_text=data.get('update_text'),
            status_change=f"{old_status} -> {new_status}"
        )
        db.session.add(update)
    
    db.session.commit()
    
    # Emit real-time update
    socketio.emit('issue_updated', {
        'issue_id': issue.id,
        'status': new_status,
        'updated_by': current_user.name
    })
    
    return jsonify({'message': 'Issue updated successfully'})

@app.route('/api/issues/<int:issue_id>', methods=['DELETE'])
@token_required
def delete_issue(current_user, issue_id):
    issue = Issue.query.get_or_404(issue_id)
    
    # Only admin can delete
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete associated updates
    IssueUpdate.query.filter_by(issue_id=issue.id).delete()
    
    # Delete image file if exists
    if issue.image_url:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], issue.image_url.split('/')[-1]))
        except:
            pass
    
    db.session.delete(issue)
    db.session.commit()
    
    return jsonify({'message': 'Issue deleted successfully'})

@app.route('/api/admin/stats', methods=['GET'])
@token_required
def get_admin_stats(current_user):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    total_issues = Issue.query.count()
    pending_issues = Issue.query.filter(Issue.status.in_(['reported', 'acknowledged'])).count()
    in_progress_issues = Issue.query.filter_by(status='in_progress').count()
    resolved_issues = Issue.query.filter_by(status='resolved').count()
    
    # Recent issues (last 7 days)
    from datetime import timedelta
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_issues = Issue.query.filter(Issue.created_at >= week_ago).count()
    
    # Issues by type
    issue_types = db.session.query(Issue.issue_type, db.func.count(Issue.id)).group_by(Issue.issue_type).all()
    
    return jsonify({
        'total_issues': total_issues,
        'pending_issues': pending_issues,
        'in_progress_issues': in_progress_issues,
        'resolved_issues': resolved_issues,
        'recent_issues': recent_issues,
        'issue_types': dict(issue_types),
        'response_time_avg': 2.3  # Mock data - calculate actual average response time
    })

@app.route('/api/issues/<int:issue_id>/updates', methods=['GET'])
@token_required
def get_issue_updates(current_user, issue_id):
    updates = IssueUpdate.query.filter_by(issue_id=issue_id).order_by(IssueUpdate.created_at.desc()).all()
    
    updates_data = []
    for update in updates:
        user = User.query.get(update.user_id)
        updates_data.append({
            'id': update.id,
            'update_text': update.update_text,
            'status_change': update.status_change,
            'created_at': update.created_at.isoformat(),
            'user_name': user.name if user else 'Unknown'
        })
    
    return jsonify({'updates': updates_data})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# WebSocket events
@socketio.on('connect')
def on_connect():
    print('Client connected')

@socketio.on('disconnect')
def on_disconnect():
    print('Client disconnected')

@socketio.on('join_admin')
def on_join_admin(data):
    # Verify admin token
    try:
        token = data.get('token')
        if token:
            user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if user_data.get('role') == 'admin':
                join_room('admin')
                emit('joined_admin', {'status': 'success'})
    except:
        emit('joined_admin', {'status': 'error'})

# Initialize database
@app.before_first_request
def create_tables():
    try:
        db.create_all()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
