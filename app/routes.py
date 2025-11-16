from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import User, EncryptedFile, SharedFile, FinancialReport, PerformanceMetric
from app.forms import RegistrationForm, LoginForm, FileUploadForm, FinancialReportForm, ShareFileForm
from app.crypto_utils import CryptoEngine, encrypt_financial_data, decrypt_financial_data
from app.utils import (allowed_file, generate_file_id, get_file_type, format_file_size, 
                       format_execution_time, create_financial_report_template, 
                       parse_financial_report, log_operation)
import os
from io import BytesIO
from datetime import datetime
from sqlalchemy import or_

main = Blueprint('main', __name__)


@main.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@main.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
        else:
            # Log form errors for debugging
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')
    
    return render_template('login.html', form=form)


@main.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


@main.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing uploaded and shared files"""
    # Get user's files
    user_files = EncryptedFile.query.filter_by(user_id=current_user.id).order_by(EncryptedFile.uploaded_at.desc()).all()
    
    # Get files shared with user
    shared_file_ids = [sf.file_id for sf in SharedFile.query.filter_by(recipient_id=current_user.id).all()]
    shared_files = EncryptedFile.query.filter(EncryptedFile.id.in_(shared_file_ids)).all() if shared_file_ids else []
    
    return render_template('dashboard.html', user_files=user_files, shared_files=shared_files)


@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """File upload and encryption"""
    form = FileUploadForm()
    
    if form.validate_on_submit():
        file = form.file.data
        algorithm = form.algorithm.data
        
        if file and allowed_file(file.filename):
            # Secure the filename
            original_filename = secure_filename(file.filename)
            file_id = generate_file_id()
            
            # Save file temporarily
            temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], f'{file_id}_{original_filename}')
            file.save(temp_path)
            
            try:
                # Encrypt the file — CryptoEngine now returns a wrapped DEK blob instead of raw key
                encrypted_data, wrapped_key, iv, exec_time, original_size, encrypted_size = CryptoEngine.encrypt_file(
                    temp_path, algorithm
                )
                
                # Save encrypted file
                encrypted_filename = f'{file_id}_encrypted'
                encrypted_path = os.path.join(current_app.config['ENCRYPTED_FOLDER'], encrypted_filename)
                
                with open(encrypted_path, 'wb') as f:
                    f.write(encrypted_data)
                
                # Store metadata in database
                file_type = get_file_type(original_filename)
                encrypted_file = EncryptedFile(
                    file_id=file_id,
                    filename=encrypted_filename,
                    original_filename=original_filename,
                    file_type=file_type,
                    file_size=original_size,
                    encrypted_path=encrypted_path,
                    algorithm=algorithm,
                    # store the wrapped DEK blob in new column
                    wrapped_key=wrapped_key,
                    wrapped_key_version='V1',
                    # keep legacy column None to avoid confusion
                    encryption_key=None,
                    iv=iv,
                    user_id=current_user.id
                )
                db.session.add(encrypted_file)
                db.session.commit()
                
                # Store performance metrics
                metric = PerformanceMetric(
                    file_id=encrypted_file.id,
                    algorithm=algorithm,
                    operation='encryption',
                    data_type=file_type,
                    execution_time=exec_time,
                    input_size=original_size,
                    output_size=encrypted_size
                )
                db.session.add(metric)
                db.session.commit()
                
                # Log operation
                log_operation(current_user.id, file_id, 'upload', algorithm, True, None, request.remote_addr)
                
                # Parse financial report if it's an Excel file
                if file_type == 'spreadsheet':
                    financial_data = parse_financial_report(temp_path)
                    if financial_data:
                        # Encrypt financial data (uses same wrapped_key produced earlier)
                        encrypted_dict, _, _ = encrypt_financial_data(financial_data, algorithm, wrapped_key)
                        
                        # Store in database
                        report = FinancialReport(
                            file_id=encrypted_file.id,
                            **encrypted_dict
                        )
                        db.session.add(report)
                        db.session.commit()
                
                # Remove temporary file
                os.remove(temp_path)
                
                flash(f'File encrypted successfully using {algorithm}!', 'success')
                return redirect(url_for('main.file_detail', file_id=file_id))
                
            except Exception as e:
                db.session.rollback()
                log_operation(current_user.id, file_id, 'upload', algorithm, False, str(e), request.remote_addr)
                flash(f'Error encrypting file: {str(e)}', 'danger')
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            flash('Invalid file type.', 'danger')
    
    return render_template('upload.html', form=form)


@main.route('/financial-report', methods=['GET', 'POST'])
@login_required
def financial_report():
    """Create financial report from form"""
    form = FinancialReportForm()
    
    if form.validate_on_submit():
        algorithm = form.algorithm.data
        
        # Collect form data
        financial_data = {
            'company_name': form.company_name.data,
            'report_period': form.report_period.data,
            'department': form.department.data,
            'total_revenue': str(form.total_revenue.data),
            'total_expenses': str(form.total_expenses.data),
            'net_profit': str(form.net_profit.data) if form.net_profit.data else '0',
            'budget_allocated': str(form.budget_allocated.data),
            'budget_spent': str(form.budget_spent.data),
            'variance': str(form.variance.data) if form.variance.data else '0',
            'notes': form.notes.data if form.notes.data else ''
        }
        
        try:
            # Generate file ID
            file_id = generate_file_id()
            
            # Create Excel file
            temp_filename = f'{file_id}_report.xlsx'
            temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
            create_financial_report_template(temp_path)
            
            # Populate the template with data
            import openpyxl
            wb = openpyxl.load_workbook(temp_path)
            ws = wb.active
            
            ws['B3'] = financial_data['company_name']
            ws['B4'] = financial_data['report_period']
            ws['B5'] = financial_data['department']
            ws['B8'] = float(financial_data['total_revenue'])
            ws['B9'] = float(financial_data['total_expenses'])
            ws['B13'] = float(financial_data['budget_allocated'])
            ws['B14'] = float(financial_data['budget_spent'])
            ws['A18'] = financial_data['notes']
            
            wb.save(temp_path)
            
            # Encrypt the file — returns encrypted bytes + wrapped DEK
            encrypted_data, wrapped_key, iv, exec_time, original_size, encrypted_size = CryptoEngine.encrypt_file(
                temp_path, algorithm
            )
            
            # Save encrypted file
            encrypted_filename = f'{file_id}_encrypted'
            encrypted_path = os.path.join(current_app.config['ENCRYPTED_FOLDER'], encrypted_filename)
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Store metadata
            encrypted_file = EncryptedFile(
                file_id=file_id,
                filename=encrypted_filename,
                original_filename=temp_filename,
                file_type='spreadsheet',
                file_size=original_size,
                encrypted_path=encrypted_path,
                algorithm=algorithm,
                    # store wrapped DEK in new column
                    wrapped_key=wrapped_key,
                    wrapped_key_version='V1',
                    encryption_key=None,
                iv=iv,
                user_id=current_user.id
            )
            db.session.add(encrypted_file)
            db.session.commit()
            
            # Store performance metrics
            metric = PerformanceMetric(
                file_id=encrypted_file.id,
                algorithm=algorithm,
                operation='encryption',
                data_type='numerical',
                execution_time=exec_time,
                input_size=original_size,
                output_size=encrypted_size
            )
            db.session.add(metric)
            
            # Encrypt and store financial data (use wrapped_key)
            encrypted_dict, _, _ = encrypt_financial_data(financial_data, algorithm, wrapped_key)
            report = FinancialReport(
                file_id=encrypted_file.id,
                **encrypted_dict
            )
            db.session.add(report)
            db.session.commit()
            
            # Log operation
            log_operation(current_user.id, file_id, 'upload', algorithm, True, None, request.remote_addr)
            
            # Remove temporary file
            os.remove(temp_path)
            
            flash(f'Financial report created and encrypted successfully using {algorithm}!', 'success')
            return redirect(url_for('main.file_detail', file_id=file_id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating financial report: {str(e)}', 'danger')
    
    return render_template('financial_report_form.html', form=form)


@main.route('/file/<file_id>')
@login_required
def file_detail(file_id):
    """View file details"""
    file = EncryptedFile.query.filter_by(file_id=file_id).first_or_404()
    
    # Check if user has permission to view
    if file.user_id != current_user.id:
        shared = SharedFile.query.filter_by(file_id=file.id, recipient_id=current_user.id).first()
        if not shared:
            flash('You do not have permission to view this file.', 'danger')
            return redirect(url_for('main.dashboard'))
    
    # Get performance metrics
    metrics = PerformanceMetric.query.filter_by(file_id=file.id).all()
    
    # Get financial report if exists
    financial_report = FinancialReport.query.filter_by(file_id=file.id).first()
    decrypted_report = None
    
    if financial_report:
        try:
            encrypted_dict = {
                'encrypted_company_name': financial_report.encrypted_company_name,
                'encrypted_report_period': financial_report.encrypted_report_period,
                'encrypted_department': financial_report.encrypted_department,
                'encrypted_total_revenue': financial_report.encrypted_total_revenue,
                'encrypted_total_expenses': financial_report.encrypted_total_expenses,
                'encrypted_net_profit': financial_report.encrypted_net_profit,
                'encrypted_budget_allocated': financial_report.encrypted_budget_allocated,
                'encrypted_budget_spent': financial_report.encrypted_budget_spent,
                'encrypted_variance': financial_report.encrypted_variance,
                'encrypted_notes': financial_report.encrypted_notes,
            }
            # Prefer wrapped_key column, fall back to legacy encryption_key
            wrapped = file.wrapped_key if getattr(file, 'wrapped_key', None) else file.encryption_key
            decrypted_report = decrypt_financial_data(encrypted_dict, file.algorithm, wrapped, file.iv)
        except Exception as e:
            flash(f'Error decrypting financial data: {str(e)}', 'warning')
    
    # Get shared users
    shared_with = db.session.query(User).join(SharedFile).filter(SharedFile.file_id == file.id).all()
    
    return render_template('file_detail.html', 
                         file=file, 
                         metrics=metrics, 
                         financial_report=decrypted_report,
                         shared_with=shared_with,
                         format_size=format_file_size,
                         format_time=format_execution_time)


@main.route('/file/<file_id>/download')
@login_required
def download_file(file_id):
    """Download and decrypt file"""
    file = EncryptedFile.query.filter_by(file_id=file_id).first_or_404()
    
    # Check permission
    if file.user_id != current_user.id:
        shared = SharedFile.query.filter_by(file_id=file.id, recipient_id=current_user.id).first()
        if not shared or not shared.can_download:
            flash('You do not have permission to download this file.', 'danger')
            return redirect(url_for('main.dashboard'))
    
    try:
        # Read encrypted file
        with open(file.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt file — prefer wrapped_key column, fallback to legacy encryption_key
        wrapped = file.wrapped_key if getattr(file, 'wrapped_key', None) else file.encryption_key
        decrypted_data, exec_time = CryptoEngine.decrypt_file(
            encrypted_data, file.algorithm, wrapped, file.iv
        )
        
        # Store decryption performance metric
        metric = PerformanceMetric(
            file_id=file.id,
            algorithm=file.algorithm,
            operation='decryption',
            data_type=file.file_type,
            execution_time=exec_time,
            input_size=len(encrypted_data),
            output_size=len(decrypted_data)
        )
        db.session.add(metric)
        db.session.commit()
        
        # Log operation
        log_operation(current_user.id, file_id, 'download', file.algorithm, True, None, request.remote_addr)
        
        # Send file
        return send_file(
            BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file.original_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        log_operation(current_user.id, file_id, 'download', file.algorithm, False, str(e), request.remote_addr)
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('main.file_detail', file_id=file_id))


@main.route('/file/<file_id>/share', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    """Share file with another user"""
    file = EncryptedFile.query.filter_by(file_id=file_id).first_or_404()
    
    # Only owner can share
    if file.user_id != current_user.id:
        flash('You do not have permission to share this file.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    form = ShareFileForm()
    
    if form.validate_on_submit():
        recipient = User.query.filter_by(username=form.recipient_username.data).first()
        
        if recipient.id == current_user.id:
            flash('You cannot share a file with yourself.', 'warning')
        else:
            # Check if already shared
            existing_share = SharedFile.query.filter_by(file_id=file.id, recipient_id=recipient.id).first()
            
            if existing_share:
                flash('File is already shared with this user.', 'info')
            else:
                # Create share
                share = SharedFile(file_id=file.id, recipient_id=recipient.id)
                db.session.add(share)
                db.session.commit()
                
                # Log operation
                log_operation(current_user.id, file_id, 'share', file.algorithm, True, None, request.remote_addr)
                
                flash(f'File shared successfully with {recipient.username}!', 'success')
                return redirect(url_for('main.file_detail', file_id=file_id))
    
    return render_template('share_file.html', form=form, file=file)


@main.route('/file/<file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete file"""
    file = EncryptedFile.query.filter_by(file_id=file_id).first_or_404()
    
    # Only owner can delete
    if file.user_id != current_user.id:
        flash('You do not have permission to delete this file.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    try:
        # Delete encrypted file from storage
        if os.path.exists(file.encrypted_path):
            os.remove(file.encrypted_path)
        
        # Delete from database (cascades to related records)
        db.session.delete(file)
        db.session.commit()
        
        flash('File deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting file: {str(e)}', 'danger')
    
    return redirect(url_for('main.dashboard'))


@main.route('/performance')
@login_required
def performance():
    """View performance comparison"""
    # Get all metrics for user's files
    user_file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=current_user.id).all()]
    metrics = PerformanceMetric.query.filter(PerformanceMetric.file_id.in_(user_file_ids)).all() if user_file_ids else []
    
    # Organize metrics by algorithm and operation
    performance_data = {
        'AES': {'encryption': [], 'decryption': []},
        'DES': {'encryption': [], 'decryption': []},
        'RC4': {'encryption': [], 'decryption': []}
    }
    
    for metric in metrics:
        if metric.algorithm in performance_data and metric.operation in performance_data[metric.algorithm]:
            performance_data[metric.algorithm][metric.operation].append(metric)
    
    return render_template('performance.html', 
                         metrics=metrics,
                         performance_data=performance_data,
                         format_size=format_file_size,
                         format_time=format_execution_time)


@main.route('/download-template')
@login_required
def download_template():
    """Download financial report template"""
    try:
        # Create template
        temp_filename = 'Financial_Report_Template.xlsx'
        temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
        create_financial_report_template(temp_path)
        
        # Send file
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=temp_filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        flash(f'Error creating template: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))


@main.route('/shared-files')
@login_required
def shared_files():
    """View files shared with user"""
    shared_file_ids = [sf.file_id for sf in SharedFile.query.filter_by(recipient_id=current_user.id).all()]
    files = EncryptedFile.query.filter(EncryptedFile.id.in_(shared_file_ids)).all() if shared_file_ids else []
    
    return render_template('shared_files.html', files=files, format_size=format_file_size)