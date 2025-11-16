import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
import pandas as pd

ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'jpg', 'jpeg', 'png', 'gif', 'pdf'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_file_id():
    """Generate a unique file identifier using UUID"""
    return str(uuid.uuid4())

def get_file_type(filename):
    """Determine file type category"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['xlsx', 'xls']:
        return 'spreadsheet'
    elif ext in ['jpg', 'jpeg', 'png', 'gif']:
        return 'image'
    elif ext == 'pdf':
        return 'pdf'
    else:
        return 'other'

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f'{size_bytes:.2f} {unit}'
        size_bytes /= 1024.0
    return f'{size_bytes:.2f} TB'

def format_execution_time(time_seconds):
    """Format execution time in human-readable format"""
    if time_seconds < 0.001:
        return f'{time_seconds * 1000000:.2f} μs'
    elif time_seconds < 1:
        return f'{time_seconds * 1000:.2f} ms'
    else:
        return f'{time_seconds:.4f} s'

def create_financial_report_template(output_path):
    """
    Create an Excel template for financial reports
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Financial Report'
    
    # Define styles
    header_fill = PatternFill(start_color='366092', end_color='366092', fill_type='solid')
    header_font = Font(color='FFFFFF', bold=True, size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Title
    ws['A1'] = 'CONFIDENTIAL FINANCIAL REPORT'
    ws['A1'].font = Font(bold=True, size=16)
    ws.merge_cells('A1:D1')
    
    # Company Information
    ws['A3'] = 'Company Name:'
    ws['B3'] = '[Enter Company Name]'
    ws['A4'] = 'Report Period:'
    ws['B4'] = '[e.g., Q1 2024]'
    ws['A5'] = 'Department:'
    ws['B5'] = '[Enter Department]'
    
    # Revenue Section
    ws['A7'] = 'REVENUE SUMMARY'
    ws['A7'].font = header_font
    ws['A7'].fill = header_fill
    ws.merge_cells('A7:D7')
    
    ws['A8'] = 'Total Revenue'
    ws['B8'] = 0
    ws['A9'] = 'Total Expenses'
    ws['B9'] = 0
    ws['A10'] = 'Net Profit'
    ws['B10'] = '=B8-B9'
    ws['B10'].font = Font(bold=True)
    
    # Budget Section
    ws['A12'] = 'BUDGET ANALYSIS'
    ws['A12'].font = header_font
    ws['A12'].fill = header_fill
    ws.merge_cells('A12:D12')
    
    ws['A13'] = 'Budget Allocated'
    ws['B13'] = 0
    ws['A14'] = 'Budget Spent'
    ws['B14'] = 0
    ws['A15'] = 'Variance'
    ws['B15'] = '=B13-B14'
    ws['B15'].font = Font(bold=True)
    
    # Notes Section
    ws['A17'] = 'NOTES'
    ws['A17'].font = header_font
    ws['A17'].fill = header_fill
    ws.merge_cells('A17:D17')
    
    ws['A18'] = '[Add any additional notes or comments here]'
    ws.merge_cells('A18:D20')
    
    # Apply borders
    for row in range(3, 16):
        for col in range(1, 3):
            ws.cell(row=row, column=col).border = border
    
    # Set column widths
    ws.column_dimensions['A'].width = 25
    ws.column_dimensions['B'].width = 20
    
    wb.save(output_path)
    return output_path

def parse_financial_report(file_path):
    """
    Parse financial data from Excel file
    Returns: Dictionary of financial data
    """
    try:
        df = pd.read_excel(file_path, header=None)
        
        # Extract data from specific cells
        data = {
            'company_name': str(df.iloc[2, 1]) if pd.notna(df.iloc[2, 1]) else '',
            'report_period': str(df.iloc[3, 1]) if pd.notna(df.iloc[3, 1]) else '',
            'department': str(df.iloc[4, 1]) if pd.notna(df.iloc[4, 1]) else '',
            'total_revenue': str(df.iloc[7, 1]) if pd.notna(df.iloc[7, 1]) else '0',
            'total_expenses': str(df.iloc[8, 1]) if pd.notna(df.iloc[8, 1]) else '0',
            'net_profit': str(df.iloc[9, 1]) if pd.notna(df.iloc[9, 1]) else '0',
            'budget_allocated': str(df.iloc[12, 1]) if pd.notna(df.iloc[12, 1]) else '0',
            'budget_spent': str(df.iloc[13, 1]) if pd.notna(df.iloc[13, 1]) else '0',
            'variance': str(df.iloc[14, 1]) if pd.notna(df.iloc[14, 1]) else '0',
            'notes': str(df.iloc[17, 0]) if pd.notna(df.iloc[17, 0]) else ''
        }
        
        return data
    except Exception as e:
        print(f'Error parsing financial report: {e}')
        return None

def log_operation(user_id, file_id, operation, algorithm=None, success=True, error_message=None, ip_address=None):
    """
    Log encryption/decryption operations
    """
    from app.models import EncryptionLog
    from app import db
    
    log = EncryptionLog(
        user_id=user_id,
        file_id=file_id,
        operation=operation,
        algorithm=algorithm,
        success=success,
        error_message=error_message,
        ip_address=ip_address,
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()