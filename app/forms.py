from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DecimalField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from app.models import User

class RegistrationForm(FlaskForm):
    """User registration form"""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80, message='Username must be between 3 and 80 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')


class LoginForm(FlaskForm):
    """User login form"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class FileUploadForm(FlaskForm):
    """File upload form with encryption algorithm selection"""
    file = FileField('Select File', validators=[
        FileRequired(),
        FileAllowed(['xlsx', 'xls', 'jpg', 'jpeg', 'png', 'gif', 'pdf'], 
                   'Only Excel files, images, and PDFs are allowed!')
    ])
    algorithm = SelectField('Encryption Algorithm', 
                           choices=[('AES', 'AES-256 (CBC)'), 
                                   ('DES', 'DES (CBC)'), 
                                   ('RC4', 'RC4')],
                           validators=[DataRequired()])
    submit = SubmitField('Upload and Encrypt')


class FinancialReportForm(FlaskForm):
    """Form for entering financial report data"""
    company_name = StringField('Company Name', validators=[DataRequired()])
    report_period = StringField('Report Period', validators=[DataRequired()])
    department = StringField('Department', validators=[DataRequired()])
    
    total_revenue = DecimalField('Total Revenue', validators=[DataRequired()])
    total_expenses = DecimalField('Total Expenses', validators=[DataRequired()])
    net_profit = DecimalField('Net Profit', validators=[Optional()])
    
    budget_allocated = DecimalField('Budget Allocated', validators=[DataRequired()])
    budget_spent = DecimalField('Budget Spent', validators=[DataRequired()])
    variance = DecimalField('Variance', validators=[Optional()])
    
    notes = TextAreaField('Notes', validators=[Optional()])
    
    algorithm = SelectField('Encryption Algorithm', 
                           choices=[('AES', 'AES-256 (CBC)'), 
                                   ('DES', 'DES (CBC)'), 
                                   ('RC4', 'RC4')],
                           validators=[DataRequired()])
    
    submit = SubmitField('Submit and Encrypt Report')


class ShareFileForm(FlaskForm):
    """Form for sharing files with other users"""
    recipient_username = StringField('Recipient Username', validators=[DataRequired()])
    submit = SubmitField('Share File')
    
    def validate_recipient_username(self, recipient_username):
        user = User.query.filter_by(username=recipient_username.data).first()
        if not user:
            raise ValidationError('User not found. Please enter a valid username.')