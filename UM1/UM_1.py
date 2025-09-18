from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import qrcode
from io import BytesIO
import base64
import logging
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)

    user = db.relationship('User', backref=db.backref('login_logs', lazy=True))


class ServicePackage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    feature_1 = db.Column(db.Boolean, default=False)
    feature_2 = db.Column(db.Boolean, default=False)
    feature_3 = db.Column(db.Boolean, default=False)
    feature_4 = db.Column(db.Boolean, default=False)
    feature_5 = db.Column(db.Boolean, default=False)
    feature_6 = db.Column(db.Boolean, default=False)
    feature_7 = db.Column(db.Boolean, default=False)
    feature_8 = db.Column(db.Boolean, default=False)
    feature_9 = db.Column(db.Boolean, default=False)
    feature_10 = db.Column(db.Boolean, default=False)
    price = db.Column(db.Float, nullable=False)
    validity_days = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ServicePackage {self.name}>'


class UserService(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    package_id = db.Column(db.Integer, db.ForeignKey('service_package.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    transaction_id = db.Column(db.String(100), unique=True)

    user = db.relationship('User', backref=db.backref('services', lazy=True))
    package = db.relationship('ServicePackage', backref=db.backref('user_services', lazy=True))


# 装饰器：需要登录
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# 装饰器：需要管理员权限
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('需要管理员权限', 'danger')
            return redirect(url_for('index'))

        return f(*args, **kwargs)

    return decorated_function


# 路由定义
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('密码不匹配', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('邮箱已存在', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email, phone=phone)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # 这里简化了验证码处理，实际应用中应该实现验证码功能
        captcha = request.form.get('captcha')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id

            # 记录登录日志
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(login_log)
            db.session.commit()

            flash('登录成功', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('已退出登录', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    active_services = UserService.query.filter_by(user_id=user.id).filter(
        UserService.end_date > datetime.utcnow()
    ).all()

    return render_template('dashboard.html', user=user, active_services=active_services,now=datetime.now())


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user = User.query.get(session['user_id'])

        if not user.check_password(current_password):
            flash('当前密码错误', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('新密码不匹配', 'danger')
            return redirect(url_for('change_password'))

        user.set_password(new_password)
        db.session.commit()

        flash('密码修改成功', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()

        if user:
            # 生成临时密码并发送邮件
            temp_password = str(uuid.uuid4())[:8]
            user.set_password(temp_password)
            db.session.commit()

            # 这里应该实现发送邮件的功能
            # send_email(user.email, '密码重置', f'您的新密码是: {temp_password}')

            flash('新密码已发送到您的邮箱', 'success')
            return redirect(url_for('login'))
        else:
            flash('邮箱不存在', 'danger')

    return render_template('forgot_password.html')


@app.route('/services')
@login_required
def services():
    packages = ServicePackage.query.filter_by(is_active=True).all()
    return render_template('services.html', packages=packages)


@app.route('/purchase/<int:package_id>')
@login_required
def purchase(package_id):
    package = ServicePackage.query.get_or_404(package_id)

    # 生成交易ID
    transaction_id = str(uuid.uuid4())

    # 创建用户服务记录
    user_service = UserService(
        user_id=session['user_id'],
        package_id=package.id,
        transaction_id=transaction_id,
        start_date=datetime.utcnow(),
        end_date=datetime.utcnow() + timedelta(days=package.validity_days)
    )

    # 处理已有服务的有效期顺延
    existing_services = UserService.query.filter_by(user_id=session['user_id']).all()
    for service in existing_services:
        if service.end_date > user_service.start_date:
            service.end_date = user_service.end_date + (service.end_date - service.start_date)

    db.session.add(user_service)
    db.session.commit()

    # 生成支付二维码
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(f"payment:{transaction_id}:{package.price}")
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return render_template('purchase.html', package=package, qr_code=img_str, transaction_id=transaction_id)


# 管理员路由
@app.route('/admin')
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    package_count = ServicePackage.query.filter_by(is_active=True).count()
    service_count = UserService.query.count()
    recent_logs = LoginLog.query.all()

    return render_template('admin/dashboard.html',user_count=user_count, package_count=package_count, service_count=service_count,recent_logs=recent_logs)


@app.route('/admin/packages')
@admin_required
def admin_packages():
    packages = ServicePackage.query.all()
    return render_template('admin/packages.html', packages=packages)


@app.route('/admin/package/add', methods=['GET', 'POST'])
@admin_required
def admin_add_package():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        validity_days = int(request.form.get('validity_days'))

        features = []
        for i in range(1, 11):
            features.append(request.form.get(f'feature_{i}') == 'on')

        package = ServicePackage(
            name=name,
            description=description,
            price=price,
            validity_days=validity_days,
            feature_1=features[0],
            feature_2=features[1],
            feature_3=features[2],
            feature_4=features[3],
            feature_5=features[4],
            feature_6=features[5],
            feature_7=features[6],
            feature_8=features[7],
            feature_9=features[8],
            feature_10=features[9]
        )

        db.session.add(package)
        db.session.commit()

        flash('服务套餐添加成功', 'success')
        return redirect(url_for('admin_packages'))

    return render_template('admin/package_form.html')


@app.route('/admin/package/edit/<int:package_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_package(package_id):
    package = ServicePackage.query.get_or_404(package_id)

    if request.method == 'POST':
        package.name = request.form.get('name')
        package.description = request.form.get('description')
        package.price = float(request.form.get('price'))
        package.validity_days = int(request.form.get('validity_days'))

        for i in range(1, 11):
            setattr(package, f'feature_{i}', request.form.get(f'feature_{i}') == 'on')

        db.session.commit()

        flash('服务套餐更新成功', 'success')
        return redirect(url_for('admin_packages'))

    return render_template('admin/package_form.html', package=package)


@app.route('/admin/package/delete/<int:package_id>')
@admin_required
def admin_delete_package(package_id):
    package = ServicePackage.query.get_or_404(package_id)
    package.is_active = False
    db.session.commit()

    flash('服务套餐已禁用', 'success')
    return redirect(url_for('admin_packages'))


@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/user/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('admin_add_user'))

        if User.query.filter_by(email=email).first():
            flash('邮箱已存在', 'danger')
            return redirect(url_for('admin_add_user'))

        user = User(username=username, email=email, phone=phone, is_admin=is_admin)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash('用户添加成功', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin/user_form.html')


@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.phone = request.form.get('phone')
        user.is_admin = request.form.get('is_admin') == 'on'

        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)

        db.session.commit()

        flash('用户信息更新成功', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin/user_form.html', user=user)


@app.route('/admin/user/delete/<int:user_id>')
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    flash('用户已删除', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/user_services')
@admin_required
def admin_user_services():
    username = request.args.get('username', '')
    user_services = UserService.query

    if username:
        user = User.query.filter_by(username=username).first()
        if user:
            user_services = user_services.filter_by(user_id=user.id)

    user_services = user_services.all()
    return render_template('admin/user_services.html', user_services=user_services, username=username,now=datetime.now())


@app.route('/admin/user_service/edit/<int:service_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user_service(service_id):
    user_service = UserService.query.get_or_404(service_id)

    if request.method == 'POST':
        days_to_add = int(request.form.get('days_to_add', 0))

        if days_to_add > 0:
            user_service.end_date += timedelta(days=days_to_add)
            db.session.commit()
            flash('服务有效期已延长', 'success')
        else:
            flash('请输入有效的天数', 'danger')

        return redirect(url_for('admin_user_services'))

    return render_template('admin/user_service_edit.html', user_service=user_service,now=datetime.now())


# 初始化数据库
@app.before_request
def create_tables():
    db.create_all()

    # 创建默认管理员账户
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        logger.info('默认管理员账户已创建: admin/admin123')


if __name__ == '__main__':
    app.run(debug=True)