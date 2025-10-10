from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import uuid
import qrcode
from io import BytesIO
import base64
import logging
from functools import wraps
import random
import ipaddress
import os
import requests  # 添加requests库
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 短信配置
app.config['SMS_API_URL'] = 'https://push.spug.cc/send/qwL1K8enkBmW4nO1'  # 请替换为实际的短信API URL
app.config['SMS_API_NAME'] = '推送助手'

# 邮件配置
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'  # Hotmail/Outlook的SMTP服务器
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'yao0099@hotmail.com'  # 您的Hotmail邮箱
app.config['MAIL_PASSWORD'] = 'XXXXXXXX'  # 您的邮箱密码或应用专用密码
app.config['MAIL_DEFAULT_SENDER'] = 'yao0099@hotmail.com'

db = SQLAlchemy(app)
mail = Mail(app)

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_beijing_time():
    """获取北京时间（UTC+8）"""
    # 创建UTC+8时区
    beijing_tz = timezone(timedelta(hours=8))
    # 获取当前UTC时间并转换为北京时间
    return datetime.now(beijing_tz)

def get_current_time():
    """获取当前时间（带时区信息）"""
    return get_beijing_time()

def get_client_ip():
    """获取客户端真实IP地址（带验证）"""
    # 可能的代理头列表
    proxy_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP',
        'CF-Connecting-IP',
        'True-Client-IP',
    ]

    for header in proxy_headers:
        ip = request.headers.get(header)
        if ip:
            # 处理多个IP的情况
            if ',' in ip:
                ip = ip.split(',')[0].strip()

            # 验证IP地址格式
            if is_valid_ip(ip):
                return ip

    # 如果没有代理头，使用remote_addr
    return request.remote_addr if is_valid_ip(request.remote_addr) else '0.0.0.0'


def is_valid_ip(ip):
    """验证IP地址格式"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_default_start_date(user_id):
    """计算默认生效日期：已购服务的最后一天，如果没有则从当天开始"""
    print('user_id', user_id)
    # 获取用户当前有效的服务
    active_services = UserService.query.filter_by(user_id=user_id).filter(
        UserService.end_date > datetime.utcnow()
    ).order_by(UserService.end_date.desc()).all()

    if active_services:
        # 如果有有效服务，使用最后一天作为默认开始日期
        latest_end_date = active_services[0].end_date
        # 默认开始日期为最后一天的下一天
        default_start_date = latest_end_date + timedelta(days=1)
    else:
        # 如果没有有效服务，从当天开始
        default_start_date = datetime.utcnow()

    return default_start_date


# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # 改为可选
    phone = db.Column(db.String(20), unique=True, nullable=False)  # 改为必填
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=get_beijing_time)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default = get_beijing_time)
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
    created_at = db.Column(db.DateTime, default=get_beijing_time)

    def __repr__(self):
        return f'<ServicePackage {self.name}>'


class UserService(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    package_id = db.Column(db.Integer, db.ForeignKey('service_package.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=get_beijing_time)  # 修改这里
    start_date = db.Column(db.DateTime, default=get_beijing_time)  # 修改这里
    end_date = db.Column(db.DateTime)
    transaction_id = db.Column(db.String(100), unique=True)

    user = db.relationship('User', backref=db.backref('services', lazy=True))
    package = db.relationship('ServicePackage', backref=db.backref('user_services', lazy=True))

# # 上传并展示微信支付码
# class WeChatQRCodeViewer:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("微信个人收款码展示程序")
#         self.root.geometry("500x600")
#
#         # 创建界面元素
#         self.create_widgets()
#
#     def create_widgets(self):
#         # 标题
#         title_label = tk.Label(self.root, text="微信个人收款码展示", font=("Arial", 16, "bold"))
#         title_label.pack(pady=20)
#
#         # 说明文本
#         info_text = """
#         注意：根据微信政策，无法直接生成收款码。
#         请通过微信APP生成您的收款码并保存为图片，
#         然后使用本程序加载展示。
#
#         微信生成收款码步骤：
#         1. 打开微信APP
#         2. 点击右上角"+"号
#         3. 选择"收付款"
#         4. 点击"二维码收款"
#         5. 点击"保存收款码"
#         """
#         info_label = tk.Label(self.root, text=info_text, justify=tk.LEFT, font=("Arial", 10))
#         info_label.pack(pady=10, padx=20)
#
#         # 图片显示区域
#         self.image_label = tk.Label(self.root, text="暂无收款码图片", relief=tk.SUNKEN, width=40, height=20)
#         self.image_label.pack(pady=20)
#
#         # 按钮区域
#         button_frame = tk.Frame(self.root)
#         button_frame.pack(pady=10)
#
#         load_btn = tk.Button(button_frame, text="加载收款码图片", command=self.load_image)
#         load_btn.pack(side=tk.LEFT, padx=10)
#
#         clear_btn = tk.Button(button_frame, text="清空", command=self.clear_image)
#         clear_btn.pack(side=tk.LEFT, padx=10)
#
#     def load_image(self):
#         file_path = filedialog.askopenfilename(
#             title="选择微信收款码图片",
#             filetypes=[("图片文件", "*.png;*.jpg;*.jpeg;*.bmp")]
#         )
#
#         if file_path:
#             try:
#                 image = Image.open(file_path)
#                 # 调整图片大小以适应显示区域
#                 image.thumbnail((300, 300))
#                 photo = ImageTk.PhotoImage(image)
#
#                 self.image_label.configure(image=photo, text="")
#                 self.image_label.image = photo  # 保持引用
#             except Exception as e:
#                 messagebox.showerror("错误", f"加载图片失败: {str(e)}")
#
#     def clear_image(self):
#         self.image_label.configure(image=None, text="暂无收款码图片")
#         if hasattr(self.image_label, 'image'):
#             self.image_label.image = None
#


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




def generate_math_problem():
    """生成10以内的加减法运算式"""
    a = random.randint(0, 10)
    b = random.randint(0, 10)

    # 随机选择加法或减法
    if random.choice([True, False]):
        # 加法
        problem = f"{a} + {b}"
        answer = a + b
    else:
        # 减法，确保结果不为负数
        if a < b:
            a, b = b, a
        problem = f"{a} - {b}"
        answer = a - b

    return problem, answer


def generate_sms_code():
    """生成6位数字短信验证码"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def send_sms_code(phone, code):
    """发送短信验证码"""
    try:
        url = app.config['SMS_API_URL']
        data = {
            'name': app.config['SMS_API_NAME'],
            'code': code,
            'targets': phone
        }

        response = requests.post(url, json=data)
        result = response.json()

        if response.status_code == 200:
            logger.info(f"短信验证码发送成功: 手机号 {phone}, 验证码 {code}")
            print(f"手机号: {phone}",f"短信验证码: {code}")  # 用于测试，实际环境中应该删除
            return True
        else:
            logger.error(f"短信验证码发送失败: {result}")
            return False
    except Exception as e:
        logger.error(f"发送短信验证码时出现异常: {str(e)}")
        return False

def generate_random_password():
    """生成8位随机密码"""
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(8))

# 路由定义
@app.route('/')
def index():
    return render_template('index.html')


# 修改注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        sms_code = request.form.get('sms_code')

        # 验证必填字段
        if not username or not phone or not sms_code:
            flash('用户名、手机号和验证码为必填项', 'danger')
            return redirect(url_for('register'))

        # 验证短信验证码
        stored_code = session.get(f'sms_code_{phone}')
        code_expire = session.get(f'sms_code_expire_{phone}')

        if not stored_code or not code_expire:
            flash('请先获取短信验证码', 'danger')
            return redirect(url_for('register'))

        # 修复时间比较问题：统一使用带时区的时间
        if get_current_time() > code_expire:
            flash('验证码已过期，请重新获取', 'danger')
            return redirect(url_for('register'))

        if sms_code != stored_code:
            flash('验证码不正确', 'danger')
            return redirect(url_for('register'))

        # 验证密码
        if password != confirm_password:
            flash('密码不匹配', 'danger')
            return redirect(url_for('register'))

        # 如果密码为空，使用手机号作为密码
        if not password:
            password = phone

        # 检查用户名和手机号是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(phone=phone).first():
            flash('手机号已存在', 'danger')
            return redirect(url_for('register'))

        # # 邮箱可选，但如果提供了需要检查唯一性
        # if email and User.query.filter_by(email=email).first():
        #     flash('邮箱已存在', 'danger')
        #     return redirect(url_for('register'))

        # 创建用户
        user = User(username=username, email=email, phone=phone)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        # 注册成功后清除验证码
        session.pop(f'sms_code_{phone}', None)
        session.pop(f'sms_code_expire_{phone}', None)

        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# 添加发送短信验证码的路由
@app.route('/send_sms_code', methods=['POST'])
def send_sms_code_route():
    """发送短信验证码"""
    phone = request.json.get('phone')

    if not phone:
        return jsonify({'success': False, 'message': '手机号不能为空'})

    # 检查手机号是否已注册
    if User.query.filter_by(phone=phone).first():
        return jsonify({'success': False, 'message': '该手机号已注册'})

    # 生成验证码
    code = generate_sms_code()
    expire_time = datetime.now() + timedelta(minutes=5)  # 5分钟后过期

    # 发送短信
    if send_sms_code(phone, code):
        # 存储验证码到session
        session[f'sms_code_{phone}'] = code
        session[f'sms_code_expire_{phone}'] = expire_time

        logger.info(f"验证码发送成功: {phone} -> {code} (过期时间: {expire_time})")
        return jsonify({'success': True, 'message': '验证码发送成功'})
    else:
        return jsonify({'success': False, 'message': '验证码发送失败，请稍后重试'})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        problem, answer = generate_math_problem()
        problem_id = str(uuid.uuid4())
        session[problem_id] = answer
        session['problem_id'] = problem_id
        return render_template('login.html', problem=problem, problem_id=problem_id)

    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_answer = request.form.get('answer', '').strip()
        problem_id = request.form.get('problem_id', '').strip()

        # 验证验证码
        correct_answer = session.get(problem_id)
        captcha_valid = False

        if correct_answer is not None:
            try:
                user_answer_int = int(user_answer)
                if user_answer_int == correct_answer:
                    captcha_valid = True
                    session.pop(problem_id, None)
                else:
                    flash('验证码错误！', 'danger')
            except ValueError:
                flash('请输入有效的验证码数字！', 'danger')
        else:
            flash('验证码已过期，请刷新重试', 'danger')

        # 验证用户名和密码
        user = User.query.filter_by(username=username).first()
        password_valid = user and user.check_password(password)

        if not password_valid:
            flash('用户名或密码错误', 'danger')

        if captcha_valid and password_valid:
            session['user_id'] = user.id
            login_log = LoginLog(
                user_id=user.id,
                login_time=get_beijing_time(),
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(login_log)
            db.session.commit()
            flash('登录成功', 'success')
            return redirect(url_for('dashboard'))

        problem, answer = generate_math_problem()
        problem_id = str(uuid.uuid4())
        session[problem_id] = answer
        session['problem_id'] = problem_id
        return render_template('login.html', problem=problem, problem_id=problem_id, username=username)


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


# 添加忘记密码发送短信验证码的路由
@app.route('/forgot_password_send_sms', methods=['POST'])
def forgot_password_send_sms():
    print("Received request for forgot_password_send_sms")
    """忘记密码 - 发送短信验证码"""
    phone = request.json.get('phone')

    if not phone:
        return jsonify({'success': False, 'message': '手机号不能为空'})

    # 检查手机号是否已注册
    user = User.query.filter_by(phone=phone).first()
    if not user:
        return jsonify({'success': False, 'message': '该手机号未注册'})

    # 生成验证码
    code = generate_sms_code()
    expire_time = get_current_time() + timedelta(minutes=5)  # 5分钟后过期
    print(code)
    # 发送短信
    if send_sms_code(phone, code):
        # 存储验证码到session
        session[f'forgot_password_sms_code_{phone}'] = code
        session[f'forgot_password_sms_expire_{phone}'] = expire_time
        session[f'forgot_password_phone'] = phone  # 保存手机号用于后续验证

        logger.info(f"忘记密码验证码发送成功: {phone} -> {code} (过期时间: {expire_time})")
        return jsonify({'success': True, 'message': '验证码发送成功'})
    else:
        return jsonify({'success': False, 'message': '验证码发送失败，请稍后重试'})


# 修改忘记密码路由
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        phone = request.form.get('phone')
        sms_code = request.form.get('sms_code')

        # 验证必填字段
        if not phone or not sms_code:
            flash('手机号和验证码为必填项', 'danger')
            return redirect(url_for('forgot_password'))

        # 验证短信验证码
        stored_code = session.get(f'forgot_password_sms_code_{phone}')
        code_expire = session.get(f'forgot_password_sms_expire_{phone}')

        if not stored_code or not code_expire:
            flash('请先获取短信验证码', 'danger')
            return redirect(url_for('forgot_password'))

        # 验证验证码是否过期
        if get_current_time() > code_expire:
            flash('验证码已过期，请重新获取', 'danger')
            return redirect(url_for('forgot_password'))

        if sms_code != stored_code:
            flash('验证码不正确', 'danger')
            return redirect(url_for('forgot_password'))

        # 查找用户
        user = User.query.filter_by(phone=phone).first()
        if not user:
            flash('手机号未注册', 'danger')
            return redirect(url_for('forgot_password'))

        # 生成新密码
        new_password = generate_random_password()
        user.set_password(new_password)
        db.session.commit()

        # 清除session中的验证码
        session.pop(f'forgot_password_sms_code_{phone}', None)
        session.pop(f'forgot_password_sms_expire_{phone}', None)
        session.pop(f'forgot_password_phone', None)

        # 显示账号和新密码
        return render_template('forgot_password_result.html',
                               username=user.username,
                               new_password=new_password)

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

    user = User.query.get(session['user_id'])

    # 创建用户服务记录
    user_service = UserService(
        user_id=session['user_id'],
        package_id=package.id,
        transaction_id=transaction_id,
        start_date=get_default_start_date(user.id),
        end_date=get_default_start_date(user.id) + timedelta(days=package.validity_days)
    )

    # # 处理已有服务的有效期顺延
    # existing_services = UserService.query.filter_by(user_id=session['user_id']).all()
    # for service in existing_services:
    #     if service.end_date > user_service.start_date:
    #         service.end_date = user_service.end_date + (service.end_date - service.start_date)

    db.session.add(user_service)
    db.session.commit()

    # 根据package_id决定显示二维码还是图片
    qr_code = None
    use_image = False
    image_filename = None

    if package_id in [1, 2, 3]:
        use_image = True
        image_filename = f'Pay_{package_id}.jpg'
        # 记录使用图片支付的情况
        logger.info(f"用户 {session['user_id']} 购买套餐 {package_id}，使用图片支付: {image_filename}")
    else:
        # 生成支付二维码（针对其他套餐）
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
        qr_code = base64.b64encode(buffered.getvalue()).decode()

    return render_template('purchase.html',
                           package=package,
                           qr_code=qr_code,
                           transaction_id=transaction_id,
                           use_image=use_image,
                           image_filename=image_filename)


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

    try:
        # 1. 先删除该用户的登录日志
        login_logs = LoginLog.query.filter_by(user_id=user_id).all()
        for log in login_logs:
            db.session.delete(log)

        # 2. 再删除该用户的服务记录
        user_services = UserService.query.filter_by(user_id=user_id).all()
        for service in user_services:
            db.session.delete(service)

        # 3. 最后删除用户记录
        db.session.delete(user)

        db.session.commit()
        flash('用户已删除', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"删除用户失败: {str(e)}")
        flash('删除用户失败，请重试', 'danger')

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




@app.route('/verify', methods=['POST'])
def verify():
    """验证用户输入的答案"""
    user_answer = request.form.get('answer', '').strip()
    problem_id = request.form.get('problem_id', '').strip()

    # 从session中获取正确答案
    correct_answer = session.get(problem_id)

    if correct_answer is None:
        return jsonify({"success": False, "message": "验证码已过期，请刷新重试"})

    try:
        user_answer = int(user_answer)

        if user_answer == correct_answer:
            # 验证成功后删除session中的答案
            session.pop(problem_id, None)
            return jsonify({"success": True, "message": "验证成功！"})
        else:
            return jsonify({"success": False, "message": f"验证失败，正确答案是 {correct_answer}"})
    except ValueError:
        return jsonify({"success": False, "message": "请输入有效的数字！"})


@app.route('/refresh_captcha')
def refresh_captcha():
    """刷新生成新的验证码"""
    problem, answer = generate_math_problem()
    problem_id = str(uuid.uuid4())
    session[problem_id] = answer
    session['problem_id'] = problem_id
    return jsonify({"problem": problem, "problem_id": problem_id})


def send_password_reset_email(user_email, temp_password):
    """发送密码重置邮件"""
    try:
        subject = "密码重置通知 - 您的账户新密码"

        # HTML邮件内容
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #0078D4;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: #f9f9f9;
                    padding: 20px;
                    border-radius: 0 0 5px 5px;
                    border: 1px solid #ddd;
                }}
                .password-box {{
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 15px;
                    margin: 15px 0;
                    border-radius: 5px;
                    font-size: 18px;
                    font-weight: bold;
                    text-align: center;
                }}
                .warning {{
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    color: #721c24;
                }}
                .footer {{
                    margin-top: 20px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    font-size: 12px;
                    color: #666;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>密码重置通知</h1>
            </div>
            <div class="content">
                <p>尊敬的用户，您好！</p>
                <p>我们收到了您重置密码的请求。以下是您的新临时密码：</p>

                <div class="password-box">
                    {temp_password}
                </div>

                <div class="warning">
                    <strong>安全提示：</strong>
                    <ul>
                        <li>请立即使用此临时密码登录系统</li>
                        <li>登录后请尽快修改为您自己的密码</li>
                        <li>请不要将此密码分享给任何人</li>
                        <li>如果您没有请求重置密码，请立即联系管理员</li>
                    </ul>
                </div>

                <p>请点击以下链接登录系统：</p>
                <p>
                    <a href="{url_for('login', _external=True)}" 
                       style="background-color: #0078D4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        立即登录
                    </a>
                </p>

                <p>如果按钮无法点击，请复制以下链接到浏览器地址栏：</p>
                <p>{url_for('login', _external=True)}</p>
            </div>
            <div class="footer">
                <p>此邮件由系统自动发送，请勿回复。</p>
                <p>如果您有任何问题，请联系系统管理员。</p>
                <p>&copy; 2024 用户管理系统. 保留所有权利.</p>
            </div>
        </body>
        </html>
        """

        # 纯文本版本
        text_body = f"""
        密码重置通知

        尊敬的用户，您好！

        我们收到了您重置密码的请求。以下是您的新临时密码：

        {temp_password}

        安全提示：
        - 请立即使用此临时密码登录系统
        - 登录后请尽快修改为您自己的密码
        - 请不要将此密码分享给任何人
        - 如果您没有请求重置密码，请立即联系管理员

        登录链接：{url_for('login', _external=True)}

        此邮件由系统自动发送，请勿回复。
        """

        # 创建邮件消息
        msg = Message(
            subject=subject,
            recipients=[user_email],
            html=html_body,
            body=text_body
        )

        # 发送邮件
        mail.send(msg)
        logger.info(f"密码重置邮件已发送至: {user_email}")
        return True

    except Exception as e:
        logger.error(f"发送邮件失败: {str(e)}")
        return False

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)