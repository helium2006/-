#!/usr/bin/env python3
# file_encryptor_gui_plus_pro.py  –  单用户版，注册登录后使用

import sys, os, json, time, mmap, ctypes, hashlib, hmac, struct, secrets
from pathlib import Path
from datetime import datetime, timezone

import ico_mgr
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QEvent
from PyQt6.QtGui import QFont, QIcon, QGuiApplication

# ---------------- 路径常量 ----------------
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).absolute().parent
else:
    BASE_DIR = Path.home()
    print(BASE_DIR)

CONFIG_DIR = BASE_DIR / 'FileEncryptor_data'
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# 定义加密文件保存的隐藏文件夹
try:
    ENCRYPTED_FOLDER = Path('D:/files/.enc')
    
    # 确保隐藏文件夹存在
    ENCRYPTED_FOLDER.mkdir(parents=True, exist_ok=True)
    # 在Windows上设置文件夹为隐藏属性
    if sys.platform == 'win32':
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(str(ENCRYPTED_FOLDER), FILE_ATTRIBUTE_HIDDEN)
        except Exception as e:
            print(f"设置隐藏文件夹属性失败: {e}")
except Exception as e:
    # 如果D盘不存在或其他错误，使用用户目录作为备选
    ENCRYPTED_FOLDER = Path.home() / '.enc'
    ENCRYPTED_FOLDER.mkdir(parents=True, exist_ok=True)
    print(f"无法创建D:/files/.enc目录，已使用备用目录: {ENCRYPTED_FOLDER}")

KEYFILE   = CONFIG_DIR / 'keyfile.bin'
PWDB      = CONFIG_DIR / 'password_db.enc'
LOG       = CONFIG_DIR / 'logs.enc'
MASTER_SALT_FILE = CONFIG_DIR / 'master_salt.bin'
USER_FILE = CONFIG_DIR / 'user.enc'          # <<< 新增：单用户凭证文件

SALT_LEN = 16
IV_LEN   = 16
MAC_LEN  = 32

# ---------------- 安全存储实现（保持原样） ----------------
try:
    if sys.platform == 'win32':
        import win32security, win32crypt
        HAS_SECURE_STORAGE = True
    elif sys.platform == 'darwin':
        import keyring
        HAS_SECURE_STORAGE = True
    else:
        try:
            import keyring
            HAS_SECURE_STORAGE = True
        except:
            HAS_SECURE_STORAGE = False
except:
    HAS_SECURE_STORAGE = False

def secure_store(data: bytes, label: str) -> bool:
    if not HAS_SECURE_STORAGE:
        return False
    try:
        if sys.platform == 'win32':
            entropy = os.urandom(16)
            encrypted = win32crypt.CryptProtectData(data, label, entropy, None, None, 0)
            (CONFIG_DIR / f'{label}.dat').write_bytes(entropy + encrypted)
            return True
        else:
            keyring.set_password("file_encryptor", label, data.hex())
            return True
    except Exception:
        return False

def secure_retrieve(label: str) -> bytes:
    if not HAS_SECURE_STORAGE:
        return None
    try:
        if sys.platform == 'win32':
            data = (CONFIG_DIR / f'{label}.dat').read_bytes()
            entropy, encrypted = data[:16], data[16:]
            return win32crypt.CryptUnprotectData(encrypted, entropy, None, None, 0)[1]
        else:
            hex_data = keyring.get_password("file_encryptor", label)
            return bytes.fromhex(hex_data) if hex_data else None
    except Exception:
        return None

def secure_delete_storage(label: str):
    if not HAS_SECURE_STORAGE:
        return
    try:
        if sys.platform == 'win32':
            (CONFIG_DIR / f'{label}.dat').unlink(missing_ok=True)
        else:
            keyring.delete_password("file_encryptor", label)
    except:
        pass

# ---------------- 密码强度验证（保持原样） ----------------
def validate_password_strength(password: str):
    if len(password) < 12:
        return False, "密码长度至少需要12个字符"
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "密码必须包含大写字母、小写字母、数字和特殊字符"
    common = ["123", "abc", "qwerty", "password", "admin", "welcome", "login"]
    for p in common:
        if p in password.lower():
            return False, "密码包含常见弱密码模式"
    return True, "密码强度足够"

# ---------------- 加密核心工具（保持原样） ----------------
def secure_delete(b: bytearray):
    try:
        if 'linux' in sys.platform or 'darwin' in sys.platform:
            try:
                ctypes.libc.mlock(ctypes.addressof(ctypes.c_char.from_buffer(b)), len(b))
            except:
                pass
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(b)), 0, len(b))
            try:
                ctypes.libc.munlock(ctypes.addressof(ctypes.c_char.from_buffer(b)), len(b))
            except:
                pass
        else:
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(b)), 0, len(b))
    except:
        pass

def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

def derive_master_key(password: bytes, keyfile: bytes, salt: bytes) -> bytes:
    combined = password + keyfile
    try:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(secret=combined, salt=salt, time_cost=4,
                               memory_cost=64*1024, parallelism=2, hash_len=32, type=Type.ID)
    except ImportError:
        return hashlib.pbkdf2_hmac('sha256', combined, salt, 100000)

def get_master_salt():
    if MASTER_SALT_FILE.exists():
        return MASTER_SALT_FILE.read_bytes()
    salt = random_bytes(SALT_LEN)
    MASTER_SALT_FILE.write_bytes(salt)
    try:
        MASTER_SALT_FILE.chmod(0o600)
    except:
        pass
    return salt

def encrypt_blob(blob: bytes, mk: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad
    salt = random_bytes(SALT_LEN)
    iv = random_bytes(IV_LEN)
    fek = derive_master_key(mk, salt, salt)
    cipher = AES.new(fek, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(blob, AES.block_size))
    mac = hmac.new(fek, salt+iv+ct, SHA256).digest()
    return salt + iv + ct + mac

def decrypt_blob(blob: bytes, mk: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import unpad
    salt, iv, ct, mac = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN+IV_LEN], blob[SALT_LEN+IV_LEN:-MAC_LEN], blob[-MAC_LEN:]
    fek = derive_master_key(mk, salt, salt)
    if not hmac.compare_digest(hmac.new(fek, salt+iv+ct, SHA256).digest(), mac):
        raise ValueError('完整性验证失败')
    cipher = AES.new(fek, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def gen_keyfile() -> bytes:
    if KEYFILE.exists():
        return KEYFILE.read_bytes()
    kf = random_bytes(32)
    KEYFILE.write_bytes(kf)
    try:
        KEYFILE.chmod(0o600)
    except:
        pass
    return kf

# --------------- 日志/密码数据库（保持原样） ---------------
def load_pwdb(mk: bytes) -> dict:
    return json.loads(decrypt_blob(PWDB.read_bytes(), mk).decode()) if PWDB.exists() else {}

def save_pwdb(mk: bytes, db: dict):
    PWDB.write_bytes(encrypt_blob(json.dumps(db).encode(), mk))

def append_log(mk: bytes, action: str, path: str):
    entry = json.dumps({'time': datetime.now(timezone.utc).isoformat(), 'action': action, 'path': path})
    if LOG.exists():
        blob = decrypt_blob(LOG.read_bytes(), mk) + b'\n' + entry.encode()
    else:
        blob = entry.encode()
    LOG.write_bytes(encrypt_blob(blob, mk))

def remove_log_entries(mk: bytes, file_path: str):
    if not LOG.exists():
        return
    try:
        blob = decrypt_blob(LOG.read_bytes(), mk)
        filtered = [e for e in blob.split(b'\n') if e and json.loads(e.decode()).get('path') != file_path]
        if filtered:
            LOG.write_bytes(encrypt_blob(b'\n'.join(filtered), mk))
        else:
            LOG.unlink()
    except Exception as e:
        print("移除日志条目失败:", e)

def load_logs(mk: bytes):
    if not LOG.exists():
        return []
    try:
        return [json.loads(line.decode()) for line in decrypt_blob(LOG.read_bytes(), mk).split(b'\n') if line]
    except Exception as e:
        print("加载日志失败:", e)
        return []

# ---------------- 日志查看对话框（保持原样） ----------------
class LogViewerDialog(QDialog):
    def __init__(self, mk, parent=None):
        super().__init__(parent)
        self.mk = mk
        self.setWindowTitle("加密日志查看器")
        self.setGeometry(100, 100, 800, 400)
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["时间", "操作", "文件路径"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self.load_logs)
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        self.load_logs()

    def load_logs(self):
        logs = load_logs(self.mk)
        self.table.setRowCount(len(logs))
        for row, log in enumerate(logs):
            try:
                time_str = datetime.fromisoformat(log['time']).strftime("%Y-%m-%d %H:%M:%S")
            except:
                time_str = log['time']
            self.table.setItem(row, 0, QTableWidgetItem(time_str))
            self.table.setItem(row, 1, QTableWidgetItem(log.get('action', '未知')))
            self.table.setItem(row, 2, QTableWidgetItem(log.get('path', '')))

    def closeEvent(self, event):
        if hasattr(self, 'mk') and self.mk:
            b = bytearray(self.mk)
            secure_delete(b)
        event.accept()

# ---------------- 用户注册对话框 ----------------
class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("首次使用 - 注册")
        self.setFixedSize(360, 200)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("用户名 (仅允许一个账户):"))
        self.user_edit = QLineEdit()
        layout.addWidget(self.user_edit)

        layout.addWidget(QLabel("主密码:"))
        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pwd_edit)

        layout.addWidget(QLabel("确认主密码:"))
        self.pwd2_edit = QLineEdit()
        self.pwd2_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pwd2_edit)

        btn_box = QHBoxLayout()
        ok_btn = QPushButton("注册")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("退出")
        cancel_btn.clicked.connect(self.reject)
        btn_box.addWidget(ok_btn)
        btn_box.addWidget(cancel_btn)
        layout.addLayout(btn_box)

    def accept(self):
        user = self.user_edit.text().strip()
        pwd  = self.pwd_edit.text()
        pwd2 = self.pwd2_edit.text()
        if not user:
            QMessageBox.warning(self, "警告", "用户名不能为空")
            return
        if pwd != pwd2:
            QMessageBox.warning(self, "警告", "两次密码不一致")
            return
        valid, msg = validate_password_strength(pwd)
        if not valid:
            QMessageBox.warning(self, "密码强度不足", msg)
            return
        super().accept()

# ---------------- 用户管理工具 ----------------
def create_user_record(username: str, password: str) -> None:
    salt = random_bytes(SALT_LEN)
    combined = (username + password).encode()
    derived = derive_master_key(combined, b'', salt)
    blob = json.dumps({"u": username}).encode()
    enc = encrypt_blob(blob, derived)
    USER_FILE.write_bytes(salt + enc)

def verify_user(username: str, password: str) -> bool:
    if not USER_FILE.exists():
        return False
    data = USER_FILE.read_bytes()
    salt, enc = data[:SALT_LEN], data[SALT_LEN:]
    combined = (username + password).encode()
    derived = derive_master_key(combined, b'', salt)
    try:
        info = json.loads(decrypt_blob(enc, derived).decode())
        return info.get("u") == username
    except Exception:
        return False

# ---------------- 主窗口（只改动认证部分） ----------------
class EncryptionThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str, bool)
    log_update = pyqtSignal(str)
    def __init__(self, operation, file_path, mk):
        super().__init__()
        self.operation, self.file_path, self.mk = operation, Path(file_path), mk
    def run(self):
        try:
            if self.operation == 'enc':
                self.log_update.emit(f"开始加密: {self.file_path}")
                enc = encrypt_blob(self.file_path.read_bytes(), self.mk)
                # 使用原始文件名，在隐藏文件夹中保存加密文件
                out = ENCRYPTED_FOLDER / (self.file_path.name + '.enc')
                out.write_bytes(enc)
                db = load_pwdb(self.mk)
                db[str(self.file_path)] = {'t': datetime.now(timezone.utc).isoformat()}
                save_pwdb(self.mk, db)
                append_log(self.mk, 'encrypt', str(self.file_path))
                self.finished.emit(f'加密成功 -> {out}', True)
            elif self.operation == 'dec':
                self.log_update.emit(f"开始解密: {self.file_path}")
                if self.file_path.suffix != '.enc':
                    self.finished.emit('仅支持 .enc 文件', False)
                    return
                data = decrypt_blob(self.file_path.read_bytes(), self.mk)
                
                # 如果加密文件在隐藏文件夹中，则解密后也保存在该文件夹
                if ENCRYPTED_FOLDER in self.file_path.parents:
                    out = ENCRYPTED_FOLDER / (self.file_path.stem)
                else:
                    # 否则保持原位置解密
                    out = self.file_path.with_suffix('')
                    
                out.write_bytes(data)
                append_log(self.mk, 'decrypt', str(self.file_path))
                self.finished.emit(f'解密成功 -> {out}', True)
        except Exception as e:
            self.finished.emit(f'错误: {str(e)}', False)
        finally:
            if hasattr(self, 'mk') and self.mk:
                b = bytearray(self.mk)
                secure_delete(b)

class FileEncryptorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.mk = None
        self.current_user = None
        self.current_file = None
        self.inactivity_timer = QTimer()
        self.inactivity_timer.timeout.connect(self.lock_interface)
        self.init_ui()
        self.check_first_run()

    # ---------- UI 初始化（保持原样，仅移除密码输入区域，因用对话框） ----------
    def init_ui(self):
        self.setWindowTitle('文件加密器 - 安全增强版（单用户）')
        self.setGeometry(100, 100, 800, 600)
        # 使用ico_mgr设置窗口图标为13.ico
        try:
            ico_mgr.set_qt_icon(QApplication.instance(), '13.ico')
        except Exception as e:
            print(f"设置图标失败: {e}")
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)

        # 左侧
        left = QWidget()
        left.setMaximumWidth(300)
        left_layout = QVBoxLayout(left)

        file_group = QGroupBox("文件操作")
        file_layout = QVBoxLayout(file_group)
        self.file_label = QLabel("未选择文件")
        self.file_label.setWordWrap(True)
        file_layout.addWidget(self.file_label)
        file_btn_layout = QHBoxLayout()
        self.select_btn = QPushButton("选择文件")
        self.select_btn.clicked.connect(self.select_file)
        self.clear_btn = QPushButton("清除")
        self.clear_btn.clicked.connect(self.clear_file)
        file_btn_layout.addWidget(self.select_btn)
        file_btn_layout.addWidget(self.clear_btn)
        file_layout.addLayout(file_btn_layout)
        left_layout.addWidget(file_group)

        # 移除原来的密码输入区，改为按钮
        auth_group = QGroupBox("身份验证")
        auth_layout = QVBoxLayout(auth_group)
        self.login_btn = QPushButton("登录")
        self.login_btn.clicked.connect(self.authenticate)
        self.lock_btn = QPushButton("锁定")
        self.lock_btn.clicked.connect(self.lock_interface)
        self.lock_btn.setEnabled(False)
        auth_layout.addWidget(self.login_btn)
        auth_layout.addWidget(self.lock_btn)
        left_layout.addWidget(auth_group)

        # 安全选项
        security_group = QGroupBox("安全选项")
        sec_layout = QVBoxLayout(security_group)
        self.auto_lock_checkbox = QCheckBox("闲置5分钟后自动锁定")
        self.auto_lock_checkbox.setChecked(True)
        self.auto_lock_checkbox.stateChanged.connect(self.toggle_auto_lock)
        sec_layout.addWidget(self.auto_lock_checkbox)
        self.secure_storage_checkbox = QCheckBox("使用安全存储(如可用)")
        self.secure_storage_checkbox.setChecked(HAS_SECURE_STORAGE)
        self.secure_storage_checkbox.setEnabled(HAS_SECURE_STORAGE)
        sec_layout.addWidget(self.secure_storage_checkbox)
        left_layout.addWidget(security_group)

        # 操作按钮
        action_group = QGroupBox("操作")
        act_layout = QVBoxLayout(action_group)
        self.encrypt_btn = QPushButton("加密文件")
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.encrypt_btn.setEnabled(False)
        act_layout.addWidget(self.encrypt_btn)
        self.decrypt_btn = QPushButton("解密文件")
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.decrypt_btn.setEnabled(False)
        act_layout.addWidget(self.decrypt_btn)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        act_layout.addWidget(self.progress_bar)
        left_layout.addWidget(action_group)
        left_layout.addStretch()

        # 右侧
        right = QTabWidget()
        log_w = QWidget()
        log_l = QVBoxLayout(log_w)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_l.addWidget(QLabel("操作日志:"))
        log_l.addWidget(self.log_text)
        log_btn_l = QHBoxLayout()
        self.view_encrypted_logs_btn = QPushButton("查看加密日志")
        self.view_encrypted_logs_btn.clicked.connect(self.view_encrypted_logs)
        self.view_encrypted_logs_btn.setEnabled(False)
        log_btn_l.addWidget(self.view_encrypted_logs_btn)
        log_l.addLayout(log_btn_l)
        right.addTab(log_w, "日志")

        hist_w = QWidget()
        hist_l = QVBoxLayout(hist_w)
        self.history_list = QListWidget()
        hist_l.addWidget(QLabel("加密历史:"))
        hist_l.addWidget(self.history_list)
        hist_btn_l = QHBoxLayout()
        self.delete_record_btn = QPushButton("删除选中记录")
        self.delete_record_btn.clicked.connect(self.delete_selected_record)
        self.delete_record_btn.setEnabled(False)
        self.refresh_history_btn = QPushButton("刷新历史")
        self.refresh_history_btn.clicked.connect(self.update_history)
        hist_btn_l.addWidget(self.delete_record_btn)
        hist_btn_l.addWidget(self.refresh_history_btn)
        hist_l.addLayout(hist_btn_l)
        right.addTab(hist_w, "历史记录")

        main_layout.addWidget(left)
        main_layout.addWidget(right)
        self.statusBar().showMessage('就绪')
        self.installEventFilter(self)
        QApplication.instance().installEventFilter(self)
        self.log_message("应用程序已启动")

    # ---------- 首次运行检查 ----------
    def check_first_run(self):
        if not USER_FILE.exists():
            reg = RegisterDialog(self)
            if reg.exec() != QDialog.DialogCode.Accepted:
                # 用户取消注册 -> 直接退出程序
                sys.exit(0)
            username = reg.user_edit.text().strip()
            password = reg.pwd_edit.text()
            create_user_record(username, password)
            QMessageBox.information(self, "注册成功", "账户已创建，请重新启动程序登录")
            sys.exit(0)  # 注册完也退出，重启后正常登录


    # ---------- 登录 ----------
    def authenticate(self):
        user, ok1 = QInputDialog.getText(self, "登录", "用户名:")
        if not ok1 or not user:
            return
        pwd, ok2 = QInputDialog.getText(self, "登录", "密码:", QLineEdit.EchoMode.Password)
        if not ok2:
            return
        if not verify_user(user, pwd):
            QMessageBox.critical(self, "错误", "用户名或密码错误")
            return

        # 认证成功，派生主密钥
        self.current_user = user
        keyfile = gen_keyfile() # 始终使用密钥文件
        master_salt = get_master_salt()
        self.mk = derive_master_key(pwd.encode(), keyfile, master_salt)

        if self.secure_storage_checkbox.isChecked():
            secure_store(self.mk, "master_key")

        self.login_btn.setEnabled(False)
        self.lock_btn.setEnabled(True)
        self.view_encrypted_logs_btn.setEnabled(True)
        self.delete_record_btn.setEnabled(True)
        if self.auto_lock_checkbox.isChecked():
            self.inactivity_timer.start(5*60*1000)
        self.log_message(f"用户 {user} 已登录")
        self.statusBar().showMessage(f'已登录: {user}')
        self.update_history()

    # ---------- 其余函数（保持原样，仅移除 pwd_input 相关） ----------
    def eventFilter(self, obj, event):
        if event.type() in [QEvent.Type.MouseMove, QEvent.Type.KeyPress,
                            QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonDblClick]:
            self.reset_inactivity_timer()
        return super().eventFilter(obj, event)

    def reset_inactivity_timer(self):
        if self.auto_lock_checkbox.isChecked() and self.mk is not None:
            self.inactivity_timer.stop()
            self.inactivity_timer.start(5*60*1000)

    def toggle_auto_lock(self, state):
        if state == Qt.CheckState.Checked and self.mk is not None:
            self.inactivity_timer.start(5*60*1000)
        else:
            self.inactivity_timer.stop()

    def log_message(self, message):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{ts}] {message}")

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*);;加密文件 (*.enc)")
        if path:
            self.current_file = path
            self.file_label.setText(path)
            self.log_message(f"已选择文件: {path}")
            if self.mk:
                self.encrypt_btn.setEnabled(not path.endswith('.enc'))
                self.decrypt_btn.setEnabled(path.endswith('.enc'))

    def clear_file(self):
        self.current_file = None
        self.file_label.setText("未选择文件")
        self.encrypt_btn.setEnabled(False)
        self.decrypt_btn.setEnabled(False)
        self.log_message("已清除文件选择")

    def encrypt_file(self):
        if self.current_file and self.mk:
            self.run_operation('enc')

    def decrypt_file(self):
        if self.current_file and self.mk:
            self.run_operation('dec')

    def run_operation(self, op):
        self.set_buttons_enabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.thread = EncryptionThread(op, self.current_file, self.mk)
        self.thread.finished.connect(self.on_operation_finished)
        self.thread.log_update.connect(self.log_message)
        self.thread.start()

    def on_operation_finished(self, msg, ok):
        self.progress_bar.setVisible(False)
        self.set_buttons_enabled(True)
        if ok:
            QMessageBox.information(self, "成功", msg)
            self.log_message(msg)
            self.update_history()
            self.clear_file()
        else:
            QMessageBox.critical(self, "错误", msg)
            self.log_message(f"操作失败: {msg}")

    def set_buttons_enabled(self, en):
        self.select_btn.setEnabled(en)
        self.encrypt_btn.setEnabled(en and self.mk and self.current_file and not self.current_file.endswith('.enc'))
        self.decrypt_btn.setEnabled(en and self.mk and self.current_file and self.current_file.endswith('.enc'))
        self.login_btn.setEnabled(en and self.mk is None)
        self.lock_btn.setEnabled(en and self.mk is not None)
        self.view_encrypted_logs_btn.setEnabled(en and self.mk is not None)
        self.delete_record_btn.setEnabled(en and self.mk is not None)

    def update_history(self):
        try:
            if self.mk and PWDB.exists():
                db = load_pwdb(self.mk)
                self.history_list.clear()
                for path, info in db.items():
                    self.history_list.addItem(f"{info.get('t','?')}: {path}")
        except Exception as e:
            self.log_message(f"更新历史失败: {str(e)}")

    def delete_selected_record(self):
        item = self.history_list.currentItem()
        if not item:
            QMessageBox.warning(self, "警告", "请先选择记录")
            return
        file_path = item.text().split(": ", 1)[1]
        reply = QMessageBox.question(self, "确认删除", f"删除 '{file_path}' 的记录？")
        if reply == QMessageBox.StandardButton.Yes:
            try:
                db = load_pwdb(self.mk)
                db.pop(file_path, None)
                save_pwdb(self.mk, db)
                remove_log_entries(self.mk, file_path)
                self.log_message(f"已删除记录: {file_path}")
                self.update_history()
            except Exception as e:
                QMessageBox.critical(self, "错误", str(e))

    def view_encrypted_logs(self):
        if not self.mk:
            QMessageBox.warning(self, "警告", "请先登录")
            return
        if not LOG.exists():
            QMessageBox.information(self, "信息", "无日志")
            return
        LogViewerDialog(self.mk, self).exec()

    def lock_interface(self):
        if self.mk:
            b = bytearray(self.mk)
            secure_delete(b)
        self.mk = None
        self.current_user = None
        self.inactivity_timer.stop()
        self.encrypt_btn.setEnabled(False)
        self.decrypt_btn.setEnabled(False)
        self.view_encrypted_logs_btn.setEnabled(False)
        self.delete_record_btn.setEnabled(False)
        self.login_btn.setEnabled(True)
        self.lock_btn.setEnabled(False)
        self.history_list.clear()
        self.log_message("界面已锁定")
        self.statusBar().showMessage('需要登录')

    def closeEvent(self, event):
        if self.mk:
            b = bytearray(self.mk)
            secure_delete(b)
        self.inactivity_timer.stop()
        self.log_message("应用程序关闭")
        event.accept()

# ---------------- 主入口 ----------------
def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    w = FileEncryptorGUI()
    w.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
