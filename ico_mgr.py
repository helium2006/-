# icon_mgr.py
import os
import sys
from pathlib import Path


def _resolve_ico(ico_name: str) -> str:
    """
    统一把相对路径的 .ico 解析成绝对路径。
    在 PyInstaller --onefile 模式下会自动落到临时目录 _MEIPASS。
    """
    if getattr(sys, 'frozen', False):
        # 打包后
        base_dir = Path(sys._MEIPASS)
    else:
        # 源码调试
        base_dir = Path(__file__).resolve().parent
    ico_path = base_dir / ico_name
    if not ico_path.exists():
        raise FileNotFoundError(ico_path)
    return str(ico_path)


def set_qt_icon(app, ico_name: str):
    """
    给 PyQt6 设置窗口图标
    app  : 已经实例化的 QApplication
    ico_name : 图标文件名（放到和 exe 同目录或源码根目录）
    """
    from PyQt6.QtGui import QIcon
    app.setWindowIcon(QIcon(_resolve_ico(ico_name)))


def set_tk_icon(root, ico_name: str):
    """
    给 Tkinter 设置窗口图标
    root : Tk 或 Toplevel 对象
    ico_name : 同上
    """
    ico = _resolve_ico(ico_name)
    # 让 Tkinter 支持 .ico（Windows）
    if os.name == 'nt':
        root.iconbitmap(ico)
    else:
        # Linux/Mac 用 iconphoto
        from PIL import Image, ImageTk
        img = ImageTk.PhotoImage(Image.open(ico))
        root.iconphoto(True, img)
