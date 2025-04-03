import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import os
import sys
import json
import base64
import tempfile
import shutil
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import platform
import requests
import socket
import argparse
import datetime
# 添加keyring库导入
import keyring

# 配置文件路径
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".campus_login_config.json")

# 定义应用程序的服务名称，用于keyring
KEYRING_SERVICE = "CampusNetworkLogin"

class CampusLoginApp:
    def __init__(self, root, auto_mode=False):
        self.root = root
        self.root.title("校园网自动登录工具")
        self.root.geometry("500x500")
        self.root.resizable(False, False)
        
        # 自动模式标志
        self.auto_mode = auto_mode
        
        # 登录重试计数器
        self.login_retry_count = 0
        self.max_retry_count = 3
        
        # Firefox路径
        self.firefox_path = ""
        
        # 初始化登录URL为空字符串
        self.login_url = ""
        
        # geckodriver路径
        self.geckodriver_path = self.extract_geckodriver()
        
        # 创建界面
        self.create_widgets()
        
        # 加载配置
        self.load_config()
        
        # 检查开机启动状态并更新UI
        self.check_autostart_status()
        
        # 自动模式处理
        if self.auto_mode:
            # 延迟几秒检测网络
            self.root.after(3000, self.auto_check_and_login)
        else:
            # 普通启动也自动检测网络，但不自动退出
            self.root.after(1000, self.check_network_on_startup)
        
    def extract_geckodriver(self):
        """提取geckodriver到临时目录"""
        try:
            # 获取当前可执行文件的路径
            if getattr(sys, 'frozen', False):
                # 如果是打包后的可执行文件
                application_path = os.path.dirname(sys.executable)
            else:
                # 如果是脚本运行
                application_path = os.path.dirname(os.path.abspath(__file__))
            
            # 首先检查当前目录是否已有geckodriver
            system = platform.system()
            if system == "Windows":
                geckodriver_name = "geckodriver.exe"
            else:
                geckodriver_name = "geckodriver"
            
            # 检查当前目录
            local_geckodriver = os.path.join(application_path, geckodriver_name)
            if os.path.exists(local_geckodriver) and os.access(local_geckodriver, os.X_OK):
                self.add_log(f"使用本地geckodriver: {local_geckodriver}")
                return local_geckodriver
            
            # 如果当前目录没有，则提取内置的geckodriver到临时目录
            temp_dir = tempfile.mkdtemp(prefix="campus_login_")
            geckodriver_path = os.path.join(temp_dir, geckodriver_name)
            
            # 如果是打包后的可执行文件，尝试从资源目录复制
            if getattr(sys, 'frozen', False):
                resource_geckodriver = os.path.join(sys._MEIPASS, geckodriver_name)
                if os.path.exists(resource_geckodriver):
                    shutil.copy2(resource_geckodriver, geckodriver_path)
                    os.chmod(geckodriver_path, 0o755)  # 确保可执行
                    self.add_log(f"从资源目录提取geckodriver到: {geckodriver_path}")
                    return geckodriver_path
            
            self.add_log("未找到geckodriver")
            return None
        except Exception as e:
            self.add_log(f"提取geckodriver失败: {str(e)}")
            return None
        
    def create_widgets(self):
        """创建界面元素"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="校园网自动登录", font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 10))
        
        # 用户名
        username_frame = ttk.Frame(main_frame)
        username_frame.pack(fill=tk.X, pady=5)
        
        username_label = ttk.Label(username_frame, text="用户名:")
        username_label.pack(side=tk.LEFT)
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(username_frame, textvariable=self.username_var, width=30)
        username_entry.pack(side=tk.RIGHT)
        
        # 密码
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=tk.X, pady=5)
        
        password_label = ttk.Label(password_frame, text="密码:")
        password_label.pack(side=tk.LEFT)
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=30)
        password_entry.pack(side=tk.RIGHT)
        
        # 自动启动选项
        autostart_frame = ttk.Frame(main_frame)
        autostart_frame.pack(fill=tk.X, pady=5)
        
        self.autostart_var = tk.BooleanVar()
        autostart_check = ttk.Checkbutton(
            autostart_frame, 
            text="开机自动启动并自动登录", 
            variable=self.autostart_var,
            command=self.toggle_autostart
        )
        autostart_check.pack(side=tk.LEFT)
        
        # 自动启动状态标签
        self.autostart_status_var = tk.StringVar(value="")
        autostart_status = ttk.Label(autostart_frame, textvariable=self.autostart_status_var, font=("Arial", 9), foreground="blue")
        autostart_status.pack(side=tk.RIGHT)
        
        # 状态显示
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Arial", 9))
        status_label.pack(pady=5)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        save_button = ttk.Button(button_frame, text="保存设置", command=self.save_config)
        save_button.pack(side=tk.LEFT, padx=5)
        
        login_button = ttk.Button(button_frame, text="立即登录", command=self.manual_login)
        login_button.pack(side=tk.LEFT, padx=5)
        
        check_button = ttk.Button(button_frame, text="检测网络", command=self.check_network_manually)
        check_button.pack(side=tk.LEFT, padx=5)
        
        clear_button = ttk.Button(button_frame, text="清除日志", command=self.clear_log)
        clear_button.pack(side=tk.LEFT, padx=5)
        
        # 日志区域
        log_label = ttk.Label(main_frame, text="运行日志:")
        log_label.pack(anchor=tk.W, pady=(10, 5))
        
        self.log_text = scrolledtext.ScrolledText(main_frame, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 自动查找Firefox路径
        self.auto_detect_firefox()
        
        # 如果有缓存的日志，显示它们
        if hasattr(self, '_log_buffer'):
            for msg in self._log_buffer:
                self.add_log(msg)
            delattr(self, '_log_buffer')
    
    def toggle_autostart(self):
        """切换自动启动状态"""
        if self.autostart_var.get():
            self.autostart_status_var.set("开机启动已启用")
        else:
            self.autostart_status_var.set("开机启动已禁用")
    
    def add_log(self, message):
        """添加日志"""
        if not hasattr(self, 'log_text'):
            # 如果日志控件还未创建，先缓存消息
            if not hasattr(self, '_log_buffer'):
                self._log_buffer = []
            self._log_buffer.append(message)
            return
            
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # 添加到文本框
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)  # 滚动到最新日志
        
        # 更新UI
        self.root.update_idletasks()
    
    def clear_log(self):
        """清除日志"""
        self.log_text.delete(1.0, tk.END)
    
    def check_network_manually(self):
        """手动检测网络"""
        self.status_var.set("正在检测网络环境...")
        self.add_log("手动触发网络检测")
        threading.Thread(target=self._check_network_thread).start()
    
    def auto_check_and_login(self):
        """自动检测网络并登录"""
        self.status_var.set("正在检测网络环境...")
        self.add_log("自动模式：检测网络环境")
        
        # 检测是否需要登录
        if self.needs_campus_login():
            self.status_var.set("检测到需要登录校园网")
            self.add_log("检测到需要登录校园网")
            
            # 检查是否有保存的账号密码
            if not self.username_var.get() or not self.password_var.get():
                # 如果没有保存的账号密码，显示窗口让用户输入
                self.status_var.set("请输入账号密码并点击立即登录")
                self.add_log("未找到保存的账号密码，请手动输入")
            else:
                # 有保存的账号密码，直接登录
                self.status_var.set("使用保存的账号密码登录...")
                self.add_log("使用保存的账号密码自动登录")
                # 重置登录重试计数器
                self.login_retry_count = 0
                threading.Thread(target=self.perform_login_and_exit).start()
        else:
            # 不需要登录，直接退出
            self.status_var.set("网络正常，无需登录")
            self.add_log("网络正常，无需登录，即将退出")
            self.root.after(2000, self.root.destroy)
    
    def perform_login_and_exit(self):
        """执行登录并在成功后退出"""
        if self.perform_login():
            # 登录成功，2秒后退出
            self.status_var.set("登录成功，即将退出...")
            self.add_log("登录成功，即将退出")
            self.root.after(2000, self.root.destroy)
        else:
            # 登录失败，检查是否需要重试
            if self.login_retry_count < self.max_retry_count:
                self.login_retry_count += 1
                self.status_var.set(f"登录失败，3秒后自动重试 ({self.login_retry_count}/{self.max_retry_count})...")
                self.add_log(f"登录失败，3秒后自动重试 ({self.login_retry_count}/{self.max_retry_count})")
                # 3秒后重试
                self.root.after(3000, lambda: threading.Thread(target=self.perform_login_and_exit).start())
            else:
                # 超过最大重试次数，显示窗口让用户处理
                self.status_var.set(f"自动登录失败 ({self.max_retry_count}次尝试)，请手动操作")
                self.add_log(f"自动登录失败 ({self.max_retry_count}次尝试)，请手动操作")
    
    def manual_login(self):
        """手动触发登录"""
        self.status_var.set("正在登录...")
        self.add_log("手动触发登录")
        # 重置登录重试计数器
        self.login_retry_count = 0
        threading.Thread(target=self.perform_login_and_save).start()
    
    def perform_login_and_save(self):
        """执行登录并保存配置"""
        if self.perform_login():
            # 登录成功，保存配置
            self.save_config(silent=True)
            self.status_var.set("登录成功，配置已保存")
            self.add_log("登录成功，配置已保存")
            # 如果是自动模式，2秒后退出
            if self.auto_mode:
                self.add_log("自动模式：登录成功，即将退出")
                self.root.after(2000, self.root.destroy)
        else:
            # 登录失败，检查是否需要重试
            if self.login_retry_count < self.max_retry_count:
                self.login_retry_count += 1
                self.status_var.set(f"登录失败，3秒后自动重试 ({self.login_retry_count}/{self.max_retry_count})...")
                self.add_log(f"登录失败，3秒后自动重试 ({self.login_retry_count}/{self.max_retry_count})")
                # 3秒后重试
                self.root.after(3000, lambda: threading.Thread(target=self.perform_login_and_save).start())
            else:
                self.status_var.set(f"登录失败 ({self.max_retry_count}次尝试)，请检查账号密码")
                self.add_log(f"登录失败 ({self.max_retry_count}次尝试)，请检查账号密码")
    
    def auto_detect_firefox(self):
        """自动检测Firefox浏览器路径"""
        system = platform.system()
        firefox_paths = []
        
        if system == "Windows":
            # 常见的Windows Firefox安装路径
            program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
            
            firefox_paths = [
                os.path.join(program_files, "Mozilla Firefox", "firefox.exe"),
                os.path.join(program_files_x86, "Mozilla Firefox", "firefox.exe"),
                os.path.join("C:\\Program Files", "Mozilla Firefox", "firefox.exe"),
                os.path.join("C:\\Program Files (x86)", "Mozilla Firefox", "firefox.exe")
            ]
        elif system == "Darwin":  # macOS
            firefox_paths = [
                "/Applications/Firefox.app/Contents/MacOS/firefox",
                os.path.expanduser("~/Applications/Firefox.app/Contents/MacOS/firefox")
            ]
        elif system == "Linux":
            firefox_paths = [
                "/usr/bin/firefox",
                "/usr/lib/firefox/firefox",
                "/snap/bin/firefox"
            ]
        
        # 检查路径是否存在
        for path in firefox_paths:
            if os.path.exists(path):
                self.firefox_path = path
                self.add_log(f"已自动检测到Firefox: {path}")
                return
        
        self.add_log("未能自动检测到Firefox，可能影响登录功能")
    
    def load_config(self):
        """加载配置"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                
                # 加载用户名
                username = config.get('username', '')
                self.username_var.set(username)
                
                # 从系统密钥环加载密码
                if username:
                    try:
                        password = keyring.get_password(KEYRING_SERVICE, username)
                        if password:
                            self.password_var.set(password)
                            self.add_log("已从系统密钥环加载密码")
                        else:
                            # 尝试从旧配置中加载密码（兼容旧版本）
                            encoded_password = config.get('password', '')
                            if encoded_password:
                                try:
                                    password = base64.b64decode(encoded_password).decode('utf-8')
                                    self.password_var.set(password)
                                    # 将密码迁移到密钥环
                                    keyring.set_password(KEYRING_SERVICE, username, password)
                                    self.add_log("已将密码从配置文件迁移到系统密钥环")
                                except:
                                    self.add_log("旧密码格式无效，无法迁移")
                            else:
                                self.add_log("未找到保存的密码")
                    except Exception as e:
                        self.add_log(f"从密钥环加载密码失败: {str(e)}")
                
                # 加载自动启动设置
                self.autostart_var.set(config.get('autostart', False))
                self.toggle_autostart()  # 更新状态标签
                
                # 加载Firefox路径
                firefox_path = config.get('firefox_path', '')
                if firefox_path and os.path.exists(firefox_path):
                    self.firefox_path = firefox_path
                
                # 加载登录URL
                self.login_url = config.get('url', '')
                
                self.add_log("已加载配置")
        except Exception as e:
            self.add_log(f"加载配置失败: {str(e)}")
    
    def save_config(self, silent=False):
        """保存配置"""
        try:
            username = self.username_var.get()
            password = self.password_var.get()
            
            # 将密码保存到系统密钥环
            if username and password:
                try:
                    keyring.set_password(KEYRING_SERVICE, username, password)
                    self.add_log("已将密码安全地保存到系统密钥环")
                except Exception as e:
                    self.add_log(f"保存密码到密钥环失败: {str(e)}")
                    if not silent:
                        messagebox.showerror("错误", f"保存密码到系统密钥环失败: {str(e)}")
                    return False
            
            # 配置文件中不再存储密码
            config = {
                'username': username,
                'autostart': self.autostart_var.get(),
                'firefox_path': self.firefox_path,
                'url': getattr(self, 'login_url', '')
            }
        
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
            
            # 设置配置文件权限（仅所有者可读写）
            try:
                if platform.system() != "Windows":  # Windows权限系统不同
                    os.chmod(CONFIG_FILE, 0o600)
            except Exception as e:
                self.add_log(f"设置配置文件权限失败: {str(e)}")
        
            # 处理自动启动
            if self.autostart_var.get():
                self.configure_autostart()
            else:
                self.remove_autostart()
        
            # 检查开机启动状态并更新UI
            self.check_autostart_status()
        
            if not silent:
                messagebox.showinfo("成功", "设置已安全保存")
                self.add_log("设置已安全保存")
            return True
        except Exception as e:
            if not silent:
                messagebox.showerror("错误", f"保存配置失败: {str(e)}")
            self.add_log(f"保存配置失败: {str(e)}")
            return False
    
    def configure_autostart(self):
        """配置开机自启动"""
        system = platform.system()
        script_path = os.path.abspath(sys.argv[0])
        
        try:
            if system == "Windows":
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_WRITE
                )
                # 添加--auto参数
                winreg.SetValueEx(key, "CampusNetworkLogin", 0, winreg.REG_SZ, f'"{sys.executable}" "{script_path}" --auto')
                self.add_log("已配置Windows开机自启动")
            
            elif system == "Darwin":  # macOS
                plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.campuslogin</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{script_path}</string>
        <string>--auto</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''
                plist_path = os.path.expanduser("~/Library/LaunchAgents/com.user.campuslogin.plist")
                with open(plist_path, 'w') as f:
                    f.write(plist_content)
                os.system(f"launchctl load {plist_path}")
                self.add_log("已配置macOS开机自启动")
                
            elif system == "Linux":
                desktop_content = f'''[Desktop Entry]
Type=Application
Name=Campus Network Login
Exec={sys.executable} {script_path} --auto
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
'''
                autostart_dir = os.path.expanduser("~/.config/autostart")
                if not os.path.exists(autostart_dir):
                    os.makedirs(autostart_dir)
                    
                desktop_path = os.path.join(autostart_dir, "campus_login.desktop")
                with open(desktop_path, 'w') as f:
                    f.write(desktop_content)
                os.chmod(desktop_path, 0o755)
                self.add_log("已配置Linux开机自启动")
        except Exception as e:
            self.add_log(f"配置自动启动失败: {str(e)}")
    
    def remove_autostart(self):
        """移除开机自启动"""
        system = platform.system()
        
        try:
            if system == "Windows":
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_WRITE
                )
                try:
                    winreg.DeleteValue(key, "CampusNetworkLogin")
                    self.add_log("已移除Windows开机自启动")
                except:
                    pass
                
            elif system == "Darwin":  # macOS
                plist_path = os.path.expanduser("~/Library/LaunchAgents/com.user.campuslogin.plist")
                if os.path.exists(plist_path):
                    os.system(f"launchctl unload {plist_path}")
                    os.remove(plist_path)
                    self.add_log("已移除macOS开机自启动")
                
            elif system == "Linux":
                desktop_path = os.path.expanduser("~/.config/autostart/campus_login.desktop")
                if os.path.exists(desktop_path):
                    os.remove(desktop_path)
                    self.add_log("已移除Linux开机自启动")
        except Exception as e:
            self.add_log(f"移除自动启动失败: {str(e)}")
    
    def check_autostart_status(self):
        """检查开机启动状态并更新UI"""
        is_configured = self.is_autostart_configured()
        self.autostart_var.set(is_configured)
        self.toggle_autostart()  # 更新状态标签
        
        if is_configured:
            self.status_var.set("开机启动已启用")
            self.add_log("开机启动已启用")
        else:
            self.status_var.set("开机启动未启用")
            self.add_log("开机启动未启用")

    def is_autostart_configured(self):
        """检查是否已配置自动启动"""
        system = platform.system()
    
        if system == "Windows":
            import winreg
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_READ
                )
                winreg.QueryValueEx(key, "CampusNetworkLogin")
                return True
            except:
                return False
        elif system == "Darwin":  # macOS
            plist_path = os.path.expanduser("~/Library/LaunchAgents/com.user.campuslogin.plist")
            return os.path.exists(plist_path)
        elif system == "Linux":
            autostart_path = os.path.expanduser("~/.config/autostart/campus_login.desktop")
            return os.path.exists(autostart_path)
    
        return False
    
    def check_network_on_startup(self):
        """普通启动时检测网络"""
        self.status_var.set("正在检测网络环境...")
        self.add_log("普通启动：检测网络环境")
    
        # 在后台线程中检测网络
        threading.Thread(target=self._check_network_thread).start()

    def _check_network_thread(self):
        """后台检测网络线程"""
        try:
            # 检测是否需要登录
            if self.needs_campus_login():
                self.status_var.set("检测到需要登录校园网，请点击立即登录")
                self.add_log("检测到需要登录校园网")
            else:
                self.status_var.set("网络正常，无需登录")
                self.add_log("网络正常，无需登录")
        except Exception as e:
            self.status_var.set(f"网络检测出错: {str(e)}")
            self.add_log(f"网络检测出错: {str(e)}")
    
    def needs_campus_login(self):
        """检测是否需要登录校园网 - 多道验证"""
        self.add_log("开始多道验证检测网络状态")
        
        # 方法1: 尝试访问多个外部网站，检查是否被重定向
        test_sites = [
            "http://www.baidu.com",
            "http://www.qq.com",
            "http://www.163.com",
            "http://www.sina.com.cn",
            "http://www.sohu.com"
        ]
        
        self.add_log("检测方法1: 检查外部网站访问")
        redirect_count = 0
        
        for site in test_sites:
            try:
                session = requests.Session()
                response = session.get(site, timeout=5, allow_redirects=True)
                
                # 检查是否被重定向
                if response.url != site and response.url != site + "/":
                    redirect_count += 1
                    self.add_log(f"被重定向: {site} -> {response.url}")
                    
                    # 检查重定向URL是否可能是登录页面
                    if self.is_likely_login_page(response.url, response.text):
                        # 更新登录URL
                        self.login_url = response.url
                        self.add_log(f"确认为登录页面: {response.url}")
                        return True
                else:
                    self.add_log(f"成功访问: {site}")
            except Exception as e:
                self.add_log(f"访问 {site} 时出错: {str(e)}")
        
        # 方法2: 检查DNS解析是否被劫持
        self.add_log("检测方法2: 检查DNS解析")
        try:
            import socket
            # 尝试解析一个知名域名
            ip_address = socket.gethostbyname("www.baidu.com")
            self.add_log(f"www.baidu.com 解析为: {ip_address}")
            
            # 检查解析的IP是否是私有IP（可能是校园网DNS劫持）
            if ip_address.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
                                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", 
                                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", 
                                     "172.31.", "192.168.")):
                self.add_log(f"检测到DNS劫持，域名解析到私有IP: {ip_address}")
                return True
        except Exception as e:
            self.add_log(f"DNS检查出错: {str(e)}")
        
        # 方法3: 尝试下载一个小文件，检查是否成功
        self.add_log("检测方法3: 尝试下载测试文件")
        try:
            # 使用中国大陆CDN下载小文件
            test_file_urls = [
                "https://cdn.bootcdn.net/ajax/libs/jquery/3.6.0/jquery.min.js",  # BootCDN
                "https://lib.baomitu.com/jquery/3.6.0/jquery.min.js",           # 360 前端库 CDN
                "https://g.alicdn.com/code/lib/jquery/3.6.0/jquery.min.js"      # 阿里云 CDN
            ]
            
            download_success = False
            for test_url in test_file_urls:
                try:
                    self.add_log(f"尝试从 {test_url} 下载测试文件")
                    response = requests.get(test_url, timeout=5)
                    
                    if response.status_code == 200 and len(response.content) > 1000:
                        self.add_log(f"成功下载测试文件，大小: {len(response.content)} 字节")
                        download_success = True
                        break
                    else:
                        self.add_log(f"文件下载异常，状态码: {response.status_code}, 大小: {len(response.content)} 字节")
                except Exception as e:
                    self.add_log(f"从 {test_url} 下载出错: {str(e)}")
            
            if not download_success:
                self.add_log("所有CDN下载测试均失败，可能需要登录")
                return True
                
        except Exception as e:
            self.add_log(f"下载测试出错: {str(e)}")
            return True
        
        # 方法4: 检查是否可以访问特定的校园网外部服务
        self.add_log("检测方法4: 检查特定外部服务")
        special_sites = [
            "https://www.bilibili.com",  # B站，通常校园网会允许
            "https://weibo.com",         # 微博，通常校园网会允许
            "https://zhihu.com"          # 知乎，通常校园网会允许
        ]
        
        block_count = 0
        for site in special_sites:
            try:
                response = requests.get(site, timeout=3)
                if response.status_code == 200:
                    self.add_log(f"成功访问: {site}")
                else:
                    block_count += 1
                    self.add_log(f"无法正常访问: {site}, 状态码: {response.status_code}")
            except:
                block_count += 1
                self.add_log(f"无法访问: {site}")
        
        # 如果特定网站大部分被拦截，可能是在校园网环境
        if block_count >= 2:
            self.add_log(f"特定网站访问受限 ({block_count}/{len(special_sites)})")
            # 但这不一定意味着需要登录，继续检查
        
        # 如果重定向次数超过阈值，可能需要登录
        if redirect_count >= 3:
            self.add_log(f"多个网站被重定向 ({redirect_count}/{len(test_sites)})，可能需要登录")
            return True
        
        # 如果所有检测都通过，说明不需要登录
        self.add_log("所有检测通过，网络连接正常")
        return False
    
    def is_likely_login_page(self, url, html_content):
        """判断URL和HTML内容是否可能是登录页面"""
        # 排除已知的非登录页面
        excluded_patterns = [
            '192.168.1.1', '192.168.0.1', '192.168.2.1',  # 常见路由器IP
            'tplogin.cn', 'tendawifi.com', 'phicomm.me',  # 常见路由器域名
            'router', 'admin', 'setup'                    # 常见路由器关键词
        ]
        
        # 检查是否在排除列表中
        url_lower = url.lower()
        for pattern in excluded_patterns:
            if pattern in url_lower:
                self.add_log(f"URL匹配排除模式: {pattern}，跳过")
                return False
        
        # 检查URL是否包含登录指示词
        url_indicators = ['login', 'portal', 'auth', 'authenticate', 'sso', 'captive']
        
        url_match = False
        for indicator in url_indicators:
            if indicator in url_lower:
                self.add_log(f"URL包含登录指示词: {indicator}")
                url_match = True
                break
        
        # 检查HTML内容
        if isinstance(html_content, str):
            html_lower = html_content.lower()
            
            # 排除路由器管理页面的特征
            router_indicators = [
                'router', 'admin', 'wireless setting', 'wan setting', 
                'firmware', 'bandwidth', 'dhcp', 'nat', 'qos'
            ]
            
            for indicator in router_indicators:
                if indicator in html_lower:
                    self.add_log(f"页面内容包含路由器指示词: {indicator}，跳过")
                    return False
            
            # 检查表单元素
            form_indicators = [
                '<form', 'type="password"', 'name="password"', 'id="password"',
                'name="username"', 'id="username"', 'type="submit"', 'login', '登录',
                '用户名', '密码', 'username', 'password', 'submit', 'login-button'
            ]
            
            # 校园网特有的指示词
            campus_indicators = [
                '校园网', '学号', '学工号', '校园', '学生', '教师', '教工',
                'campus', 'student', 'faculty', 'university', 'college'
            ]
            
            matches = 0
            campus_matches = 0
            
            for indicator in form_indicators:
                if indicator in html_lower:
                    matches += 1
                    self.add_log(f"页面内容包含登录表单指示词: {indicator}")
            
            for indicator in campus_indicators:
                if indicator in html_lower:
                    campus_matches += 1
                    self.add_log(f"页面内容包含校园网指示词: {indicator}")
            
            # 如果匹配了多个指示词，可能是登录页面
            # 要求：1. URL匹配 或 2. 表单匹配数>=4 且 校园网指示词>=1
            if url_match or (matches >= 4 and campus_matches >= 1):
                self.add_log(f"HTML内容匹配了{matches}个登录指示词和{campus_matches}个校园网指示词")
                return True
        
        return False
    
    def perform_login(self):
        """执行登录操作"""
        username = self.username_var.get()
        password = self.password_var.get()
        url = getattr(self, 'login_url', '')
        
        if not username or not password:
            self.status_var.set("请填写用户名和密码")
            self.add_log("登录失败：用户名或密码为空")
            return False
        
        if not self.firefox_path or not os.path.exists(self.firefox_path):
            self.status_var.set("未找到Firefox浏览器")
            self.add_log("登录失败：Firefox路径无效")
            return False
        
        # 如果URL为空，尝试自动检测
        if not url:
            self.status_var.set("尝试自动检测登录页面...")
            self.add_log("尝试自动检测登录页面")
            if self.needs_campus_login():
                url = self.login_url
                self.add_log(f"自动检测到登录页面: {url}")
            else:
                self.status_var.set("无法自动检测登录页面")
                self.add_log("无法自动检测登录页面")
                return False
        
        try:
            # 设置Firefox选项
            options = webdriver.FirefoxOptions()
            options.add_argument('--headless')  # 无头模式
            options.binary_location = self.firefox_path
            
            # 使用geckodriver
            if not self.geckodriver_path:
                self.status_var.set("未找到geckodriver")
                self.add_log("登录失败：未找到geckodriver")
                return False
            
            # 创建Firefox服务
            service = Service(executable_path=self.geckodriver_path)
            
            # 启动浏览器
            self.add_log("启动Firefox浏览器")
            driver = webdriver.Firefox(service=service, options=options)
            driver.get(url)
            
            # 等待页面加载完成
            self.add_log("等待页面加载完成")
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            
            self.status_var.set("分析登录页面元素...")
            self.add_log("分析登录页面元素")
            
            # 尝试多种可能的选择器来找到用户名输入框
            username_selectors = [
                (By.NAME, "username"),
                (By.CSS_SELECTOR, "input[placeholder='学工号/校友号']"),
                (By.CSS_SELECTOR, "input[name='username']"),
                (By.CSS_SELECTOR, "input.ant-input[name='username']"),
                (By.ID, "username"),
                (By.CSS_SELECTOR, "input[type='text']")
            ]
            
            # 尝试多种可能的选择器来找到密码输入框
            password_selectors = [
                (By.CSS_SELECTOR, "input[type='password']"),
                (By.CSS_SELECTOR, "input[placeholder='请输入密码']"),
                (By.CSS_SELECTOR, "input.ant-input[type='password']"),
                (By.NAME, "password"),
                (By.ID, "password")
            ]
            
            # 尝试多种可能的选择器来找到登录按钮
            login_button_selectors = [
                (By.CSS_SELECTOR, "button[type='submit']"),
                (By.CSS_SELECTOR, "button.login-button"),
                (By.XPATH, "//button[contains(text(), '登')]"),
                (By.XPATH, "//span[contains(text(), '登')]/parent::button"),
                (By.ID, "login-button"),
                (By.ID, "loginBtn"),
                (By.CSS_SELECTOR, "input[type='submit']")
            ]
            
            # 查找并填写用户名
            username_element = None
            for selector_type, selector in username_selectors:
                try:
                    username_element = WebDriverWait(driver, 2).until(
                        EC.presence_of_element_located((selector_type, selector))
                    )
                    self.add_log(f"找到用户名输入框: {selector_type}={selector}")
                    break
                except:
                    continue
            
            if not username_element:
                self.status_var.set("无法找到用户名输入框")
                self.add_log("无法找到用户名输入框")
                driver.quit()
                return False
            
            username_element.clear()
            username_element.send_keys(username)
            self.add_log("已填写用户名")
            
            # 查找并填写密码
            password_element = None
            for selector_type, selector in password_selectors:
                try:
                    password_element = WebDriverWait(driver, 2).until(
                        EC.presence_of_element_located((selector_type, selector))
                    )
                    self.add_log(f"找到密码输入框: {selector_type}={selector}")
                    break
                except:
                    continue
            
            if not password_element:
                self.status_var.set("无法找到密码输入框")
                self.add_log("无法找到密码输入框")
                driver.quit()
                return False
            
            password_element.clear()
            password_element.send_keys(password)
            self.add_log("已填写密码")
            
            # 查找并点击登录按钮
            login_button = None
            for selector_type, selector in login_button_selectors:
                try:
                    login_button = WebDriverWait(driver, 2).until(
                        EC.element_to_be_clickable((selector_type, selector))
                    )
                    self.add_log(f"找到登录按钮: {selector_type}={selector}")
                    break
                except:
                    continue
            
            if not login_button:
                self.status_var.set("无法找到登录按钮")
                self.add_log("无法找到登录按钮")
                driver.quit()
                return False
            
            login_button.click()
            self.add_log("已点击登录按钮")
            
            # 等待登录成功（页面URL变化或特定元素出现）
            try:
                # 等待URL变化或页面内容变化
                self.add_log("等待登录结果...")
                WebDriverWait(driver, 10).until(
                    lambda d: "login" not in d.current_url.lower() or 
                              "portal" not in d.current_url.lower() or
                              "success" in d.page_source.lower()
                )
                self.status_var.set("登录成功")
                self.add_log("登录成功")
                driver.quit()
                return True
            except TimeoutException:
                self.status_var.set("登录失败，请检查用户名和密码")
                self.add_log("登录失败，请检查用户名和密码")
                driver.quit()
                return False
        
        except Exception as e:
            self.status_var.set(f"登录出错: {str(e)}")
            self.add_log(f"登录出错: {str(e)}")
            try:
                driver.quit()
            except:
                pass
            return False

# 主程序入口
if __name__ == "__main__":
    # 添加命令行参数解析
    parser = argparse.ArgumentParser(description="校园网自动登录工具")
    parser.add_argument("--auto", action="store_true", help="自动模式")
    args = parser.parse_args()
    
    # 检查是否已安装keyring库
    try:
        import keyring
    except ImportError:
        print("错误: 未安装keyring库。请使用以下命令安装:")
        print("pip install keyring")
        sys.exit(1)
    
    root = tk.Tk()
    
    # 自动模式不再隐藏窗口
    app = CampusLoginApp(root, auto_mode=args.auto)
    root.mainloop()