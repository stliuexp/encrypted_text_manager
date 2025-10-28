import os
import sys
import json
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import tkinter.filedialog as filedialog

class EncryptedTextManager:
    def __init__(self, root):
        self.root = root
        self.root.title("加密文本管理器")
        self.root.geometry("1000x600")
        self.root.minsize(800, 500)
        
        self.current_user = None
        self.current_key = None
        self.current_file = None
        
        # 设置应用程序数据目录
        self.app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        self.users_dir = os.path.join(self.app_dir, "users")
        self.files_dir = os.path.join(self.app_dir, "files")
        
        # 确保目录存在
        for directory in [self.app_dir, self.users_dir, self.files_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
        
        # 显示登录界面
        self.show_login_screen()
    
    def show_login_screen(self):
        # 清除当前窗口内容
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # 创建登录框架
        login_frame = ttk.Frame(self.root, padding="20")
        login_frame.pack(expand=True)
        
        # 标题
        ttk.Label(login_frame, text="加密文本管理器", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=20)
        
        # 用户名
        ttk.Label(login_frame, text="用户名:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_var = tk.StringVar()
        username_entry = ttk.Entry(login_frame, textvariable=username_var, width=30)
        username_entry.grid(row=1, column=1, pady=5)
        username_entry.focus()
        
        # 密码
        ttk.Label(login_frame, text="密码:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(login_frame, textvariable=password_var, show="*", width=30)
        password_entry.grid(row=2, column=1, pady=5)
        
        # 按钮框架
        button_frame = ttk.Frame(login_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        # 登录按钮
        login_button = ttk.Button(
            button_frame, 
            text="登录", 
            command=lambda: self.login(username_var.get(), password_var.get())
        )
        login_button.pack(side=tk.LEFT, padx=5)
        
        # 注册按钮
        register_button = ttk.Button(
            button_frame, 
            text="注册", 
            command=lambda: self.register(username_var.get(), password_var.get())
        )
        register_button.pack(side=tk.LEFT, padx=5)
        
        # 绑定回车键
        self.root.bind("<Return>", lambda event: self.login(username_var.get(), password_var.get()))
    
    def show_main_screen(self):
        # 清除当前窗口内容
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # 创建主界面
        self.root.title(f"加密文本管理器 - {self.current_user}")
        
        # 创建菜单栏
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="新建文件", command=self.new_file)
        file_menu.add_command(label="新建文件夹", command=self.new_folder)
        file_menu.add_separator()
        file_menu.add_command(label="保存", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="修改密码", command=self.change_password)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.logout)
        
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建左右分隔窗格
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # 左侧文件树框架
        left_frame = ttk.Frame(paned_window, width=200)
        paned_window.add(left_frame, weight=1)
        
        # 文件树标题
        ttk.Label(left_frame, text="文件夹", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # 创建树状视图
        self.tree = ttk.Treeview(left_frame)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # 树状视图滚动条
        tree_scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右侧文本编辑框架
        right_frame = ttk.Frame(paned_window, width=600)
        paned_window.add(right_frame, weight=3)
        
        # 文本编辑标题
        self.file_title = ttk.Label(right_frame, text="未选择文件", font=("Arial", 12, "bold"))
        self.file_title.pack(anchor=tk.W, pady=(0, 5))
        
        # 创建文本编辑器
        self.text_editor = ScrolledText(right_frame, wrap=tk.WORD, undo=True)
        self.text_editor.pack(fill=tk.BOTH, expand=True)
        
        # 状态栏
        self.status_bar = ttk.Label(self.root, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 绑定树状视图选择事件
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        
        # 加载文件树
        self.load_file_tree()
    
    def login(self, username, password):
        if not username or not password:
            messagebox.showerror("错误", "用户名和密码不能为空")
            return
        
        user_file = os.path.join(self.users_dir, f"{username}.json")
        
        if not os.path.exists(user_file):
            messagebox.showerror("错误", "用户不存在")
            return
        
        try:
            with open(user_file, "r") as f:
                user_data = json.load(f)
            
            # 验证密码
            salt = base64.b64decode(user_data["salt"])
            stored_hash = user_data["password_hash"]
            
            # 计算密码哈希
            password_hash = hashlib.sha256((password + base64.b64encode(salt).decode()).encode()).hexdigest()
            
            if password_hash != stored_hash:
                messagebox.showerror("错误", "密码错误")
                return
            
            # 生成加密密钥
            self.current_key = self.generate_key(password, salt)
            self.current_user = username
            
            # 创建用户文件目录
            user_files_dir = os.path.join(self.files_dir, username)
            if not os.path.exists(user_files_dir):
                os.makedirs(user_files_dir)
            
            # 显示主界面
            self.show_main_screen()
            
        except Exception as e:
            messagebox.showerror("错误", f"登录失败: {str(e)}")
    
    def register(self, username, password):
        if not username or not password:
            messagebox.showerror("错误", "用户名和密码不能为空")
            return
        
        user_file = os.path.join(self.users_dir, f"{username}.json")
        
        if os.path.exists(user_file):
            messagebox.showerror("错误", "用户已存在")
            return
        
        try:
            # 生成盐值
            salt = os.urandom(16)
            
            # 计算密码哈希
            password_hash = hashlib.sha256((password + base64.b64encode(salt).decode()).encode()).hexdigest()
            
            # 保存用户信息
            user_data = {
                "username": username,
                "password_hash": password_hash,
                "salt": base64.b64encode(salt).decode()
            }
            
            with open(user_file, "w") as f:
                json.dump(user_data, f)
            
            # 创建用户文件目录
            user_files_dir = os.path.join(self.files_dir, username)
            if not os.path.exists(user_files_dir):
                os.makedirs(user_files_dir)
            
            messagebox.showinfo("成功", "注册成功，请登录")
            
        except Exception as e:
            messagebox.showerror("错误", f"注册失败: {str(e)}")
    
    def generate_key(self, password, salt):
        """从密码生成加密密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def encrypt_text(self, text):
        """加密文本"""
        if not self.current_key:
            raise ValueError("未设置加密密钥")
        
        return self.current_key.encrypt(text.encode()).decode()
    
    def decrypt_text(self, encrypted_text):
        """解密文本"""
        if not self.current_key:
            raise ValueError("未设置加密密钥")
        
        return self.current_key.decrypt(encrypted_text.encode()).decode()
    
    def load_file_tree(self):
        """加载文件树"""
        # 清空树
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 用户文件根目录
        user_files_dir = os.path.join(self.files_dir, self.current_user)
        
        # 添加根节点
        root_node = self.tree.insert("", "end", text=self.current_user, open=True, values=(user_files_dir, "dir"))
        
        # 递归添加文件和文件夹
        self.add_directory_to_tree(root_node, user_files_dir)
    
    def add_directory_to_tree(self, parent, path):
        """递归添加目录到树"""
        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                
                if os.path.isdir(item_path):
                    # 添加文件夹
                    folder_node = self.tree.insert(parent, "end", text=item, values=(item_path, "dir"))
                    self.add_directory_to_tree(folder_node, item_path)
                else:
                    # 添加文件
                    self.tree.insert(parent, "end", text=item, values=(item_path, "file"))
        except Exception as e:
            print(f"加载目录错误: {str(e)}")
    
    def on_tree_select(self, event):
        """处理树节点选择事件"""
        selected_item = self.tree.selection()
        
        if not selected_item:
            return
        
        item_id = selected_item[0]
        item_values = self.tree.item(item_id, "values")
        
        if not item_values:
            return
        
        item_path = item_values[0]
        item_type = item_values[1]
        
        if item_type == "file":
            self.open_file(item_path)
    
    def open_file(self, file_path):
        """打开文件"""
        try:
            # 保存当前文件
            if self.current_file:
                self.save_file()
            
            # 设置当前文件
            self.current_file = file_path
            
            # 更新文件标题
            file_name = os.path.basename(file_path)
            self.file_title.config(text=file_name)
            
            # 读取文件内容
            with open(file_path, "r") as f:
                encrypted_content = f.read()
            
            # 解密内容
            if encrypted_content:
                try:
                    decrypted_content = self.decrypt_text(encrypted_content)
                except:
                    messagebox.showerror("错误", "无法解密文件，可能密钥不正确")
                    decrypted_content = ""
            else:
                decrypted_content = ""
            
            # 更新文本编辑器
            self.text_editor.delete(1.0, tk.END)
            self.text_editor.insert(tk.END, decrypted_content)
            
            # 更新状态栏
            self.status_bar.config(text=f"已打开: {file_path}")
            
        except Exception as e:
            messagebox.showerror("错误", f"打开文件失败: {str(e)}")
    
    def save_file(self):
        """保存当前文件"""
        if not self.current_file:
            return self.save_file_as()
        
        try:
            # 获取文本内容
            content = self.text_editor.get(1.0, tk.END)
            
            # 加密内容
            encrypted_content = self.encrypt_text(content)
            
            # 保存到文件
            with open(self.current_file, "w") as f:
                f.write(encrypted_content)
            
            # 更新状态栏
            self.status_bar.config(text=f"已保存: {self.current_file}")
            
            return True
        except Exception as e:
            messagebox.showerror("错误", f"保存文件失败: {str(e)}")
            return False
    
    def save_file_as(self):
        """另存为文件"""
        user_files_dir = os.path.join(self.files_dir, self.current_user)
        file_path = filedialog.asksaveasfilename(
            initialdir=user_files_dir,
            title="保存文件",
            filetypes=(("文本文件", "*.txt"), ("所有文件", "*.*"))
        )
        
        if not file_path:
            return False
        
        # 确保文件有扩展名
        if not os.path.splitext(file_path)[1]:
            file_path += ".txt"
        
        # 设置当前文件
        self.current_file = file_path
        
        # 更新文件标题
        file_name = os.path.basename(file_path)
        self.file_title.config(text=file_name)
        
        # 保存文件
        return self.save_file()
    
    def new_file(self):
        """创建新文件"""
        # 保存当前文件
        if self.current_file:
            self.save_file()
        
        # 获取用户文件目录
        user_files_dir = os.path.join(self.files_dir, self.current_user)
        
        # 获取选中的目录
        selected_item = self.tree.selection()
        if selected_item:
            item_id = selected_item[0]
            item_values = self.tree.item(item_id, "values")
            if item_values and item_values[1] == "dir":
                parent_dir = item_values[0]
            else:
                parent_dir = user_files_dir
        else:
            parent_dir = user_files_dir
        
        # 获取文件名
        file_name = simpledialog.askstring("新建文件", "请输入文件名:")
        if not file_name:
            return
        
        # 确保文件有扩展名
        if not os.path.splitext(file_name)[1]:
            file_name += ".txt"
        
        # 创建文件路径
        file_path = os.path.join(parent_dir, file_name)
        
        # 创建空文件
        try:
            with open(file_path, "w") as f:
                f.write("")
            
            # 刷新文件树
            self.load_file_tree()
            
            # 打开新文件
            self.open_file(file_path)
            
        except Exception as e:
            messagebox.showerror("错误", f"创建文件失败: {str(e)}")
    
    def new_folder(self):
        """创建新文件夹"""
        # 获取用户文件目录
        user_files_dir = os.path.join(self.files_dir, self.current_user)
        
        # 获取选中的目录
        selected_item = self.tree.selection()
        if selected_item:
            item_id = selected_item[0]
            item_values = self.tree.item(item_id, "values")
            if item_values and item_values[1] == "dir":
                parent_dir = item_values[0]
            else:
                parent_dir = user_files_dir
        else:
            parent_dir = user_files_dir
        
        # 获取文件夹名
        folder_name = simpledialog.askstring("新建文件夹", "请输入文件夹名:")
        if not folder_name:
            return
        
        # 创建文件夹路径
        folder_path = os.path.join(parent_dir, folder_name)
        
        # 创建文件夹
        try:
            os.makedirs(folder_path, exist_ok=True)
            
            # 刷新文件树
            self.load_file_tree()
            
        except Exception as e:
            messagebox.showerror("错误", f"创建文件夹失败: {str(e)}")
    
    def change_password(self):
        """修改密码"""
        # 创建修改密码对话框
        change_pwd_window = tk.Toplevel(self.root)
        change_pwd_window.title("修改密码")
        change_pwd_window.geometry("300x200")
        change_pwd_window.resizable(False, False)
        change_pwd_window.transient(self.root)
        change_pwd_window.grab_set()
        
        # 创建表单
        frame = ttk.Frame(change_pwd_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # 当前密码
        ttk.Label(frame, text="当前密码:").grid(row=0, column=0, sticky=tk.W, pady=5)
        current_pwd_var = tk.StringVar()
        current_pwd_entry = ttk.Entry(frame, textvariable=current_pwd_var, show="*", width=20)
        current_pwd_entry.grid(row=0, column=1, pady=5)
        current_pwd_entry.focus()
        
        # 新密码
        ttk.Label(frame, text="新密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        new_pwd_var = tk.StringVar()
        new_pwd_entry = ttk.Entry(frame, textvariable=new_pwd_var, show="*", width=20)
        new_pwd_entry.grid(row=1, column=1, pady=5)
        
        # 确认新密码
        ttk.Label(frame, text="确认新密码:").grid(row=2, column=0, sticky=tk.W, pady=5)
        confirm_pwd_var = tk.StringVar()
        confirm_pwd_entry = ttk.Entry(frame, textvariable=confirm_pwd_var, show="*", width=20)
        confirm_pwd_entry.grid(row=2, column=1, pady=5)
        
        # 按钮
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        # 确认按钮
        confirm_button = ttk.Button(
            button_frame, 
            text="确认", 
            command=lambda: self._process_password_change(
                current_pwd_var.get(), 
                new_pwd_var.get(), 
                confirm_pwd_var.get(),
                change_pwd_window
            )
        )
        confirm_button.pack(side=tk.LEFT, padx=5)
        
        # 取消按钮
        cancel_button = ttk.Button(
            button_frame, 
            text="取消", 
            command=change_pwd_window.destroy
        )
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        # 绑定回车键
        change_pwd_window.bind("<Return>", lambda event: self._process_password_change(
            current_pwd_var.get(), 
            new_pwd_var.get(), 
            confirm_pwd_var.get(),
            change_pwd_window
        ))
    
    def _process_password_change(self, current_pwd, new_pwd, confirm_pwd, window):
        """处理密码修改逻辑"""
        if not current_pwd or not new_pwd or not confirm_pwd:
            messagebox.showerror("错误", "所有密码字段都不能为空", parent=window)
            return
        
        if new_pwd != confirm_pwd:
            messagebox.showerror("错误", "新密码与确认密码不匹配", parent=window)
            return
        
        if current_pwd == new_pwd:
            messagebox.showerror("错误", "新密码不能与当前密码相同", parent=window)
            return
        
        # 验证当前密码
        user_file = os.path.join(self.users_dir, f"{self.current_user}.json")
        
        try:
            with open(user_file, "r") as f:
                user_data = json.load(f)
            
            # 验证密码
            salt = base64.b64decode(user_data["salt"])
            stored_hash = user_data["password_hash"]
            
            # 计算密码哈希
            password_hash = hashlib.sha256((current_pwd + base64.b64encode(salt).decode()).encode()).hexdigest()
            
            if password_hash != stored_hash:
                messagebox.showerror("错误", "当前密码错误", parent=window)
                return
            
            # 计算新密码哈希
            new_password_hash = hashlib.sha256((new_pwd + base64.b64encode(salt).decode()).encode()).hexdigest()
            
            # 保存当前文件
            if self.current_file:
                self.save_file()
            
            # 重新加密所有文件
            old_key = self.current_key
            new_key = self.generate_key(new_pwd, salt)
            
            # 更新用户数据
            user_data["password_hash"] = new_password_hash
            with open(user_file, "w") as f:
                json.dump(user_data, f)
            
            # 重新加密所有文件
            user_files_dir = os.path.join(self.files_dir, self.current_user)
            self._reencrypt_files(user_files_dir, old_key, new_key)
            
            # 更新当前密钥
            self.current_key = new_key
            
            # 关闭对话框
            window.destroy()
            
            # 显示成功消息
            messagebox.showinfo("成功", "密码已成功修改，所有文件已重新加密")
            
        except Exception as e:
            messagebox.showerror("错误", f"修改密码失败: {str(e)}", parent=window)
    
    def _reencrypt_files(self, directory, old_key, new_key):
        """使用新密钥重新加密目录中的所有文件"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # 读取加密内容
                    with open(file_path, "r") as f:
                        encrypted_content = f.read()
                    
                    # 如果文件为空，跳过
                    if not encrypted_content:
                        continue
                    
                    # 使用旧密钥解密
                    try:
                        decrypted_content = old_key.decrypt(encrypted_content.encode()).decode()
                    except:
                        # 如果解密失败，跳过该文件
                        continue
                    
                    # 使用新密钥加密
                    new_encrypted_content = new_key.encrypt(decrypted_content.encode()).decode()
                    
                    # 保存重新加密的内容
                    with open(file_path, "w") as f:
                        f.write(new_encrypted_content)
                        
                except Exception as e:
                    print(f"重新加密文件 {file_path} 失败: {str(e)}")
    
    def logout(self):
        """退出登录"""
        # 保存当前文件
        if self.current_file:
            self.save_file()
        
        # 清除当前用户和密钥
        self.current_user = None
        self.current_key = None
        self.current_file = None
        
        # 显示登录界面
        self.show_login_screen()

def main():
    root = tk.Tk()
    app = EncryptedTextManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()