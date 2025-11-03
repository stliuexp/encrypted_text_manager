import os
import shutil
import PyInstaller.__main__

# 清理旧的构建文件
if os.path.exists('dist'):
    shutil.rmtree('dist')
if os.path.exists('build'):
    shutil.rmtree('build')

# 使用PyInstaller打包
PyInstaller.__main__.run([
    'main.py',
    '--name=加密文本管理器',
    '--onefile',
    '--windowed',
    '--icon=NONE',
    '--add-data=requirements.txt;.',
])

# 创建数据目录
os.makedirs('dist/data/users', exist_ok=True)
os.makedirs('dist/data/files', exist_ok=True)

print("打包完成！可执行文件位于 dist 目录中。")