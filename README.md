# 信息安全导论作业 2：S-AES 算法实现

本目录提供 S-AES 的 16-bit 分组加解密、Tkinter 图形界面和五关离线测试。程序只依赖 Python 标准库，不需要联网或模型服务。

## 运行

在本目录打开终端：

```powershell
python app.py
```

测试五关并重新生成保留记录：

```powershell
python test_saes.py
```

运行环境：Python 3.10 或更新版本；图形界面需要 Python 安装包包含 Tkinter。当前测试环境为 Python 3.13.5。

## 文件

- `saes_core.py`：S-AES 算法、字符串分组、双重/三重加密、中间相遇搜索和 CBC。
- `app.py`：四个功能页：基本加解密、ASCII、双重/三重加密与中间相遇、CBC 与篡改实验。
- `test_saes.py`：五关测试脚本，包含一个矩阵表示的独立本地参考实现。
- `算法与实现说明.md`：状态布局、轮变换、扩展功能约定与限制。
- `外部交叉测试向量.md`：供同学间交换程序时复核的固定输入和输出。
- `results/测试结果.md`：本次实际运行生成的测试结果。

