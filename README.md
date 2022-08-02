# SetWinSetupSplashText

实时修改Windows在安装过程在进度屏幕中显示的状态文本。可以在Windows安装的联机配置阶段运行无人值守程序时，通过此程序来修改进度屏幕上的状态文本，以实时反馈工作状态。

![1659446667175](image/README/1659446667175.png)

## 使用说明

Windows安装处于*联机配置*阶段时，本程序可以修改由 `winlogon.exe`生成的进度界面的进度文本。

调用命令行：

```plaintext
SetWinSetupSplashText.exe [<要修改的文字>]
```

如果没有传递任何参数，那么会从输入中读取文字。

## 实现原理

通过获取到进度屏幕的文本控件句柄，并通过线程注入的方式修改现实内容。
