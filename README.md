# CalculationParameters - Burp Suite参数统计插件

这是一个Burp Suite插件，用于计算HTTP请求中参数的数量和已赋值参数的数量，并将结果显示在请求的备注中。

## 功能

- 统计HTTP请求体中的参数总数
- 统计已赋值的参数数量
- 支持多种请求体格式（如form表单、JSON等）
- 结果自动添加到请求备注
- 支持批量处理多个请求

## 使用方法

1. 在Burp Suite中加载插件：
   - 打开Burp Suite
   - 转到"Extensions"选项卡
   - 点击"Add"按钮
   - 选择"Java"作为扩展类型
   - 选择编译好的jar文件
   - 点击"Next"完成加载

2. 使用插件：
   - 转到"Proxy" > "HTTP history"标签页
   - 选择一个或多个请求（可选，不选则处理所有请求）
   - 右键单击，选择"计算参数量"菜单项
   - 统计结果将显示在每个请求的"Comment"列中

## 统计结果格式

统计结果将以以下格式显示在备注中：
```
已赋值: [已赋值数量] / 参数数量: [总数] 
```

## 构建

要构建此插件，需要以下环境：
- Java 17
- Maven

使用以下命令构建：
```bash
mvn clean package
```

编译后的JAR文件将位于`target`目录中。

## 依赖

- Burp Suite Montoya API v0.9.25

## 兼容性

兼容Burp Suite 2023以上版本。

## 开发

此项目使用Maven管理依赖。主要源代码位于`src/main/java`目录。 