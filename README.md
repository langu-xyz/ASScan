![ASScan](https://socialify.git.ci/langu-xyz/ASScan/image?description=1&language=1&name=1&owner=1&theme=Light)

## Introduction

BurpSuite的功能已经非常强大，这个插件产生的缘由是在一些场景下需要静默的去收集信息分析攻击面，便产生了这个插件，目标是不主动发送除正常请求外的任何一个请求包。它不会准确的发现并验证漏洞，但是会极大的辅助你挖掘漏洞。

## 介绍

Hello, Attack Surface Scan
The Real Passive Scan, It's like a submarine.

BurpSuite完全被动扫描插件，不主动发送任何请求，适合挂机使用。

### 功能

1. 从JS文件中发现API、SubDomain或其它信息.
2. 从JS文件中发现AccessKey/SecretKey.
3. IDOR越权参数点发现.
4. 响应值中敏感数据发现，例如手机号.
5. SSRF等漏洞触发点发现.
6. 流量转存Sqlite数据库.
7. Not to stay up ...

### 开发

插件采用插件化的架构，可以方便的进行新增功能。

<img width="197" alt="image" src="https://user-images.githubusercontent.com/12745454/174215584-48564539-c6a6-466b-84b7-308cf811677e.png">

### 使用

导入依赖包 https://github.com/langu-xyz/ASScan/blob/main/resources/sqlite-jdbc-3.7.2.jar

![image](https://user-images.githubusercontent.com/12745454/178136815-8dec4286-c5f9-46e9-957d-1ba4d0f9b2b4.png)

加载插件 

![image](https://user-images.githubusercontent.com/12745454/178136864-c3c7ae8c-8738-4490-99c4-95331a55972e.png)

查看扫描结果

![image](https://user-images.githubusercontent.com/12745454/178136884-3e19aabd-4778-4340-abaf-00caa1bb866a.png)
![image](https://user-images.githubusercontent.com/12745454/178136923-e3f3198a-425b-4244-bf50-beb538d9c799.png)

流量日志存储相关

<img width="200" alt="image" src="https://user-images.githubusercontent.com/12745454/178136972-021d5516-b648-4b5b-9a06-b8713466b68e.png">
<img width="975" alt="image" src="https://user-images.githubusercontent.com/12745454/178153825-a57c0ee0-7567-48b5-96b3-b1bcc3e58498.png">
<img width="216" alt="image" src="https://user-images.githubusercontent.com/12745454/178153832-c12bff87-1776-43a5-8af8-62980b76452a.png">




## Workflow

<img width="280" alt="image" src="https://user-images.githubusercontent.com/12745454/174216180-c76a5482-bf03-4e8c-aa91-3163689a9ae5.png">




Enjoy your hacking life.

## 参考
https://github.com/righettod/log-requests-to-sqlite

