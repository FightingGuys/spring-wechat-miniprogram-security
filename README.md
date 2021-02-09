# Spring Security 微信小程序鉴权模块

## 前言
基于Spring Security的微信小程序鉴权模块  
使用 Json Web Token 作为验证身份密钥，可以融合Spring Security的hasAuthority使用

**目前还在开发阶段，不推荐大家直接用在生产环境**  
**还有很多文档、单元测试未编写**

[Gitee 国内镜像](https://gitee.com/FightingGuys/spring-wechat-miniprogram-security)

## 安装

[Maven 中央仓库](https://search.maven.org/artifact/cn.fightingguys.security.web/spring-wechat-miniprogram-security/0.0.1/jar)

### 使用 Maven 引用
```xml
<dependency>
    <groupId>cn.fightingguys.security.web</groupId>
    <artifactId>spring-wechat-miniprogram-security</artifactId>
    <version>0.0.1</version>
</dependency>
```

### 使用 Gradle 引用
```groovy
implementation 'cn.fightingguys.security.web:spring-wechat-miniprogram-security:0.0.1'
```

## 快速上手
[简单例子](samples/wechat-miniprogram-authentication)

## 使用文档
（暂无）
