/*
 *    Copyright 2021 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        https://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package cn.fightingguys.security.web.wechat.config;

import cn.fightingguys.security.web.wechat.auth.WeChatMiniProgramAuthenticationProvider;
import org.springframework.util.Assert;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public class WeChatMiniProgramSecurityJwtSettings {

    private final Map<String, Object> settings = new HashMap<>();

    private static final String PROVIDER_SETTING_BASE = "wechat.jwt.settings.";
    public static final String ISSUER = PROVIDER_SETTING_BASE.concat("issuer");
    public static final String PRIVATE_KEY = PROVIDER_SETTING_BASE.concat("private-key");

    public WeChatMiniProgramSecurityJwtSettings() {
        withDefault();
    }

    public WeChatMiniProgramSecurityJwtSettings(Map<String, Object> settings) {
        this.settings.putAll(settings);
    }

    public WeChatMiniProgramSecurityJwtSettings issuer(String issuer) {
        return setting(ISSUER, issuer);
    }

    public String issuer() {
        return setting(ISSUER);
    }

    public WeChatMiniProgramSecurityJwtSettings privateKey(Key privateKey) {
        return setting(PRIVATE_KEY, privateKey);
    }

    public Key privateKey() {
        return setting(PRIVATE_KEY);
    }

    private WeChatMiniProgramSecurityJwtSettings setting(String key, Object object) {
        Assert.hasText(key, "key cannot be empty");
        Assert.notNull(object, "object cannot be null");
        this.settings.put(key, object);
        return this;
    }

    @SuppressWarnings("unchecked")
    public <T> T setting(String name) {
        Assert.hasText(name, "name cannot be empty");
        return (T) this.settings.get(name);
    }

    public Map<String, Object> settings() {
        return this.settings;
    }

    private void withDefault() {
        this.settings.put(ISSUER, WeChatMiniProgramAuthenticationProvider.DEFAULT_ISSUER_NAME);
    }

}
