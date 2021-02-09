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

import cn.fightingguys.security.web.wechat.auth.WeChatMiniProgramAuthenticationFilter;
import cn.fightingguys.security.web.wechat.auth.WeChatMiniProgramAuthenticationProvider;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

public class WeChatMiniProgramSecurityProviderSettings {

    private final Map<String, Object> settings = new HashMap<>();

    private static final String PROVIDER_SETTING_BASE = "wechat.auth.provider.";
    public static final String APP_ID = PROVIDER_SETTING_BASE.concat("appId");
    public static final String SECRET = PROVIDER_SETTING_BASE.concat("secret");
    /**
     * @see WeChatMiniProgramSecurityProviderSettings#AUTHORIZATION_NAME
     */
    public static final String AUTHORIZATION_NAME = PROVIDER_SETTING_BASE.concat("authorization-name");
    public static final String AUTHORIZATION_TOKEN_TYPE = PROVIDER_SETTING_BASE.concat("authorization-token-type");
    public static final String AUTHORIZATION_ENDPOINT = PROVIDER_SETTING_BASE.concat("authorization-endpoint");

    public WeChatMiniProgramSecurityProviderSettings() {
        withDefault();
    }

    public WeChatMiniProgramSecurityProviderSettings(Map<String, Object> settings) {
        this.settings.putAll(settings);
    }

    public WeChatMiniProgramSecurityProviderSettings endpoint(String endpoint) {
        return setting(AUTHORIZATION_ENDPOINT, endpoint);
    }

    public String authorizationEndpoint() {
        return setting(AUTHORIZATION_ENDPOINT);
    }

    public WeChatMiniProgramSecurityProviderSettings appId(String appId) {
        return setting(APP_ID, appId);
    }

    public String appId() {
        return setting(APP_ID);
    }

    public WeChatMiniProgramSecurityProviderSettings secret(String secret) {
        return setting(SECRET, secret);
    }

    public String secret() {
        return setting(SECRET);
    }

    /**
     * @see WeChatMiniProgramSecurityProviderSettings#AUTHORIZATION_NAME
     */
    public WeChatMiniProgramSecurityProviderSettings authorizationName(String authorizationName) {
        return setting(AUTHORIZATION_NAME, authorizationName);
    }

    public String authorizationName() {
        return setting(AUTHORIZATION_NAME);
    }

    public WeChatMiniProgramSecurityProviderSettings authorizationTokenType(String authorizationTokenType) {
        return setting(AUTHORIZATION_TOKEN_TYPE, authorizationTokenType);
    }

    public String authorizationTokenType() {
        return setting(AUTHORIZATION_TOKEN_TYPE);
    }

    private WeChatMiniProgramSecurityProviderSettings setting(String key, Object object) {
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
        settings.put(AUTHORIZATION_ENDPOINT, WeChatMiniProgramAuthenticationFilter.DEFAULT_ANT_PATH_REQUEST_MATCHER.getPattern());
        settings.put(AUTHORIZATION_TOKEN_TYPE, WeChatMiniProgramAuthenticationFilter.DEFAULT_AUTH_TOKEN_TYPE);
        settings.put(AUTHORIZATION_NAME, WeChatMiniProgramAuthenticationProvider.DEFAULT_AUTHORITIES_NAME);
    }

}
