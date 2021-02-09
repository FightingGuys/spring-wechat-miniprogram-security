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

import cn.fightingguys.security.web.wechat.auth.InMemoryWeChatUserDetailsManager;
import cn.fightingguys.security.web.wechat.auth.WeChatMiniProgramAuthenticationFilter;
import cn.fightingguys.security.web.wechat.auth.WeChatMiniProgramAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.Map;

public class WeChatMiniProgramSecurityConfigurer<B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<WeChatMiniProgramSecurityConfigurer<B>, B> {

    private static final Logger log = LoggerFactory.getLogger(WeChatMiniProgramSecurityConfigurer.class);

    private RequestMatcher authorizationEndpointMatcher;
    private final RequestMatcher endpointsMatcher = (request) ->
            this.authorizationEndpointMatcher.matches(request);

    @Override
    public void init(B builder) throws Exception {
        WeChatMiniProgramSecurityProviderSettings providerSettings = getProviderSettings(builder);
        initEndpointMatchers(providerSettings);

        WeChatMiniProgramAuthenticationProvider provider = initWeChatMiniProgramAuthenticationProvider(providerSettings, getJwtSettings(builder), getUserDetailsManager(builder));
        builder.authenticationProvider(postProcess(provider));
    }

    @Override
    public void configure(B builder) throws Exception {
        WeChatMiniProgramSecurityProviderSettings providerSettings = getProviderSettings(builder);
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

        WeChatMiniProgramAuthenticationFilter weChatMiniProgramAuthenticationFilter
                = new WeChatMiniProgramAuthenticationFilter(authenticationManager, authorizationEndpointMatcher, providerSettings.authorizationTokenType());
        builder.addFilterBefore(weChatMiniProgramAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class);
    }

    public RequestMatcher getEndpointsMatcher() {
        return this.endpointsMatcher;
    }

    private WeChatMiniProgramAuthenticationProvider initWeChatMiniProgramAuthenticationProvider(
            WeChatMiniProgramSecurityProviderSettings providerSettings,
            WeChatMiniProgramSecurityJwtSettings jwtSettings,
            UserDetailsManager detailsManager) {
        return new WeChatMiniProgramAuthenticationProvider(providerSettings, jwtSettings, detailsManager);
    }

    private void initEndpointMatchers(WeChatMiniProgramSecurityProviderSettings settings) {
        this.authorizationEndpointMatcher = new AntPathRequestMatcher(
                settings.authorizationEndpoint(),
                HttpMethod.POST.name());
    }

    private static <B extends HttpSecurityBuilder<B>> WeChatMiniProgramSecurityProviderSettings getProviderSettings(B builder) {
        WeChatMiniProgramSecurityProviderSettings providerSettings = builder.getSharedObject(WeChatMiniProgramSecurityProviderSettings.class);
        if (providerSettings == null) {
            providerSettings = getOptionalBean(builder, WeChatMiniProgramSecurityProviderSettings.class);
            if (providerSettings == null) {
                providerSettings = new WeChatMiniProgramSecurityProviderSettings();
            }
            builder.setSharedObject(WeChatMiniProgramSecurityProviderSettings.class, providerSettings);
        }
        return providerSettings;
    }

    private static <B extends HttpSecurityBuilder<B>> WeChatMiniProgramSecurityJwtSettings getJwtSettings(B builder) {
        WeChatMiniProgramSecurityJwtSettings JwtSettings = builder.getSharedObject(WeChatMiniProgramSecurityJwtSettings.class);
        if (JwtSettings == null) {
            JwtSettings = getOptionalBean(builder, WeChatMiniProgramSecurityJwtSettings.class);
            if (JwtSettings == null) {
                JwtSettings = new WeChatMiniProgramSecurityJwtSettings();
            }
            builder.setSharedObject(WeChatMiniProgramSecurityJwtSettings.class, JwtSettings);
        }
        return JwtSettings;
    }

    private static <B extends HttpSecurityBuilder<B>> UserDetailsManager getUserDetailsManager(B builder) {
        UserDetailsManager userDetailsManager = builder.getSharedObject(UserDetailsManager.class);
        if (userDetailsManager == null) {
            userDetailsManager = getOptionalBean(builder, UserDetailsManager.class);
            if (userDetailsManager == null) {
                userDetailsManager = new InMemoryWeChatUserDetailsManager();
                if (log.isWarnEnabled()) {
                    log.warn("\nUsing the default in-memory user details manager\n");
                }
            }
            builder.setSharedObject(UserDetailsManager.class, userDetailsManager);
        }
        return userDetailsManager;
    }

    private static <B extends HttpSecurityBuilder<B>, T> T getOptionalBean(B builder, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
                builder.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                    "Expected single matching bean of type '" + type.getName() + "' but found " +
                            beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }
}
