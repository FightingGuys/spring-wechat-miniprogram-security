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

package cn.fightingguys.security.web.wechat.auth;

import cn.fightingguys.security.web.wechat.config.WeChatMiniProgramSecurityJwtSettings;
import cn.fightingguys.security.web.wechat.config.WeChatMiniProgramSecurityProviderSettings;
import cn.fightingguys.security.web.wechat.entity.WeChatC2SJacksonHttpMessageConverter;
import cn.fightingguys.security.web.wechat.entity.WeChatMiniProgramCode2Session;
import cn.fightingguys.security.web.wechat.entity.WeChatMiniProgramUserDetails;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.client.RestTemplate;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class WeChatMiniProgramAuthenticationProvider implements AuthenticationProvider {

    private final Logger log = LoggerFactory.getLogger(WeChatMiniProgramAuthenticationProvider.class);

    public final static String DEFAULT_ISSUER_NAME = "WeChatAuthProviderService";

    public final static String JS_CODE_TO_SESSION_ENDPOINT =
            "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code";

    public final static String DEFAULT_AUTHORITIES_NAME = "Verified";



    /* User Define Variable */

    private String issuerName = DEFAULT_ISSUER_NAME;

    private String authoritiesName = DEFAULT_AUTHORITIES_NAME;

    private final String appId;

    private final String appSecret;

    private final Key key;

    private final UserDetailsManager userDetailsManager;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        WeChatMiniProgramAuthenticationToken wxAuthentication = (WeChatMiniProgramAuthenticationToken) authentication;
        if (!wxAuthentication.isVerify()) {
            return verifyJsCode(wxAuthentication);
        } else {
            return verifyAuthentication(wxAuthentication);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return WeChatMiniProgramAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public WeChatMiniProgramAuthenticationProvider(
            WeChatMiniProgramSecurityProviderSettings providerSettings,
            WeChatMiniProgramSecurityJwtSettings jwtSettings,
            UserDetailsManager userDetailsManager) {
        this.appId = providerSettings.appId();
        this.appSecret = providerSettings.secret();
        this.authoritiesName = providerSettings.authorizationName();
        this.key = jwtSettings.privateKey();
        this.issuerName = jwtSettings.issuer();
        this.userDetailsManager = userDetailsManager;
    }

    private void checkCode2SessionService(WeChatMiniProgramCode2Session code2Session) {
        if (code2Session == null) {
            throw new AuthenticationServiceException("code2Session is null");
        }
        if (code2Session.getErrCode() != 0) {
            throw new AuthenticationServiceException(code2Session.getErrMsg());
        }
    }

    private String createJwt(String openId) {
        Map<String, Object> claims = new HashMap<>();
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setIssuer(issuerName)
                .setSubject(openId)
                .signWith(key);
        return builder.compact();
    }

    private UserDetails createUser(String openId) {
        return WeChatMiniProgramUserDetails.builder()
                .openId(openId)
                .authorities(authoritiesName)
                .build();
    }

    private Authentication verifyJsCode(WeChatMiniProgramAuthenticationToken authentication) {
        RestTemplate restTemplate = new RestTemplateBuilder()
                .messageConverters(new WeChatC2SJacksonHttpMessageConverter())  /* Fix WeChat Code2Session Context-Type Bug */
                .build();
        String url = String.format(JS_CODE_TO_SESSION_ENDPOINT, appId, appSecret, authentication.getCredentials());
        WeChatMiniProgramCode2Session code2Session = restTemplate.getForObject(url, WeChatMiniProgramCode2Session.class);
        checkCode2SessionService(code2Session);
        String userOpenId = code2Session.getOpenId();
        return createWeChatMiniProgramAuthenticationToken(userOpenId);
    }

    private Authentication verifyAuthentication(WeChatMiniProgramAuthenticationToken authentication) {
        String jws = (String) authentication.getCredentials();
        String userOpenId;
        try {
            userOpenId = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jws).getBody().getSubject();
        } catch (JwtException e) {
            throw new AuthenticationServiceException(e.getMessage());
        }
        return createWeChatMiniProgramAuthenticationToken(userOpenId, jws);
    }

    public Authentication createWeChatMiniProgramAuthenticationToken(String openId) {
        String jws = createJwt(openId);
        return createWeChatMiniProgramAuthenticationToken(openId, jws);
    }

    private Authentication createWeChatMiniProgramAuthenticationToken(String openId, String jws) {
        UserDetails userDetails;
        if (!userDetailsManager.userExists(openId)) {
            userDetails = createUser(openId);
            userDetailsManager.createUser(userDetails);
        } else {
            userDetails = userDetailsManager.loadUserByUsername(openId);
        }
        WeChatMiniProgramAuthenticationToken weChatMiniProgramAuthenticationToken =
                new WeChatMiniProgramAuthenticationToken(jws, userDetails.getAuthorities());
        weChatMiniProgramAuthenticationToken.setDetails(userDetails);
        return weChatMiniProgramAuthenticationToken;
    }
}
