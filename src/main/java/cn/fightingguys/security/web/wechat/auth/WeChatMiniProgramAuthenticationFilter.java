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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 微信小程序验证拦截器
 */
public class WeChatMiniProgramAuthenticationFilter extends OncePerRequestFilter {

    public static final String DEFAULT_AUTH_TOKEN_TYPE = "WxToken";

    public static final String DEFAULT_JS_CODE_PARAM_KEY = "jsCode";

    public static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/wxLogin",
            "POST");

    /**
     * @link https://tools.ietf.org/html/rfc6749#section-7.1
     */
    private String filterAuthTokenType = DEFAULT_AUTH_TOKEN_TYPE;

    private RequestMatcher requestMatcher = DEFAULT_ANT_PATH_REQUEST_MATCHER;

    private final AuthenticationManager authenticationManager;

    public WeChatMiniProgramAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public WeChatMiniProgramAuthenticationFilter(AuthenticationManager authenticationManager, RequestMatcher requestMatcher, String tokenType) {
        this.authenticationManager = authenticationManager;
        this.requestMatcher = requestMatcher;
        this.filterAuthTokenType = tokenType;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            String jsCode = obtainJsCode(request);
            jsCode = (jsCode != null) ? jsCode : "";

            if (jsCode.length() == 0) {
                sendErrorResponse(response, "The jsCode is null");
                return;
            }

            WeChatMiniProgramAuthenticationToken authentication = new WeChatMiniProgramAuthenticationToken(jsCode, false);
            WeChatMiniProgramAuthenticationToken authenticationToken;
            try {
                authenticationToken = (WeChatMiniProgramAuthenticationToken) this.authenticationManager.authenticate(authentication);
            } catch (AuthenticationException e) {
                sendErrorResponse(response, e.getMessage());
                return;
            }
            sendAuthTokenResponse(response, authenticationToken);
            return;
        }

        /* WeChat Authorization Token Verify */

        String authorizationValue = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationValue == null) {
            filterChain.doFilter(request, response);
            return;
        }
        String[] authValueSplit = authorizationValue.split(" ", 2);

        if (authValueSplit.length != 2) {
            sendErrorResponse(response, "Auth token format is wrong");
            return;
        }

        String authTokenType = authValueSplit[0];
        String authTokenValue = authValueSplit[1];

        if (!authTokenType.equals(filterAuthTokenType)) {
            sendErrorResponse(response, "Auth token type is wrong");
            return;
        }

        WeChatMiniProgramAuthenticationToken authentication = new WeChatMiniProgramAuthenticationToken(authTokenValue, true);
        WeChatMiniProgramAuthenticationToken authenticationToken;
        try {
            authenticationToken = (WeChatMiniProgramAuthenticationToken) this.authenticationManager.authenticate(authentication);
        } catch (AuthenticationException e) {
            sendErrorResponse(response, e.getMessage());
            return;
        }

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);
    }

    private String obtainJsCode(HttpServletRequest request) {
        return request.getParameter(DEFAULT_JS_CODE_PARAM_KEY);
    }

    private void sendErrorResponse(HttpServletResponse response, String msg) throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        String outputString = String.format("{\"msg\": \"%s\"}", msg);
        response.getWriter().print(outputString);
    }

    private void sendAuthTokenResponse(HttpServletResponse response, WeChatMiniProgramAuthenticationToken token) throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        String outputString = String.format("{\"token\": \"%s\"}", token.getCredentials());
        response.getWriter().print(outputString);
    }

}
