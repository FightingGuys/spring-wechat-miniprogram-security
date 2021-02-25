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

import cn.fightingguys.security.web.wechat.entity.WeChatMiniProgramUserDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public class WeChatMiniProgramAuthenticationToken extends AbstractAuthenticationToken {

    private String credentials;

    private boolean verify;

    public WeChatMiniProgramAuthenticationToken(String token, boolean verify) {
        super(null);
        this.credentials = token;
        this.verify = verify;
    }

    public WeChatMiniProgramAuthenticationToken(String token, WeChatMiniProgramUserDetails userDetails) {
        super(userDetails.getAuthorities());
        this.credentials = token;
        super.setDetails(userDetails);
        super.setAuthenticated(true);
    }

    /**
     * 验证模式
     *
     * @return 返回 false 为验证认证模式，否则为验证模式
     */
    public boolean isVerify() {
        return verify;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return super.getDetails();
    }
}
