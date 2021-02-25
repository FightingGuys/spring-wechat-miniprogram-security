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

package cn.fightingguys.security.web.wechat.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class WeChatMiniProgramUserDetails implements UserDetails {

    private final String nickName;
    private final String openId;
    private final String unionId;
    private String sessionKey;
    private final boolean enabled;
    private final boolean accountNonExpired;
    private final boolean credentialsNonExpired;
    private final boolean accountNonLocked;
    private final Collection<? extends GrantedAuthority> authorities;

    public WeChatMiniProgramUserDetails(String openId, String nickName, String unionId, String sessionKey, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        Assert.hasText(openId, "OpenId cannot be null");
        this.openId = openId;
        this.nickName = nickName;
        this.unionId = unionId;
        this.sessionKey = sessionKey;
        this.enabled = enabled;
        this.accountNonExpired = accountNonExpired;
        this.credentialsNonExpired = credentialsNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.authorities = authorities;
    }

    public String getNickName() {
        return nickName;
    }

    public String getUnionId() {
        return unionId;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    @Override
    public String getUsername() {
        return openId;
    }

    public String getOpenId() {
        return openId;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String toString() {
        return getClass().getName() + " [" +
                "OpenId=" + getOpenId() + ", " +
                "Nickname=" + getNickName() + ", " +
                "Enabled=" + isEnabled() + ", " +
                "AccountNonExpired=" + isAccountNonExpired() + ", " +
                "credentialsNonExpired=" + isCredentialsNonExpired() + ", " +
                "AccountNonLocked=" + isAccountNonLocked() + ", " +
                "Granted Authorities=" + getAuthorities() + "]";
    }

    @Override
    public int hashCode() {
        return openId.hashCode();
    }

    public static UserBuilder builder() {
        return new WeChatMiniProgramUserDetails.UserBuilder();
    }

    public static final class UserBuilder {

        private String openId;

        private String nickname;

        private String unionId;

        private String sessionKey;

        private List<GrantedAuthority> authorities;

        private boolean accountExpired;

        private boolean accountLocked;

        private boolean credentialsExpired;

        private boolean disabled;

        private UserBuilder() {
        }

        public WeChatMiniProgramUserDetails.UserBuilder openId(String openId) {
            Assert.notNull(openId, "username cannot be null");
            this.openId = openId;
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder unionId(String unionId) {
            this.unionId = unionId;
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder sessionKey(String sessionKey) {
            this.sessionKey = sessionKey;
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder nickname(String nickname) {
            this.nickname = nickname;
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder roles(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList<>(roles.length);
            for (String role : roles) {
                Assert.isTrue(!role.startsWith("ROLE_"),
                        () -> role + " cannot start with ROLE_ (it is automatically added)");
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            return authorities(authorities);
        }

        public WeChatMiniProgramUserDetails.UserBuilder authorities(GrantedAuthority... authorities) {
            return authorities(Arrays.asList(authorities));
        }

        public WeChatMiniProgramUserDetails.UserBuilder authorities(Collection<? extends GrantedAuthority> authorities) {
            this.authorities = new ArrayList<>(authorities);
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder authorities(String... authorities) {
            return authorities(AuthorityUtils.createAuthorityList(authorities));
        }

        public WeChatMiniProgramUserDetails.UserBuilder accountExpired(boolean accountExpired) {
            this.accountExpired = accountExpired;
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder accountLocked(boolean accountLocked) {
            this.accountLocked = accountLocked;
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder credentialsExpired(boolean credentialsExpired) {
            this.credentialsExpired = credentialsExpired;
            return this;
        }

        public WeChatMiniProgramUserDetails.UserBuilder disabled(boolean disabled) {
            this.disabled = disabled;
            return this;
        }

        public WeChatMiniProgramUserDetails build() {
            return new WeChatMiniProgramUserDetails(this.openId, this.nickname, this.unionId, this.sessionKey, !this.disabled, !this.accountExpired,
                    !this.credentialsExpired, !this.accountLocked, this.authorities);
        }

    }
}
