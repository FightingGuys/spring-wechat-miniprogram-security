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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

public class InMemoryWeChatUserDetailsManager implements UserDetailsManager {

    private final Map<String, WeChatMiniProgramUserDetails> users = new HashMap<>();

    @Override
    public void createUser(UserDetails user) {
        Assert.isTrue(user instanceof WeChatMiniProgramUserDetails, "must WeChatMiniProgramUserDetails instance");
        WeChatMiniProgramUserDetails userDetails = (WeChatMiniProgramUserDetails) user;
        Assert.isTrue(!userExists(userDetails.getOpenId()), "wechat user should not exist");
        this.users.put(userDetails.getOpenId(), userDetails);
    }

    @Override
    public void updateUser(UserDetails user) {
        Assert.isTrue(user instanceof WeChatMiniProgramUserDetails, "must WeChatMiniProgramUserDetails instance");
        WeChatMiniProgramUserDetails userDetails = (WeChatMiniProgramUserDetails) user;
        Assert.isTrue(userExists(userDetails.getOpenId()), "wechat user should exist");
        this.users.put(userDetails.getOpenId(), userDetails);
    }

    @Override
    public void deleteUser(String openId) {
        this.users.remove(openId);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
    }

    @Override
    public boolean userExists(String openId) {
        return this.users.containsKey(openId);
    }

    @Override
    public UserDetails loadUserByUsername(String openId) throws UsernameNotFoundException {
        WeChatMiniProgramUserDetails user = this.users.get(openId);
        if (user == null) {
            throw new UsernameNotFoundException(openId);
        }
        return new WeChatMiniProgramUserDetails(
                user.getOpenId(), user.getNickName(), user.getUnionId(), user.getSessionKey(), user.isEnabled(), user.isAccountNonExpired(),
                user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
    }
}
