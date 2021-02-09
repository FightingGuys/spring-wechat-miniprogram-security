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

package samples.auth.controller;

import cn.fightingguys.security.web.wechat.auth.WeChatMiniProgramAuthenticationProvider;
import cn.fightingguys.security.web.wechat.entity.WeChatMiniProgramUserDetails;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    /* Verified 验证提供者默认权限名称 */
    @PreAuthorize("hasAuthority('Verified')")
    @GetMapping("pri")
    public String authentication() {
        WeChatMiniProgramUserDetails userDetails =
                (WeChatMiniProgramUserDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
        return "Hi, The OpenId is" + userDetails.getOpenId();
    }

    @PreAuthorize("hasAuthority('Admin')")
    @GetMapping("admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/")
    public String home() {
        return "Welcome";
    }
}
