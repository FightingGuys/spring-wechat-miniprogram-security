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

package samples.auth.config;

import cn.fightingguys.security.web.wechat.auth.InMemoryWeChatUserDetailsManager;
import cn.fightingguys.security.web.wechat.config.WeChatMiniProgramSecurityConfiguration;
import cn.fightingguys.security.web.wechat.config.WeChatMiniProgramSecurityConfigurer;
import cn.fightingguys.security.web.wechat.config.WeChatMiniProgramSecurityJwtSettings;
import cn.fightingguys.security.web.wechat.config.WeChatMiniProgramSecurityProviderSettings;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.Key;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Import(WeChatMiniProgramSecurityConfiguration.class)
public class WeChatAuthConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.apply(new WeChatMiniProgramSecurityConfigurer<>());
        return http.build();
    }

    /*
     * 例子使用的临时 Jwt 私钥，仅在当前进程有效，Springboot程序关闭将失去私钥
     */
    private final static Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    @Bean
    public WeChatMiniProgramSecurityProviderSettings weChatMiniProgramSecurityProviderSetting() {
        /*
         *  在开发设置页面查看AppID和AppSecret
         *  https://mp.weixin.qq.com/
         */
        return new WeChatMiniProgramSecurityProviderSettings()
                // todo 按需修改配置文件
                .appId("")  // 微信小程序 AppId
                .secret(""); // 微信小程序 Secret
    }

    @Bean
    public WeChatMiniProgramSecurityJwtSettings weChatMiniProgramSecurityJwtSettings() {
        return new WeChatMiniProgramSecurityJwtSettings()
                .issuer("http://example.com/")  // 设置 Jwt 发布者信息
                .privateKey(key);               // 设置 Jwt 签名私钥
    }


    /**
     * @return InMemoryWeChatUserDetailsManager
     * @see InMemoryWeChatUserDetailsManager
     */
    @Bean
    public UserDetailsManager userDetailsManager() {
        /* 微信用户信息服务，用户可自定义信息，可实现数据库存储用户信息
         * 继承 InMemoryWeChatUserDetailsManager，否则控制器无法获取用户信息
         * 不用也行，默认的 User 类也可以，Username是OpenId、Password就不用
         * 控制器就转成自己写的 UserDetails 就可以
         */
        return new InMemoryWeChatUserDetailsManager();
    }

}
