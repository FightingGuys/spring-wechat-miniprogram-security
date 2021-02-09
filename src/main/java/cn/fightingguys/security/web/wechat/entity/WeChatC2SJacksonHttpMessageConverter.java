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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

import java.util.Arrays;

/* Fix WeChat Code2Session Server Response Context-Type Bug */
public class WeChatC2SJacksonHttpMessageConverter extends MappingJackson2HttpMessageConverter {

    public WeChatC2SJacksonHttpMessageConverter() {
        this(Jackson2ObjectMapperBuilder.json().build());
    }

    public WeChatC2SJacksonHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
        super.setSupportedMediaTypes(Arrays.asList(MediaType.TEXT_PLAIN, MediaType.APPLICATION_JSON));
    }

}
