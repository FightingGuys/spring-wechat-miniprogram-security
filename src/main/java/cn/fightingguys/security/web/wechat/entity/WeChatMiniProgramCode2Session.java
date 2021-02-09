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

import com.fasterxml.jackson.annotation.JsonProperty;

public class WeChatMiniProgramCode2Session {

    @JsonProperty("openid")
    private String openId;

    @JsonProperty("session_key")
    private String sessionKey;

    @JsonProperty("unionid")
    private String unionId;

    @JsonProperty("errcode")
    private int errCode;

    @JsonProperty("errmsg")
    private String errMsg;

    public String getOpenId() {
        return openId;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    public String getUnionId() {
        return unionId;
    }

    public int getErrCode() {
        return errCode;
    }

    public String getErrMsg() {
        return errMsg;
    }
}
