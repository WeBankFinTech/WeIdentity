/*
 *       Copyright© (2018-2019) WeBank Co., Ltd.
 *
 *       This file is part of weid-java-sdk.
 *
 *       weid-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weid-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weid-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.rpc.callback;

import java.util.HashMap;
import java.util.Map;

import org.fisco.bcos.sdk.amop.topic.AmopMsgIn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.AmopMsgType;
import com.webank.weid.protocol.amop.AmopRequestBody;
import com.webank.weid.util.DataToolUtils;

/**
 * Created by junqizhang on 08/07/2017.
 */
public class OnNotifyCallbackV2 
    extends org.fisco.bcos.sdk.amop.AmopCallback 
    implements RegistCallBack {

    private static final Logger logger = LoggerFactory.getLogger(OnNotifyCallbackV2.class);

    private Map<Integer, AmopCallback> amopCallBackMap = new HashMap<Integer, AmopCallback>();

    private AmopCallback defaultAmopCallBack = new AmopCallback();

    public void registAmopCallback(Integer msgType, AmopCallback routeCallBack) {
        amopCallBackMap.put(msgType, routeCallBack);
    }
    
    public AmopCallback getAmopCallback(Integer msgType) {
        return amopCallBackMap.get(msgType);
    }
    
    @Override
    public byte[] receiveAmopMsg(AmopMsgIn  amopMsgIn) {
        String content = new String(amopMsgIn.getContent());
        logger.info("received ChannelPush v2 msg : " + content);
        if (0 == amopCallBackMap.size()) {
            return "directRouteCallback is null on server side!".getBytes();
        }

        AmopRequestBody amopRequestBody =
            DataToolUtils.deserialize(content, AmopRequestBody.class);
        AmopMsgType msgType = amopRequestBody.getMsgType();
        AmopCallback amopCallBack = amopCallBackMap.get(msgType.getValue());
        if (amopCallBack == null) {
            amopCallBack = defaultAmopCallBack;
        }
        String messageBody = amopRequestBody.getMsgBody();
        String result = null;
        try {
            result = msgType.callOnPush(amopCallBack, amopMsgIn.getMessageID(), messageBody);
        } catch (Exception e) {
            logger.error("callOnPush error, please check the log.", e);
        }
        return result.getBytes();
    }
}
