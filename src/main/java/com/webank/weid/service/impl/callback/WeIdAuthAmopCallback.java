/*
 *       Copyright© (2018-2020) WeBank Co., Ltd.
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

package com.webank.weid.service.impl.callback;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.protocol.amop.GetWeIdAuthArgs;
import com.webank.weid.protocol.base.Challenge;
import com.webank.weid.protocol.base.PublicKeyProperty;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.response.GetWeIdAuthResponse;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.rpc.callback.AmopCallback;
import com.webank.weid.service.impl.WeIdServiceImpl;
import com.webank.weid.suite.auth.impl.WeIdAuthImpl;
import com.webank.weid.suite.auth.inf.WeIdAuth;
import com.webank.weid.suite.auth.protocol.WeIdAuthObj;
import com.webank.weid.util.DataToolUtils;


/**
 * amop callback for weIdAuth.
 * @author tonychen 2020年3月10日
 */
public class WeIdAuthAmopCallback extends AmopCallback {

    private static final Logger logger = LoggerFactory.getLogger(WeIdAuthAmopCallback.class);

    private WeIdService weIdService = new WeIdServiceImpl();

    private WeIdAuth weIdAuthService = new WeIdAuthImpl();


    /**
     * 默认获取weIdAuthObj回调.
     *
     * @param args 获取weIdAuthObj需要的参数
     * @return 返回weIdAuthObj的响应体
     */
    public GetWeIdAuthResponse onPush(GetWeIdAuthArgs args) {

        String fromWeId = args.getWeId();
        //call callback
        WeIdAuthentication weIdAuth = weIdAuthService.getCallBack().onChannelConnecting(fromWeId);
        GetWeIdAuthResponse result = new GetWeIdAuthResponse();

        //1. sign the data(challenge) with self private key to finish this challenge.
        Map<String, Object> dataMap = new HashMap<String, Object>();
        Challenge challenge = args.getChallenge();
        String rawData = challenge.toJson();
        String challengeSign = DataToolUtils.secp256k1Sign(rawData, weIdAuth.getWeIdPrivateKey());
        dataMap.put(ParamKeyConstant.WEID_AUTH_SIGN_DATA, challengeSign);

        ResponseData<WeIdDocument> weIdDocResp = weIdService.getWeIdDocument(fromWeId);
        if (weIdDocResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[WeIdAuthCallback->onPush] get weid document by weid ->{} failed.",
                fromWeId);
            result.setErrorCode(weIdDocResp.getErrorCode());
            result.setErrorMessage(weIdDocResp.getErrorMessage());
            return result;
        }
        WeIdDocument document = weIdDocResp.getResult();
        List<PublicKeyProperty> pubKeyList = document.getPublicKey();
        String pubKey = pubKeyList.get(0).getPublicKey();

        //2. generate a symmetricKey
        String symmetricKey = UUID.randomUUID().toString();
        String channelId = UUID.randomUUID().toString();
        WeIdAuthObj weIdAuthObj = new WeIdAuthObj();
        weIdAuthObj.setSymmetricKey(symmetricKey);
        weIdAuthObj.setCounterpartyWeId(fromWeId);
        weIdAuthObj.setSelfWeId(weIdAuth.getWeId());
        weIdAuthObj.setChannelId(channelId);

        Integer type = args.getType();
        //mutual
        if (type == 1) {
            Challenge challenge1 = Challenge.create(fromWeId, DataToolUtils.getRandomSalt());
            dataMap.put(ParamKeyConstant.WEID_AUTH_CHALLENGE, challenge1.toJson());
        }

        //将weidAuth对象缓存
        weIdAuthService.addWeIdAuthObj(weIdAuthObj);
        dataMap.put(ParamKeyConstant.WEID_AUTH_OBJ, DataToolUtils.serialize(weIdAuthObj));

        //3. use fromWeId's public key to encrypt data
        String data = DataToolUtils.serialize(dataMap);
        byte[] encryptData = null;
        try {
            encryptData = DataToolUtils.encrypt(data, pubKey);
        } catch (Exception e) {
            logger.error("[WeIdAuthCallback] encrypt data failed.{}", e);
            result.setErrorCode(ErrorCode.ENCRYPT_DATA_FAILED.getCode());
            result.setErrorMessage(ErrorCode.ENCRYPT_DATA_FAILED.getCodeDesc());
            return result;
        }
        result.setData(encryptData);

        //call callback
        result.setErrorCode(ErrorCode.SUCCESS.getCode());
        result.setErrorMessage(ErrorCode.SUCCESS.getCodeDesc());
        weIdAuthService.getCallBack().onChannelConnected(weIdAuthObj);
        return result;
    }


}
