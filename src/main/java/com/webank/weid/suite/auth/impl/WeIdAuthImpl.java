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

package com.webank.weid.suite.auth.impl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.AmopMsgType;
import com.webank.weid.constant.DataDriverConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.protocol.amop.GetWeIdAuthArgs;
import com.webank.weid.protocol.amop.RequestVerifyChallengeArgs;
import com.webank.weid.protocol.base.Challenge;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.response.GetWeIdAuthResponse;
import com.webank.weid.protocol.response.RequestVerifyChallengeResponse;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.AmopService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.service.impl.AmopServiceImpl;
import com.webank.weid.service.impl.WeIdServiceImpl;
import com.webank.weid.service.impl.callback.RequestVerifyChallengeCallback;
import com.webank.weid.service.impl.callback.WeIdAuthAmopCallback;
import com.webank.weid.suite.api.persistence.inf.Persistence;
import com.webank.weid.suite.auth.inf.WeIdAuth;
import com.webank.weid.suite.auth.inf.WeIdAuthCallback;
import com.webank.weid.suite.auth.protocol.WeIdAuthObj;
import com.webank.weid.suite.persistence.mysql.driver.MysqlDriver;
import com.webank.weid.util.DataToolUtils;

/**
 * weIdAuth service.
 *
 * @author tonychen 2020年3月10日
 */
@Setter
@Getter
public class WeIdAuthImpl implements WeIdAuth {

    private static final Logger logger = LoggerFactory.getLogger(WeIdAuthImpl.class);

    /**
     * amop service instance.
     */
    private static AmopService amopService = new AmopServiceImpl();
    private static WeIdAuthCallback weIdAuthCallback;
    private static WeIdAuthAmopCallback weIdAuthAmopCallback = new WeIdAuthAmopCallback();
    private static RequestVerifyChallengeCallback VerifyChallengeCallback =
        new RequestVerifyChallengeCallback();

    private static Persistence dataDriver;
    /**
     * specify who has right to get weid auth.
     */
    private static List<String> whitelistWeId;

    static {
        amopService.registerCallback(
            AmopMsgType.GET_WEID_AUTH.getValue(),
            weIdAuthAmopCallback
        );
        amopService.registerCallback(AmopMsgType.REQUEST_VERIFY_CHALLENGE.getValue(),
            VerifyChallengeCallback);
    }

    private WeIdService weIdService = new WeIdServiceImpl();

    private static Persistence getDataDriver() {
        if (dataDriver == null) {
            dataDriver = new MysqlDriver();
        }
        return dataDriver;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.suite.auth.inf.WeIdAuth#createAuthenticatedChannel(java.lang.String,
     * com.webank.weid.protocol.base.WeIdAuthentication)
     */
    @Override
    public ResponseData<WeIdAuthObj> createAuthenticatedChannel(
        String toAmopId,
        WeIdAuthentication weIdAuthentication) {

        if (StringUtils.isBlank(toAmopId) || weIdAuthentication == null) {

            logger.error("[createAuthenticatedChannel] illegal input!");
            return new ResponseData<WeIdAuthObj>(null, ErrorCode.ILLEGAL_INPUT);
        }

        Challenge challenge = Challenge
            .create(String.valueOf(System.currentTimeMillis()), DataToolUtils.getRandomSalt());
        GetWeIdAuthArgs getWeIdAuthArgs = new GetWeIdAuthArgs();
        getWeIdAuthArgs.setChallenge(challenge);
        getWeIdAuthArgs.setWeId(weIdAuthentication.getWeId());
        //single auth
        getWeIdAuthArgs.setType(0);
        ResponseData<GetWeIdAuthResponse> weIdAuthObjResp = amopService
            .getWeIdAuth(toAmopId, getWeIdAuthArgs);
        Integer errCode = weIdAuthObjResp.getErrorCode();
        String errMsg = weIdAuthObjResp.getErrorMessage();
        if (errCode.intValue() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[createAuthenticatedChannel] get weid auth object failed. error code: {}, "
                    + "error message is:{}",
                errCode, errMsg);
            return new ResponseData<WeIdAuthObj>(null, ErrorCode.getTypeByErrorCode(errCode));
        }

        logger.info("[createAuthenticatedChannel] get weid auth object with success.");
        byte[] encryptData = weIdAuthObjResp.getResult().getData();
        //decrypt
        byte[] originalData = null;
        try {
            originalData = DataToolUtils
                .decrypt(encryptData, weIdAuthentication.getWeIdPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error(
                "[createAuthenticatedChannel] decrypt weid auth object failed.  "
                    + "error message is:{}",
                e);
            return new ResponseData<WeIdAuthObj>(null, ErrorCode.DECRYPT_DATA_FAILED);
        }
        String dataStr = DataToolUtils.byteToString(originalData);
        Map<String, Object> dataMap = DataToolUtils.deserialize(dataStr, HashMap.class);
        String weidAuth = (String) dataMap.get(ParamKeyConstant.WEID_AUTH_OBJ);
        WeIdAuthObj weIdAuthObj = DataToolUtils.deserialize(weidAuth, WeIdAuthObj.class);
        String challengeSignData = (String) dataMap.get(ParamKeyConstant.WEID_AUTH_SIGN_DATA);
        String rawData = challenge.toJson();
        ResponseData<WeIdDocument> weIdDoc = weIdService.getWeIdDocument(weIdAuthObj.getSelfWeId());
        Integer weidDocErrorCode = weIdDoc.getErrorCode();
        if (weidDocErrorCode != ErrorCode.SUCCESS.getCode()) {
            logger
                .error("[createMutualAuthenticatedChannel] get weid document failed,"
                        + " Error code:{}",
                    weidDocErrorCode);
            return new ResponseData<WeIdAuthObj>(null,
                ErrorCode.getTypeByErrorCode(weidDocErrorCode));
        }
        WeIdDocument weIdDocument = weIdDoc.getResult();
        ErrorCode verifyErrorCode = DataToolUtils
            .verifySecp256k1SignatureFromWeId(rawData, challengeSignData, weIdDocument, null);
        if (verifyErrorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<WeIdAuthObj>(null, verifyErrorCode);
        }
        return new ResponseData<WeIdAuthObj>(weIdAuthObj, ErrorCode.SUCCESS);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.suite.auth.inf.WeIdAuth#createMutualAuthenticatedChannel(
     * java.lang.String, com.webank.weid.protocol.base.WeIdAuthentication)
     */
    @Override
    public ResponseData<WeIdAuthObj> createMutualAuthenticatedChannel(
        String toOrgId,
        WeIdAuthentication weIdAuthentication) {

        //检查参数
        if (StringUtils.isBlank(toOrgId) || weIdAuthentication == null) {

            logger.error("[createMutualAuthenticatedChannel] illegal input!");
            return new ResponseData<WeIdAuthObj>(null, ErrorCode.ILLEGAL_INPUT);
        }

        //生成随机的challenge，发给对手方，进行challenge
        Challenge challenge = Challenge
            .create(String.valueOf(System.currentTimeMillis()), DataToolUtils.getRandomSalt());
        GetWeIdAuthArgs getWeIdAuthArgs = new GetWeIdAuthArgs();
        getWeIdAuthArgs.setChallenge(challenge);
        getWeIdAuthArgs.setWeId(weIdAuthentication.getWeId());
        //单向auth
        getWeIdAuthArgs.setType(1);
        ResponseData<GetWeIdAuthResponse> weIdAuthObjResp = amopService
            .getWeIdAuth(toOrgId, getWeIdAuthArgs);
        Integer errCode = weIdAuthObjResp.getErrorCode();
        String errMsg = weIdAuthObjResp.getErrorMessage();
        if (errCode.intValue() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[createMutualAuthenticatedChannel] get weid auth object failed. "
                    + "error code: {}, error message is:{}",
                errCode, errMsg);
            return new ResponseData<WeIdAuthObj>(null, ErrorCode.getTypeByErrorCode(errCode));
        }

        logger.info("[createMutualAuthenticatedChannel] get weid auth object with success.");

        //拿自己私钥解密对手方发来的auth相关的数据
        byte[] encryptData = weIdAuthObjResp.getResult().getData();
        //decrypt
        byte[] originalData = null;
        try {
            originalData = DataToolUtils
                .decrypt(encryptData, weIdAuthentication.getWeIdPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error("[createMutualAuthenticatedChannel] decrypt data failed, "
                + "message:{}", e);
            return new ResponseData<WeIdAuthObj>(null, ErrorCode.DECRYPT_DATA_FAILED);
        }
        String dataStr = DataToolUtils.byteToString(originalData);
        Map<String, Object> dataMap = DataToolUtils.deserialize(dataStr, HashMap.class);
        String weidAuth = (String) dataMap.get(ParamKeyConstant.WEID_AUTH_OBJ);
        WeIdAuthObj weIdAuthObj = DataToolUtils.deserialize(weidAuth, WeIdAuthObj.class);

        String challengeSignData = (String) dataMap.get(ParamKeyConstant.WEID_AUTH_SIGN_DATA);
        String rawData = challenge.toJson();
        ResponseData<WeIdDocument> weIdDoc = weIdService.getWeIdDocument(weIdAuthObj.getSelfWeId());
        Integer weidDocErrorCode = weIdDoc.getErrorCode();
        if (weidDocErrorCode != ErrorCode.SUCCESS.getCode()) {
            logger
                .error("[createMutualAuthenticatedChannel] get weid document failed, "
                        + "Error code:{}",
                    weidDocErrorCode);
            return new ResponseData<WeIdAuthObj>(null,
                ErrorCode.getTypeByErrorCode(weidDocErrorCode));
        }
        WeIdDocument weIdDocument = weIdDoc.getResult();

        //验证对手方对challenge的签名
        ErrorCode verifyErrorCode = DataToolUtils
            .verifySecp256k1SignatureFromWeId(rawData, challengeSignData, weIdDocument, null);
        if (verifyErrorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<WeIdAuthObj>(null, verifyErrorCode);
        }

        //双向auth，发起方也需要对对手方的challenge进行签名
        String challenge1 = (String) dataMap.get(ParamKeyConstant.WEID_AUTH_CHALLENGE);
        String signData = DataToolUtils.secp256k1Sign(
            challenge1, weIdAuthentication.getWeIdPrivateKey());
        RequestVerifyChallengeArgs verifyChallengeArgs = new RequestVerifyChallengeArgs();
        verifyChallengeArgs.setSignData(signData);
        verifyChallengeArgs.setChallenge(Challenge.fromJson(challenge1));
        verifyChallengeArgs.setChannelId(weIdAuthObj.getChannelId());
        ResponseData<RequestVerifyChallengeResponse> verifyResult = amopService
            .requestVerifyChallenge(toOrgId, verifyChallengeArgs);
        int code = verifyResult.getErrorCode();
        if (code != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[createMutualAuthenticatedChannel] request verify challenge signature "
                    + "failed, Error code:{}",
                code);
            return new ResponseData<WeIdAuthObj>(null, ErrorCode.getTypeByErrorCode(code));
        }

        //都认证完之后，则可以将WeIdAuthObj数据返回给调用方
        return new ResponseData<WeIdAuthObj>(weIdAuthObj, ErrorCode.SUCCESS);
    }


    /* (non-Javadoc)
     * @see com.webank.weid.suite.auth.inf.WeIdAuth#setWhiteList(java.util.List, java.util.List)
     */
    @Override
    public Integer setWhiteList(List<String> whiteWeIdlist) {

        if (whitelistWeId != null) {

            whitelistWeId = whiteWeIdlist;
        }
        return 0;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.suite.auth.inf.WeIdAuth#addWeIdAuthObj(
     * com.webank.weid.suite.auth.protocol.WeIdAuthObj)
     */
    @Override
    public Integer addWeIdAuthObj(WeIdAuthObj weIdAuthObj) {

        String weIdAuthData = DataToolUtils.serialize(weIdAuthObj);
        String channelId = weIdAuthObj.getChannelId();
        ResponseData<Integer> dbResp = getDataDriver().addOrUpdate(
            DataDriverConstant.DOMAIN_WEID_AUTH,
            channelId,
            weIdAuthData);
        Integer errorCode = dbResp.getErrorCode();
        if (errorCode != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[addWeIdAuthObj] save weIdAuthObj to db failed, channel id:{}, error code is {}",
                channelId,
                errorCode);
            return errorCode;
        }
        return ErrorCode.SUCCESS.getCode();
    }

    /* (non-Javadoc)
     * @see com.webank.weid.suite.auth.inf.WeIdAuth#getWeIdAuthObjByChannelId(java.lang.String)
     */
    @Override
    public WeIdAuthObj getWeIdAuthObjByChannelId(String channelId) {

        ResponseData<String> dbResp = getDataDriver().get(
            DataDriverConstant.DOMAIN_WEID_AUTH,
            channelId);
        Integer errorCode = dbResp.getErrorCode();
        if (errorCode != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[addWeIdAuthObj] get weIdAuthObj from db failed, channel id:{}, error code is {}",
                channelId,
                errorCode);
            return null;
        }
        String weIdAuthJson = dbResp.getResult();
        WeIdAuthObj weIdAuthObj = DataToolUtils.deserialize(weIdAuthJson, WeIdAuthObj.class);
        return weIdAuthObj;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.suite.auth.inf.WeIdAuth#registerCallBack(
     * com.webank.weid.suite.auth.inf.WeIdAuthCallback)
     */
    @Override
    public Integer registerCallBack(WeIdAuthCallback callback) {

        weIdAuthCallback = callback;
        return 0;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.suite.auth.inf.WeIdAuth#getCallBack()
     */
    @Override
    public WeIdAuthCallback getCallBack() {

        return weIdAuthCallback;
    }

}
