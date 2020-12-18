/*
 *       Copyright© (2018) WeBank Co., Ltd.
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

package com.webank.weid.full.weid;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.ServiceArgs;
import com.webank.weid.protocol.response.ResponseData;

/**
 * setService method for testing WeIdService.
 *
 * @author v_wbgyang
 */
public class TestSetService extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestSetService.class);

    @Override
    public synchronized void testInit() {
        super.testInit();
    }

    /**
     * case: set success.
     */
    @Test
    public void testSetService_sucess() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(createWeIdResult.getWeId(),
            setServiceArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: two services(type different) set success.
     */
    @Test
    public void testSetService_twoTypeDifferentServices() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        ResponseData<Boolean> response = weIdService.setService(createWeIdResult.getWeId(),
            setServiceArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        ServiceArgs setServiceArgs1 = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        setServiceArgs1.setType("1234");
        ResponseData<Boolean> response1 = weIdService.setService(createWeIdResult.getWeId(),
            setServiceArgs1, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response1);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());
        Assert.assertEquals(true, response1.getResult());

        ResponseData<WeIdDocument> weIdDoc =
            weIdService.getWeIdDocument(createWeIdResult.getWeId());
        LogUtil.info(logger, "setService", weIdDoc);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), weIdDoc.getErrorCode().intValue());
        Assert.assertEquals(2, weIdDoc.getResult().getService().size());


    }

    /**
     * case: two services(endpoint different) set success.
     */
    @Test
    public void testSetService_twoEndpointDifferentServices() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        ResponseData<Boolean> response = weIdService.setService(createWeIdResult.getWeId(),
            setServiceArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        ServiceArgs setServiceArgs1 = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        setServiceArgs1.setServiceEndpoint("http:test.com");
        ResponseData<Boolean> response1 = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs1,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response1);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());
        Assert.assertEquals(true, response1.getResult());

        ResponseData<WeIdDocument> weIdDoc =
            weIdService.getWeIdDocument(createWeIdResult.getWeId());
        LogUtil.info(logger, "setService", weIdDoc);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), weIdDoc.getErrorCode().intValue());
        Assert.assertEquals(2, weIdDoc.getResult().getService().size());
    }

    /**
     * case: WeIdentity DID is blank.
     */
    @Test
    public void testSetService_weIdIsNull() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(null, setServiceArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is bad format.
     */
    @Test
    public void testSetService_invalidWeId() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService("di:weid:0xsdg!@#$%^&《》",
            setServiceArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is not exists.
     */
    @Test
    public void testSetService_weIdNotExist() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(
            "did:weid:0xbbd97a63365b6c9fb6b011a8d294307a3b7dac7a",
            setServiceArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_DOES_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is too long.
     */
    @Test
    public void testSetService_weIdTooLong() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        char[] chars = new char[1000];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (i % 127);
        }
        String weId = String.valueOf(chars);
        weId = "did:weid:0xbbd97a63365b6c9fb6b011a8d294307a3b7dac7" + weId;
        ResponseData<Boolean> response = weIdService.setService(weId, setServiceArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: other WeIdentity DID.
     */
    @Test
    public void testSetService_otherWeId() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(createWeIdNew.getWeId(),
            setServiceArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: type is null.
     */
    @Test
    public void testSetService_typeNull() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        setServiceArgs.setType(null);

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: type contain interger special string.
     */
    @Test
    public void testSetService_typeIsAnyString() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        setServiceArgs.setType("x123!@#$%^&*()_+=-?><:;sdf");

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(
            ErrorCode.WEID_SERVICE_TYPE_OVERLIMIT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: type too long.
     */
    @Test
    public void testSetService_typeTooLong() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        setServiceArgs
            .setType("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_SERVICE_TYPE_OVERLIMIT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: serviceEndpoint is null.
     */
    @Test
    public void testSetService_endpointNull() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        setServiceArgs.setServiceEndpoint(null);

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: userWeIdPrivateKey is null.
     */
    @Test
    public void testSetService_priKeyNull() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            null);
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }


    /**
     * case: the private key belongs to other WeIdentity DID.
     */
    @Test
    public void testSetService_priKeyIsOtherWeid() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            createWeIdNew.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the private key does not match the current weId.
     */
    @Test
    public void testSetService_prikeyNotMatch() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            new WeIdPrivateKey("111111111"));
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey and privateKey of WeIdentity DID do not match.
     */
    @Test
    public void testSetServiceCase12() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);
        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(),
            setServiceArgs,
            passwordKey.getPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: setServiceArgs is null.
     */
    @Test
    public void testSetServiceCase17() {

        ResponseData<Boolean> response = weIdService.setService(createWeIdResult.getWeId(),
            null, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: private key is invalid.
     */
    @Test
    public void testSetServiceCase18() {

        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createWeIdResult);

        ResponseData<Boolean> response = weIdService.setService(
            createWeIdResult.getWeId(), setServiceArgs, new WeIdPrivateKey("xxxxxxx"));
        LogUtil.info(logger, "setService", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }
}
