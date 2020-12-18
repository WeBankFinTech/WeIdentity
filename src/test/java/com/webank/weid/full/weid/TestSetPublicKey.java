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

package com.webank.weid.full.weid;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.PublicKeyArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

/**
 * addPublicKey method for testing WeIdService.
 *
 * @author v_wbgyang
 */
public class TestSetPublicKey extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestSetPublicKey.class);

    /**
     * case: set one public key for authentication success.
     */
    @Test
    public void testSetPublicKey_oneAuthPubKeySuccess() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        setPublicKeyArgs.setPublicKey(TestBaseUtil.createEcKeyPair().getPublicKey().getPublicKey());
        ResponseData<Integer> response = weIdService.addPublicKey(
            createWeIdResult.getWeId(), setPublicKeyArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: WeIdentity DID is blank.
     */
    @Test
    public void testSetPublicKey_weIdIsNull() {
        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);

        ResponseData<Integer> response = weIdService.addPublicKey(
            null, setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: WeIdentity DID is bad format.
     */
    @Test
    public void testSetPublicKey_badFormat() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);

        ResponseData<Integer> response = weIdService.addPublicKey(
            "di:weid:0xbbd97a63365b6c9fb6b011a8d294307a3b7dac73", setPublicKeyArgs,
            createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: WeIdentity DID is not exists.
     */
    @Test
    public void testSetPublicKeyCase4() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);

        ResponseData<Integer> response = weIdService.addPublicKey("did:weid:0aaaaaaaaaaaa",
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: publicKey is a new key.
     */
    @Test
    public void testSetPublicKey_newKey() {
        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();
        setPublicKeyArgs.setPublicKey(passwordKey.getPublicKey().getPublicKey());

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: publicKey is null.
     */
    @Test
    public void testSetPublicKey_pubKeyIsNull() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        setPublicKeyArgs.setPublicKey(null);

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: publicKey contain specialChar.
     */
    @Test
    public void testSetPublicKey_pubKeyIsAnyString() {

        final CreateWeIdDataResult weId = super.createWeId();
        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(weId);
        setPublicKeyArgs.setPublicKey(" a!~@#$%^&*(123456789asfs ");

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: userWeIdPrivateKey is null.
     */
    @Test
    public void testSetPublicKey_privateKeyIsNull() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, null);
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: privateKey is invalid.
     */
    @Test
    public void testSetPublicKey_priKeyIsInvalid() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        setPublicKeyArgs.setPublicKey(TestBaseUtil.createEcKeyPair().getPublicKey().getPublicKey());
        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, new WeIdPrivateKey("xxx"));
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case: privateKey and privateKey of WeIdentity DID does not match.
     */
    @Test
    public void testSetPublicKey_priKeyNotMatch() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();
        setPublicKeyArgs.setPublicKey(passwordKey.getPublicKey().getPublicKey());

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, passwordKey.getPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: the private key belongs to the private key of other WeIdentity DID.
     */
    @Test
    public void testSetPublicKeyCase13() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        setPublicKeyArgs.setPublicKey(TestBaseUtil.createEcKeyPair().getPublicKey().getPublicKey());

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdNew.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: other WeIdentity DID.
     */
    @Test
    public void testSetPublicKeyCase14() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdNew.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: owner is the WeIdentity DID.
     */
    @Test
    public void testSetPublicKey_ownerIsWeId() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        setPublicKeyArgs.setPublicKey(TestBaseUtil.createEcKeyPair().getPublicKey().getPublicKey());
        setPublicKeyArgs.setOwner(createWeIdResult.getWeId());

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: owner is other WeIdentity DID.
     */
    @Test
    public void testSetPublicKey_ownerIsOtherWeId() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        setPublicKeyArgs.setPublicKey(TestBaseUtil.createEcKeyPair().getPublicKey().getPublicKey());
        setPublicKeyArgs.setOwner(createWeIdNew.getWeId());

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: owner is invalid.
     */
    @Test
    public void testSetPublicKey_ownerIsInvalid() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        setPublicKeyArgs.setOwner("xxxxxxxxxxxxxxxxx");

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: owner is invalid.
     */
    @Test
    public void testSetPublicKey_ownerIsTooLong() {

        PublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createWeIdResult);
        char[] chars = new char[1000];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (i % 127);
        }
        String owner = String.valueOf(chars);
        setPublicKeyArgs.setOwner(owner);
        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            setPublicKeyArgs, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }

    /**
     * case: setAuthenticationArgs is null.
     */
    @Test
    public void testSetPublicKeyCase21() {

        ResponseData<Integer> response = weIdService.addPublicKey(createWeIdResult.getWeId(),
            null, createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "addPublicKey", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(WeIdConstant.ADD_PUBKEY_FAILURE_CODE.intValue(),
            response.getResult().intValue());
    }
}
