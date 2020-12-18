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

package com.webank.weid.full.auth;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

/**
 * removeAuthorityIssuer method for testing AuthorityIssuerService.
 *
 * @author v_wbgyang/rockyxia
 */
public class TestRemoveAuthorityIssuer extends TestBaseService {

    private static final Logger logger =
        LoggerFactory.getLogger(TestRemoveAuthorityIssuer.class);

    /**
     * case: WeIdentity DID is invalid.
     */
    @Test
    public void testRemoveAuthorityIssuer_invalidWeId() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.setWeId("x123~-=><?:',bvhgf;,");

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is null.
     */
    @Test
    public void testRemoveAuthorityIssuer_weIdNull() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.setWeId(null);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is blank.
     */
    @Test
    public void testRemoveAuthorityIssuer_weIdBlank() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.setWeId("");

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is bad format.
     */
    @Test
    public void testRemoveAuthorityIssuer_weIdFormat() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.setWeId("di:weid:0x29f3fe8d4536966af41392f7ddc756b6f452df09");

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID contains zh.
     */
    @Test
    public void testRemoveAuthorityIssuer_weIdContainZh() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.setWeId("中国");

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is exist but toUpper.
     */
    @Test
    public void testRemoveAuthorityIssuer_weIdUpper() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.setWeId(createWeIdResult.getWeId().toUpperCase());

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is not exists.
     */
    @Test
    public void testRemoveAuthorityIssuer_weIdNotExist() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        String weId = createWeIdResult.getWeId();
        removeAuthorityIssuerArgs
            .setWeId(weId.replace(weId.substring(weId.length() - 4, weId.length()), "ffff"));

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: remove AuthorityIssuer repeat.
     */
    @Test
    public void testRemoveAuthorityIssuer_removeRepeat() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs = removeAuthoritySuccess();
        Assert.assertNotNull(removeAuthorityIssuerArgs);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: remove success.
     */
    @Test
    public void testRemoveAuthorityIssuer_success() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs = removeAuthoritySuccess();
        Assert.assertNotNull(removeAuthorityIssuerArgs);
    }

    private RemoveAuthorityIssuerArgs removeAuthoritySuccess() {
        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);

        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            String name = registerAuthorityIssuerArgs.getAuthorityIssuer().getName();
            registerAuthorityIssuerArgs.getAuthorityIssuer().setName(name + Math.random());
            response = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> response1 =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response1);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());
        Assert.assertEquals(true, response1.getResult());
        return removeAuthorityIssuerArgs;
    }

    /**
     * case: the WeIdentity DID is removed.
     */
    @Test
    public void testRemoveAuthorityIssuer_weIdIsRemoved() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs = removeAuthoritySuccess();

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: removeAuthorityIssuerArgs is null.
     */
    @Test
    public void testRemoveAuthorityIssuer_issuerArgsIsNull() {

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(null);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: weIdPrivateKey is null.
     */
    @Test
    public void testRemoveAuthorityIssuer_priKeyNull() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.setWeIdPrivateKey(null);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey is null.
     */
    @Test
    public void testRemoveAuthorityIssuer_setPriKeyNull() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey(null);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: weIdPrivateKey is blank.
     */
    @Test
    public void testRemoveAuthorityIssuer_priKeyBlank() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey("");
        removeAuthorityIssuerArgs.setWeIdPrivateKey(weIdPrivateKey);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey is invalid.
     */
    @Test
    public void testRemoveAuthorityIssuer_invalidPriKey() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        removeAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey("123~!@#$<>?-+sz中国");

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey is valid,but not the sdk admin.
     */
    @Test
    public void testRemoveAuthorityIssuer_noPermission() {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeIdResult, privateKey);
        WeIdPrivateKey badPrikey = TestBaseUtil.createEcKeyPair().getPrivateKey();
        removeAuthorityIssuerArgs.setWeIdPrivateKey(badPrikey);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey belongs to the private key of other WeIdentity DID.
     */
    @Test
    public void testRemoveAuthorityIssuerCase12() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> responseRegister = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);

        while (responseRegister.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            String name = registerAuthorityIssuerArgs.getAuthorityIssuer().getName();
            registerAuthorityIssuerArgs.getAuthorityIssuer().setName(name + Math.random());
            responseRegister = authorityIssuerService
                .registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", responseRegister);

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeId, privateKey);
        removeAuthorityIssuerArgs.setWeIdPrivateKey(createWeIdNew.getUserWeIdPrivateKey());

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey and private key of WeIdentity DID do not match.
     */
    @Test
    public void testRemoveAuthorityIssuerCase13() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> responseRegister = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);

        while (responseRegister.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            String name = registerAuthorityIssuerArgs.getAuthorityIssuer().getName();
            registerAuthorityIssuerArgs.getAuthorityIssuer().setName(name + Math.random());
            responseRegister = authorityIssuerService
                .registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", responseRegister);

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeId, privateKey);
        removeAuthorityIssuerArgs.setWeIdPrivateKey(TestBaseUtil.createEcKeyPair().getPrivateKey());

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }
}
