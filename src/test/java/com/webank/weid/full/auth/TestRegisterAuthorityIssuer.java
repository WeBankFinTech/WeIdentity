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

package com.webank.weid.full.auth;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.RawTransactionService;
import com.webank.weid.service.impl.RawTransactionServiceImpl;
import com.webank.weid.util.DateUtils;

/**
 * registerAuthorityIssuer method for testing AuthorityIssuerService.
 *
 * @author v_wbgyang
 */
public class TestRegisterAuthorityIssuer extends TestBaseService {

    private static final Logger logger =
        LoggerFactory.getLogger(TestRegisterAuthorityIssuer.class);

    /**
     * case: WeIdentity DID is invalid.
     */
    @Test
    public void testRegisterAuthorityIssuer_invalidWeId() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setWeId("xxxxxxxxxxxxxxxx");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: WeIdentity DID is bad format.
     */
    @Test
    public void testRegisterAuthorityIssuer_weIdFormat() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setWeId("di:weid:0x29f3fe8d4536966af41392f7ddc756b6f452df02");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the WeIdentity DID address is not exists.
     */
    @Test
    public void testRegisterAuthorityIssuer_weIdNotExist() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setWeId("did:weid:0x29f3" + System.currentTimeMillis());

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the WeIdentity DID is null or "" or " ".
     */
    @Test
    public void testRegisterAuthorityIssuer_weIdNull() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setWeId(null);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the WeIdentity DID is null or "" or " ".
     */
    @Test
    public void testRegisterAuthorityIssuer_weIdBlank() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setWeId("");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the created  after now.
     */
    @Test
    public void testRegisterAuthorityIssuer_createFuture() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(super.createWeId(), privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setCreated(DateUtils.getNoMillisecondTimeStamp() + 4000);

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
    }

    /**
     * case: the created before now .
     */
    @Test
    public void testRegisterAuthorityIssuer_createPassed() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setCreated(DateUtils.getNoMillisecondTimeStamp() - 4000);

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
    }

    /**
     * case: the created  is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_createNull() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setCreated(null);

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
    }

    /**
     * case: the created  is 19600101.
     */
    @Test
    public void testRegisterAuthorityIssuer_create19600101() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setCreated(-19600101L);
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
    }

    /**
     * case: the accValue is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_accValueNull() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setAccValue(null);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the accValue is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_accValueBlank() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setAccValue("");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the accValue is any spec.
     */
    @Test
    public void testRegisterAuthorityIssuer_accValueSpecialChar() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setAccValue("adssdf");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the accValue is any spec.
     */
    @Test
    public void testRegisterAuthorityIssuer_accValueIsInteger() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(super.createWeId(), privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setAccValue("123456789");

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);

        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            String name = registerAuthorityIssuerArgs.getAuthorityIssuer().getName();
            registerAuthorityIssuerArgs.getAuthorityIssuer().setName(name + Math.random());
            response = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: the accValue is any spec.
     */
    @Test
    public void testRegisterAuthorityIssuer_accValueIsFloat() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setAccValue("123456789.2");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * Happy path: register full authority issuer info.
     */
    @Test
    public void testRegisterAuthorityIssuer_FullInfo() {
        CreateWeIdDataResult createWeIdDataResult = createWeIdWithSetAttr();
        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdDataResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setName("temp" + Math.random());
        String desc = "WB1";
        registerAuthorityIssuerArgs.getAuthorityIssuer().setDescription(desc);
        List<String> extraStr = new ArrayList<>();
        extraStr.add("temp");
        extraStr.add("test");
        registerAuthorityIssuerArgs.getAuthorityIssuer().setExtraStr32(extraStr);
        List<Integer> extraInt = new ArrayList<>();
        extraInt.add(123);
        extraInt.add(234);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setExtraInt(extraInt);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        Assert.assertEquals(true, response.getResult());

        ResponseData<AuthorityIssuer> queryResp =
            authorityIssuerService.queryAuthorityIssuerInfo(createWeIdDataResult.getWeId());
        Assert.assertEquals(queryResp.getResult().getDescription(), desc);
        Assert.assertEquals(queryResp.getResult().getExtraStr32(), extraStr);
        Assert.assertEquals(queryResp.getResult().getExtraInt(), extraInt);
    }

    /**
     * Register authority issuer info with erroneous params.
     */
    @Test
    public void testRegisterAuthorityIssuer_ErroneousInfo() {
        CreateWeIdDataResult createWeIdDataResult = createWeIdWithSetAttr();
        RegisterAuthorityIssuerArgs arg =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdDataResult, privateKey);
        arg.getAuthorityIssuer().setName("temp" + Math.random());
        String desc = "WB1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        arg.getAuthorityIssuer().setDescription(desc);
        Assert.assertFalse(authorityIssuerService.registerAuthorityIssuer(arg).getResult());

        desc = "WB1";
        arg.getAuthorityIssuer().setDescription(desc);
        List<String> extraStr = new ArrayList<>();
        extraStr.add("temp");
        extraStr.add("WB1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        arg.getAuthorityIssuer().setExtraStr32(extraStr);
        Assert.assertFalse(authorityIssuerService.registerAuthorityIssuer(arg).getResult());

        extraStr = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            extraStr.add("temp");
        }
        arg.getAuthorityIssuer().setExtraStr32(extraStr);
        Assert.assertFalse(authorityIssuerService.registerAuthorityIssuer(arg).getResult());

        arg.getAuthorityIssuer().setExtraStr32(new ArrayList<>());
        List<Integer> extraInt = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            extraInt.add(123);
        }
        arg.getAuthorityIssuer().setExtraInt(extraInt);
        Assert.assertFalse(authorityIssuerService.registerAuthorityIssuer(arg).getResult());
    }

    /**
     * case: the accValue is any spec.
     */
    @Test
    public void testRegisterAuthorityIssuer_accValueIsNegInteger() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setAccValue("-123456");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: no acc value.
     */
    @Test
    public void testRegisterAuthorityIssuer_noAccValue() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);

        AuthorityIssuer authorityIssuer = new AuthorityIssuer();
        authorityIssuer.setWeId(registerAuthorityIssuerArgs.getAuthorityIssuer().getWeId());
        authorityIssuer.setName("hk123");
        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs1 =
            new RegisterAuthorityIssuerArgs();
        registerAuthorityIssuerArgs1
            .setAuthorityIssuer(authorityIssuer);
        registerAuthorityIssuerArgs1
            .setWeIdPrivateKey(registerAuthorityIssuerArgs.getWeIdPrivateKey());
        ResponseData<Boolean> response1 =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs1);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(false, response1.getResult());
    }

    /**
     * case: registerAuthorityIssuer success.
     */

    @Test
    public void testRegisterAuthorityIssuer_weIdUpper() {

        CreateWeIdDataResult createWeId = super.createWeId();
        createWeId.setWeId(createWeId.getWeId().toUpperCase());

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

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }


    /**
     * case: registerAuthorityIssuer with Chinese Name (utf-8).
     */
    @Test
    public void testRegisterAuthorityIssuerChineseName() {

        final CreateWeIdDataResult weId = super.createWeId();
        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(weId, privateKey);

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);

        String chiName = null;
        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            chiName = "中文" + DateUtils.getCurrentTimeStampString();
            registerAuthorityIssuerArgs.getAuthorityIssuer().setName(chiName);
            response = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        ResponseData<AuthorityIssuer> queryResponse = authorityIssuerService
            .queryAuthorityIssuerInfo(weId.getWeId());
        Assert.assertTrue(queryResponse.getResult().getName().equalsIgnoreCase(chiName));
        ResponseData<String> weIdresp = authorityIssuerService.getWeIdByOrgId(chiName);
        Assert.assertTrue(weIdresp.getResult().equalsIgnoreCase(weId.getWeId()));
    }

    /**
     * case: registerAuthorityIssuer success.
     */
    @Test
    public void testRegisterAuthorityIssuer_weIdTooLong() {

        CreateWeIdDataResult createWeId = super.createWeId();
        char[] chars = new char[1000];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (i % 127);
        }
        String weId = String.valueOf(chars);
        createWeId.setWeId(weId);

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

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the WeIdentity DID is registed.
     */
    @Test
    public void testRegisterAuthorityIssuer_repeat() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(super.createWeId(), privateKey);

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

        ResponseData<Boolean> response1 =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response1);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_ALREADY_EXIST.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(false, response1.getResult());
    }

    /**
     * case: the WeIdentity DID has been registed,issuer name is different.
     */
    @Test
    public void testRegisterAuthorityIssuer_weIdHasRegister() {

        final CreateWeIdDataResult weId = super.createWeId();
        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(weId, privateKey);

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

        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setName("weId 已经被注册" + (int)(Math.random() * 10000));
        ResponseData<Boolean> response1 =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response1);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_ALREADY_EXIST.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(false, response1.getResult());
    }

    /**
     * case: registerAuthorityIssuerArgs is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_argsNull() {
        RegisterAuthorityIssuerArgs args = new RegisterAuthorityIssuerArgs();
        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(args);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: authorityIssuer is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_authorityIssuerNull() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.setAuthorityIssuer(null);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: weIdPrivateKey is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_priKeyNull() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.setWeIdPrivateKey(null);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_setPriKeyNull() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey(null);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey is blank.
     */
    @Test
    public void testRegisterAuthorityIssuer_setPriKeyBlank() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey("");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey is invalid.
     * TODO RegisterAuthorityIssuerArgs里面最好放WeIdAuthentication
     */
    @Test
    public void testRegisterAuthorityIssuer_invalidPrikey() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey("xxxxxxx");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey is valid but is a random integer.
     */
    public void testRegisterAuthorityIssuer_prikeyIsInteger() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey("123456789");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: privateKey belongs to the private key of other WeIdentity DID.
     */
    public void testRegisterAuthorityIssuer_otherPrivateKey() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);
        registerAuthorityIssuerArgs.setWeIdPrivateKey(createWeIdNew.getUserWeIdPrivateKey());

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: the private key is the private key of the members of the committee.
     */
    @Test
    public void testRegisterAuthorityIssuerCase17() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer().setName(
            String.valueOf(System.currentTimeMillis()));
        registerAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey(issuerPrivateList.get(1));

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: authorityIssuer.name is already exist.
     */
    @Test
    public void testRegisterAuthorityIssuer_issuerNameOnly() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);
        String name = null;
        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            name = registerAuthorityIssuerArgs.getAuthorityIssuer().getName();
            registerAuthorityIssuerArgs.getAuthorityIssuer().setName(name + Math.random());
            response = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs1
            = TestBaseUtil.buildRegisterAuthorityIssuerArgs(super.createWeId(), privateKey);
        registerAuthorityIssuerArgs1.getAuthorityIssuer().setName(
            registerAuthorityIssuerArgs.getAuthorityIssuer().getName());
        ResponseData<Boolean> response1
            = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs1);

        Assert.assertNotEquals(registerAuthorityIssuerArgs.getAuthorityIssuer().getWeId(),
            registerAuthorityIssuerArgs1.getAuthorityIssuer().getWeId());
        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(false, response1.getResult());

    }

    /**
     * one WeId can not register one more AuthorityIssuer with diferent name.
     */
    @Test
    public void testRegisterAuthorityIssuer_registerIssers() {

        CreateWeIdDataResult createWeId = super.createWeId();

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);
        String name = null;
        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            name = registerAuthorityIssuerArgs.getAuthorityIssuer().getName();
            registerAuthorityIssuerArgs.getAuthorityIssuer().setName(name + Math.random());
            name = registerAuthorityIssuerArgs.getAuthorityIssuer().getName();
            response = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        AuthorityIssuer authorityIssuer = new AuthorityIssuer();
        authorityIssuer.setWeId(registerAuthorityIssuerArgs.getAuthorityIssuer().getWeId());
        authorityIssuer.setName(name + 1);
        authorityIssuer.setAccValue("0");
        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs1
            = new RegisterAuthorityIssuerArgs();
        registerAuthorityIssuerArgs1.setAuthorityIssuer(authorityIssuer);
        registerAuthorityIssuerArgs1
            .setWeIdPrivateKey(registerAuthorityIssuerArgs.getWeIdPrivateKey());
        ResponseData<Boolean> response1 = authorityIssuerService
            .registerAuthorityIssuer(registerAuthorityIssuerArgs1);

        Assert.assertEquals(registerAuthorityIssuerArgs.getAuthorityIssuer().getWeId(),
            registerAuthorityIssuerArgs1.getAuthorityIssuer().getWeId());
        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_ALREADY_EXIST.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(false, response1.getResult());

    }

    /**
     * one WeId can not register one more AuthorityIssuer with diferent name.
     */
    @Test
    public void testRegisterAuthorityIssuer_noIssuerName() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);

        AuthorityIssuer authorityIssuer = new AuthorityIssuer();
        authorityIssuer.setWeId(registerAuthorityIssuerArgs.getAuthorityIssuer().getWeId());
        authorityIssuer.setAccValue("0");
        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs1
            = new RegisterAuthorityIssuerArgs();
        registerAuthorityIssuerArgs1.setAuthorityIssuer(authorityIssuer);
        registerAuthorityIssuerArgs1
            .setWeIdPrivateKey(registerAuthorityIssuerArgs.getWeIdPrivateKey());
        ResponseData<Boolean> response1 = authorityIssuerService
            .registerAuthorityIssuer(registerAuthorityIssuerArgs1);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(false, response1.getResult());

    }

    /**
     * case: authorityIssuer.name is digtal.
     */
    @Test
    public void testRegisterAuthorityIssuer_issuerNameIsDigtal() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(super.createWeId(), privateKey);

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);
        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            registerAuthorityIssuerArgs.getAuthorityIssuer()
                .setName("12435367890" + Math.random() * 10);
            response =
                authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }

        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: authorityIssuer.name is too long.
     */
    @Test
    public void testRegisterAuthorityIssuer_issuerTooLong() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setName("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: authorityIssuer.name contain zh.
     */
    @Test
    public void testRegisterAuthorityIssuer_issuerNameContainZh() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(super.createWeId(), privateKey);

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);

        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            registerAuthorityIssuerArgs.getAuthorityIssuer()
                .setName("公安行政系统" + (int)(Math.random() * 10000));
            response = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: authorityIssuer.name is null.
     */
    @Test
    public void testRegisterAuthorityIssuer_issuerNameNull() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setName(null);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: authorityIssuer.name is blank.
     */
    @Test
    public void testRegisterAuthorityIssuer_issuerNameBlank() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeIdResult, privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setName("");

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: authorityIssuer.name contains Special character.
     */
    @Test
    public void testRegisterAuthorityIssuer_issuerNameContainsSpecialChar() {

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(super.createWeId(), privateKey);

        ResponseData<Boolean> response = new ResponseData<>(false,
            ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS);

        while (response.getErrorCode()
            == ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NAME_ALREADY_EXISTS.getCode()) {
            registerAuthorityIssuerArgs.getAuthorityIssuer()
                .setName("！@#￥%……&*-+<>?x" + (int)(Math.random() * 1000));
            response = authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        }
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: call transactionhex null - arbitrary.
     */
    @Test
    public void testRegisterAuthorityIssuerCase22() {
        String hex = StringUtils.EMPTY;
        RawTransactionService rawTransactionService = new RawTransactionServiceImpl();
        ResponseData<String> response = rawTransactionService.registerAuthorityIssuer(hex);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(StringUtils.isEmpty(response.getResult()));
    }

    /**
     * case: call transactionhex method - arbitrary.
     */
    @Test
    public void testRegisterAuthorityIssuerCase23() {
        String hex = "11111";
        RawTransactionService rawTransactionService = new RawTransactionServiceImpl();
        ResponseData<String> response = rawTransactionService.registerAuthorityIssuer(hex);
        Assert.assertEquals(ErrorCode.TRANSACTION_EXECUTE_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(StringUtils.isEmpty(response.getResult()));
    }
}
