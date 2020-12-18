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

import mockit.Mock;
import mockit.MockUp;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.exception.PrivateKeyIllegalException;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CreateWeIdArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.RawTransactionService;
import com.webank.weid.service.impl.RawTransactionServiceImpl;
import com.webank.weid.service.impl.engine.BaseEngine;

/**
 * a parametric createWeId method for testing WeIdService.
 *
 * @author v_wbgyang
 */
public class TestCreateWeId2 extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestCreateWeId2.class);

    /**
     * case: create weid with param success.
     */
    @Test
    public void testCreateWeId_paramSucess() {
        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case: when createWeIdArgs is null,then return ILLEGAL_INPUT.
     */
    @Test
    public void testCreateWeId_weIdArgsIsNull() {
        CreateWeIdArgs createWeIdArgs = null;
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: when public key is wrong,then return WEID_PRIVATEKEY_INVALID.
     */
    @Test
    public void testCreateWeId_publicKeyIsW() {
        CreateWeIdArgs createWeIdArgs = new CreateWeIdArgs();
        createWeIdArgs.setPublicKey("019WEASDFE");
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: when publickey is digtal,then return WEID_PRIVATEKEY_INVALID.
     */
    @Test
    public void testCreateWeId_publicKeyIsDigtal() {
        CreateWeIdArgs createWeIdArgs = new CreateWeIdArgs();
        createWeIdArgs.setPublicKey("1234567493064");
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: when public key is start with ox,then return WEID_PRIVATEKEY_INVALID.
     */
    @Test
    public void testCreateWeId_publicKeyIsHex() {
        CreateWeIdArgs createWeIdArgs = new CreateWeIdArgs();
        createWeIdArgs.setPublicKey("0x11a3c3123");
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: when public key contain special char,then return WEID_PRIVATEKEY_INVALID.
     */
    @Test
    public void testCreateWeId_publicKeyContainSpecialChar() {
        CreateWeIdArgs createWeIdArgs = new CreateWeIdArgs();
        createWeIdArgs.setPublicKey("-~!@#$%^&.");
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: when public key contain zh,then return WEID_PRIVATEKEY_INVALID.
     */
    @Test
    public void testCreateWeId_publicKeyContainZh() {
        CreateWeIdArgs createWeIdArgs = new CreateWeIdArgs();
        createWeIdArgs.setPublicKey("我爱你中国");
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: when public key is too long ,then return WEID_PRIVATEKEY_INVALID.
     */
    @Test
    public void testCreateWeId_publicKeyIsTooLong() {
        CreateWeIdArgs createWeIdArgs = new CreateWeIdArgs();
        char[] chars = new char[100];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) i;
        }
        createWeIdArgs.setPublicKey(chars.toString());
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: publicKey is null.
     */
    @Test
    public void testCreateWeId_publicKeyIsNull() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        createWeIdArgs.setPublicKey(null);

        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PUBLICKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: publicKey is Non integer string.
     */
    @Test
    public void testCreateWeId_keyNotMatch() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        createWeIdArgs.setPublicKey("abc");

        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: when publicKey has been used,return WEID_ALREADY_EXIST.
     */
    @Test
    public void testCreateWeId_pubKeyUsed() {
        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        String publicKey = createWeIdArgs.getPublicKey();
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        createWeIdArgs.setPublicKey(publicKey);
        ResponseData<String> response1 = weIdService.createWeId(createWeIdArgs);
        Assert.assertEquals(ErrorCode.WEID_ALREADY_EXIST.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response1.getResult());
    }

    /**
     * case: when private key has been used,return WEID_ALREADY_EXIST.
     */
    @Test
    public void testCreateWeId_priKeyUsed() {
        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        CreateWeIdArgs createWeIdArgs1 = TestBaseUtil.buildCreateWeIdArgs();
        createWeIdArgs1.setWeIdPrivateKey(createWeIdArgs.getWeIdPrivateKey());

        ResponseData<String> response1 = weIdService.createWeId(createWeIdArgs1);
        Assert.assertEquals(ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response1.getResult());
    }

    /**
     * case: weIdPrivateKey is null.
     */
    @Test
    public void testCreateWeId_privateKeyIsNull() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        createWeIdArgs.setWeIdPrivateKey(null);

        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: weIdPrivateKey contains interer and string.
     */
    @Test
    public void testCreateWeId_privateKeyContainIntAndChar() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey("019WEASDFE");
        createWeIdArgs.setWeIdPrivateKey(weIdPrivateKey);
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: weIdPrivateKey contains interer and string.
     */
    @Test
    public void testCreateWeId_privateKeyIsInteger() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey("1234567493064");
        createWeIdArgs.setWeIdPrivateKey(weIdPrivateKey);
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: privateKey is null.
     */
    @Test
    public void testCreateWeId_setPrivateKeyNull() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        createWeIdArgs.getWeIdPrivateKey().setPrivateKey(null);

        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: privateKey is invalid.
     */
    @Test
    public void testCreateWeId_privateKeyIsInvaild() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        createWeIdArgs.getWeIdPrivateKey().setPrivateKey("xxxxxxxxxxxx");

        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: privateKey has been used.
     */
    @Test
    public void testCreateWeId_privateKeyIsExist() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        WeIdPrivateKey weIdPrivateKey = createWeIdArgs.getWeIdPrivateKey();
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());

        createWeIdArgs.setWeIdPrivateKey(weIdPrivateKey);
        ResponseData<String> response1 = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response1);
        Assert.assertEquals(ErrorCode.WEID_ALREADY_EXIST.getCode(),
            response1.getErrorCode().intValue());
    }

    /**
     * case: privateKey and publicKey misMatch.
     */
    @Test
    public void testCreateWeIdCase8() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();
        createWeIdArgs.setWeIdPrivateKey(passwordKey.getPrivateKey());

        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: call transactionhex null - arbitrary.
     */

    @Test
    public void testCreateWeIdCase7() {
        String hex = StringUtils.EMPTY;
        RawTransactionService rawTransactionService = new RawTransactionServiceImpl();
        ResponseData<String> response = rawTransactionService.createWeId(hex);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(StringUtils.isEmpty(response.getResult()));
    }

    /**
     * case: call transactionhex method - arbitrary.
     */
    @Test
    public void testCreateWeIdCase81() {
        String hex = "11111";
        RawTransactionService rawTransactionService = new RawTransactionServiceImpl();
        ResponseData<String> response = rawTransactionService.createWeId(hex);
        Assert.assertEquals(ErrorCode.TRANSACTION_EXECUTE_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(StringUtils.isEmpty(response.getResult()));
    }


    /**
     * case: Simulation throws an PrivateKeyIllegalException when calling the reloadContract
     * method.
     */
    @Test
    public void testCreateWeIdCase13() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();

        new MockUp<BaseEngine>() {
            @Mock
            public <T> T reloadContract(
                String contractAddress, 
                WeIdPrivateKey privateKey,
                Class<T> cls
            ) throws PrivateKeyIllegalException {
                throw new PrivateKeyIllegalException();
            }
        };

        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(StringUtils.EMPTY, response.getResult());
    }

    /**
     * case: create again.
     */
    @Test
    public void testCreateWeId_repeatCreate() {

        CreateWeIdArgs createWeIdArgs = TestBaseUtil.buildCreateWeIdArgs();
        ResponseData<String> response = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        ResponseData<String> response1 = weIdService.createWeId(createWeIdArgs);
        LogUtil.info(logger, "createWeId", response1);

        Assert.assertEquals(ErrorCode.WEID_ALREADY_EXIST.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertNotNull(response1.getResult());
    }
}
