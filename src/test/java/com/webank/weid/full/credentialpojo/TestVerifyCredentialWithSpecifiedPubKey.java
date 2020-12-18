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

package com.webank.weid.full.credentialpojo;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.CredentialWrapper;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.request.CreateCredentialArgs;
import com.webank.weid.protocol.response.ResponseData;

/**
 * verifyCredentialWithSpecifiedPubKey method for testing CredentialService.
 *
 * @author v_wbgyang
 */
public class TestVerifyCredentialWithSpecifiedPubKey extends TestBaseService {

    private static final Logger logger =
        LoggerFactory.getLogger(TestVerifyCredentialWithSpecifiedPubKey.class);

    protected PasswordKey newPasswordKey = null;

    @Override
    public synchronized void testInit() {
        super.testInit();
        newPasswordKey = TestBaseUtil.createEcKeyPair();
    }

    /**
     * case: verifyCredentialWithSpecifiedPubKey success.
     */
    @Test
    public void testVerifyCredentialWithSpecifiedPubKeyCase1() {

        CreateCredentialArgs createCredentialArgs =
            TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
        createCredentialArgs.setCptId(cptBaseInfo.getCptId());

        createCredentialArgs.setWeIdPrivateKey(newPasswordKey.getPrivateKey());

        CredentialWrapper credentialWrapper = super.createCredential(createCredentialArgs);

        ResponseData<Boolean> response =
            credentialService.verifyCredentialWithSpecifiedPubKey(
                credentialWrapper, newPasswordKey.getPublicKey());
        LogUtil.info(logger, "verifyCredentialWithSpecifiedPubKey", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: verifyCredentialWithSpecifiedPubKey fail.
     */
    @Test
    public void testVerifyCredentialWithSpecifiedPubKeyCase2() {

        CreateCredentialArgs createCredentialArgs =
            TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
        createCredentialArgs.setCptId(cptBaseInfo.getCptId());

        createCredentialArgs.setWeIdPrivateKey(newPasswordKey.getPrivateKey());

        CredentialWrapper credentialWrapper = super.createCredential(createCredentialArgs);

        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();

        ResponseData<Boolean> response =
            credentialService.verifyCredentialWithSpecifiedPubKey(
                credentialWrapper, passwordKey.getPublicKey());
        LogUtil.info(logger, "verifyCredentialWithSpecifiedPubKey", response);

        Assert.assertTrue(ErrorCode.CREDENTIAL_SIGNATURE_BROKEN.getCode()
            == response.getErrorCode().intValue() || ErrorCode.CREDENTIAL_VERIFY_FAIL.getCode()
            == response.getErrorCode().intValue() || response.getErrorCode().intValue()
            == ErrorCode.CREDENTIAL_EXCEPTION_VERIFYSIGNATURE.getCode());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: verifyCredentialWithSpecifiedPubKey publicKey is null.
     */
    @Test
    public void testVerifyCredentialWithSpecifiedPubKeyCase3() {

        CreateCredentialArgs createCredentialArgs =
            TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
        createCredentialArgs.setCptId(cptBaseInfo.getCptId());

        createCredentialArgs.setWeIdPrivateKey(newPasswordKey.getPrivateKey());

        CredentialWrapper credentialWrapper = super.createCredential(createCredentialArgs);

        ResponseData<Boolean> response =
            credentialService.verifyCredentialWithSpecifiedPubKey(credentialWrapper, null);
        LogUtil.info(logger, "verifyCredentialWithSpecifiedPubKey", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: verifyCredentialArgs is null.
     */
    @Test
    public void testVerifyCredentialWithSpecifiedPubKeyCase4() {

        ResponseData<Boolean> response =
            credentialService.verifyCredentialWithSpecifiedPubKey(
                null, newPasswordKey.getPublicKey());
        LogUtil.info(logger, "verifyCredentialWithSpecifiedPubKey", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }


    /**
     * case: verifyCredentialWithSpecifiedPubKey publicKey is "xxxxxxxxxxxxx".
     */
    @Test
    public void testVerifyCredentialWithSpecifiedPubKeyCase7() {

        CreateCredentialArgs createCredentialArgs =
            TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
        createCredentialArgs.setCptId(cptBaseInfo.getCptId());

        createCredentialArgs.setWeIdPrivateKey(newPasswordKey.getPrivateKey());

        CredentialWrapper credentialWrapper = super.createCredential(createCredentialArgs);

        WeIdPublicKey weIdPublicKey = new WeIdPublicKey();
        weIdPublicKey.setPublicKey("xxxxxxxxxxxxx");

        ResponseData<Boolean> response =
            credentialService.verifyCredentialWithSpecifiedPubKey(credentialWrapper, weIdPublicKey);
        LogUtil.info(logger, "verifyCredentialWithSpecifiedPubKey", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_VERIFY_FAIL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }
}
