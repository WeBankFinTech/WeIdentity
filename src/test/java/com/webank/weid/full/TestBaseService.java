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

package com.webank.weid.full;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.BaseTest;
import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.CredentialWrapper;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.request.AuthenticationArgs;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CreateCredentialArgs;
import com.webank.weid.protocol.request.CreateCredentialPojoArgs;
import com.webank.weid.protocol.request.CreateWeIdArgs;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.ServiceArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.util.CredentialUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * testing basic method classes.
 *
 * @author v_wbgyang
 */
public abstract class TestBaseService extends BaseTest {

    /**
     * log4j.
     */
    private static final Logger logger = LoggerFactory.getLogger(TestBaseService.class);

    /**
     * private key of authority membership list.
     */
    public static volatile List<String> issuerPrivateList = null;

    /**
     * whether to initialize authority list.
     */
    protected static volatile boolean isInitIssuer = false;

    /**
     * weId information required for use cases.
     */
    protected static volatile CreateWeIdDataResult createWeIdResult = null;

    /**
     * new weId information required for use cases.
     */
    protected static volatile CreateWeIdDataResult createWeIdNew = null;

    /**
     * weId information and set related attribute.
     */
    protected static volatile CreateWeIdDataResult createWeIdResultWithSetAttr = null;

    /**
     * parameters needed to create credentials.
     */
    protected static volatile CreateCredentialArgs createCredentialArgs = null;

    /**
     * parameters needed to create credentialPojos.
     */
    protected static volatile CreateCredentialPojoArgs<Map<String, Object>>
        createCredentialPojoArgs = null;

    /**
     * parameters needed to create credentialPojos.
     */
    protected static volatile CreateCredentialPojoArgs<Map<String, Object>>
        createCredentialPojoArgs1 = null;

    /**
     * parameters needed to create credentialPojos.
     */
    protected static volatile CreateCredentialPojoArgs<Map<String, Object>>
        createCredentialPojoArgs2 = null;

    /**
     * parameters needed to create credentialPojos.
     */
    protected static volatile CreateCredentialPojoArgs<Map<String, Object>>
        createCredentialPojoArgs3 = null;

    /**
     * parameters needed to create credentialPojos.
     */
    protected static volatile CreateCredentialPojoArgs<Map<String, Object>>
        createCredentialPojoArgs4 = null;

    /**
     * parameters needed to create credentialPojos.
     */
    protected static volatile CreateCredentialPojoArgs<Map<String, Object>>
        createCredentialPojoArgsNew = null;

    /**
     * CredentialPojo information required for use cases.  selectiveCredential.
     */
    protected static volatile CredentialPojo credentialPojo = null;

    /**
     * selectiveCredentialPojo information required for use cases.
     */
    protected static volatile CredentialPojo selectiveCredentialPojo = null;


    /**
     * parameters needed to register CPT.
     */
    protected static volatile CptMapArgs registerCptArgs = null;

    /**
     * parameters needed to register CPT.
     */
    protected static volatile CptMapArgs registerCptArgs1 = null;

    /**
     * parameters needed to register CPT.
     */
    protected static volatile CptMapArgs registerCptArgs2 = null;

    /**
     * parameters needed to register CPT.
     */
    protected static volatile CptMapArgs registerCptArgs3 = null;

    /**
     * parameters needed to register CPT.
     */
    protected static volatile CptMapArgs registerCptArgs4 = null;

    /**
     * CPT registration information.
     */
    protected static volatile CptBaseInfo cptBaseInfo = null;

    /**
     * CPT registration information.
     */
    protected static volatile CptBaseInfo cptBaseInfo1 = null;

    /**
     * CPT registration information.
     */
    protected static volatile CptBaseInfo cptBaseInfo2 = null;

    /**
     * CPT registration information.
     */
    protected static volatile CptBaseInfo cptBaseInfo3 = null;

    /**
     * CPT registration information.
     */
    protected static volatile CptBaseInfo cptBaseInfo4 = null;

    /**
     * initializing related services.
     */
    @Override
    public synchronized void testInit() {

        if (!isInitIssuer) {
            try {
                issuerPrivateList = new ArrayList<String>();
                issuerPrivateList.add(privateKey.getPrivateKey());
                initIssuer("org1.txt");
                isInitIssuer = true;
            } catch (Exception e) {
                logger.error("initIssuer error", e);
                Assert.assertTrue(false);
            }
        }

        if (createWeIdResult == null) {
            createWeIdResult = this.createWeId();
        }
        if (createWeIdResultWithSetAttr == null) {
            createWeIdResultWithSetAttr = this.createWeIdWithSetAttr();
        }
        if (createWeIdNew == null) {
            createWeIdNew = this.createWeId();
        }
        if (createCredentialArgs == null) {
            registerCptArgs = TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
            createCredentialArgs =
                TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
            cptBaseInfo = this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs);
            createCredentialArgs.setCptId(cptBaseInfo.getCptId());
        }
        if (createCredentialPojoArgs == null) {
            createCredentialPojoArgs =
                TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
            CptBaseInfo cptBaseInfo =
                this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs);
            createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        }
        if (createCredentialPojoArgsNew == null) {
            CptMapArgs registerCptArgs = TestBaseUtil.buildCptArgs(createWeIdNew);
            createCredentialPojoArgsNew =
                TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdNew);
            CptBaseInfo cptBaseInfo = this.registerCpt(createWeIdNew, registerCptArgs);
            createCredentialPojoArgsNew.setCptId(cptBaseInfo.getCptId());
        }
        if (credentialPojo == null) {
            credentialPojo = this.createCredentialPojo(createCredentialPojoArgs);
        }
        if (selectiveCredentialPojo == null) {
            selectiveCredentialPojo = this.createSelectiveCredentialPojo(credentialPojo);
        }
    }


    /**
     * test init for multilevel cpt.
     */
    public synchronized void testInit4MlCpt() {

        if (!isInitIssuer) {
            try {
                issuerPrivateList = new ArrayList<String>();
                issuerPrivateList.add(privateKey.getPrivateKey());
                initIssuer("org1.txt");
                //isInitIssuer = true;
            } catch (Exception e) {
                logger.error("initIssuer error", e);
                Assert.assertTrue(false);
            }
        }

        if (createWeIdResult == null) {
            createWeIdResult = this.createWeId();
        }
        if (createWeIdResultWithSetAttr == null) {
            createWeIdResultWithSetAttr = this.createWeIdWithSetAttr();
        }
        if (createWeIdNew == null) {
            createWeIdNew = this.createWeId();
        }
        if (createCredentialPojoArgs1 == null) {
            registerCptArgs1 = TestBaseUtil.buildCptArgs4MlCpt(createWeIdResultWithSetAttr);
            createCredentialPojoArgs1 =
                TestBaseUtil.buildCreateCredentialPojoArgs4MlCpt(createWeIdResultWithSetAttr);
            cptBaseInfo1 = this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs1);
            createCredentialPojoArgs1.setCptId(cptBaseInfo1.getCptId());
        }
    }


    /**
     * initializing related services,test init for multiple cpt.
     */
    public synchronized void testInit4MultiCpt() {

        if (!isInitIssuer) {
            try {
                issuerPrivateList = new ArrayList<String>();
                issuerPrivateList.add(privateKey.getPrivateKey());
                initIssuer("org1.txt");
            } catch (Exception e) {
                logger.error("initIssuer error", e);
                Assert.assertTrue(false);
            }
        }

        if (createWeIdResult == null) {
            createWeIdResult = this.createWeId();
        }
        if (createWeIdResultWithSetAttr == null) {
            createWeIdResultWithSetAttr = this.createWeIdWithSetAttr();
        }
        if (createWeIdNew == null) {
            createWeIdNew = this.createWeId();
        }
        if (createCredentialArgs == null) {
            registerCptArgs = TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
            createCredentialArgs =
                TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
            cptBaseInfo = this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs);
            createCredentialArgs.setCptId(cptBaseInfo.getCptId());
        }
        if (createCredentialPojoArgs2 == null) {
            registerCptArgs2 = TestBaseUtil.buildCptArgs4MlCpt(createWeIdResultWithSetAttr);
            createCredentialPojoArgs2 =
                TestBaseUtil.buildCreateCredentialPojoArgs4MlCpt(createWeIdResultWithSetAttr);
            cptBaseInfo2 = this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs2);
            createCredentialPojoArgs2.setCptId(cptBaseInfo2.getCptId());
        }
        //support multiple CPT
        if (createCredentialPojoArgs3 == null) {
            registerCptArgs3 = TestBaseUtil.buildCptArgs4MultiCpt(createWeIdResultWithSetAttr);
            createCredentialPojoArgs3 =
                TestBaseUtil
                    .buildCreateCredentialPojoArgs4MultiCpt(createWeIdResultWithSetAttr);
            cptBaseInfo3 = this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs3);
            createCredentialPojoArgs3.setCptId(cptBaseInfo3.getCptId());
        }
    }

    /**
     * test init for specify pdf template cpt.
     */
    public synchronized void testInitSpecTplCpt() {

        if (!isInitIssuer) {
            try {
                issuerPrivateList = new ArrayList<String>();
                issuerPrivateList.add(privateKey.getPrivateKey());
                initIssuer("org1.txt");
                //isInitIssuer = true;
            } catch (Exception e) {
                logger.error("initIssuer error", e);
                Assert.assertTrue(false);
            }
        }

        if (createWeIdResult == null) {
            createWeIdResult = this.createWeId();
        }
        if (createWeIdResultWithSetAttr == null) {
            createWeIdResultWithSetAttr = this.createWeIdWithSetAttr();
        }
        if (createWeIdNew == null) {
            createWeIdNew = this.createWeId();
        }
        if (createCredentialPojoArgs4 == null) {
            registerCptArgs4 = TestBaseUtil.buildCptArgs4SpecTplCpt(createWeIdResultWithSetAttr);
            createCredentialPojoArgs4 =
                TestBaseUtil.buildCreateCredentialPojoArgs4SpecTplCpt(createWeIdResultWithSetAttr);
            cptBaseInfo4 = this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs4);
            createCredentialPojoArgs4.setCptId(cptBaseInfo4.getCptId());
        }
    }

    /**
     * according to the analysis of the private key to create WeIdentity DID,and registered as an
     * authority, and its private key is recorded.
     *
     * @param fileName fileName
     */
    private void initIssuer(String fileName) {

        PasswordKey passwordKey = TestBaseUtil.resolvePk(fileName);
        WeIdPublicKey publicKey = passwordKey.getPublicKey();
        WeIdPrivateKey privateKey = passwordKey.getPrivateKey();

        CreateWeIdArgs createWeIdArgs1 = TestBaseUtil.buildCreateWeIdArgs();
        createWeIdArgs1.setPublicKey(publicKey.getPublicKey());
        createWeIdArgs1.setWeIdPrivateKey(privateKey);
        ResponseData<String> response1 = weIdService.createWeId(createWeIdArgs1);
        if (response1.getErrorCode().intValue() != ErrorCode.WEID_ALREADY_EXIST.getCode()
            && response1.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            Assert.assertTrue(false);
        }

        String weId = WeIdUtils.convertPublicKeyToWeId(publicKey);

        CreateWeIdDataResult createResult = new CreateWeIdDataResult();
        createResult.setWeId(weId);
        createResult.setUserWeIdPrivateKey(new WeIdPrivateKey());
        createResult.setUserWeIdPublicKey(new WeIdPublicKey());
        createResult.getUserWeIdPrivateKey().setPrivateKey(privateKey.getPrivateKey());
        createResult.getUserWeIdPublicKey().setPublicKey(publicKey.getPublicKey());

        this.setPublicKey(createResult, publicKey, createResult.getWeId());
        this.setAuthentication(createResult, publicKey, createResult.getWeId());

        CreateWeIdDataResult createWeId = new CreateWeIdDataResult();
        createWeId.setWeId(weId);

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs =
            TestBaseUtil.buildRegisterAuthorityIssuerArgs(createWeId, this.privateKey);
        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        /*if (response.getErrorCode()
            .intValue() != ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_ALREADY_EXIST.getCode()
            && response.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            Assert.assertTrue(false);
        }*/

        issuerPrivateList.add(privateKey.getPrivateKey());
        logger.info("initIssuer success");
    }

    /**
     * verifyCredential.
     *
     * @param credential credential
     */
    protected ResponseData<Boolean> verifyCredential(Credential credential) {

        ResponseData<Boolean> response = credentialService.verify(credential);
        return response;
    }

    /**
     * verifyCredentialPojo by issuer.
     *
     * @param credentialPojo credentialPojo
     */
    protected ResponseData<Boolean> verifyCredentialPojo(CredentialPojo credentialPojo) {

        ResponseData<Boolean> response = credentialPojoService.verify(
            credentialPojo.getIssuer(), credentialPojo);
        return response;
    }

    /**
     * verifyCredentialPojo by weidpublic.
     *
     * @param credentialPojo credentialPojo
     */
    protected ResponseData<Boolean> verifyCredentialPojo(
        WeIdPublicKey weIdPublicKey,
        CredentialPojo credentialPojo) {

        ResponseData<Boolean> response = credentialPojoService
            .verify(weIdPublicKey, credentialPojo);
        return response;
    }

    /**
     * createCredential.
     *
     * @param createCredentialArgs createCredentialArgs
     */
    protected CredentialWrapper createCredential(CreateCredentialArgs createCredentialArgs) {

        ResponseData<CredentialWrapper> response =
            credentialService.createCredential(createCredentialArgs);
        LogUtil.info(logger, "createCredential", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        return response.getResult();
    }

    /**
     * createCredentialPojo.
     */
    protected CredentialPojo createCredentialPojo(
        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs) {

        if (createCredentialPojoArgs == null) {
            CptMapArgs registerCptArgs = TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
            createCredentialPojoArgs =
                TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
            CptBaseInfo cptBaseInfo =
                this.registerCpt(createWeIdResultWithSetAttr, registerCptArgs);
            createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        }

        ResponseData<CredentialPojo> response = credentialPojoService
            .createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        return response.getResult();
    }

    /**
     * createSelectiveCredentialPojo.
     */
    protected CredentialPojo createSelectiveCredentialPojo(CredentialPojo credentialPojo) {

        ClaimPolicy claimPolicy = new ClaimPolicy();
        claimPolicy.setFieldsToBeDisclosed("{\"name\":1,\"gender\":0,\"age\":1,\"id\":1}");

        ResponseData<CredentialPojo> response =
            credentialPojoService.createSelectiveCredential(credentialPojo, claimPolicy);
        LogUtil.info(logger, "TestCreateSelectiveCredential", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        return response.getResult();
    }

    /**
     * cpt register.
     *
     * @param createWeId createWeId
     * @param registerCptArgs registerCptArgs
     */
    protected CptBaseInfo registerCpt(
        CreateWeIdDataResult createWeId,
        CptMapArgs registerCptArgs) {

        ResponseData<CptBaseInfo> response = cptService.registerCpt(registerCptArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        return response.getResult();
    }

    /**
     * cpt register.
     *
     * @param createWeId createWeId
     */
    protected CptBaseInfo registerCpt(CreateWeIdDataResult createWeId) {

        CptMapArgs registerCptArgs = TestBaseUtil.buildCptArgs(createWeId);

        CptBaseInfo cptBaseInfo = registerCpt(createWeId, registerCptArgs);

        return cptBaseInfo;
    }

    /**
     * create WeIdentity DID and registerAuthorityIssuer.
     *
     * @return CreateWeIdDataResult
     */
    protected CreateWeIdDataResult registerAuthorityIssuer() {

        CreateWeIdDataResult createWeId = this.createWeId();

        registerAuthorityIssuer(createWeId);

        return createWeId;
    }

    /**
     * registerAuthorityIssuer default.
     */
    protected void registerAuthorityIssuer(CreateWeIdDataResult createWeId) {

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
        logger.info("registerAuthorityIssuer result:");
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * register and return issuerType.
     */
    public String registerIssuerType(String issuerType) {

        WeIdAuthentication weIdAuthentication = TestBaseUtil
            .buildWeIdAuthentication(createWeIdNew);

        ResponseData<Boolean> response
            = authorityIssuerService.registerIssuerType(weIdAuthentication, issuerType);
        LogUtil.info(logger, "registerIssuerType", response);

        return issuerType;
    }

    /**
     * create WeIdentity DID and set Attribute default.
     *
     * @return CreateWeIdDataResult
     */
    protected CreateWeIdDataResult createWeIdWithSetAttr() {

        CreateWeIdDataResult createWeId = this.createWeId();

        this.setPublicKey(createWeId, createWeId.getUserWeIdPublicKey(),
            createWeId.getWeId());
        this.setAuthentication(createWeId, createWeId.getUserWeIdPublicKey(),
            createWeId.getWeId());
        this.setService(createWeId, TestData.SERVICE_TYPE, TestData.SERVICE_ENDPOINT);
        return createWeId;
    }

    /**
     * create WeIdentity DID without set Attribute default.
     *
     * @return CreateWeIdDataResult
     */
    protected CreateWeIdDataResult createWeId() {

        ResponseData<CreateWeIdDataResult> createWeIdDataResult = weIdService.createWeId();
        LogUtil.info(logger, "createWeId", createWeIdDataResult);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            createWeIdDataResult.getErrorCode().intValue());
        Assert.assertNotNull(createWeIdDataResult.getResult());

        return createWeIdDataResult.getResult();
    }

    /**
     * addPublicKey default.
     *
     * @param createResult createResult
     * @param publicKey publicKey
     * @param owner owner
     */
    protected void setPublicKey(
        CreateWeIdDataResult createResult,
        WeIdPublicKey publicKey,
        String owner) {

        // No longer required, since this will be automatically set now.

        // SetPublicKeyArgs setPublicKeyArgs = TestBaseUtil.buildSetPublicKeyArgs(createResult);
        // setPublicKeyArgs.setPublicKey(publicKey);
        // setPublicKeyArgs.setOwner(owner);

        // ResponseData<Integer> responseSetPub = weIdService.addPublicKey(setPublicKeyArgs);
        // LogUtil.info(logger, "addPublicKey", responseSetPub);

        // Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
        //     responseSetPub.getErrorCode().intValue());
        // Assert.assertNotEquals(0, responseSetPub.getResult().intValue());
    }

    /**
     * setService default.
     *
     * @param createResult createResult
     * @param serviceType serviceType
     * @param serviceEnpoint serviceEnpoint
     */
    protected void setService(
        CreateWeIdDataResult createResult,
        String serviceType,
        String serviceEnpoint) {

        // setService for this WeIdentity DID
        ServiceArgs setServiceArgs = TestBaseUtil.buildSetServiceArgs(createResult);
        setServiceArgs.setType(serviceType);
        setServiceArgs.setServiceEndpoint(serviceEnpoint);

        ResponseData<Boolean> responseSetSer = weIdService.setService(createResult.getWeId(),
            setServiceArgs, createResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setService", responseSetSer);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), responseSetSer.getErrorCode().intValue());
        Assert.assertEquals(true, responseSetSer.getResult());
    }

    /**
     * setAuthenticate default.
     *
     * @param createResult createResult
     * @param publicKey publicKey
     * @param owner owner
     */
    protected void setAuthentication(
        CreateWeIdDataResult createResult,
        WeIdPublicKey publicKey,
        String owner) {

        // setAuthenticate for this WeIdentity DID
        AuthenticationArgs setAuthenticationArgs =
            TestBaseUtil.buildSetAuthenticationArgs(createResult);
        setAuthenticationArgs.setOwner(owner);
        setAuthenticationArgs.setPublicKey(publicKey.getPublicKey());
        ResponseData<Boolean> responseSetAuth =
            weIdService.setAuthentication(createResult.getWeId(), setAuthenticationArgs,
                createResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "setAuthentication", responseSetAuth);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), responseSetAuth.getErrorCode().intValue());
        Assert.assertEquals(true, responseSetAuth.getResult());
    }

    protected CredentialPojo copyCredentialPojo(CredentialPojo credentialPojo) {
        return CredentialUtils.copyCredential(credentialPojo);
    }

    protected CreateWeIdDataResult copyCreateWeId(CreateWeIdDataResult createWeId) {
        CreateWeIdDataResult copyWeId = new CreateWeIdDataResult();
        copyWeId.setWeId(createWeId.getWeId());
        copyWeId.setUserWeIdPrivateKey(new WeIdPrivateKey());
        copyWeId.getUserWeIdPrivateKey()
            .setPrivateKey(createWeId.getUserWeIdPrivateKey().getPrivateKey());
        copyWeId.setUserWeIdPublicKey(new WeIdPublicKey());
        copyWeId.getUserWeIdPublicKey()
            .setPublicKey(createWeId.getUserWeIdPublicKey().getPublicKey());
        return copyWeId;
    }
}
