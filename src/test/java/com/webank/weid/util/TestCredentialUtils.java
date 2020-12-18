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

package com.webank.weid.util;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import com.webank.weid.constant.CredentialConstant.CredentialProofType;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CreateCredentialArgs;

/**
 * test crentialUtils.
 *
 * @author v_wbjnzhang
 */
public class TestCredentialUtils {

    @Test
    public void getCredentialFieldsTest() {

        // test arg is null
        Map<String, Object> map = new HashMap<>();
        String result = CredentialUtils.getCredentialThumbprintWithoutSig(null, map);
        Assert.assertEquals(result, "");
    }

    @Test
    public void extractCredentialMetadataTest() {

        CreateCredentialArgs result = CredentialUtils.extractCredentialMetadata(null);
        Assert.assertNull(result);

        Credential arg = new Credential();
        result = CredentialUtils.extractCredentialMetadata(arg);
        Assert.assertNotNull(result);

        arg.setContext(CredentialUtils.getDefaultCredentialContext());
        arg.setId(UUID.randomUUID().toString());
        arg.setCptId(14356);
        arg.setIssuer("gdsgshher");
        arg.setExpirationDate(Long.valueOf(System.currentTimeMillis()));
        arg.setIssuanceDate(Long.valueOf(System.currentTimeMillis()));
        Assert.assertNotEquals(CredentialUtils.isCredentialValid(arg), ErrorCode.SUCCESS);
        arg.setExpirationDate(Long.valueOf(System.currentTimeMillis()) + new Long(1000));
        arg.setIssuanceDate(Long.valueOf(System.currentTimeMillis()));
        Assert.assertNotEquals(CredentialUtils.isCredentialValid(arg), ErrorCode.SUCCESS);
        LinkedHashMap<String, Object> claim = new LinkedHashMap<>();
        claim.put("sfsfs", "sfsfs");
        claim.put("SampleAttrib", 10);
        arg.setClaim(claim);
        Map<String, String> proof = new HashMap<>();
        proof.put(ParamKeyConstant.PROOF_CREATOR, arg.getIssuer());
        proof.put(ParamKeyConstant.PROOF_CREATED, arg.getIssuanceDate().toString());
        proof.put(ParamKeyConstant.PROOF_TYPE, CredentialProofType.ECDSA.getTypeName());
        proof.put(ParamKeyConstant.CREDENTIAL_SIGNATURE, "xxxxxxxxxxx");
        arg.setProof(proof);
        String privateKey =
            "58317564669857453586637110679746575832914889677346283755719850144028639639651";
        Assert.assertNotNull(CredentialUtils.getCredentialSignature(
            arg, new WeIdPrivateKey(privateKey), null));
        String fh = CredentialUtils.getFieldHash(arg);
        Assert.assertNotNull(fh);
        result = CredentialUtils.extractCredentialMetadata(arg);
        Assert.assertNotEquals(CredentialUtils.isCredentialValid(arg), ErrorCode.SUCCESS);
        Assert.assertNotNull(CredentialUtils.isCreateCredentialArgsValid(result));
        Assert.assertTrue(CredentialUtils.isValidUuid(arg.getId()));
        Assert.assertNotNull(CredentialUtils.convertCredentialIdToBytes32(arg.getId()));
        Assert.assertNotNull(CredentialUtils.convertCredentialIdToBytes32(StringUtils.EMPTY));
        Assert.assertNotNull(CredentialUtils.extractCredentialMetadata(arg));
        Assert.assertNotNull(CredentialUtils.getClaimHash(arg, null));
        Assert.assertNotNull(result);
        String thumbprint = CredentialUtils.getCredentialThumbprint(arg, null);
        Assert.assertNotNull(thumbprint);
        String thumbprintAll = CredentialUtils.getCredentialThumbprintWithoutSig(arg, null);
        Assert.assertNotNull(thumbprintAll);
        Credential test = CredentialUtils.copyCredential(arg);
        Assert.assertTrue(CredentialUtils.isEqual(arg, test));
    }
}
