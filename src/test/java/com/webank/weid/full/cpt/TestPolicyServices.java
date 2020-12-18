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

package com.webank.weid.full.cpt;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import com.webank.weid.full.TestBaseService;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.PresentationPolicyE;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.util.DataToolUtils;

/**
 * Testing policy services related methods.
 *
 * @author chaoxinhu
 */

public class TestPolicyServices extends TestBaseService {

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (cptBaseInfo == null) {
            cptBaseInfo = super.registerCpt(createWeIdResultWithSetAttr);
        }
    }

    @Test
    public void happyPathPolicyAll() {
        WeIdAuthentication auth = new WeIdAuthentication();
        CreateWeIdDataResult cwdr = createWeIdWithSetAttr();
        auth.setWeId(cwdr.getWeId());
        auth.setWeIdPublicKeyId(cwdr.getUserWeIdPublicKey().getPublicKey() + "#keys-0");
        auth.setWeIdPrivateKey(cwdr.getUserWeIdPrivateKey());
        ClaimPolicy claimPolicy = new ClaimPolicy();
        claimPolicy.setFieldsToBeDisclosed("{\"name\":0,\"gender\":0,\"age\":0,\"id\":0}");
        Integer cptId = cptBaseInfo.getCptId();
        ResponseData<Integer> registerResp = policyService
            .registerClaimPolicy(cptId, claimPolicy.getFieldsToBeDisclosed(), auth);
        Assert.assertTrue(registerResp.getResult() > 0);
        registerResp = policyService
            .registerClaimPolicy(cptId, claimPolicy.getFieldsToBeDisclosed(), auth);
        Assert.assertTrue(registerResp.getResult() > 0);
        registerResp = policyService
            .registerClaimPolicy(cptId, claimPolicy.getFieldsToBeDisclosed(), auth);
        Assert.assertTrue(registerResp.getResult() > 0);
        ResponseData<List<Integer>> allPoliciesList = policyService
            .getAllClaimPolicies(0, 3);
        Assert.assertEquals(allPoliciesList.getResult().size(), 3);
        System.out.println(DataToolUtils.serialize(allPoliciesList.getResult()));
        ClaimPolicy claimPolicyFromChain = policyService.getClaimPolicy(registerResp.getResult())
            .getResult();
        Assert.assertFalse(StringUtils.isEmpty(claimPolicyFromChain.getFieldsToBeDisclosed()));
        System.out.println(claimPolicyFromChain.getFieldsToBeDisclosed());
        ResponseData<List<Integer>> getClaimFromCptResp = policyService
            .getClaimPoliciesFromCpt(cptId);
        Assert.assertTrue(getClaimFromCptResp.getResult().size() > 0);
        ResponseData<Integer> presentationResp = policyService
            .registerPresentationPolicy(getClaimFromCptResp.getResult(), auth);
        Assert.assertTrue(presentationResp.getResult() >= 0);
        ResponseData<PresentationPolicyE> getClaimFromPresResp = policyService
            .getPresentationPolicy(presentationResp.getResult());
        Assert.assertNotNull(getClaimFromPresResp.getResult());
        System.out.println(DataToolUtils.serialize(getClaimFromPresResp.getResult()));
    }
}
