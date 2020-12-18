package com.webank.weid.full.auth;

import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;


public class TestGetAllAuthorityIssuerList extends TestBaseService {

    private static final Logger logger =
        LoggerFactory.getLogger(TestGetAllAuthorityIssuerList.class);

    private static CreateWeIdDataResult createWeId;

    @Override
    public synchronized void testInit()  {

        super.testInit();
        if (createWeId == null) {
            createWeId = super.registerAuthorityIssuer();
        }
    }

    /**
     * case:get all authority issuer list.
     */

    @Test
    public void testGetAllAuthorityIssuerList_success() {

        ResponseData<List<AuthorityIssuer>> response1 =
            authorityIssuerService.getAllAuthorityIssuerList(0, 2);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response1);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());
        Assert.assertNotNull(response1.getResult());
    }

    /**
     * case:get all authority issuer list that index is minus.
     */

    @Test
    public void testGetAllAuthorityIssuerList_indexIsMinus() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(-1, 2);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());

    }

    /**
     * case:get all authority issuer list that num is minus.
     */
    @Test
    public void testGetAllAuthorityIssuerList_numIsMinus() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(0, -1);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());

    }

    /**
     * case:get all authority issuer list that num is zero.
     */
    @Test
    public void testGetAllAuthorityIssuerList_numIsZero() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(0, 0);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case:get all authority issuer list that num is zero.
     */
    @Test
    public void testGetAllAuthorityIssuerList_indexBigNum() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(999, 9);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertTrue(CollectionUtils.isEmpty(response.getResult()));
    }


    /**
     * case:get all authority issuer list that index=0 and num=99.
     */
    @Test
    public void testGetAllAuthorityIssuerList_bigNum() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(0, 99);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case:get all authority issuer list that index=0 and num=99.
     */
    @Test
    public void testGetAllAuthorityIssuerList_biggestNum() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(0, 50);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case:get all authority issuer list that index=0 and num=99.
     */
    @Test
    public void testGetAllAuthorityIssuerList_removeListThenQuery() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(0, 5);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        List<AuthorityIssuer> authorityIssuers = response.getResult();

        for (int i = 0; i < authorityIssuers.size(); i++) {
            String weId = authorityIssuers.get(i).getWeId();
            if (!weId.equals(createWeId.getWeId())) {
                RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
                    new RemoveAuthorityIssuerArgs();
                removeAuthorityIssuerArgs.setWeId(weId);
                removeAuthorityIssuerArgs.setWeIdPrivateKey(privateKey);
                authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
                ResponseData<AuthorityIssuer> info
                    = authorityIssuerService.queryAuthorityIssuerInfo(weId);
                LogUtil.info(logger, "queryAuthorityIssuer", info);

                Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
                    info.getErrorCode().intValue());
            }
        }
    }

    /**
     * case:get all authority issuer list many times.
     */
    @Test
    public void testGetAllAuthorityIssuerList_queryMoreTimes() {

        ResponseData<List<AuthorityIssuer>> response =
            authorityIssuerService.getAllAuthorityIssuerList(0, 50);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<List<AuthorityIssuer>> response1 =
            authorityIssuerService.getAllAuthorityIssuerList(1, 50);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response1);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());

        ResponseData<List<AuthorityIssuer>> response2 =
            authorityIssuerService.getAllAuthorityIssuerList(1, 50);
        LogUtil.info(logger, "TestGetAllAuthorityIssuerList", response2);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response2.getErrorCode().intValue());

    }

}
