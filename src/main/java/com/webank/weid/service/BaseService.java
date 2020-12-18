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

package com.webank.weid.service;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.contract.precompiled.cns.CnsInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.config.ContractConfig;
import com.webank.weid.config.FiscoConfig;
import com.webank.weid.constant.AmopMsgType;
import com.webank.weid.constant.CnsType;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.amop.AmopRequestBody;
import com.webank.weid.protocol.amop.CheckAmopMsgHealthArgs;
import com.webank.weid.protocol.amop.base.AmopBaseMsgArgs;
import com.webank.weid.protocol.response.AmopNotifyMsgResult;
import com.webank.weid.protocol.response.AmopResponse;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.callback.RegistCallBack;
import com.webank.weid.service.fisco.WeServer;
import com.webank.weid.service.impl.base.AmopCommonArgs;
import com.webank.weid.service.impl.engine.DataBucketServiceEngine;
import com.webank.weid.service.impl.engine.EngineFactory;
import com.webank.weid.util.DataToolUtils;

/**
 * The BaseService for other RPC classes.
 *
 * @author tonychen
 */
public abstract class BaseService {

    private static final Logger logger = LoggerFactory.getLogger(BaseService.class);

    protected static FiscoConfig fiscoConfig;

    protected static Integer masterGroupId;

    protected static WeServer weServer;

    static {
        fiscoConfig = FiscoConfig.getInstance();
        masterGroupId = Integer.parseInt(fiscoConfig.getGroupId());
    }

    protected static DataBucketServiceEngine getBucket(CnsType cnsType) {
        return EngineFactory.createDataBucketServiceEngine(cnsType);
    }

    protected static WeServer getWeServer() {
        if (weServer == null) {
            weServer = WeServer.getInstance(fiscoConfig);
        }
        return weServer;
    }

    /**
     * Gets the web3j.
     *
     * @return the web3j
     */
    public static Client getClient() {
        return getClient(masterGroupId);
    }

    /**
     * Gets the web3j .
     * 
     * @param groupId 群组ID
     * @return the web3j
     */
    public static Client getClient(Integer groupId) {
        return getWeServer().getClient(groupId);
    }

    /**
     * get current blockNumber.
     *
     * @return return blockNumber
     */
    public static int getBlockNumber() {
        return getBlockNumber(masterGroupId);
    }

    /**
     * get current blockNumber.
     *
     * @param groupId 群组编号
     * @return return blockNumber
     */
    public static int getBlockNumber(Integer groupId) {
        return getWeServer().getBlockNumber(groupId);
    }

    /**
     * get FISCO-BCOS version.
     *
     * @return return nodeVersion
     */
    public static String getVersion() {
        return getWeServer().getVersion();
    }

    /**
     * 查询bucket地址信息.
     * 
     * @param cnsType cns类型枚举对象
     * @return 返回bucket地址
     */
    public static CnsInfo getBucketByCns(CnsType cnsType) {
        return getWeServer().getBucketByCns(cnsType);
    }

    /**
     * 检查群组是否存在.
     * 
     * @param groupId 被检查群组
     * @return true表示群组存在，false表示群组不存在
     */
    public static boolean checkGroupId(Integer groupId) {
        return getWeServer().getGroupList().contains(groupId);
    }
    
    /**
     * Get the Sequence parameter.
     *
     * @return the seq
     */
    protected static String getSeq() {
        return DataToolUtils.getUuId32();
    }

    /**
     * On-demand build the contract config info.
     *
     * @return the contractConfig instance
     */
    protected static ContractConfig buildContractConfig() {
        ContractConfig contractConfig = new ContractConfig();
        contractConfig.setWeIdAddress(fiscoConfig.getWeIdAddress());
        contractConfig.setCptAddress(fiscoConfig.getCptAddress());
        contractConfig.setIssuerAddress(fiscoConfig.getIssuerAddress());
        contractConfig.setEvidenceAddress(fiscoConfig.getEvidenceAddress());
        contractConfig.setSpecificIssuerAddress(fiscoConfig.getSpecificIssuerAddress());
        return contractConfig;
    }

    /**
     * Get the RegistCallBack.
     *
     * @return the RegistCallBack
     */
    protected RegistCallBack getPushCallback() {
        return getWeServer().getPushCallback();
    }

    /**
     * the checkDirectRouteMsgHealth。.
     *
     * @param toAmopId target amopId.
     * @param arg the message
     * @return return the health result
     */
    public ResponseData<AmopNotifyMsgResult> checkDirectRouteMsgHealth(
        String toAmopId,
        CheckAmopMsgHealthArgs arg) {

        return this.getImpl(
            fiscoConfig.getAmopId(),
            toAmopId,
            arg,
            CheckAmopMsgHealthArgs.class,
            AmopNotifyMsgResult.class,
            AmopMsgType.TYPE_CHECK_DIRECT_ROUTE_MSG_HEALTH,
            WeServer.AMOP_REQUEST_TIMEOUT
        );
    }

    protected <T, F extends AmopBaseMsgArgs> ResponseData<T> getImpl(
        String fromAmopId,
        String toAmopId,
        F arg,
        Class<F> argsClass,
        Class<T> resultClass,
        AmopMsgType msgType,
        int timeOut
    ) {
        arg.setFromAmopId(fromAmopId);
        arg.setToAmopId(toAmopId);

        String msgBody = DataToolUtils.serialize(arg);
        AmopRequestBody amopRequestBody = new AmopRequestBody();
        amopRequestBody.setMsgType(msgType);
        amopRequestBody.setMsgBody(msgBody);
        String requestBodyStr = DataToolUtils.serialize(amopRequestBody);

        AmopCommonArgs amopCommonArgs = new AmopCommonArgs();
        amopCommonArgs.setToAmopId(toAmopId);
        amopCommonArgs.setMessage(requestBodyStr);
        amopCommonArgs.setMessageId(getSeq());
        logger.info("direct route request, seq : {}, body ：{}", amopCommonArgs.getMessageId(),
            requestBodyStr);
        AmopResponse response = getWeServer().sendChannelMessage(amopCommonArgs, timeOut);
        logger.info("direct route response, seq : {}, errorCode : {}, errorMsg : {}, body : {}",
            response.getMessageId(),
            response.getErrorCode(),
            response.getErrorMessage(),
            response.getResult()
        );
        ResponseData<T> responseStruct = new ResponseData<>();
        if (102 == response.getErrorCode()) {
            responseStruct.setErrorCode(ErrorCode.DIRECT_ROUTE_REQUEST_TIMEOUT);
        } else if (0 != response.getErrorCode()) {
            responseStruct.setErrorCode(ErrorCode.DIRECT_ROUTE_MSG_BASE_ERROR);
        } else {
            responseStruct.setErrorCode(ErrorCode.getTypeByErrorCode(response.getErrorCode()));
        }
        T msgBodyObj = DataToolUtils.deserialize(response.getResult(), resultClass);
        if (null == msgBodyObj) {
            responseStruct.setErrorCode(ErrorCode.UNKNOW_ERROR);
        }
        responseStruct.setResult(msgBodyObj);
        return responseStruct;
    }

    /**
     * 重新拉取合约地址 并且重新加载相关合约.
     */
    protected static void reloadAddress() {
        fiscoConfig.load();
        String module = WeIdConstant.CNS_GLOBAL_KEY;
        CnsType cnsType = CnsType.ORG_CONFING;
        String  weIdAddress = getAddress(cnsType, module, WeIdConstant.CNS_WEID_ADDRESS);
        String  issuerAddress = getAddress(cnsType, module, WeIdConstant.CNS_AUTH_ADDRESS);
        String  specificAddress = getAddress(cnsType, module, WeIdConstant.CNS_SPECIFIC_ADDRESS);
        String  evidenceAddress = getAddress(cnsType, module, WeIdConstant.CNS_EVIDENCE_ADDRESS); 
        String  cptAddress = getAddress(cnsType, module, WeIdConstant.CNS_CPT_ADDRESS);
        String  chainId = getAddress(cnsType, module, WeIdConstant.CNS_CHAIN_ID);
        fiscoConfig.setChainId(chainId);
        fiscoConfig.setWeIdAddress(weIdAddress);
        fiscoConfig.setCptAddress(cptAddress);
        fiscoConfig.setIssuerAddress(issuerAddress);
        fiscoConfig.setSpecificIssuerAddress(specificAddress);
        fiscoConfig.setEvidenceAddress(evidenceAddress); 
        if (!fiscoConfig.checkAddress()) {
            throw new WeIdBaseException(
                "can not found the contract address, please enable by admin. ");
        }
    }

    private static String getAddress(CnsType cnsType, String hash, String key) {
        return getBucket(cnsType).get(hash, key).getResult();
    }
    
    /**
     * 获取chainId.
     * @return 返回chainId
     */
    public static String getChainId() {
        if (StringUtils.isBlank(fiscoConfig.getChainId())) {
            reloadAddress();
        }
        return fiscoConfig.getChainId();
    }
}