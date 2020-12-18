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

package com.webank.weid.suite.transportation;

import org.apache.commons.lang3.StringUtils;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ServiceType;
import com.webank.weid.exception.ProtocolSuiteException;
import com.webank.weid.protocol.amop.GetTransDataArgs;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.suite.api.transportation.params.TransMode;
import com.webank.weid.suite.api.transportation.params.TransType;
import com.webank.weid.suite.entity.TransBaseData;
import com.webank.weid.suite.entity.TransCodeBaseData;
import com.webank.weid.suite.transmission.TransmissionRequest;
import com.webank.weid.util.DataToolUtils;

/**
 * 二维码传输协议抽象类定义.
 * @author v_wbgyang
 *
 */
public abstract class AbstractCodeTransportation extends AbstractJsonTransportation {

    protected TransmissionRequest<GetTransDataArgs> buildRequest(
        TransType type, 
        TransCodeBaseData codeData,
        WeIdAuthentication weIdAuthentication
    ) {
        TransmissionRequest<GetTransDataArgs> request = new TransmissionRequest<>();
        request.setAmopId(codeData.getAmopId());
        request.setServiceType(ServiceType.SYS_GET_TRANS_DATA.name());
        request.setWeIdAuthentication(weIdAuthentication);
        request.setArgs(getCodeDataArgs(codeData, weIdAuthentication));
        request.setTransType(type);
        return request;
    }
    
    protected GetTransDataArgs getCodeDataArgs(
        TransCodeBaseData codeData, 
        WeIdAuthentication weIdAuthentication
    ) {
        GetTransDataArgs args = new GetTransDataArgs();
        args.setResourceId(codeData.getId());
        args.setToAmopId(codeData.getAmopId());
        args.setFromAmopId(fiscoConfig.getAmopId());
        args.setWeId(weIdAuthentication.getWeId());
        args.setClassName(codeData.getClass().getName());
        String signValue = DataToolUtils.secp256k1Sign(
            codeData.getId(), 
            weIdAuthentication.getWeIdPrivateKey()
        );
        args.setSignValue(signValue);
        return args;
    }
    
    /**
     * 根据协议字符串判断协议为下载模式协议还是纯数据模式协议.
     * 
     * @param transString 协议字符串
     * @return 返回TransMode
     */
    protected TransMode getTransMode(String transString) {
        if (StringUtils.isBlank(transString)) {
            throw new ProtocolSuiteException(ErrorCode.TRANSPORTATION_PROTOCOL_STRING_INVALID);
        }
        String[] trans = transString.split(TransBaseData.PARTITION_FOR_SPLIT);
        if (trans.length == 3) {
            return TransMode.DOWNLOAD_MODE;
        }
        return TransMode.DATA_MODE;
    } 
}
