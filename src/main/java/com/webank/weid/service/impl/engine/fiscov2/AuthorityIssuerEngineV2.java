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

package com.webank.weid.service.impl.engine.fiscov2;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.datatypes.Address;
import org.fisco.bcos.sdk.abi.datatypes.generated.tuples.generated.Tuple2;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.v2.AuthorityIssuerController;
import com.webank.weid.contract.v2.AuthorityIssuerController.AuthorityIssuerRetLogEventResponse;
import com.webank.weid.contract.v2.SpecificIssuerController;
import com.webank.weid.contract.v2.SpecificIssuerController.SpecificIssuerRetLogEventResponse;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.TransactionInfo;
import com.webank.weid.service.impl.engine.AuthorityIssuerServiceEngine;
import com.webank.weid.service.impl.engine.BaseEngine;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * AuthorityIssuerEngine calls authority issuer contract which runs on FISCO BCOS 2.0.
 *
 * @author tonychen 2019年6月25日
 */
public class AuthorityIssuerEngineV2 extends BaseEngine implements AuthorityIssuerServiceEngine {

    private static final Logger logger = LoggerFactory.getLogger(AuthorityIssuerEngineV2.class);

    private static AuthorityIssuerController authorityIssuerController;
    private static SpecificIssuerController specificIssuerController;

    /**
     * 构造函数.
     */
    public AuthorityIssuerEngineV2() {
        if (authorityIssuerController == null || specificIssuerController == null) {
            reload();
        }
    }

    /**
     * 重新加载静态合约对象.
     */
    public void reload() {
        authorityIssuerController = getContractService(fiscoConfig.getIssuerAddress(),
            AuthorityIssuerController.class);
        specificIssuerController = getContractService(fiscoConfig.getSpecificIssuerAddress(),
            SpecificIssuerController.class);
    }

    @Override
    public ResponseData<String> getWeIdFromOrgId(String orgId) {
        try {
            byte[] name = new byte[32];
            System.arraycopy(orgId.getBytes(), 0, name, 0, orgId.getBytes().length);
            String address = authorityIssuerController.getAddressFromName(name);
            if (WeIdConstant.EMPTY_ADDRESS.equalsIgnoreCase(address)) {
                return new ResponseData<>(StringUtils.EMPTY,
                    ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS);
            }
            return new ResponseData<>(WeIdUtils.convertAddressToWeId(address), ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("get authority issuer WeID failed.", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #addAuthorityIssuer(com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs)
     */
    @Override
    public ResponseData<Boolean> addAuthorityIssuer(RegisterAuthorityIssuerArgs args) {
        AuthorityIssuer authorityIssuer = args.getAuthorityIssuer();
        String weAddress = WeIdUtils.convertWeIdToAddress(authorityIssuer.getWeId());
        List<byte[]> stringAttributes = new ArrayList<byte[]>();
        stringAttributes.add(authorityIssuer.getName().getBytes());
        if (!StringUtils.isEmpty(authorityIssuer.getDescription())) {
            stringAttributes.add(authorityIssuer.getDescription().getBytes());
        }
        List<String> extraStr32s = authorityIssuer.getExtraStr32();
        for (int index = 0; index < extraStr32s.size(); index++) {
            stringAttributes.add(extraStr32s.get(index).getBytes());
        }
        List<BigInteger> longAttributes = new ArrayList<>();
        Long createDate = DateUtils.getNoMillisecondTimeStamp();
        longAttributes.add(BigInteger.valueOf(createDate));
        // The second integer value is updated to be added
        longAttributes.add(BigInteger.valueOf(createDate));
        List<Integer> extraInts = authorityIssuer.getExtraInt();
        for (int index = 0; index < extraInts.size(); index++) {
            longAttributes.add(BigInteger.valueOf(extraInts.get(index)));
        }
        try {
            AuthorityIssuerController authorityIssuerController = reloadContract(
                fiscoConfig.getIssuerAddress(),
                args.getWeIdPrivateKey().getPrivateKey(),
                AuthorityIssuerController.class);

            TransactionReceipt receipt = authorityIssuerController.addAuthorityIssuer(
                weAddress,
                DataToolUtils.bytesArrayListToBytes32ArrayList(
                    stringAttributes,
                    WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH
                ),
                DataToolUtils.listToListBigInteger(
                    longAttributes,
                    WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH
                ),
                authorityIssuer.getAccValue().getBytes()
            );
            ErrorCode errorCode = resolveRegisterAuthorityIssuerEvents(receipt);
            TransactionInfo info = new TransactionInfo(receipt);
            if (errorCode.equals(ErrorCode.SUCCESS)) {
                return new ResponseData<>(Boolean.TRUE, ErrorCode.SUCCESS, info);
            } else {
                return new ResponseData<>(Boolean.FALSE, errorCode, info);
            }
        } catch (Exception e) {
            logger.error("register authority issuer failed.", e);
            return new ResponseData<>(Boolean.FALSE, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    private ErrorCode resolveRegisterAuthorityIssuerEvents(
        TransactionReceipt transactionReceipt) {
        List<AuthorityIssuerRetLogEventResponse> eventList =
            authorityIssuerController.getAuthorityIssuerRetLogEvents(transactionReceipt);

        AuthorityIssuerRetLogEventResponse event = eventList.get(0);
        if (event != null) {
            ErrorCode errorCode = verifyAuthorityIssuerRelatedEvent(
                event,
                WeIdConstant.ADD_AUTHORITY_ISSUER_OPCODE
            );
            return errorCode;
        } else {
            logger.error(
                "register authority issuer failed due to transcation event decoding failure.");
            return ErrorCode.AUTHORITY_ISSUER_ERROR;
        }
    }

    private ErrorCode verifyAuthorityIssuerRelatedEvent(
        AuthorityIssuerRetLogEventResponse event,
        Integer opcode) {

        if (event.addr == null || event.operation == null || event.retCode == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        Integer eventOpcode = event.operation.intValue();
        if (eventOpcode.equals(opcode)) {
            Integer eventRetCode = event.retCode.intValue();
            return ErrorCode.getTypeByErrorCode(eventRetCode);
        } else {
            return ErrorCode.AUTHORITY_ISSUER_OPCODE_MISMATCH;
        }

    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #removeAuthorityIssuer(com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs)
     */
    @Override
    public ResponseData<Boolean> removeAuthorityIssuer(RemoveAuthorityIssuerArgs args) {
        String weId = args.getWeId();
        try {
            AuthorityIssuerController authorityIssuerController = reloadContract(
                fiscoConfig.getIssuerAddress(),
                args.getWeIdPrivateKey().getPrivateKey(),
                AuthorityIssuerController.class);
            TransactionReceipt receipt = authorityIssuerController
                .removeAuthorityIssuer(WeIdUtils.convertWeIdToAddress(weId));
            List<AuthorityIssuerRetLogEventResponse> eventList =
                authorityIssuerController.getAuthorityIssuerRetLogEvents(receipt);

            TransactionInfo info = new TransactionInfo(receipt);
            AuthorityIssuerRetLogEventResponse event = eventList.get(0);

            if (event != null) {
                ErrorCode errorCode = verifyAuthorityIssuerRelatedEvent(
                    event,
                    WeIdConstant.REMOVE_AUTHORITY_ISSUER_OPCODE
                );
                if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
                    return new ResponseData<>(false, errorCode, info);
                } else {
                    return new ResponseData<>(true, errorCode, info);
                }
            } else {
                logger.error("remove authority issuer failed, transcation event decoding failure.");
                return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR, info);
            }
        } catch (Exception e) {
            logger.error("remove authority issuer failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    @Override
    public ResponseData<Boolean> recognizeWeId(Boolean isRecognize, String addr,
        String privateKey) {
        try {
            AuthorityIssuerController authorityIssuerController = reloadContract(
                fiscoConfig.getIssuerAddress(),
                privateKey,
                AuthorityIssuerController.class);
            TransactionReceipt receipt;
            if (isRecognize) {
                receipt = authorityIssuerController.recognizeAuthorityIssuer(addr);
            } else {
                receipt = authorityIssuerController.deRecognizeAuthorityIssuer(addr);
            }
            List<AuthorityIssuerRetLogEventResponse> eventList =
                authorityIssuerController.getAuthorityIssuerRetLogEvents(receipt);
            TransactionInfo info = new TransactionInfo(receipt);
            AuthorityIssuerRetLogEventResponse event = eventList.get(0);
            if (event != null) {
                ErrorCode errorCode;
                if (isRecognize) {
                    errorCode = verifyAuthorityIssuerRelatedEvent(
                        event,
                        WeIdConstant.ADD_AUTHORITY_ISSUER_OPCODE
                    );
                } else {
                    errorCode = verifyAuthorityIssuerRelatedEvent(
                        event,
                        WeIdConstant.REMOVE_AUTHORITY_ISSUER_OPCODE
                    );
                }
                if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
                    return new ResponseData<>(false, errorCode, info);
                } else {
                    return new ResponseData<>(true, errorCode, info);
                }
            } else {
                logger.error("(de-)recognize authority issuer failed, event decoding failure.");
                return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR, info);
            }

        } catch (Exception e) {
            logger.error("(de-)recognize authority issuer failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR.getCode(),
                e.getMessage());
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #isAuthorityIssuer(java.lang.String)
     */
    @Override
    public ResponseData<Boolean> isAuthorityIssuer(String address) {
        ResponseData<Boolean> resultData = new ResponseData<Boolean>();
        try {
            Boolean result = authorityIssuerController.isAuthorityIssuer(address);
            resultData.setResult(result);
            if (result) {
                resultData.setErrorCode(ErrorCode.SUCCESS);
            } else {
                resultData.setErrorCode(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS);
            }
            return resultData;
        } catch (Exception e) {
            logger.error("check authority issuer id failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }

    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #getAuthorityIssuerInfoNonAccValue(java.lang.String)
     */
    @Override
    public ResponseData<AuthorityIssuer> getAuthorityIssuerInfoNonAccValue(String weId) {
        ResponseData<AuthorityIssuer> resultData = new ResponseData<AuthorityIssuer>();
        try {
            Tuple2<List<byte[]>, List<BigInteger>> rawResult =
                authorityIssuerController.getAuthorityIssuerInfoNonAccValue(
                    WeIdUtils.convertWeIdToAddress(weId));
            if (rawResult == null) {
                return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
            }

            List<byte[]> bytes32Attributes = rawResult.getValue1();
            List<BigInteger> int256Attributes = rawResult.getValue2();

            AuthorityIssuer result = new AuthorityIssuer();
            result.setWeId(weId);

            String name = new String(bytes32Attributes.get(0)).trim();
            result.setName(name);

            if (!DataToolUtils.isByteArrayEmpty(bytes32Attributes.get(1))) {
                String desc = new String(bytes32Attributes.get(1)).trim();
                result.setDescription(desc);
            }

            List<String> extraStr32s = new ArrayList<>();
            for (int index = 0; index < WeIdConstant.AUTHORITY_ISSUER_EXTRA_PARAM_LENGTH; index++) {
                byte[] extraByte = bytes32Attributes.get(index + 2);
                if (!DataToolUtils.isByteArrayEmpty(extraByte)) {
                    extraStr32s.add(new String(extraByte).trim());
                }
            }
            result.setExtraStr32(extraStr32s);

            // 0 is created, 1 is reserved for updated
            List<Integer> extraInts = new ArrayList<>();
            for (int index = 0; index < WeIdConstant.AUTHORITY_ISSUER_EXTRA_PARAM_LENGTH; index++) {
                Integer intValue = int256Attributes.get(index + 2).intValue();
                if (intValue == 0) {
                    continue;
                }
                extraInts.add(intValue);
            }
            result.setExtraInt(extraInts);

            Long createDate = Long
                .valueOf(int256Attributes.get(0).longValue());
            if (StringUtils.isEmpty(name) && createDate.equals(WeIdConstant.LONG_VALUE_ZERO)) {
                return new ResponseData<>(
                    null, ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS
                );
            }
            result.setCreated(createDate);

            // Accumulator Value is unable to load due to Solidity 0.4.4 restrictions - left blank.
            result.setAccValue("");

            // Set recognition status
            boolean recognized = Long.valueOf(int256Attributes.get(15).longValue())
                .equals(WeIdConstant.RECOGNIZED_AUTHORITY_ISSUER_FLAG) ? true : false;
            result.setRecognized(recognized);
            resultData.setResult(result);
            return resultData;
        } catch (Exception e) {
            logger.error("query authority issuer failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #getAuthorityIssuerAddressList(java.lang.Integer, java.lang.Integer)
     */
    @Override
    public List<String> getAuthorityIssuerAddressList(Integer index, Integer num) {
        List<String> addressList = new ArrayList<>();
        try {
            addressList =
                authorityIssuerController.getAuthorityIssuerAddressList(
                    new BigInteger(index.toString()),
                    new BigInteger(num.toString())
                );
        } catch (Exception e) {
            logger.error("query authority issuer failed.", e);
        }
        return addressList;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #removeIssuer(java.lang.String, java.lang.String)
     */
    @Override
    public ResponseData<Boolean> removeIssuer(String issuerType, String issuerAddress,
        String privateKey) {
        try {

            SpecificIssuerController specificIssuerController = reloadContract(
                fiscoConfig.getSpecificIssuerAddress(),
                privateKey,
                SpecificIssuerController.class);
            TransactionReceipt receipt = specificIssuerController.removeIssuer(
                DataToolUtils.stringToByte32Array(issuerType),
                issuerAddress);

            ErrorCode errorCode = resolveSpecificIssuerEvents(receipt, false, issuerAddress);
            TransactionInfo info = new TransactionInfo(receipt);
            return new ResponseData<>(errorCode.getCode() == ErrorCode.SUCCESS.getCode(),
                errorCode, info);
        } catch (Exception e) {
            logger.error("remove issuer from type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    private ErrorCode resolveSpecificIssuerEvents(
        TransactionReceipt transactionReceipt,
        boolean isRegister,
        String address) {
        List<SpecificIssuerRetLogEventResponse> eventList =
            specificIssuerController.getSpecificIssuerRetLogEvents(transactionReceipt);

        SpecificIssuerRetLogEventResponse event = eventList.get(0);
        if (event != null) {
            if (isRegister) {
                // this might be the register type, or the register specific issuer case
                if (event.operation.intValue()
                    != WeIdConstant.ADD_AUTHORITY_ISSUER_OPCODE
                    || !StringUtils.equalsIgnoreCase(event.addr.toString(), address)) {
                    return ErrorCode.TRANSACTION_EXECUTE_ERROR;
                }
            } else {
                // this is the remove specific issuer case
                if (event.operation.intValue()
                    != WeIdConstant.REMOVE_AUTHORITY_ISSUER_OPCODE
                    || !StringUtils.equalsIgnoreCase(event.addr.toString(), address)) {
                    return ErrorCode.TRANSACTION_EXECUTE_ERROR;
                }
            }
            Integer eventRetCode = event.retCode.intValue();
            return ErrorCode.getTypeByErrorCode(eventRetCode);
        } else {
            logger.error(
                "specific issuer type resolution failed due to event decoding failure.");
            return ErrorCode.UNKNOW_ERROR;
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #isSpecificTypeIssuer(java.lang.String, java.lang.String)
     */
    @Override
    public ResponseData<Boolean> isSpecificTypeIssuer(String issuerType, String address) {
        try {
            Boolean result = specificIssuerController.isSpecificTypeIssuer(
                DataToolUtils.stringToByte32Array(issuerType),
                address
            );

            if (!result) {
                return new ResponseData<>(result,
                    ErrorCode.SPECIFIC_ISSUER_CONTRACT_ERROR_ALREADY_NOT_EXIST);
            }
            return new ResponseData<>(result, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("check issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.AuthorityIssuerController
     * #getSpecificTypeIssuerList(java.lang.String, java.lang.Integer, java.lang.Integer)
     */
    @Override
    public ResponseData<List<String>> getSpecificTypeIssuerList(String issuerType, Integer index,
        Integer num) {
        List<String> addresses = new ArrayList<>();
        try {

            addresses = specificIssuerController.getSpecificTypeIssuerList(
                DataToolUtils.stringToByte32Array(issuerType),
                new BigInteger(index.toString()),
                new BigInteger(num.toString())
            );
            List<String> addressList = new ArrayList<>();
            for (String addr : addresses) {
                if (!WeIdUtils.isEmptyStringAddress(addr)) {
                    addressList.add(addr);
                }
            }
            return new ResponseData<>(addressList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("check issuer type failed.", e);
            return new ResponseData<List<String>>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.IssuerContractController
     * #registerIssuerType(java.lang.String)
     */
    @Override
    public ResponseData<Boolean> registerIssuerType(String issuerType, String privateKey) {
        try {
            SpecificIssuerController specificIssuerController = reloadContract(
                fiscoConfig.getSpecificIssuerAddress(),
                privateKey,
                SpecificIssuerController.class);
            TransactionReceipt receipt = specificIssuerController
                .registerIssuerType(DataToolUtils.stringToByte32Array(issuerType));

            // pass-in empty address
            String emptyAddress = new Address(BigInteger.ZERO).toString();
            ErrorCode errorCode = resolveSpecificIssuerEvents(receipt, true, emptyAddress);
            TransactionInfo info = new TransactionInfo(receipt);
            return new ResponseData<>(errorCode.getCode() == ErrorCode.SUCCESS.getCode(),
                errorCode, info);
        } catch (Exception e) {
            logger.error("register issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.IssuerContractController
     * #addIssuer(java.lang.String, java.lang.String)
     */
    @Override
    public ResponseData<Boolean> addIssuer(String issuerType, String issuerAddress,
        String privateKey) {
        try {
            SpecificIssuerController specificIssuerController = reloadContract(
                fiscoConfig.getSpecificIssuerAddress(),
                privateKey,
                SpecificIssuerController.class);
            TransactionReceipt receipt = specificIssuerController.addIssuer(
                DataToolUtils.stringToByte32Array(issuerType),
                issuerAddress
            );
            ErrorCode errorCode = resolveSpecificIssuerEvents(receipt, true, issuerAddress);
            TransactionInfo info = new TransactionInfo(receipt);
            return new ResponseData<>(errorCode.getCode() == ErrorCode.SUCCESS.getCode(),
                errorCode, info);
        } catch (Exception e) {
            logger.error("add issuer into type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

}
