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

package com.webank.weid.contract.deploy.v2;

import java.math.BigInteger;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.utils.Numeric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.config.FiscoConfig;
import com.webank.weid.constant.CnsType;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.deploy.AddressProcess;
import com.webank.weid.contract.v2.EvidenceContract;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.service.BaseService;
import com.webank.weid.util.DataToolUtils;

public class DeployEvidenceV2 extends AddressProcess {
    
    /**
     * log4j.
     */
    private static final Logger logger = LoggerFactory.getLogger(DeployEvidenceV2.class);

    /**
     * The credentials.
     */
    private static CryptoKeyPair cryptoKeyPair;
    
    /**
     * Inits the credentials.
     *
     * @return true, if successful
     */
    private static String initCryptoKeyPair(String inputPrivateKey) {
        if (StringUtils.isNotBlank(inputPrivateKey)) {
            logger.info("[DeployEvidenceV2] begin to init credentials by privateKey..");
            cryptoKeyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(inputPrivateKey));
        } else {
            // 此分支逻辑实际情况不会执行，因为通过build-tool进来是先给创建私钥
            logger.info("[DeployEvidenceV2] begin to init credentials..");
            cryptoKeyPair = DataToolUtils.createKeyPair();
            byte[] priBytes = Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey());
            byte[] pubBytes = Numeric.hexStringToByteArray(cryptoKeyPair.getHexPublicKey());
            String privateKey = new BigInteger(1, priBytes).toString();
            String publicKey = new BigInteger(1, pubBytes).toString();
            writeAddressToFile(publicKey, "ecdsa_key.pub");
            writeAddressToFile(privateKey, "ecdsa_key");
        }

        if (cryptoKeyPair == null) {
            logger.error("[DeployEvidenceV2] credentials init failed. ");
            return StringUtils.EMPTY;
        }
        byte[] priBytes = Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey());
        return new BigInteger(1, priBytes).toString();
    }
    
    protected static Client getClient(Integer groupId) {
        return BaseService.getClient(groupId);
    }
    
    public static String deployContract(
        FiscoConfig fiscoConfig,
        String inputPrivateKey, 
        Integer groupId, 
        boolean instantEnable
    ) {
        String privateKey = initCryptoKeyPair(inputPrivateKey);
        // 构建私钥对象
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(privateKey);
        
        String evidenceAddress = deployEvidenceContractsNew(groupId);
        // 将地址注册到cns中
        CnsType cnsType = CnsType.SHARE;
        RegisterAddressV2.registerAllCns(weIdPrivateKey);
        // 根据群组和evidence Address获取hash
        String hash = getHashForShare(groupId, evidenceAddress);
        // 将evidence地址注册到cns中
        RegisterAddressV2.registerAddress(
            cnsType, 
            hash, 
            evidenceAddress, 
            WeIdConstant.CNS_EVIDENCE_ADDRESS, 
            weIdPrivateKey
        );
        // 将群组编号注册到cns中
        RegisterAddressV2.registerAddress(
            cnsType, 
            hash, 
            groupId.toString(), 
            WeIdConstant.CNS_GROUP_ID, 
            weIdPrivateKey
        );
        
        if (instantEnable) {
            //将evidence hash配置到机构配置cns中
            RegisterAddressV2.registerHashToOrgConfig(
                fiscoConfig.getCurrentOrgId(), 
                WeIdConstant.CNS_EVIDENCE_HASH + groupId.toString(), 
                hash, 
                weIdPrivateKey
            );
            //将evidence地址配置到机构配置cns中
            RegisterAddressV2.registerHashToOrgConfig(
                fiscoConfig.getCurrentOrgId(), 
                WeIdConstant.CNS_EVIDENCE_ADDRESS + groupId.toString(), 
                evidenceAddress, 
                weIdPrivateKey
            );
            // 合约上也启用hash
            RegisterAddressV2.enableHash(cnsType, hash, weIdPrivateKey);
        }
        return hash;
    }
    
    private static String deployEvidenceContractsNew(Integer groupId) {
        try {
            EvidenceContract evidenceContract =
                EvidenceContract.deploy(
                    getClient(groupId),
                    cryptoKeyPair
                );
            String evidenceContractAddress = evidenceContract.getContractAddress();
            return evidenceContractAddress;
        } catch (Exception e) {
            logger.error("EvidenceFactory deploy exception", e);
        }
        return StringUtils.EMPTY;
    }
}
