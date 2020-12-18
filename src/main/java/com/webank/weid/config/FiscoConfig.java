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

package com.webank.weid.config;

import java.util.ArrayList;
import java.util.List;

import lombok.Data;
import net.sf.oval.ConstraintViolation;
import net.sf.oval.Validator;
import net.sf.oval.constraint.MatchPattern;
import net.sf.oval.constraint.Min;
import net.sf.oval.constraint.NotEmpty;
import net.sf.oval.constraint.NotNull;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.util.PropertyUtils;

/**
 * FISCO-BCOS Config that loaded by java process, not Spring applicationContext anymore.
 *
 * @author chaoxinhu
 * @since 2019.6
 */
@Data
public class FiscoConfig {

    private static final Logger logger = LoggerFactory.getLogger(FiscoConfig.class);
    private static final Validator validator = new Validator();
    // 配置topic
    public static String topic;

    private static FiscoConfig instance;

    private FiscoConfig() {
        
    }
    // Note that all keys are appended with a colon ":" to support regex auto-loading

    @NotNull(message = "the bcos.version is undefined")
    @NotEmpty(message = "the value of bcos.version is null")
    @MatchPattern(pattern = "[0-9]+(\\.\\w*)?", message = "the value of bcos.version is invalid")
    private String version;
    
    @NotNull(message = "the nodes is undefined")
    @NotEmpty(message = "the value of nodes is null")
    private String nodes;
    
    private String weIdAddress;
    private String cptAddress;
    private String issuerAddress;
    private String evidenceAddress;
    private String specificIssuerAddress;
    private String chainId;
    
    @NotNull(message = "the web3sdk.timeout is undefined")
    @NotEmpty(message = "the value of web3sdk.timeout is null")
    @MatchPattern(pattern = "\\d+", message = "the value of web3sdk.timeout is invalid")
    @Min(value = 5, message = "the the minimum value of web3sdk.timeout is 5")
    private String web3sdkTimeout;
    
    @NotNull(message = "the web3sdk.core-pool-size is undefined")
    @NotEmpty(message = "the value of web3sdk.core-pool-size is null")
    @MatchPattern(pattern = "\\d+", message = "the value of web3sdk.core-pool-size is invalid")
    private String web3sdkCorePoolSize;
    
    @NotNull(message = "the web3sdk.max-pool-size is undefined")
    @NotEmpty(message = "the value of web3sdk.max-pool-size is null")
    @MatchPattern(pattern = "\\d+", message = "the value of web3sdk.max-pool-size is invalid")
    private String web3sdkMaxPoolSize;
    
    @NotNull(message = "the web3sdk.queue-capacity is undefined")
    @NotEmpty(message = "the value of web3sdk.queue-capacity is null")
    @MatchPattern(pattern = "\\d+", message = "the value of web3sdk.queue-capacity is invalid")
    private String web3sdkQueueSize;
    
    @NotNull(message = "the web3sdk.keep-alive-seconds is undefined")
    @NotEmpty(message = "the value of web3sdk.keep-alive-seconds is null")
    @MatchPattern(pattern = "\\d+", message = "the value of web3sdk.keep-alive-seconds is invalid")
    private String web3sdkKeepAliveSeconds;
    
    @NotNull(message = "the group.id is undefined")
    @NotEmpty(message = "the value of group.id is null")
    @MatchPattern(pattern = "\\d+", message = "the value of group.id is invalid")
    private String groupId;
    
    @NotNull(message = "the encrypt.type is undefined")
    @NotEmpty(message = "the value of encrypt.type is null")
    @MatchPattern(pattern = "[0,1]", message = "the value of encrypt.type should be in [0,1]")
    private String encryptType;
    
    @NotNull(message = "the v1.ca-crt-path is undefined")
    @NotEmpty(message = "the value of v1.ca-crt-path is null")
    private String v1CaCrtPath;
    
    @NotNull(message = "the v1.client-crt-password is undefined")
    @NotEmpty(message = "the value of v1.client-crt-password is null")
    private String v1ClientCrtPassword;
    
    @NotNull(message = "the v1.client-key-store-path is undefined")
    @NotEmpty(message = "the value of v1.client-key-store-path is null")
    private String v1ClientKeyStorePath;
    
    @NotNull(message = "the v1.key-store-password is undefined")
    @NotEmpty(message = "the value of v1.key-store-password is null")
    private String v1KeyStorePassword;
    
    @NotNull(message = "the v2.ca-crt-path is undefined")
    @NotEmpty(message = "the value of v2.ca-crt-path is null")
    private String v2CaCrtPath;
    
    @NotNull(message = "the v2.node-crt-path is undefined")
    @NotEmpty(message = "the value of v2.node-crt-path is null")
    private String v2NodeCrtPath;
    
    @NotNull(message = "the v2.node-key-path is undefined")
    @NotEmpty(message = "the value of v2.node-key-path is null")
    private String v2NodeKeyPath;
    
    @NotNull(message = "the blockchain.orgid is undefined")
    @NotEmpty(message = "the value of blockchain.orgid is null")
    private String currentOrgId;
    
    @NotNull(message = "the amop.id is undefined")
    @NotEmpty(message = "the value of amop.id is null")
    private String amopId;
    
    private String cnsContractFollow;

    /**
     * load configuration without Spring context required.
     *
     * @return true if success, else false
     */
    public boolean load() {
        try {
            // node info is obtained from weidentity.properties.tpl
            nodes = PropertyUtils.getProperty("nodes");

            version = PropertyUtils.getProperty("bcos.version");
            weIdAddress = PropertyUtils.getProperty("weId.contractaddress");
            cptAddress = PropertyUtils.getProperty("cpt.contractaddress");
            issuerAddress = PropertyUtils.getProperty("issuer.contractaddress");
            evidenceAddress = PropertyUtils.getProperty("evidence.contractaddress");
            specificIssuerAddress = PropertyUtils.getProperty("specificissuer.contractaddress");
            chainId = PropertyUtils.getProperty("chain.id");
            web3sdkTimeout = PropertyUtils.getProperty("web3sdk.timeout");
            web3sdkCorePoolSize = PropertyUtils.getProperty("web3sdk.core-pool-size");
            web3sdkMaxPoolSize = PropertyUtils.getProperty("web3sdk.max-pool-size");
            web3sdkQueueSize = PropertyUtils.getProperty("web3sdk.queue-capacity");
            web3sdkKeepAliveSeconds = PropertyUtils.getProperty("web3sdk.keep-alive-seconds");
            groupId = PropertyUtils.getProperty("group.id");
            encryptType = PropertyUtils.getProperty("encrypt.type");
            v1CaCrtPath = PropertyUtils.getProperty("v1.ca-crt-path");
            v1ClientCrtPassword = PropertyUtils.getProperty("v1.client-crt-password");
            v1ClientKeyStorePath = PropertyUtils.getProperty("v1.client-key-store-path");
            v1KeyStorePassword = PropertyUtils.getProperty("v1.key-store-password");
            v2CaCrtPath = PropertyUtils.getProperty("v2.ca-crt-path");
            v2NodeCrtPath = PropertyUtils.getProperty("v2.node-crt-path");
            v2NodeKeyPath = PropertyUtils.getProperty("v2.node-key-path");
            currentOrgId = PropertyUtils.getProperty("blockchain.orgid");
            amopId = PropertyUtils.getProperty("amop.id");
            cnsContractFollow = PropertyUtils.getProperty("cns.contract.follow");
            return true;
        } catch (Exception e) {
            logger.error("Error occurred during loading Fisco-Bcos properties: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * check the attribute value for FiscoConfig.
     */
    public void check() {
        List<ConstraintViolation> constraintViolationSet = validator.validate(this);
        List<String> messageList = new ArrayList<String>();
        constraintViolationSet.forEach(violationInfo -> {
            messageList.add(violationInfo.getMessage());
        });
        if (messageList.size() > 0) {
            logger.error("[FiscoConfig.check] message: {}", messageList.get(0));
            throw new WeIdBaseException(messageList.get(0));
        }
    }
    
    /**
     * check the contract address.
     * @return 返回地址是否存在
     */
    public boolean checkAddress() {
        return StringUtils.isNotBlank(this.getWeIdAddress()) 
            && StringUtils.isNotBlank(this.getIssuerAddress())
            && StringUtils.isNotBlank(this.getSpecificIssuerAddress()) 
            && StringUtils.isNotBlank(this.getEvidenceAddress()) 
            && StringUtils.isNotBlank(this.getCptAddress());
    }

    public int getEncryptType() {
        return Integer.parseInt(instance.encryptType);
    }

    public static FiscoConfig getInstance() {
        if (instance == null) {
            instance = new FiscoConfig();
            if (!instance.load()) {
                logger.error("[BaseService] Failed to load Fisco-BCOS blockchain node information.");
            }
            instance.check();
        }
        return instance;
    }
}