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

package com.webank.weid.contract.deploy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.config.FiscoConfig;
import com.webank.weid.contract.deploy.v2.DeployEvidenceV2;
import com.webank.weid.protocol.base.WeIdPrivateKey;

/**
 * The Class DeployContract.
 *
 * @author tonychen
 */
public abstract class DeployEvidence {

    /**
     * log4j.
     */
    private static final Logger logger = LoggerFactory.getLogger(DeployEvidence.class);

    /**
     * The Fisco Config bundle.
     */
    protected static final FiscoConfig fiscoConfig;

    static {
        fiscoConfig = FiscoConfig.getInstance();
    }

    /**
     * The main method.
     *
     * @param args the arguments
     */
    public static void main(String[] args) {

        // args = new String[] {"2"};

        if (args == null || args.length == 0) {
            logger.error("input param illegal");
            System.exit(1);
        }

        String groupStr = args[0];
        Integer groupId = Integer.parseInt(groupStr);

        String privateKey = null;
        if (args != null && args.length > 1) {
            privateKey = args[1];
        }

        deployContract(new WeIdPrivateKey(privateKey), groupId, true);
        System.exit(0);
    }
    
    /**
     * 部署evidence合约.
     * 
     * @param privateKey 私钥地址
     * @param groupId 群组编号
     * @param instantEnable 是否即时启用
     * @return 返回部署的hash值
     */
    public static String deployContract(WeIdPrivateKey privateKey, Integer groupId, boolean instantEnable) {
        return DeployEvidenceV2.deployContract(fiscoConfig, privateKey, groupId, instantEnable);
    }
}
