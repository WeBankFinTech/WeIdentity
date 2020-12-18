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

package com.webank.weid.contract.deploy;

import org.apache.commons.lang3.StringUtils;

import com.webank.weid.config.FiscoConfig;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.deploy.v2.DeployContractV2;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.WeIdPrivateKey;

/**
 * The Class DeployContract.
 *
 * @author tonychen
 */
public abstract class DeployContract {

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
        
        String chainId = args[0];
        String privateKey = null;
        if (args != null && args.length > 2) {
            privateKey = args[1];
        }
        if (StringUtils.isBlank(privateKey)) {
            privateKey = AddressProcess.getAddressFromFile("ecdsa_key");
        }
        fiscoConfig.setChainId(chainId);
        try {
            deployContract(new WeIdPrivateKey(privateKey), true);
        } catch (WeIdBaseException e) {
            if (e.getErrorCode().getCode() == ErrorCode.CNS_NO_PERMISSION.getCode()) {
                System.out.println("deploy fail, Maybe your private key is incorrect. Please make "
                    + "sure that the root directory of the private key file ecdsa_key that "
                    + "you deployed for the first time exists in the root directory.");
            }
            throw e;
        }
        System.exit(0);
    }
    
    public static void deployContract(WeIdPrivateKey privateKey, boolean instantEnable) {
        if (fiscoConfig.getVersion().startsWith(WeIdConstant.FISCO_BCOS_1_X_VERSION_PREFIX)) {
            throw new WeIdBaseException(ErrorCode.THIS_IS_UNSUPPORTED);
        } else {
            DeployContractV2.deployContract(privateKey, fiscoConfig, instantEnable);
        } 
    }
}
