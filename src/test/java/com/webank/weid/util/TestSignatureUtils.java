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

package com.webank.weid.util;

import java.math.BigInteger;

import org.apache.commons.codec.binary.Base64;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.crypto.signature.ECDSASignatureResult;
import org.fisco.bcos.sdk.utils.Numeric;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test SignatureUtils.
 *
 * @author v_wbjnzhang and chaoxinhu
 */
public class TestSignatureUtils {

    private static final Logger logger = LoggerFactory.getLogger(TestSignatureUtils.class);

    @Test
    public void testSignatureUtils()
        throws Exception {

        String privateKey =
            "58317564669857453586637110679746575832914889677346283755719850144028639639651";
        BigInteger publicKey = DataToolUtils.publicKeyFromPrivate(new BigInteger(privateKey));
        logger.info("publicKey:{} ", publicKey);

        CryptoKeyPair keyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(privateKey));
        logger.info("publicKey:{} ", keyPair.getHexPublicKey());
        logger.info("privateKey:{}", keyPair.getHexPrivateKey());

        String str = "hello world...........................yes";
        ECDSASignatureResult sigData = DataToolUtils.secp256k1SignToSignature(str, keyPair);
        byte[] serialized = DataToolUtils.simpleSignatureSerialization(sigData);
        ECDSASignatureResult newSigData = DataToolUtils.simpleSignatureDeserialization(serialized);
        logger.info(newSigData.toString());
        ECDSASignatureResult signatureData = DataToolUtils
            .convertBase64StringToSignatureData(new String(Base64.encodeBase64(serialized)));
        logger.info(signatureData.toString());
    }

    @Test
    public void testSecp256k1Signatures() {
        String hexPrivKey =
            "58317564669857453586637110679746575832914889677346283755719850144028639639651";
        String msg = "12345";
        CryptoKeyPair keyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(hexPrivKey));
        String sig = DataToolUtils.secp256k1Sign(msg, new BigInteger(hexPrivKey, 10));
        BigInteger bigPublicKey = 
            new BigInteger(1, Numeric.hexStringToByteArray(keyPair.getHexPublicKey()));
        Boolean result = DataToolUtils.verifySecp256k1Signature(msg, sig, bigPublicKey);
        Assert.assertTrue(result);
    }
}
