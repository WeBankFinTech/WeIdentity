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

package com.webank.weid.full;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.utils.Numeric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.JsonSchemaConstant;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.AuthenticationArgs;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.request.CreateCredentialArgs;
import com.webank.weid.protocol.request.CreateCredentialPojoArgs;
import com.webank.weid.protocol.request.CreateWeIdArgs;
import com.webank.weid.protocol.request.PublicKeyArgs;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.request.ServiceArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.util.DataToolUtils;

/**
 * testing basic entity object building classes.
 *
 * @author v_wbgyang
 */
public class TestBaseUtil {

    /**
     * log4j.
     */
    private static final Logger logger = LoggerFactory.getLogger(TestBaseUtil.class);

    /**
     * build CreateCredentialArgs no cptId.
     */
    public static CreateCredentialArgs buildCreateCredentialArgs(CreateWeIdDataResult createWeId) {

        CreateCredentialArgs createCredentialArgs = new CreateCredentialArgs();
        createCredentialArgs.setIssuer(createWeId.getWeId());
        createCredentialArgs.setExpirationDate(System.currentTimeMillis() + (1000 * 60 * 60 * 24));
        createCredentialArgs.setWeIdPrivateKey(new WeIdPrivateKey());
        createCredentialArgs.getWeIdPrivateKey()
            .setPrivateKey(createWeId.getUserWeIdPrivateKey().getPrivateKey());
        createCredentialArgs.setClaim(buildCptJsonSchemaData());

        return createCredentialArgs;
    }

    /**
     * build default CreateCredentialArgs.
     */
    public static CreateCredentialArgs buildCreateCredentialArgs(
        CreateWeIdDataResult createWeId,
        CptBaseInfo cptBaseInfo) {

        CreateCredentialArgs createCredentialArgs = buildCreateCredentialArgs(createWeId);
        createCredentialArgs.setCptId(cptBaseInfo.getCptId());
        return createCredentialArgs;
    }

    /**
     * build CreateCredentialPojoArgs no cptId.
     *
     * @return CreateCredentialPojoArgs
     */
    public static CreateCredentialPojoArgs<Map<String, Object>> buildCreateCredentialPojoArgs(
        CreateWeIdDataResult createWeId) {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            new CreateCredentialPojoArgs<Map<String, Object>>();

        createCredentialPojoArgs.setIssuer(createWeId.getWeId());
        createCredentialPojoArgs.setExpirationDate(
            System.currentTimeMillis() + (1000 * 60 * 60 * 24));
        createCredentialPojoArgs.setWeIdAuthentication(buildWeIdAuthentication(createWeId));
        try {
            Map<String, Object> claimMap = buildCptJsonSchemaDataFromFile();
            claimMap.put("id", createWeId.getWeId());
            createCredentialPojoArgs.setClaim(claimMap);

        } catch (IOException e) {
            logger.error("buildCreateCredentialPojoArgs failed. ", e);
            return null;
        }

        return createCredentialPojoArgs;
    }

    /**
     * build CreateCredentialPojoArgs no cptId.
     *
     * @return CreateCredentialPojoArgs
     */
    public static CreateCredentialPojoArgs<Map<String, Object>> buildCreateCredentialPojoArgs4MlCpt(
        CreateWeIdDataResult createWeId) {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            new CreateCredentialPojoArgs<Map<String, Object>>();

        createCredentialPojoArgs.setIssuer(createWeId.getWeId());
        createCredentialPojoArgs.setExpirationDate(
            System.currentTimeMillis() + (1000 * 60 * 60 * 24));
        createCredentialPojoArgs.setWeIdAuthentication(buildWeIdAuthentication(createWeId));
        try {
            createCredentialPojoArgs.setClaim(buildCptJsonSchemaDataFromFile4MlCpt());
        } catch (IOException e) {
            logger.error("buildCreateCredentialPojoArgs failed. ", e);
            return null;
        }

        return createCredentialPojoArgs;
    }

    /**
     * build CreateCredentialPojoArgs no cptId.
     *
     * @return CreateCredentialPojoArgs
     */
    public static CreateCredentialPojoArgs<Map<String, Object>>
        buildCreateCredentialPojoArgs4MultiCpt(
        CreateWeIdDataResult createWeId) {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            new CreateCredentialPojoArgs<Map<String, Object>>();

        createCredentialPojoArgs.setIssuer(createWeId.getWeId());
        createCredentialPojoArgs.setExpirationDate(
            System.currentTimeMillis() + (1000 * 60 * 60 * 24));
        createCredentialPojoArgs.setWeIdAuthentication(buildWeIdAuthentication(createWeId));
        try {
            createCredentialPojoArgs.setClaim(buildCptJsonSchemaDataFromFile4MultiCpt());
        } catch (IOException e) {
            logger.error("buildCreateCredentialPojoArgs failed. ", e);
            return null;
        }

        return createCredentialPojoArgs;
    }

    /**
     * build CreateCredentialPojoArgs no cptId.
     *
     * @return CreateCredentialPojoArgs
     */
    public static CreateCredentialPojoArgs<Map<String, Object>>
        buildCreateCredentialPojoArgs4SpecTplCpt(
        CreateWeIdDataResult createWeId) {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs4 =
            new CreateCredentialPojoArgs<Map<String, Object>>();

        createCredentialPojoArgs4.setIssuer(createWeId.getWeId());
        createCredentialPojoArgs4.setExpirationDate(
            System.currentTimeMillis() + (1000 * 60 * 60 * 24));
        createCredentialPojoArgs4.setWeIdAuthentication(buildWeIdAuthentication(createWeId));
        try {
            createCredentialPojoArgs4.setClaim(buildCptJsonSchemaDataFromFile4SpecTplCpt());
        } catch (IOException e) {
            logger.error("buildCreateCredentialPojoArgs failed. ", e);
            return null;
        }

        return createCredentialPojoArgs4;
    }

    /**
     * buildWeIdAuthentication.
     *
     * @param weIdData weId
     * @return WeIdAuthentication
     */
    public static WeIdAuthentication buildWeIdAuthentication(CreateWeIdDataResult weIdData) {
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(weIdData.getWeId());
        weIdAuthentication.setWeIdPublicKeyId(weIdData.getWeId() + "#keys-0");
        weIdAuthentication.setWeIdPrivateKey(new WeIdPrivateKey());
        weIdAuthentication.getWeIdPrivateKey().setPrivateKey(
            weIdData.getUserWeIdPrivateKey().getPrivateKey());
        return weIdAuthentication;
    }

    /**
     * build cpt json schemaData.
     *
     * @return HashMap
     * @throws IOException IOException
     */
    public static HashMap<String, Object> buildCptJsonSchemaDataFromFile() throws IOException {

        HashMap<String, Object> cptJsonSchemaData = new HashMap<String, Object>();
        JsonNode jsonNode = JsonLoader.fromResource("/claim.json");
        cptJsonSchemaData = DataToolUtils.deserialize(jsonNode.toString(), HashMap.class);
        return cptJsonSchemaData;
    }

    /**
     * build cpt json schemaData.
     *
     * @return HashMap
     * @throws IOException IOException
     */
    public static HashMap<String, Object> buildCptJsonSchemaDataFromFile4MultiCpt()
        throws IOException {

        HashMap<String, Object> cptJsonSchemaData = new HashMap<String, Object>();
        JsonNode jsonNode = JsonLoader.fromResource("/test-singlelevel-claim.json");
        cptJsonSchemaData = DataToolUtils.deserialize(jsonNode.toString(), HashMap.class);
        return cptJsonSchemaData;
    }

    /**
     * build cpt json schemaData.
     *
     * @return HashMap
     * @throws IOException IOException
     */
    public static HashMap<String, Object> buildCptJsonSchemaDataFromFile4MlCpt()
        throws IOException {

        HashMap<String, Object> cptJsonSchemaData = new HashMap<String, Object>();
        JsonNode jsonNode = JsonLoader.fromResource("/test-multilevel-claim.json");
        cptJsonSchemaData = DataToolUtils.deserialize(jsonNode.toString(), HashMap.class);
        return cptJsonSchemaData;
    }

    /**
     * build cpt json schemaData.
     *
     * @return HashMap
     * @throws IOException IOException
     */
    public static HashMap<String, Object> buildCptJsonSchemaDataFromFile4SpecTplCpt()
        throws IOException {

        HashMap<String, Object> cptJsonSchemaData = new HashMap<String, Object>();
        JsonNode jsonNode = JsonLoader.fromResource("/test-spectpl-claim.json");
        cptJsonSchemaData = DataToolUtils.deserialize(jsonNode.toString(), HashMap.class);
        return cptJsonSchemaData;
    }

    /**
     * build default CptMapArgs.
     *
     * @param createWeId WeId
     * @return CptMapArgs
     */
    public static CptMapArgs buildCptArgs(CreateWeIdDataResult createWeId) {

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setCptJsonSchema(buildCptJsonSchema());
        cptMapArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));

        return cptMapArgs;
    }

    /**
     * build MultiLevel CptMapArgs.
     *
     * @param createWeId WeId
     * @return CptMapArgs
     */
    public static CptMapArgs buildCptArgs4MlCpt(CreateWeIdDataResult createWeId) {

        //build cpt from file
        CptStringArgs cptStringArgs = new CptStringArgs();
        try {
            cptStringArgs = buildCptStringArgs4MlCpt(createWeId, true);
        } catch (IOException e) {
            logger.error("buildCptArgs4MlCpt failed. ", e);
        }

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));
        cptMapArgs.setCptJsonSchema(
            DataToolUtils.deserialize(cptStringArgs.getCptJsonSchema(), HashMap.class));

        return cptMapArgs;
    }

    /**
     * build default CptMapArgs.
     *
     * @param createWeId WeId
     * @return CptMapArgs
     */
    public static CptMapArgs buildCptArgs4MultiCpt(CreateWeIdDataResult createWeId) {

        //build cpt from file
        CptStringArgs cptStringArgs = new CptStringArgs();
        try {
            cptStringArgs = buildCptStringArgs4MultiCpt(createWeId, true);
        } catch (IOException e) {
            logger.error("buildCptArgs4MultiCpt failed. ", e);
        }

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));
        cptMapArgs.setCptJsonSchema(
            DataToolUtils.deserialize(cptStringArgs.getCptJsonSchema(), HashMap.class));

        return cptMapArgs;
    }

    /**
     * build default CptMapArgs.
     *
     * @param createWeId WeId
     * @return CptMapArgs
     */
    public static CptMapArgs buildCptArgs4SpecTplCpt(CreateWeIdDataResult createWeId) {

        //build cpt from file
        CptStringArgs cptStringArgs = new CptStringArgs();
        try {
            cptStringArgs = buildCptStringArgs4SpecTplCpt(createWeId, true);
        } catch (IOException e) {
            logger.error("buildCptArgs4SpecTplCpt failed. ", e);
        }

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));
        cptMapArgs.setCptJsonSchema(
            DataToolUtils.deserialize(cptStringArgs.getCptJsonSchema(), HashMap.class));

        return cptMapArgs;
    }

    /**
     * build default buildCptStringArgs.
     */
    public static CptStringArgs buildCptStringArgs(
        CreateWeIdDataResult createWeId,
        Boolean isFormatFile) throws IOException {

        String jsonSchema = TestData.SCHEMA;
        if (isFormatFile) {
            JsonNode jsonNode = JsonLoader.fromResource("/json-schema-cpt.json");
            jsonSchema = jsonNode.toString();
        }

        CptStringArgs cptStringArgs = new CptStringArgs();
        cptStringArgs.setCptJsonSchema(jsonSchema);
        cptStringArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));
        return cptStringArgs;
    }

    /**
     * build MultiLevel buildCptStringArgs.
     */
    public static CptStringArgs buildCptStringArgs4MlCpt(
        CreateWeIdDataResult createWeId,
        Boolean isFormatFile) throws IOException {

        String jsonSchema = TestData.SCHEMA;
        if (isFormatFile) {
            JsonNode jsonNode = JsonLoader.fromResource("/test-multilevel-cpt.json");
            jsonSchema = jsonNode.toString();
        }

        CptStringArgs cptStringArgs = new CptStringArgs();
        cptStringArgs.setCptJsonSchema(jsonSchema);
        cptStringArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));

        return cptStringArgs;
    }

    /**
     * build MultiLevel buildCptStringArgs.
     */
    public static CptStringArgs buildCptStringArgs4MultiCpt(
        CreateWeIdDataResult createWeId,
        Boolean isFormatFile) throws IOException {

        String jsonSchema = TestData.SCHEMA;
        if (isFormatFile) {
            JsonNode jsonNode = JsonLoader.fromResource("/test-singlelevel-cpt.json");
            jsonSchema = jsonNode.toString();
        }

        CptStringArgs cptStringArgs = new CptStringArgs();
        cptStringArgs.setCptJsonSchema(jsonSchema);
        cptStringArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));

        return cptStringArgs;
    }

    /**
     * build specify pdf template cpt.
     */
    public static CptStringArgs buildCptStringArgs4SpecTplCpt(
        CreateWeIdDataResult createWeId,
        Boolean isFormatFile) throws IOException {

        String jsonSchema = TestData.SCHEMA;
        if (isFormatFile) {
            JsonNode jsonNode = JsonLoader.fromResource("/test-spectpl-cpt.json");
            jsonSchema = jsonNode.toString();
        }

        CptStringArgs cptStringArgs = new CptStringArgs();
        cptStringArgs.setCptJsonSchema(jsonSchema);
        cptStringArgs.setWeIdAuthentication(buildWeIdAuthority(createWeId));

        return cptStringArgs;
    }

    /**
     * build weId authority.
     */
    public static WeIdAuthentication buildWeIdAuthority(CreateWeIdDataResult createWeId) {

        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeId.getWeId());
        weIdAuthentication.setWeIdPrivateKey(new WeIdPrivateKey());
        weIdAuthentication.getWeIdPrivateKey()
            .setPrivateKey(createWeId.getUserWeIdPrivateKey().getPrivateKey());
        return weIdAuthentication;
    }


    /**
     * build cpt json schema.
     *
     * @return HashMap
     */
    public static HashMap<String, Object> buildCptJsonSchema() {

        HashMap<String, Object> cptJsonSchemaNew = new HashMap<String, Object>(3);
        cptJsonSchemaNew.put(JsonSchemaConstant.TITLE_KEY, "Digital Identity");
        cptJsonSchemaNew.put(JsonSchemaConstant.DESCRIPTION_KEY, "this is a cpt template");

        HashMap<String, Object> propertitesMap1 = new HashMap<String, Object>(2);
        propertitesMap1.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_STRING);
        propertitesMap1.put(JsonSchemaConstant.DESCRIPTION_KEY, "this is name");

        String[] genderEnum = {"F", "M"};
        HashMap<String, Object> propertitesMap2 = new HashMap<String, Object>(2);
        propertitesMap2.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_STRING);
        propertitesMap2.put(JsonSchemaConstant.DATA_TYPE_ENUM, genderEnum);

        HashMap<String, Object> propertitesMap3 = new HashMap<String, Object>(2);
        propertitesMap3.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_NUMBER);
        propertitesMap3.put(JsonSchemaConstant.DESCRIPTION_KEY, "this is age");

        HashMap<String, Object> propertitesMap4 = new HashMap<String, Object>(2);
        propertitesMap4.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_STRING);
        propertitesMap4.put(JsonSchemaConstant.DESCRIPTION_KEY, "this is weid");

        HashMap<String, Object> cptJsonSchema = new HashMap<String, Object>(3);
        cptJsonSchema.put("name", propertitesMap1);
        cptJsonSchema.put("gender", propertitesMap2);
        cptJsonSchema.put("age", propertitesMap3);
        cptJsonSchema.put("id", propertitesMap4);
        cptJsonSchemaNew.put(JsonSchemaConstant.PROPERTIES_KEY, cptJsonSchema);

        String[] genderRequired = {"id", "name", "gender"};
        cptJsonSchemaNew.put(JsonSchemaConstant.REQUIRED_KEY, genderRequired);

        return cptJsonSchemaNew;
    }

    /**
     * build cpt json schemaData.
     *
     * @return HashMap
     */
    public static HashMap<String, Object> buildCptJsonSchemaData() {

        HashMap<String, Object> cptJsonSchemaData = new HashMap<String, Object>(3);
        cptJsonSchemaData.put("name", "zhang san");
        cptJsonSchemaData.put("gender", "F");
        cptJsonSchemaData.put("age", 18);
        cptJsonSchemaData.put("id", "did:weid:101:0xe4bee5a07f282ffd3109699e21663cde0210fb64");
        return cptJsonSchemaData;
    }

    /**
     * build default RegisterAuthorityIssuerArgs.
     *
     * @return RegisterAuthorityIssuerArgs
     */
    public static RegisterAuthorityIssuerArgs buildRegisterAuthorityIssuerArgs(
        CreateWeIdDataResult createWeId,
        String privateKey) {

        AuthorityIssuer authorityIssuer = new AuthorityIssuer(
            createWeId.getWeId(),
            TestData.AUTHORITY_ISSUER_NAME,
            TestData.AUTHORITY_ISSUER_ACCVALUE,
            null,
            null,
            null);

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs = new RegisterAuthorityIssuerArgs();
        registerAuthorityIssuerArgs.setAuthorityIssuer(authorityIssuer);
        registerAuthorityIssuerArgs.setWeIdPrivateKey(new WeIdPrivateKey());
        registerAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey(privateKey);

        return registerAuthorityIssuerArgs;
    }

    /**
     * build default CreateWeIdArgs.
     *
     * @return CreateWeIdArgs
     */
    public static CreateWeIdArgs buildCreateWeIdArgs() {
        CreateWeIdArgs args = new CreateWeIdArgs();
        PasswordKey passwordKey = createEcKeyPair();
        args.setPublicKey(passwordKey.getPublicKey());

        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(passwordKey.getPrivateKey());

        args.setWeIdPrivateKey(weIdPrivateKey);

        return args;
    }

    /**
     * buildSetPublicKeyArgs.
     *
     * @return SetAuthenticationArgs
     */
    public static AuthenticationArgs buildSetAuthenticationArgs(
        CreateWeIdDataResult createWeId) {

        AuthenticationArgs setAuthenticationArgs = new AuthenticationArgs();
        setAuthenticationArgs.setPublicKey(createWeId.getUserWeIdPublicKey().getPublicKey());

        return setAuthenticationArgs;
    }

    /**
     * buildSetPublicKeyArgs.
     *
     * @param createWeId WeId
     * @return SetPublicKeyArgs
     */
    public static PublicKeyArgs buildSetPublicKeyArgs(CreateWeIdDataResult createWeId) {

        PublicKeyArgs setPublicKeyArgs = new PublicKeyArgs();
        setPublicKeyArgs.setPublicKey(createWeId.getUserWeIdPublicKey().getPublicKey());

        return setPublicKeyArgs;
    }

    /**
     * buildSetPublicKeyArgs.
     *
     * @param createWeId WeId
     * @return SetServiceArgs
     */
    public static ServiceArgs buildSetServiceArgs(CreateWeIdDataResult createWeId) {

        ServiceArgs serviceArgs = new ServiceArgs();
        serviceArgs.setType(TestData.SERVICE_TYPE);
        serviceArgs.setServiceEndpoint(TestData.SERVICE_ENDPOINT);
        return serviceArgs;
    }

    /**
     * buildRemoveAuthorityIssuerArgs.
     *
     * @param createWeId WeId
     * @param privateKey privateKey
     * @return RemoveAuthorityIssuerArgs
     */
    public static RemoveAuthorityIssuerArgs buildRemoveAuthorityIssuerArgs(
        CreateWeIdDataResult createWeId,
        String privateKey) {

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs = new RemoveAuthorityIssuerArgs();
        removeAuthorityIssuerArgs.setWeId(createWeId.getWeId());
        removeAuthorityIssuerArgs.setWeIdPrivateKey(new WeIdPrivateKey());
        removeAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey(privateKey);

        return removeAuthorityIssuerArgs;
    }

    /**
     * create a new public key - private key.
     *
     * @return PasswordKey
     */
    public static PasswordKey createEcKeyPair() {

        PasswordKey passwordKey = new PasswordKey();
        CryptoKeyPair keyPair = DataToolUtils.createKeyPair();
        BigInteger bigPublicKey = 
            new BigInteger(1, Numeric.hexStringToByteArray(keyPair.getHexPublicKey()));
        BigInteger bigPrivateKey = 
            new BigInteger(1, Numeric.hexStringToByteArray(keyPair.getHexPrivateKey()));
        
        String publicKey = String.valueOf(bigPublicKey);
        String privateKey = String.valueOf(bigPrivateKey);
        passwordKey.setPrivateKey(privateKey);
        passwordKey.setPublicKey(publicKey);
        LogUtil.info(logger, "createEcKeyPair", passwordKey);
        return passwordKey;
    }

    /**
     * to test the public and private key from the file.
     *
     * @param fileName fileName
     * @return PasswordKey
     */
    public static PasswordKey resolvePk(String fileName) {

        BufferedReader br = null;
        FileInputStream fis = null;
        InputStreamReader isr = null;

        PasswordKey passwordKey = new PasswordKey();
        try {

            URL fileUrl = TestBaseUtil.class.getClassLoader().getResource(fileName);
            if (fileUrl == null) {
                return passwordKey;
            }

            String filePath = fileUrl.getFile();
            if (filePath == null) {
                return passwordKey;
            }

            fis = new FileInputStream(fileUrl.getFile());
            isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
            br = new BufferedReader(isr);

            List<String> strList = new ArrayList<String>();
            String line = null;
            while ((line = br.readLine()) != null) {
                strList.add(line);
            }

            String[] pk = new String[2];
            for (int i = 0; i < strList.size(); i++) {
                String str = strList.get(i);
                if (StringUtils.isBlank(str)) {
                    continue;
                }
                String[] lineStr = str.split(":");

                if (lineStr.length == 2) {
                    pk[i] = lineStr[1];
                }
            }
            passwordKey.setPublicKey(pk[0]);
            passwordKey.setPrivateKey(pk[1]);
            logger.info("publicKey:{}", passwordKey.getPublicKey());
            logger.info("privateKey:{}", passwordKey.getPrivateKey());
            return passwordKey;
        } catch (FileNotFoundException e) {
            logger.error("the file is not exists:", e);
        } catch (IOException e) {
            logger.error("resolvePk error:", e);
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    logger.error("BufferedReader close error:", e);
                }
            }
            if (isr != null) {
                try {
                    isr.close();
                } catch (IOException e) {
                    logger.error("InputStreamReader close error:", e);
                }
            }
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    logger.error("FileInputStream close error:", e);
                }
            }
        }
        return passwordKey;
    }


    /**
     * Read key form file.
     *
     * @param fileName filename
     * @return private key
     */
    public static String readPrivateKeyFromFile(String fileName) {

        BufferedReader br = null;
        FileInputStream fis = null;
        InputStreamReader isr = null;
        StringBuffer privateKey = new StringBuffer();

        URL fileUrl = TestBaseUtil.class.getClassLoader().getResource(fileName);
        if (fileUrl == null) {
            return privateKey.toString();
        }

        String filePath = fileUrl.getFile();
        if (filePath == null) {
            return privateKey.toString();
        }

        try {
            fis = new FileInputStream(fileUrl.getFile());
            isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
            br = new BufferedReader(isr);

            String line = null;
            while ((line = br.readLine()) != null) {
                privateKey.append(line);
            }
        } catch (Exception e) {
            logger.error("read privateKey from {} failed, error:{}", fileName, e);
        } finally {
            closeStream(br, fis, isr);
        }

        return privateKey.toString();
    }

    private static void closeStream(BufferedReader br, FileInputStream fis, InputStreamReader isr) {
        if (br != null) {
            try {
                br.close();
            } catch (IOException e) {
                logger.error("BufferedReader close error:", e);
            }
        }
        if (isr != null) {
            try {
                isr.close();
            } catch (IOException e) {
                logger.error("InputStreamReader close error:", e);
            }
        }
        if (fis != null) {
            try {
                fis.close();
            } catch (IOException e) {
                logger.error("FileInputStream close error:", e);
            }
        }
    }
}
