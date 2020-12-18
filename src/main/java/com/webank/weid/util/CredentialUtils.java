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

package com.webank.weid.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.datatypes.generated.Bytes32;

import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.CredentialConstant.CredentialProofType;
import com.webank.weid.constant.CredentialFieldDisclosureValue;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.CredentialWrapper;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CreateCredentialArgs;

/**
 * The Class CredentialUtils.
 *
 * @author chaoxinhu 2019.1
 */
public final class CredentialUtils {

    /**
     * Concat all fields of Credential info, without Proof, in Json format. This should be invoked
     * when calculating Credential Signature as the raw message. Return null if credential format is
     * illegal. The Json return value satisfy the following format: 1. Keys are dict-ordered; 2.
     * Claim comes from standard getClaimHash() to support selective disclosure; 3. Compact output
     * without any extra space or linebreaks, to avoid different Json format beautification.
     *
     * @param credential target Credential object
     * @param disclosures disclosures of the credential
     * @return Hash value in String.
     */
    public static String getCredentialThumbprintWithoutSig(
        Credential credential,
        Map<String, Object> disclosures) {
        try {
            Credential rawCredential = copyCredential(credential);
            rawCredential.setProof(null);
            return getCredentialThumbprint(rawCredential, disclosures);
        } catch (Exception e) {
            return StringUtils.EMPTY;
        }
    }

    /**
     * Check if the two credentials are equal. Will traverse each field.
     *
     * @param credOld first credential
     * @param credNew second credential
     * @return true if yes, false otherwise
     */
    public static boolean isEqual(Credential credOld, Credential credNew) {
        if (credOld == null && credNew == null) {
            return true;
        }
        if (credOld == null || credNew == null) {
            return false;
        }
        return credOld.getHash().equalsIgnoreCase(credNew.getHash())
            && credOld.getCptId().equals(credNew.getCptId())
            && credOld.getExpirationDate().equals(credNew.getExpirationDate())
            && credOld.getProof().equals(credNew.getProof())
            && credOld.getContext().equalsIgnoreCase(credNew.getContext())
            && credOld.getId().equalsIgnoreCase(credNew.getId())
            && credOld.getIssuanceDate().equals(credNew.getIssuanceDate())
            && credOld.getIssuer().equalsIgnoreCase(credNew.getIssuer());
    }

    /**
     * Build the credential Proof.
     *
     * @param credential the credential
     * @param privateKey the privatekey
     * @param disclosureMap the disclosureMap
     * @return the Proof structure
     */
    public static Map<String, String> buildCredentialProof(
        Credential credential,
        WeIdPrivateKey privateKey,
        Map<String, Object> disclosureMap) {
        Map<String, String> proof = new HashMap<>();
        proof.put(ParamKeyConstant.PROOF_CREATED, credential.getIssuanceDate().toString());
        proof.put(ParamKeyConstant.PROOF_CREATOR, credential.getIssuer());
        proof.put(ParamKeyConstant.PROOF_TYPE, getDefaultCredentialProofType());
        proof.put(ParamKeyConstant.CREDENTIAL_SIGNATURE,
            getCredentialSignature(credential, privateKey, disclosureMap));
        return proof;
    }

    /**
     * A clean deep copy method of a Credential which pays special attention on Map object. todo:
     * preserve the claim key order
     *
     * @param credential target Credential object
     * @return new credential
     */
    public static Credential copyCredential(Credential credential) {
        Credential ct = new Credential();
        ct.setContext(credential.getContext());

        Map<String, String> originalProof = credential.getProof();
        if (originalProof != null) {
            Map<String, String> proof = DataToolUtils
                .deserialize(DataToolUtils.serialize(originalProof), HashMap.class);
            ct.setProof(proof);
        }
        Map<String, Object> originalClaim = credential.getClaim();
        if (originalClaim != null) {
            Map<String, Object> claim = DataToolUtils
                .deserialize(DataToolUtils.serialize(originalClaim), HashMap.class);
            ct.setClaim(claim);
        }

        ct.setIssuanceDate(credential.getIssuanceDate());
        ct.setCptId(credential.getCptId());
        ct.setExpirationDate(credential.getExpirationDate());
        ct.setIssuer(credential.getIssuer());
        ct.setId(credential.getId());
        return ct;
    }


    /**
     * A clean deep copy method of a CredentialPojo which pays special attention on Map object.
     *
     * @param credentialPojo target CredentialPojo object
     * @return new credentialPojo
     */
    public static CredentialPojo copyCredential(CredentialPojo credentialPojo) {
        CredentialPojo cpj = new CredentialPojo();
        cpj.setContext(credentialPojo.getContext());
        cpj.setIssuanceDate(credentialPojo.getIssuanceDate());
        cpj.setCptId(credentialPojo.getCptId());
        cpj.setExpirationDate(credentialPojo.getExpirationDate());
        cpj.setIssuer(credentialPojo.getIssuer());
        cpj.setId(credentialPojo.getId());

        Map<String, Object> originalProof = credentialPojo.getProof();
        if (originalProof != null) {
            Map<String, Object> proof = DataToolUtils
                .deserialize(DataToolUtils.serialize(originalProof), HashMap.class);
            cpj.setProof(proof);
        }
        Map<String, Object> originalClaim = credentialPojo.getClaim();
        if (originalClaim != null) {
            Map<String, Object> claim = DataToolUtils
                .deserialize(DataToolUtils.serialize(originalClaim), HashMap.class);
            cpj.setClaim(claim);
        }
        List<String> originalType = credentialPojo.getType();
        if (originalType != null) {
            List<String> type = new ArrayList<>(originalType.size());
            if (originalType.size() > 0) {
                for (String originalTypeItem : originalType) {
                    type.add(originalTypeItem);
                }
            }
            cpj.setType(type);
        }

        return cpj;
    }

    /**
     * Concat all fields of Credential info, with signature. This should be invoked when calculating
     * credential hash value for Credential Evidence. Return null if credential format is illegal.
     * The Json return value satisfy the same standard as the thumbprint without signature.
     *
     * @param credential target Credential object
     * @param disclosures the disclosure map
     * @return Hash value in String.
     */
    public static String getCredentialThumbprint(
        Credential credential,
        Map<String, Object> disclosures) {
        try {
            Map<String, Object> credMap = DataToolUtils.objToMap(credential);
            String claimHash = getClaimHash(credential, disclosures);
            credMap.put(ParamKeyConstant.CLAIM, claimHash);
            return DataToolUtils.mapToCompactJson(credMap);
        } catch (Exception e) {
            return StringUtils.EMPTY;
        }
    }

    /**
     * Get the claim hash. This is irrelevant to selective disclosure.
     *
     * @param credential Credential
     * @param disclosures Disclosure Map
     * @return the unique claim hash value
     */
    public static String getClaimHash(Credential credential, Map<String, Object> disclosures) {

        Map<String, Object> claim = credential.getClaim();
        Map<String, Object> claimHashMap = new HashMap<>(claim);
        Map<String, Object> disclosureMap;

        if (disclosures == null) {
            disclosureMap = new HashMap<>(claim);
            for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
                disclosureMap.put(
                    entry.getKey(),
                    CredentialFieldDisclosureValue.DISCLOSED.getStatus()
                );
            }
        } else {
            disclosureMap = disclosures;
        }

        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            claimHashMap.put(entry.getKey(), getFieldHash(claimHashMap.get(entry.getKey())));
        }

        List<Map.Entry<String, Object>> list = new ArrayList<Map.Entry<String, Object>>(
            claimHashMap.entrySet()
        );
        Collections.sort(list, new Comparator<Map.Entry<String, Object>>() {

            @Override
            public int compare(Entry<String, Object> o1, Entry<String, Object> o2) {
                return o1.getKey().compareTo(o2.getKey());
            }
        });

        StringBuffer hash = new StringBuffer();
        for (Map.Entry<String, Object> en : list) {
            hash.append(en.getKey()).append(en.getValue());
        }
        return hash.toString();
    }

    /**
     * convert a field to hash.
     *
     * @param field which will be converted to hash.
     * @return hash value.
     */
    public static String getFieldHash(Object field) {
        return DataToolUtils.sha3(String.valueOf(field));
    }

    /**
     * Get default Credential Context String.
     *
     * @return Context value in String.
     */
    public static String getDefaultCredentialContext() {
        return CredentialConstant.DEFAULT_CREDENTIAL_CONTEXT;
    }

    /**
     * Extract GenerateCredentialArgs from Credential.
     *
     * @param arg the arg
     * @return GenerateCredentialArgs
     */
    public static CreateCredentialArgs extractCredentialMetadata(Credential arg) {
        if (arg == null) {
            return null;
        }
        CreateCredentialArgs generateCredentialArgs = new CreateCredentialArgs();
        generateCredentialArgs.setCptId(arg.getCptId());
        generateCredentialArgs.setIssuer(arg.getIssuer());
        generateCredentialArgs.setIssuanceDate(arg.getIssuanceDate());
        generateCredentialArgs.setExpirationDate(arg.getExpirationDate());
        generateCredentialArgs.setClaim(arg.getClaim());
        return generateCredentialArgs;
    }

    /**
     * Create the signature for this Credential. The original signature value, will be set empty
     * whether its original value is already empty or not. The rawData input for the signature
     * creation is the credential thumbprint result based on an empty signature value filled in.
     *
     * @param credential target credential object
     * @param privateKey the privatekey for signing
     * @param disclosureMap the disclosure map
     * @return the String signature value
     */
    public static String getCredentialSignature(
        Credential credential, 
        WeIdPrivateKey privateKey,
        Map<String, Object> disclosureMap
    ) {
        String rawData = CredentialUtils
            .getCredentialThumbprintWithoutSig(credential, disclosureMap);
        return DataToolUtils.secp256k1Sign(rawData, privateKey);
    }

    /**
     * Create a full Credential Hash for a Credential based on all its fields. This should be
     * invoked when getting Credential Evidence. Please note: the result is a String with fixed
     * length 66 bytes including the first two bytes ("0x") and 64 bytes Hash value.
     *
     * @param arg the args
     * @return Hash in byte array
     */
    public static String getCredentialHash(Credential arg) {
        String rawData = getCredentialThumbprint(arg, null);
        if (StringUtils.isEmpty(rawData)) {
            return StringUtils.EMPTY;
        }
        return DataToolUtils.sha3(rawData);
    }

    /**
     * Create a full CredentialWrapper Hash for a Credential based on all its fields, which is
     * resistant to selective disclosure.
     *
     * @param arg the args
     * @return Hash in byte array
     */
    public static String getCredentialWrapperHash(CredentialWrapper arg) {
        String rawData = getCredentialThumbprint(arg.getCredential(), arg.getDisclosure());
        if (StringUtils.isEmpty(rawData)) {
            return StringUtils.EMPTY;
        }
        return DataToolUtils.sha3(rawData);
    }

    /**
     * Convert a Credential ID to a Bytes32 object. The "-" connector will be removed.
     *
     * @param id the Credential id
     * @return a Bytes32 object
     */
    public static Bytes32 convertCredentialIdToBytes32(String id) {
        if (!isValidUuid(id)) {
            return new Bytes32(new byte[32]);
        }
        String mergedId = id.replaceAll(WeIdConstant.UUID_SEPARATOR, StringUtils.EMPTY);
        byte[] uuidBytes = mergedId.getBytes(StandardCharsets.UTF_8);
        return DataToolUtils.bytesArrayToBytes32(uuidBytes);
    }

    /**
     * Check whether the given String is a valid UUID.
     *
     * @param id the Credential id
     * @return true if yes, false otherwise
     */
    public static boolean isValidUuid(String id) {
        Pattern p = Pattern.compile(WeIdConstant.UUID_PATTERN);
        return p.matcher(id).matches();
    }

    /**
     * Check the given CreateCredentialArgs validity based on its input params.
     *
     * @param args CreateCredentialArgs
     * @return true if yes, false otherwise
     */
    public static ErrorCode isCreateCredentialArgsValid(
        CreateCredentialArgs args) {
        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (args.getCptId() == null || args.getCptId().intValue() < 0) {
            return ErrorCode.CPT_ID_ILLEGAL;
        }
        if (!WeIdUtils.isWeIdValid(args.getIssuer())) {
            return ErrorCode.CREDENTIAL_ISSUER_INVALID;
        }
        Long issuanceDate = args.getIssuanceDate();
        if (issuanceDate != null && issuanceDate <= 0) {
            return ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL;
        }
        Long expirationDate = args.getExpirationDate();
        if (expirationDate == null
            || expirationDate.longValue() < 0
            || expirationDate.longValue() == 0) {
            return ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL;
        }
        if (!DateUtils.isAfterCurrentTime(expirationDate)) {
            return ErrorCode.CREDENTIAL_EXPIRED;
        }
        if (issuanceDate != null && expirationDate < issuanceDate) {
            return ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL;
        }
        if (args.getClaim() == null || args.getClaim().isEmpty()) {
            return ErrorCode.CREDENTIAL_CLAIM_NOT_EXISTS;
        }
        return ErrorCode.SUCCESS;
    }

    /**
     * Check the given Credential validity based on its input params.
     *
     * @param args Credential
     * @return true if yes, false otherwise
     */
    public static ErrorCode isCredentialValid(Credential args) {
        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        CreateCredentialArgs createCredentialArgs = extractCredentialMetadata(args);
        ErrorCode metadataResponseData = isCreateCredentialArgsValid(createCredentialArgs);
        if (ErrorCode.SUCCESS.getCode() != metadataResponseData.getCode()) {
            return metadataResponseData;
        }
        ErrorCode contentResponseData = isCredentialContentValid(args);
        if (ErrorCode.SUCCESS.getCode() != contentResponseData.getCode()) {
            return contentResponseData;
        }
        return ErrorCode.SUCCESS;
    }

    /**
     * Check the given Credential content fields validity excluding metadata, based on its input.
     *
     * @param args Credential
     * @return true if yes, false otherwise
     */
    public static ErrorCode isCredentialContentValid(Credential args) {
        String credentialId = args.getId();
        if (StringUtils.isEmpty(credentialId) || !CredentialUtils.isValidUuid(credentialId)) {
            return ErrorCode.CREDENTIAL_ID_NOT_EXISTS;
        }
        String context = args.getContext();
        if (StringUtils.isEmpty(context)) {
            return ErrorCode.CREDENTIAL_CONTEXT_NOT_EXISTS;
        }
        Long issuanceDate = args.getIssuanceDate();
        if (issuanceDate == null) {
            return ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL;
        }
        if (issuanceDate.longValue() > args.getExpirationDate().longValue()) {
            return ErrorCode.CREDENTIAL_EXPIRED;
        }
        Map<String, String> proof = args.getProof();
        return isCredentialProofValid(proof);
    }

    private static ErrorCode isCredentialProofValid(Map<String, String> proof) {
        if (proof == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        String type = proof.get(ParamKeyConstant.PROOF_TYPE);
        if (!isCredentialProofTypeValid(type)) {
            return ErrorCode.CREDENTIAL_SIGNATURE_TYPE_ILLEGAL;
        }
        // Created is not obligatory
        Long created = Long.valueOf(proof.get(ParamKeyConstant.PROOF_CREATED));
        if (created.longValue() <= 0) {
            return ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL;
        }
        // Creator is not obligatory either
        String creator = proof.get(ParamKeyConstant.PROOF_CREATOR);
        if (!StringUtils.isEmpty(creator) && !WeIdUtils.isWeIdValid(creator)) {
            return ErrorCode.CREDENTIAL_ISSUER_INVALID;
        }
        // If the Proof type is ECDSA or other signature based scheme, check signature
        if (type.equalsIgnoreCase(CredentialProofType.ECDSA.getTypeName())) {
            String signature = proof.get(ParamKeyConstant.CREDENTIAL_SIGNATURE);
            if (StringUtils.isEmpty(signature) || !DataToolUtils.isValidBase64String(signature)) {
                return ErrorCode.CREDENTIAL_SIGNATURE_BROKEN;
            }
        }
        return ErrorCode.SUCCESS;
    }

    /**
     * Get default Credential Credential Proof Type String.
     *
     * @return Context value in String.
     */
    public static String getDefaultCredentialProofType() {
        return CredentialConstant.CredentialProofType.ECDSA.getTypeName();
    }

    private static boolean isCredentialProofTypeValid(String type) {
        // Proof type must be one of the pre-defined types.
        if (!StringUtils.isEmpty(type)) {
            for (CredentialProofType proofType : CredentialConstant.CredentialProofType.values()) {
                if (StringUtils.equalsIgnoreCase(type, proofType.getTypeName())) {
                    return true;
                }
            }
        }
        return false;
    }
}
