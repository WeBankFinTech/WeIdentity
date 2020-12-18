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

package com.webank.weid.service.impl.engine;

import java.util.List;

import com.webank.weid.protocol.base.EvidenceInfo;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.ResponseData;

public interface EvidenceServiceEngine {

    ResponseData<String> createEvidence(
        String hashValue,
        String signature,
        String log,
        Long timestamp,
        WeIdPrivateKey privateKey
    );

    ResponseData<List<Boolean>> batchCreateEvidence(
        List<String> hashValues,
        List<String> signatures,
        List<String> logs,
        List<Long> timestamp,
        List<String> signers,
        WeIdPrivateKey privateKey
    );

    ResponseData<Boolean> addLog(
        String hashValue,
        String sig,
        String log,
        Long timestamp,
        WeIdPrivateKey privateKey
    );

    ResponseData<Boolean> addLogByCustomKey(
        String hashValue,
        String signature,
        String log,
        Long timestamp,
        String customKey,
        WeIdPrivateKey privateKey
    );

    ResponseData<String> getHashByCustomKey(String customKey);

    ResponseData<String> createEvidenceWithCustomKey(
        String hashValue,
        String signature,
        String log,
        Long timestamp,
        String customKey,
        WeIdPrivateKey privateKey
    );

    ResponseData<List<Boolean>> batchCreateEvidenceWithCustomKey(
        List<String> hashValues,
        List<String> signatures,
        List<String> logs,
        List<Long> timestamps,
        List<String> signers,
        List<String> customKeys,
        WeIdPrivateKey privateKey
    );

    ResponseData<EvidenceInfo> getInfo(String evidenceAddress);

    ResponseData<EvidenceInfo> getInfoByCustomKey(String extraKey);

    ResponseData<Boolean> setAttribute(
        String hashValue,
        String key,
        String value,
        Long timestamp,
        WeIdPrivateKey privateKey
    );
}
