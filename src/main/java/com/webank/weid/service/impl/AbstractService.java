package com.webank.weid.service.impl;

import com.webank.weid.service.BaseService;
import com.webank.weid.service.impl.engine.AuthorityIssuerServiceEngine;
import com.webank.weid.service.impl.engine.CptServiceEngine;
import com.webank.weid.service.impl.engine.EngineFactory;
import com.webank.weid.service.impl.engine.RawTransactionServiceEngine;
import com.webank.weid.service.impl.engine.WeIdServiceEngine;
import com.webank.weid.suite.cache.CacheManager;

public abstract class AbstractService extends BaseService {
    
    protected static WeIdServiceEngine weIdServiceEngine;
    
    protected static RawTransactionServiceEngine rawEngine;
    
    protected static CptServiceEngine cptServiceEngine;
    
    protected static AuthorityIssuerServiceEngine authEngine;
    
    static {
        if (!fiscoConfig.checkAddress()) {
            reloadAddress();
        }
        weIdServiceEngine = EngineFactory.createWeIdServiceEngine();
        rawEngine = EngineFactory.createRawTransactionServiceEngine();
        cptServiceEngine = EngineFactory.createCptServiceEngine();
        authEngine = EngineFactory.createAuthorityIssuerServiceEngine();
    }
    
    public AbstractService() {
        super();
    }

    protected void reloadContract() {
        reloadAddress();
        weIdServiceEngine.reload();
        rawEngine.reload();
        cptServiceEngine.reload();
        authEngine.reload();
        //重载合约, 需要清理缓存，避免缓存问题
        CacheManager.clearAll();
    }
}
