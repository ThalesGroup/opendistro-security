package com.amazon.opendistroforelasticsearch.security.privileges;


import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.ActionGroupHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

/**
 * @author Divyansh Jain
 */

public class GetEvaluatorFactory {

    public static Evaluator getEvaluator(ClusterService clusterService, ThreadPool threadPool, IndexBaseConfigurationRepository cr, ActionGroupHolder ah, IndexNameExpressionResolver resolver, AuditLog auditLog, Settings settings, PrivilegesInterceptor privilegesInterceptor, ClusterInfoHolder cih, IndexResolverReplacer irr, boolean advancedModulesEnabled) {
        if(settings.get(ConfigConstants.OPENDISTRO_SECURITY_EVALUATOR).equals("com.amazon.opendistroforelasticsearch.security.privileges")) {
            return new PrivilegesEvaluator(clusterService, threadPool, cr, ah, resolver, auditLog, settings, privilegesInterceptor, cih, irr, advancedModulesEnabled);
        }
        return null;
    }

}
