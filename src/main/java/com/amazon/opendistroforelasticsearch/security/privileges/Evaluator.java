package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.ActionGroupHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationChangeListener;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.Map;
import java.util.Set;

/**
 * @author Divyansh Jain
 */

public interface Evaluator extends ConfigurationChangeListener {

    static Evaluator getEvaluator(ClusterService clusterService, ThreadPool threadPool, IndexBaseConfigurationRepository cr, ActionGroupHolder ah, IndexNameExpressionResolver resolver, AuditLog auditLog, Settings settings, PrivilegesInterceptor privilegesInterceptor, ClusterInfoHolder cih, IndexResolverReplacer irr, boolean advancedModulesEnabled) {
        if(settings.get(ConfigConstants.OPENDISTRO_SECURITY_EVALUATOR).equals("com.amazon.opendistroforelasticsearch.security.privileges")) {
            return new PrivilegesEvaluator(clusterService, threadPool, cr, ah, resolver, auditLog, settings, privilegesInterceptor, cih, irr, advancedModulesEnabled);
        }
        return null;
    }

    EvaluatorResponse evaluate(final User user, String action0, final ActionRequest request, Task task);

    boolean isInitialized();

    Set<String> mapRoles(User user, TransportAddress remoteAddress);

    Map<String, Boolean> mapTenants(User user, Set<String> securityRoles);

    boolean notFailOnForbiddenEnabled();

    boolean multitenancyEnabled();

    String kibanaIndex();

    String kibanaServerUsername();

    Set<String> getAllConfiguredTenantNames();
}
