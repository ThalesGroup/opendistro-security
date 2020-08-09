package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationChangeListener;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.tasks.Task;

import java.util.Map;
import java.util.Set;

/**
 * @author Divyansh Jain
 */

public interface PrivilegesEvaluator extends ConfigurationChangeListener {

    PrivilegesEvaluatorResponse evaluate(final User user, String action0, final ActionRequest request, Task task);

    boolean isInitialized();

    Set<String> mapRoles(User user, TransportAddress remoteAddress);

    Map<String, Boolean> mapTenants(User user, Set<String> securityRoles);

    boolean notFailOnForbiddenEnabled();

    boolean multitenancyEnabled();

    String kibanaIndex();

    String kibanaServerUsername();

    Set<String> getAllConfiguredTenantNames();
}
