package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationChangeListener;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.tasks.Task;

/**
 * @author Divyansh Jain
 */

public interface Evaluator extends ConfigurationChangeListener {

    EvaluatorResponse evaluate(final User user, String action0, final ActionRequest request, Task task);

    boolean isInitialized();
}
