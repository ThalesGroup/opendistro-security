package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Divyansh Jain
 */

public class RangerPrivilegesEvaluatorResponse implements EvaluatorResponse {
    boolean allowed = false;
    Set<String> missingPrivileges = new HashSet<String>();
    Map<String,Set<String>> allowedFlsFields;
    Map<String,Set<String>> maskedFields;
    Map<String,Set<String>> queries;
    PrivilegesEvaluatorResponse.PrivilegesEvaluatorResponseState state = PrivilegesEvaluatorResponse.PrivilegesEvaluatorResponseState.PENDING;

    RangerPrivilegesEvaluatorResponse() {}

    @Override
    public boolean isAllowed() {
        return allowed;
    }

    @Override
    public Map<String, Set<String>> getAllowedFlsFields() {
        return allowedFlsFields;
    }

    @Override
    public Map<String, Set<String>> getMaskedFields() {
        return maskedFields;
    }

    @Override
    public Map<String, Set<String>> getQueries() {
        return null;
    }

    @Override
    public Set<String> getMissingPrivileges() {
        return new HashSet<String>(missingPrivileges);
    }
}
