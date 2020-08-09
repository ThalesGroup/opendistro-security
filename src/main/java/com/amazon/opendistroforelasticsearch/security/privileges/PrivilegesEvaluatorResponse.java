package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.Map;
import java.util.Set;

/**
 * @author Divyansh Jain
 */

public interface PrivilegesEvaluatorResponse {

    boolean isAllowed();

    Map<String, Set<String>> getAllowedFlsFields();

    Map<String, Set<String>> getMaskedFields();

    Map<String, Set<String>> getQueries();

    Set<String> getMissingPrivileges();
}