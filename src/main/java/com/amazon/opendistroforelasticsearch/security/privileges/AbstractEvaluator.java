package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationChangeListener;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.MultimapBuilder;
import com.google.common.collect.SetMultimap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;

import java.util.*;
import java.util.concurrent.*;

/**
 * @author Divyansh Jain
 */

public abstract class AbstractEvaluator implements Evaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ConfigurationRepository configurationRepository;
    private PrivilegesInterceptor privilegesInterceptor;
    private ConfigConstants.RolesMappingResolution rolesMappingResolution;
    private RoleMappingHolder roleMappingHolder = null;
    private TenantHolder tenantHolder = null;

    protected AbstractEvaluator(ConfigurationRepository configurationRepository, PrivilegesInterceptor privilegesInterceptor) {
        this.configurationRepository = configurationRepository;
        this.privilegesInterceptor = privilegesInterceptor;
    }

    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("opendistro_security.dynamic.kibana.multitenancy_enabled", true);
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("opendistro_security.dynamic.kibana.do_not_fail_on_forbidden", false);
    }

    public String kibanaIndex() {
        return getConfigSettings().get("opendistro_security.dynamic.kibana.index",".kibana");
    }

    public String kibanaServerUsername() {
        return getConfigSettings().get("opendistro_security.dynamic.kibana.server_username","kibanaserver");
    }

    public Settings getRolesSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES);
    }

    public Settings getConfigSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_CONFIG);
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.roleMappingHolder.map(user, caller);
    }

    public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {
        return this.tenantHolder.mapTenants(user, roles);
    }

    public Set<String> getAllConfiguredTenantNames() {

        final Settings roles = getRolesSettings();

        if(roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }

        final Set<String> configuredTenants = new HashSet<>();
        for(String securityRole: roles.names()) {
            Settings tenants = roles.getByPrefix(securityRole+".tenants.");

            if(tenants != null) {
                configuredTenants.addAll(tenants.names());
            }

        }

        return Collections.unmodifiableSet(configuredTenants);
    }

    private class TenantHolder implements ConfigurationChangeListener {

        private SetMultimap<String, Tuple<String, Boolean>> tenantsMM = null;

        public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {

            if (user == null || tenantsMM == null) {
                return Collections.emptyMap();
            }

            final Map<String, Boolean> result = new HashMap<>(roles.size());
            result.put(user.getName(), true);

            tenantsMM.entries().stream().filter(e -> roles.contains(e.getKey())).filter(e -> !user.getName().equals(e.getValue().v1())).forEach(e -> {
                final String tenant = e.getValue().v1();
                final boolean rw = e.getValue().v2();

                if (rw || !result.containsKey(tenant)) { //RW outperforms RO
                    result.put(tenant, rw);
                }
            });
            return Collections.unmodifiableMap(result);
        }

        @Override
        public void onChange(Settings roles) {

            final Set<Future<Tuple<String, Set<Tuple<String, Boolean>>>>> futures = new HashSet<>(roles.size());

            final ExecutorService execs = Executors.newFixedThreadPool(10);

            for (String role : roles.names()) {

                Future<Tuple<String, Set<Tuple<String, Boolean>>>> future = execs.submit(new Callable<Tuple<String, Set<Tuple<String, Boolean>>>>() {
                    @Override
                    public Tuple<String, Set<Tuple<String, Boolean>>> call() throws Exception {
                        final Set<Tuple<String, Boolean>> tuples = new HashSet<>();
                        final Settings tenants = getRolesSettings().getByPrefix(role + ".tenants.");

                        if (tenants != null) {
                            for (String tenant : tenants.names()) {

                                if ("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                                    //RW
                                    tuples.add(new Tuple<String, Boolean>(tenant, true));
                                } else {
                                    //RO
                                    //if(!tenantsMM.containsValue(value)) { //RW outperforms RO
                                    tuples.add(new Tuple<String, Boolean>(tenant, false));
                                    //}
                                }
                            }
                        }

                        return new Tuple<String, Set<Tuple<String, Boolean>>>(role, tuples);
                    }
                });

                futures.add(future);

            }

            execs.shutdown();
            try {
                execs.awaitTermination(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (1) while loading roles");
                return;
            }

            try {
                final SetMultimap<String, Tuple<String, Boolean>> tenantsMM_ = MultimapBuilder.SetMultimapBuilder.hashKeys(futures.size()).hashSetValues(16).build();

                for (Future<Tuple<String, Set<Tuple<String, Boolean>>>> future : futures) {
                    Tuple<String, Set<Tuple<String, Boolean>>> result = future.get();
                    tenantsMM_.putAll(result.v1(), result.v2());
                }

                tenantsMM = tenantsMM_;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (2) while loading roles");
                return;
            } catch (ExecutionException e) {
                log.error("Error while updating roles: {}", e.getCause(), e.getCause());
                throw ExceptionsHelper.convertToElastic(e);
            }

        }
    }

    private class RoleMappingHolder {

        private ListMultimap<String, String> users;
        private ListMultimap<Set<String>, String> abars;
        private ListMultimap<String, String> bars;
        private ListMultimap<String, String> hosts;

        private RoleMappingHolder(Settings rolesMapping) {

            if (rolesMapping != null) {

                final ListMultimap<String, String> users_ = ArrayListMultimap.create();
                final ListMultimap<Set<String>, String> abars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> bars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> hosts_ = ArrayListMultimap.create();

                for (final String roleMap : rolesMapping.names()) {

                    final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);

                    for (String u : roleMapSettings.getAsList(".users")) {
                        users_.put(u, roleMap);
                    }

                    final Set<String> abar = new HashSet<String>(roleMapSettings.getAsList(".and_backendroles"));

                    if (!abar.isEmpty()) {
                        abars_.put(abar, roleMap);
                    }

                    for (String bar : roleMapSettings.getAsList(".backendroles")) {
                        bars_.put(bar, roleMap);
                    }

                    for (String host : roleMapSettings.getAsList(".hosts")) {
                        hosts_.put(host, roleMap);
                    }
                }

                users = users_;
                abars = abars_;
                bars = bars_;
                hosts = hosts_;
            }
        }

        private Set<String> map(final User user, final TransportAddress caller) {

            if (user == null || users == null || abars == null || bars == null || hosts == null) {
                return Collections.emptySet();
            }

            final Set<String> securityRoles = new TreeSet<String>();

            if (rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
                if (log.isDebugEnabled()) {
                    log.debug("Pass backendroles from {}", user);
                }
                securityRoles.addAll(user.getRoles());
            }

            if (((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {

                for (String p : WildcardMatcher.getAllMatchingPatterns(users.keySet(), user.getName())) {
                    securityRoles.addAll(users.get(p));
                }

                for (String p : WildcardMatcher.getAllMatchingPatterns(bars.keySet(), user.getRoles())) {
                    securityRoles.addAll(bars.get(p));
                }

                for (Set<String> p : abars.keySet()) {
                    if (WildcardMatcher.allPatternsMatched(p, user.getRoles())) {
                        securityRoles.addAll(abars.get(p));
                    }
                }

                if (caller != null) {
                    //IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();

                    for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), ipAddress)) {
                        securityRoles.addAll(hosts.get(p));
                    }

                    final String hostResolverMode = getConfigSettings().get("opendistro_security.dynamic.hosts_resolver_mode", "ip-only");

                    if (caller.address() != null
                            && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))) {
                        final String hostName = caller.address().getHostString();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), hostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }

                    if (caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")) {

                        final String resolvedHostName = caller.address().getHostName();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), resolvedHostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }
                }
            }

            return Collections.unmodifiableSet(securityRoles);

        }
    }


}
