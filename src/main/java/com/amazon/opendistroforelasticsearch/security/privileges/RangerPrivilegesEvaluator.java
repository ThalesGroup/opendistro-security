package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.ActionGroupHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.UserGroupMappingCache;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.base.Strings;
import com.kerb4j.client.SpnegoClient;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import javax.security.auth.Subject;
import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.Set;

/**
 * @author Divyansh Jain
 */

public class RangerPrivilegesEvaluator implements Evaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    public static final String ACCESS_TYPE_READ = "read";
    public static final String ACCESS_TYPE_WRITE = "write";
    public static final String ACCESS_TYPE_ADMIN = "es_admin";

    protected final Logger actionTrace = LogManager.getLogger("opendistro_security_action_trace");
    private final ClusterService clusterService;

    private final IndexNameExpressionResolver resolver;

    private final AuditLog auditLog;
    private ThreadContext threadContext;
    //private final static IndicesOptions DEFAULT_INDICES_OPTIONS = IndicesOptions.lenientExpandOpen();
    private final ConfigurationRepository configurationRepository;

    private PrivilegesInterceptor privilegesInterceptor;

    private final boolean checkSnapshotRestoreWritePrivileges;

    private ConfigConstants.RolesMappingResolution rolesMappingResolution;

    private final ClusterInfoHolder clusterInfoHolder;
    //private final boolean typeSecurityDisabled = false;
    private final ConfigModel configModel;
    private final IndexResolverReplacer irr;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final OpenDistroSecurityIndexAccessEvaluator securityIndexAccessEvaluator;
    private final OpenDistroProtectedIndexAccessEvaluator protectedIndexAccessEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;

    private final DlsFlsEvaluator dlsFlsEvaluator;

    // private PrivilegesEvaluator.RoleMappingHolder roleMappingHolder = null;
    // private PrivilegesEvaluator.TenantHolder tenantHolder = null;

    private final boolean advancedModulesEnabled;

    private static volatile RangerBasePlugin rangerPlugin = null;
    private String rangerUrl = null;
    private UserGroupMappingCache usrGrpCache = null;
    private boolean initUGI = false;

    public RangerPrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool,
                                     final ConfigurationRepository configurationRepository, final ActionGroupHolder ah, final IndexNameExpressionResolver resolver,
                                     AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor, final ClusterInfoHolder clusterInfoHolder,
                                     final IndexResolverReplacer irr, boolean advancedModulesEnabled) {

        super();
        this.configurationRepository = configurationRepository;
        this.clusterService = clusterService;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.privilegesInterceptor = privilegesInterceptor;

        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(settings.get(ConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString()).toUpperCase());
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution",e);
            rolesMappingResolution =  ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }

        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);

        this.clusterInfoHolder = clusterInfoHolder;
        //this.typeSecurityDisabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_DISABLE_TYPE_SECURITY, false);
        configModel = new ConfigModel(ah);
        configurationRepository.subscribeOnChange("roles", configModel);
        configurationRepository.subscribeOnChange("rolesmapping", this);
        this.irr = irr;
        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, auditLog);
        securityIndexAccessEvaluator = new OpenDistroSecurityIndexAccessEvaluator(settings, auditLog);
        protectedIndexAccessEvaluator = new OpenDistroProtectedIndexAccessEvaluator(settings, auditLog);
        dlsFlsEvaluator = new DlsFlsEvaluator(settings, threadPool);
        termsAggregationEvaluator = new TermsAggregationEvaluator();

        //tenantHolder = new PrivilegesEvaluator.TenantHolder();
        //configurationRepository.subscribeOnChange("roles", tenantHolder);

        this.advancedModulesEnabled = advancedModulesEnabled;

        String ES_PLUGIN_APP_ID = settings.get(ConfigConstants.OPENDISTRO_SECURITY_RANGER_AUTH_APP_ID);

        if (ES_PLUGIN_APP_ID == null) {
            throw new ElasticsearchSecurityException("Open Distro Ranger plugin enabled but appId config not valid");
        }

        if (!initializeUGI(settings)) {
            log.error("UGI not getting initialized.");
        }

        configureRangerPlugin(settings);
        usrGrpCache = new UserGroupMappingCache();
        usrGrpCache.init();

    }

    public void configureRangerPlugin(Settings settings) {
        String svcType = settings.get(ConfigConstants.OPENDISTRO_AUTH_RANGER_SERVICE_TYPE, "elasticsearch");
        String appId = settings.get(ConfigConstants.OPENDISTRO_AUTH_RANGER_APP_ID);

        RangerBasePlugin me = rangerPlugin;
        if (me == null) {
            synchronized(PrivilegesEvaluator.class) {
                me = rangerPlugin;
                if (me == null) {
                    me = rangerPlugin = new RangerBasePlugin(svcType, appId);
                }
            }
        }
        log.debug("Calling ranger plugin init");
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                ClassLoader cl = org.apache.ranger.authorization.hadoop.config.RangerConfiguration.class.getClassLoader();
                URL[] urls = ((URLClassLoader)cl).getURLs();
                String pluginPath = null;
                for(URL url: urls){
                    String urlFile = url.getFile();
                    int idx = urlFile.indexOf("ranger-plugins-common");
                    if (idx != -1) {
                        pluginPath = urlFile.substring(0, idx);
                    }
                }

                try {
                    Method method = URLClassLoader.class.getDeclaredMethod("addURL", new Class[]{URL.class});
                    method.setAccessible(true);
                    String rangerResourcesPath = pluginPath + "resources/";
                    method.invoke(cl, new Object[]{new File(rangerResourcesPath).toURI().toURL()});
                } catch (Exception e) {
                    log.error("Error in adding ranger config files to classpath : " + e.getMessage());
                    if (log.isDebugEnabled()) {
                        e.printStackTrace();
                    }
                }
                rangerPlugin.init();
                return null;
            }
        });
        this.rangerUrl = RangerConfiguration.getInstance().get("ranger.plugin.elasticsearch.policy.rest.url");
        log.debug("Ranger uri : " + rangerUrl);
        RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
        rangerPlugin.setResultProcessor(auditHandler);
    }

    public boolean initializeUGI(Settings settings) {
        if (initUGI) {
            return true;
        }

        String svcName = settings.get(ConfigConstants.OPENDISTRO_KERBEROS_ACCEPTOR_PRINCIPAL);
        String keytabPath = settings.get(ConfigConstants.OPENDISTRO_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH,
                HTTPSpnegoAuthenticator.SERVER_KEYTAB_PATH);
        String krbConf = settings.get(ConfigConstants.OPENDISTRO_KERBEROS_KRB5_FILEPATH,
                HTTPSpnegoAuthenticator.KRB5_CONF);

        if (Strings.isNullOrEmpty(svcName)) {
            log.error("Acceptor kerberos principal is empty or null");
            return false;
        }

        HTTPSpnegoAuthenticator.initSpnegoClient(svcName, keytabPath, krbConf);

        SpnegoClient spnegoClient = HTTPSpnegoAuthenticator.getSpnegoClient();

        if (spnegoClient == null) {
            log.error("Spnego client not initialized");
            return false;
        }

        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        initUGI = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            public Boolean run() {
                Subject subject = spnegoClient.getSubject();

                try {
                    UserGroupInformation ugi = MiscUtil.createUGIFromSubject(subject);
                    if (ugi != null) {
                        MiscUtil.setUGILoginUser(ugi, subject);
                    } else {
                        log.error("Unable to initialize UGI");
                        return false;
                    }
                } catch (Throwable t) {
                    log.error("Exception while trying to initialize UGI: " + t.getMessage());
                    return false;
                }
                return true;
            }
        });

        return initUGI;
    }

    @Override
    public EvaluatorResponse evaluate(User user, String action0, ActionRequest request, Task task) {
        return null;
    }

    @Override
    public boolean isInitialized() {
        return false;
    }

    @Override
    public Set<String> mapRoles(User user, TransportAddress remoteAddress) {
        return null;
    }

    @Override
    public Map<String, Boolean> mapTenants(User user, Set<String> securityRoles) {
        return null;
    }

    @Override
    public boolean notFailOnForbiddenEnabled() {
        return false;
    }

    @Override
    public boolean multitenancyEnabled() {
        return false;
    }

    @Override
    public String kibanaIndex() {
        return null;
    }

    @Override
    public String kibanaServerUsername() {
        return null;
    }

    @Override
    public Set<String> getAllConfiguredTenantNames() {
        return null;
    }

    @Override
    public void onChange(Settings configuration) {

    }
}
