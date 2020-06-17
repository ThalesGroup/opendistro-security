/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.ldap.util;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.*;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import joptsimple.internal.Strings;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.ldaptive.Connection;
import org.ldaptive.DerefAliases;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResult;
import org.ldaptive.SearchScope;
import org.ldaptive.referral.SearchReferralHandler;

public class LdapHelper {

    private static SearchFilter ALL = new SearchFilter("(objectClass=*)");
    public static List<LdapEntry> search(final Connection conn, final String unescapedDn, SearchFilter filter,
            final SearchScope searchScope) throws LdapException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            final String baseDn = escapeDn(unescapedDn);
            return AccessController.doPrivileged(new PrivilegedExceptionAction<List<LdapEntry>>() {
                @Override
                public List<LdapEntry> run() throws Exception {
                    final List<LdapEntry> entries = new ArrayList<>();
                    final SearchRequest request = new SearchRequest(baseDn, filter);
                    request.setReferralHandler(new SearchReferralHandler());
                    request.setSearchScope(searchScope);
                    request.setDerefAliases(DerefAliases.ALWAYS);
                    request.setReturnAttributes(ReturnAttributes.ALL.value());
                    final SearchOperation search = new SearchOperation(conn);
                    // referrals will be followed to build the response
                    final Response<SearchResult> r = search.execute(request);
                    final org.ldaptive.SearchResult result = r.getResult();
                    entries.addAll(result.getEntries());
                    return entries;
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getException() instanceof LdapException) {
                throw (LdapException) e.getException();
            } else if (e.getException() instanceof RuntimeException) {
                throw (RuntimeException) e.getException();
            } else {
                throw new RuntimeException(e);
            }
        }catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }
    }

    public static LdapEntry lookup(final Connection conn, final String unescapedDn) throws LdapException {

        final List<LdapEntry> entries = search(conn, unescapedDn, ALL, SearchScope.OBJECT);

        if (entries.size() == 1) {
            return entries.get(0);
        } else {
            return null;
        }
    }

    private static String escapeDn(String dn) throws InvalidNameException {
        final LdapName dnName = new LdapName(dn);
        final List<Rdn> escaped = new ArrayList<>(dnName.size());
        for(Rdn rdn: dnName.getRdns()) {
            escaped.add(new Rdn(rdn.getType(), escapeForwardSlash(rdn.getValue())));
        }
        return new LdapName(escaped).toString();
    }

    private static Object escapeForwardSlash(Object input) {
        if(input != null && input instanceof String) {
            return ((String)input).replace("/", "\\2f");
        } else {
            return input;
        }

    }

    public static Set<String> findUserGroup(Settings settings, String key) {
        String ldapServer = settings.getAsList(ConfigConstants.LDAP_HOSTS).get(0);
        if (Strings.isNullOrEmpty(ldapServer)) {
            return null;
        }

        String bindUserDn = settings.get(ConfigConstants.LDAP_BIND_DN);
        String passwd = settings.get(ConfigConstants.LDAP_PASSWORD);

        String userBase = settings.get(ConfigConstants.LDAP_AUTHC_USERBASE);
        String userSearchFilter = settings.get(ConfigConstants.LDAP_AUTHC_USERSEARCH);
        String userGroupAttribute = settings.get(ConfigConstants.LDAP_USER_GROUP_ATTR);

        String groupBase = settings.get(ConfigConstants.LDAP_GROUP_BASE);
        String groupSearchFilter = settings.get(ConfigConstants.LDAP_GROUP_SEARCH);
        String groupNameAttribute = settings.get(ConfigConstants.LDAP_GROUP_NAME_ATTR);

        String userToBeSearched = key;

        String userSearchDn = userBase.replaceAll("\\{0\\}", userToBeSearched);
        String userSearchFilterDn = userSearchFilter.replaceAll("\\{0\\}", userToBeSearched);

        Properties props = new Properties();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapServer);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, bindUserDn);
        props.put(Context.SECURITY_CREDENTIALS, passwd);

        DirContext ctx = null;
        NamingEnumeration<javax.naming.directory.SearchResult> results = null;
        Set<String> res = new HashSet<String>();
        Set<String> userGrpRes = new HashSet<String>();

        try {

            //ctx = new InitialDirContext(props);
            ctx = new InitialDirContext(props);
            String grpId = null;
            boolean gidFlag = false;

            if (!Strings.isNullOrEmpty(userGroupAttribute)) {
                SearchControls controls = new SearchControls();
                String[] attrIDs = { userGroupAttribute };
                controls.setReturningAttributes(attrIDs);
                controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

                results = ctx.search(userSearchDn, userSearchFilterDn, controls);
                Attribute gid = null;
                while (results.hasMore()) {
                    javax.naming.directory.SearchResult searchResult = (javax.naming.directory.SearchResult) results.next();
                    Attributes attributes = searchResult.getAttributes();
                    gid = attributes.get(userGroupAttribute);
                    break;
                }
                if (gid != null) {
                    if (userGroupAttribute.equalsIgnoreCase("gidNumber")) {
                        grpId = gid.get().toString();
                        userGrpRes.add(grpId);
                    } else {
                        for (int i = 0; i < gid.size(); i++) {
                            String grpDnName = gid.get(i).toString();
                            userGrpRes.add(grpDnName);
                        }
                    }
                }
                gidFlag = true;
            }
            if (!Strings.isNullOrEmpty(groupBase)) {
                String grpSearchDn1 = groupBase.replaceAll("\\{0\\}", userToBeSearched);
                String grpSearchFilterDn1 = groupSearchFilter.replaceAll("\\{0\\}", userToBeSearched);
                SearchControls grpCtrls = new SearchControls();
                String[] attrID1 = { userGroupAttribute, groupNameAttribute };
                grpCtrls.setReturningAttributes(attrID1);
                grpCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);

                if (gidFlag) {
                    Iterator<String> iter = userGrpRes.iterator();
                    while (iter.hasNext()) {
                        String usrGrpVal = iter.next();
                        String grpSearchDn = grpSearchDn1.replaceAll("\\{1\\}", usrGrpVal);
                        String grpSearchFilterDn = grpSearchFilterDn1.replaceAll("\\{1\\}", usrGrpVal);

                        results = ctx.search(grpSearchDn, grpSearchFilterDn, grpCtrls);
                        while (results.hasMore()) {
                            javax.naming.directory.SearchResult searchResult = (javax.naming.directory.SearchResult) results.next();
                            Attributes attributes = searchResult.getAttributes();
                            Attribute grpName = attributes.get(groupNameAttribute);
                            if (grpName != null) {
                                System.out.println("Found group name = " + grpName.get().toString());
                                res.add(grpName.get().toString());
                            }
                        }
                    }
                } else {
                    results = ctx.search(grpSearchDn1, grpSearchFilterDn1, grpCtrls);
                    while (results.hasMore()) {
                        javax.naming.directory.SearchResult searchResult = (javax.naming.directory.SearchResult) results.next();
                        Attributes attributes = searchResult.getAttributes();
                        Attribute grpName = attributes.get(groupNameAttribute);
                        if (grpName != null) {
                            System.out.println("Found group name = " + grpName.get().toString());
                            res.add(grpName.get().toString());
                        }
                    }
                }
            } else {
                res = userGrpRes;
            }
        } catch (Exception e) {
            System.out.println("Error in querying ldap : " + e.getMessage());
        }
        finally {
            try {
                //results.close();
                ctx.close(); } catch(Exception ex) { }
        }
        return res;
    }

}
