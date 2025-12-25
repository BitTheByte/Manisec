package com.manifestsecurity.rules;

import com.manifestsecurity.manifest.ComponentInfo;
import com.manifestsecurity.manifest.ComponentType;
import com.manifestsecurity.manifest.IntentDataInfo;
import com.manifestsecurity.manifest.IntentFilterInfo;
import com.manifestsecurity.manifest.ManifestModel;
import com.manifestsecurity.manifest.ManifestNode;
import com.manifestsecurity.manifest.PermissionInfo;
import com.manifestsecurity.manifest.QueryInfo;
import com.manifestsecurity.manifest.QueryIntentInfo;
import com.manifestsecurity.manifest.QueryPackageInfo;
import com.manifestsecurity.manifest.QueryProviderInfo;
import com.manifestsecurity.manifest.UsesPermissionInfo;
import com.manifestsecurity.manifest.UsesSdkInfo;
import com.manifestsecurity.report.Confidence;
import com.manifestsecurity.report.EvidenceItem;
import com.manifestsecurity.report.Finding;
import com.manifestsecurity.report.Reference;
import com.manifestsecurity.report.Severity;
import com.manifestsecurity.util.Levenshtein;
import com.manifestsecurity.util.PermissionCatalog;
import com.manifestsecurity.util.RuleUtil;
import com.manifestsecurity.util.StringUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class RuleRegistry {
    private static final List<ManifestRule> RULES = buildRules();

    private static final Reference REF_MANIFEST = new Reference("Android Manifest", "https://developer.android.com/guide/topics/manifest/manifest-intro");
    private static final Reference REF_APPLICATION = new Reference("Application Element", "https://developer.android.com/guide/topics/manifest/application-element");
    private static final Reference REF_ACTIVITY = new Reference("Activity Element", "https://developer.android.com/guide/topics/manifest/activity-element");
    private static final Reference REF_SERVICE = new Reference("Service Element", "https://developer.android.com/guide/topics/manifest/service-element");
    private static final Reference REF_RECEIVER = new Reference("Receiver Element", "https://developer.android.com/guide/topics/manifest/receiver-element");
    private static final Reference REF_PROVIDER = new Reference("Provider Element", "https://developer.android.com/guide/topics/manifest/provider-element");
    private static final Reference REF_PERMISSIONS = new Reference("Permissions Overview", "https://developer.android.com/guide/topics/permissions/overview");
    private static final Reference REF_PERMISSION_LEVELS = new Reference("Protection Levels", "https://developer.android.com/guide/topics/manifest/permission-element#plevel");
    private static final Reference REF_EXPORTED_12 = new Reference("Android 12 Exported", "https://developer.android.com/about/versions/12/behavior-changes-12#exported");
    private static final Reference REF_NETWORK_CONFIG = new Reference("Network Security Config", "https://developer.android.com/training/articles/security-config");
    private static final Reference REF_APP_LINKS = new Reference("App Links", "https://developer.android.com/training/app-links");
    private static final Reference REF_QUERIES = new Reference("Package Visibility", "https://developer.android.com/training/package-visibility/declaring");
    private static final Reference REF_SDK = new Reference("Uses SDK", "https://developer.android.com/guide/topics/manifest/uses-sdk-element");
    private static final Reference REF_STORAGE = new Reference("Scoped Storage", "https://developer.android.com/about/versions/11/privacy/storage#scoped-storage");
    private static final Reference REF_OWASP_MASVS = new Reference("OWASP MASVS", "https://github.com/OWASP/owasp-masvs");
    private static final Reference REF_OWASP_MSTG = new Reference("OWASP MSTG", "https://github.com/OWASP/owasp-mstg");

    private RuleRegistry() {
    }

    public static List<ManifestRule> allRules() {
        return RULES;
    }

    private static List<ManifestRule> buildRules() {
        List<ManifestRule> rules = new ArrayList<>();
        addExportedRules(rules);
        addIntentFilterRules(rules);
        addPermissionRules(rules);
        addNetworkRules(rules);
        addDebugBackupRules(rules);
        addSdkRules(rules);
        addQueriesRules(rules);
        addMiscRules(rules);
        return Collections.unmodifiableList(rules);
    }

    private static void addExportedRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.EXPORTED.ACTIVITY.NO_PERMISSION", "Exported activity without permission", "Exported",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        if (RuleUtil.isExported(component) && isEmpty(component.getAttribute("android:permission"))) {
                            Severity severity = Severity.MEDIUM;
                            Confidence confidence = RuleUtil.hasExplicitExported(component) ? Confidence.HIGH : Confidence.MEDIUM;
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:exported", component.getAttribute("android:exported"), "");
                            Finding finding = RuleSupport.buildFinding(rule, severity, confidence,
                                    "Activity is exported without an access-control permission.",
                                    "Any app can invoke the activity and reach internal screens.",
                                    "Set android:exported=\"false\" or require a permission.",
                                    refs(REF_ACTIVITY, REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.EXPORTED.ACTIVITY.MISSING_ATTR", "Activity missing android:exported", "Exported",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        if (!RuleUtil.hasExplicitExported(component) && component.hasIntentFilter()) {
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:exported", "", "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                    "Activity has intent-filters but missing android:exported.",
                                    "Android 12+ requires explicit exported; behavior may change or build may fail.",
                                    "Set android:exported=\"false\" or \"true\" explicitly.",
                                    refs(REF_EXPORTED_12, REF_ACTIVITY), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.EXPORTED.SERVICE.NO_PERMISSION", "Exported service without permission", "Exported",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (component.getType() != ComponentType.SERVICE) {
                            continue;
                        }
                        if (RuleUtil.isExported(component) && isEmpty(component.getAttribute("android:permission"))) {
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:exported", component.getAttribute("android:exported"), "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.HIGH,
                                    "Service is exported without a permission guard.",
                                    "External apps can start or bind to the service.",
                                    "Set android:exported=\"false\" or require a permission.",
                                    refs(REF_SERVICE, REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.EXPORTED.RECEIVER.NO_PERMISSION", "Exported receiver without permission", "Exported",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (component.getType() != ComponentType.RECEIVER) {
                            continue;
                        }
                        if (RuleUtil.isExported(component) && isEmpty(component.getAttribute("android:permission"))) {
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:exported", component.getAttribute("android:exported"), "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.HIGH,
                                    "Broadcast receiver is exported without a permission guard.",
                                    "External apps can trigger the receiver and invoke sensitive flows.",
                                    "Set android:exported=\"false\" or protect with a permission.",
                                    refs(REF_RECEIVER, REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.EXPORTED.PROVIDER.RISKY", "Exported provider is not protected", "Exported",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (component.getType() != ComponentType.PROVIDER) {
                            continue;
                        }
                        if (!RuleUtil.isExported(component)) {
                            continue;
                        }
                        String perm = component.getAttribute("android:permission");
                        String readPerm = component.getAttribute("android:readPermission");
                        String writePerm = component.getAttribute("android:writePermission");
                        String grant = component.getAttribute("android:grantUriPermissions");
                        boolean missingPerms = isEmpty(perm) && isEmpty(readPerm) && isEmpty(writePerm);
                        boolean grantUris = StringUtil.isTrue(grant);
                        if (missingPerms || grantUris) {
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:exported", component.getAttribute("android:exported"), "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.HIGH,
                                    "Content provider is exported without strict permissions or grants URI permissions.",
                                    "Data exposure via content URIs may be possible.",
                                    "Set android:exported=\"false\" or require read/write permissions.",
                                    refs(REF_PROVIDER, REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.PROVIDER.AUTHORITIES.WEAK", "Provider authorities are guessable", "Exported",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    String pkg = model.getPackageName();
                    for (ComponentInfo component : model.getComponents()) {
                        if (component.getType() != ComponentType.PROVIDER) {
                            continue;
                        }
                        String authorities = component.getAttribute("android:authorities");
                        if (authorities.isEmpty()) {
                            continue;
                        }
                        String[] parts = authorities.split(";");
                        for (String auth : parts) {
                            String trimmed = auth.trim();
                            if (trimmed.isEmpty()) {
                                continue;
                            }
                            boolean weak = trimmed.equals(pkg) || trimmed.length() < 8 || !trimmed.contains(".");
                            if (weak) {
                                EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                        "android:authorities", trimmed, "");
                                Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                        "Provider authorities appear guessable or too short.",
                                        "Predictable authorities can ease content provider probing.",
                                        "Use a unique, namespaced authority value.",
                                        refs(REF_PROVIDER), RuleSupport.evidenceList(evidence));
                                out.add(finding);
                            }
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.COMPONENT.PERMISSION.UNKNOWN", "Component permission is undefined", "Permissions",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        String perm = component.getAttribute("android:permission");
                        if (perm.isEmpty()) {
                            continue;
                        }
                        if (!ctx.isKnownPermission(perm)) {
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:permission", perm, "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                    "Component references a permission that is not defined.",
                                    "Access control may be ineffective due to a typo or missing definition.",
                                    "Use a valid framework permission or declare a custom permission.",
                                    refs(REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.COMPONENT.PERMISSION.WEAK_LEVEL", "Component permission protection is weak", "Permissions",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    Map<String, String> protectionLevels = new HashMap<>();
                    for (PermissionInfo info : model.getCustomPermissions()) {
                        protectionLevels.put(info.getName(), info.getProtectionLevel());
                    }
                    for (ComponentInfo component : model.getComponents()) {
                        String perm = component.getAttribute("android:permission");
                        if (perm.isEmpty()) {
                            continue;
                        }
                        String level = protectionLevels.get(perm);
                        if (level == null) {
                            continue;
                        }
                        String lower = level.toLowerCase();
                        if (lower.contains("normal") || lower.isEmpty() || lower.contains("dangerous")) {
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:permission", perm, "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                    "Component uses a custom permission with a weak protection level.",
                                    "Normal/dangerous permissions do not fully restrict IPC access.",
                                    "Prefer signature-level protection for privileged components.",
                                    refs(REF_PERMISSION_LEVELS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));
    }

    private static void addIntentFilterRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.INTENT.BROWSABLE.BROAD", "Browsable intent-filter is too broad", "Intent Filters",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        for (IntentFilterInfo filter : component.getIntentFilters()) {
                            if (!filter.isBrowsable()) {
                                continue;
                            }
                            for (IntentDataInfo data : filter.getData()) {
                                boolean broadHost = data.getHost().isEmpty() || "*".equals(data.getHost());
                                boolean broadPath = "/".equals(data.getPathPrefix()) || "*".equals(data.getPathPattern());
                                if (broadHost || broadPath) {
                                    EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                            "intent-filter", "browsable", "");
                                    Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                            "Browsable intent-filter accepts overly broad hosts or paths.",
                                            "Broad deep links can be abused to trigger unintended screens.",
                                            "Restrict hosts and paths to known values.",
                                            refs(REF_APP_LINKS, REF_ACTIVITY), RuleSupport.evidenceList(evidence));
                                    out.add(finding);
                                    break;
                                }
                            }
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.APP_LINKS.MISSING_AUTOVERIFY", "App links missing autoVerify", "Intent Filters",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        for (IntentFilterInfo filter : component.getIntentFilters()) {
                            if (!filter.isBrowsable()) {
                                continue;
                            }
                            boolean hasHttps = false;
                            for (IntentDataInfo data : filter.getData()) {
                                if ("https".equalsIgnoreCase(data.getScheme())) {
                                    hasHttps = true;
                                    break;
                                }
                            }
                            if (hasHttps && !filter.isAutoVerify()) {
                                EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                        "android:autoVerify", "false", "");
                                Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                                        "Browsable https intent-filter does not enable autoVerify.",
                                        "App links may be intercepted by other apps.",
                                        "Set android:autoVerify=\"true\" and configure assetlinks.json.",
                                        refs(REF_APP_LINKS), RuleSupport.evidenceList(evidence));
                                out.add(finding);
                            }
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.INTENT.FILE_OR_BROAD_MIME", "Intent filter accepts file or broad MIME", "Intent Filters",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        for (IntentFilterInfo filter : component.getIntentFilters()) {
                            for (IntentDataInfo data : filter.getData()) {
                                boolean fileScheme = "file".equalsIgnoreCase(data.getScheme());
                                boolean broadMime = data.getMimeType() != null && data.getMimeType().contains("*/*");
                                if (fileScheme || broadMime) {
                                    EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                            "intent-filter", fileScheme ? "file" : data.getMimeType(), "");
                                    Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                            "Intent-filter allows file:// or broad MIME types.",
                                            "Malicious content types can be delivered to the component.",
                                            "Restrict scheme and MIME types to expected values.",
                                            refs(REF_ACTIVITY), RuleSupport.evidenceList(evidence));
                                    out.add(finding);
                                }
                            }
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.DEEPLINK.SCHEME.COMMON", "Custom scheme is collision-prone", "Intent Filters",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    Set<String> common = new HashSet<>(Arrays.asList("app", "login", "callback", "oauth", "auth", "pay", "open"));
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        for (IntentFilterInfo filter : component.getIntentFilters()) {
                            if (!filter.isBrowsable()) {
                                continue;
                            }
                            for (IntentDataInfo data : filter.getData()) {
                                String scheme = data.getScheme();
                                if (scheme == null || scheme.isEmpty()) {
                                    continue;
                                }
                                if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                                    continue;
                                }
                                if (scheme.length() < 4 || common.contains(scheme.toLowerCase())) {
                                    EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                            "android:scheme", scheme, "");
                                    Finding finding = RuleSupport.buildFinding(rule, Severity.LOW, Confidence.MEDIUM,
                                            "Custom scheme is short or common and may collide with other apps.",
                                            "Scheme collisions allow other apps to intercept deep links.",
                                            "Use a unique, package-based scheme.",
                                            refs(REF_APP_LINKS), RuleSupport.evidenceList(evidence));
                                    out.add(finding);
                                }
                            }
                        }
                    }
                    return out;
                }));
    }

    private static void addPermissionRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.PERMISSION.UNKNOWN.USES", "Unknown uses-permission", "Permissions",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        String name = perm.getName();
                        if (name.isEmpty() || ctx.isKnownPermission(name)) {
                            continue;
                        }
                        List<String> suggestions = suggestPermission(name);
                        String detail = suggestions.isEmpty() ? "" : "Possible: " + StringUtil.join(suggestions, ", ");
                        EvidenceItem evidence = RuleSupport.evidenceForNode("uses-permission", name,
                                perm.getNode(), ctx.getSource(), "android:name", name, detail);
                        Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                "Uses-permission does not match a known framework or app-defined permission.",
                                "Typos prevent permission grants from working as intended.",
                                "Verify the permission name or declare it explicitly.",
                                refs(REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                        out.add(finding);
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.PERMISSION.DUPLICATE", "Duplicate uses-permission", "Permissions",
                (model, ctx, rule) -> {
                    Map<String, List<UsesPermissionInfo>> map = new HashMap<>();
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        if (perm.getName().isEmpty()) {
                            continue;
                        }
                        map.computeIfAbsent(perm.getName(), k -> new ArrayList<>()).add(perm);
                    }
                    List<Finding> out = new ArrayList<>();
                    for (Map.Entry<String, List<UsesPermissionInfo>> entry : map.entrySet()) {
                        if (entry.getValue().size() < 2) {
                            continue;
                        }
                        boolean conflict = false;
                        String maxSdk = null;
                        for (UsesPermissionInfo info : entry.getValue()) {
                            if (maxSdk == null) {
                                maxSdk = info.getMaxSdkVersion();
                            } else if (!maxSdk.equals(info.getMaxSdkVersion())) {
                                conflict = true;
                            }
                        }
                        if (conflict) {
                            UsesPermissionInfo info = entry.getValue().get(0);
                            EvidenceItem evidence = RuleSupport.evidenceForNode("uses-permission", entry.getKey(),
                                    info.getNode(), ctx.getSource(), "android:name", entry.getKey(), "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.LOW, Confidence.HIGH,
                                    "Duplicate uses-permission with conflicting maxSdkVersion.",
                                    "Conflicting declarations can cause inconsistent behavior across API levels.",
                                    "Keep a single, correct permission declaration.",
                                    refs(REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.PERMISSION.DEPRECATED", "Deprecated permission", "Permissions",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        String name = perm.getName();
                        if (PermissionCatalog.DEPRECATED_PERMISSIONS.contains(name)) {
                            EvidenceItem evidence = RuleSupport.evidenceForNode("uses-permission", name,
                                    perm.getNode(), ctx.getSource(), "android:name", name, "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                                    "Deprecated or removed permission declared.",
                                    "Deprecated permissions can trigger lint or policy issues.",
                                    "Remove or replace with supported APIs.",
                                    refs(REF_PERMISSIONS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.PERMISSION.DANGEROUS.INVENTORY", "Dangerous permission inventory", "Permissions",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        String name = perm.getName();
                        if (PermissionCatalog.DANGEROUS_PERMISSIONS.contains(name)) {
                            EvidenceItem evidence = RuleSupport.evidenceForNode("uses-permission", name,
                                    perm.getNode(), ctx.getSource(), "android:name", name, "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.HIGH,
                                    "Dangerous permission declared.",
                                    "Review whether the permission is required and protected by runtime checks.",
                                    "Remove unnecessary dangerous permissions.",
                                    refs(REF_PERMISSIONS, REF_OWASP_MASVS), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.PERMISSION.CUSTOM.WEAK", "Custom permission protection level is weak", "Permissions",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (PermissionInfo info : model.getCustomPermissions()) {
                        String level = info.getProtectionLevel();
                        if (level == null || level.isEmpty() || level.toLowerCase().contains("normal")) {
                            String name = info.getName();
                            if (isPrivilegedName(name)) {
                                EvidenceItem evidence = RuleSupport.evidenceForNode("permission", name,
                                        info.getNode(), ctx.getSource(), "android:protectionLevel", level, "");
                                Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                        "Custom permission protection level is normal for a privileged-sounding name.",
                                        "Normal permissions do not restrict access to same-signature apps.",
                                        "Use signature-level protection for privileged permissions.",
                                        refs(REF_PERMISSION_LEVELS), RuleSupport.evidenceList(evidence));
                                out.add(finding);
                            }
                        }
                    }
                    return out;
                }));
    }

    private static void addNetworkRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.NETWORK.CLEARTEXT.ENABLED", "Cleartext traffic enabled", "Network",
                (model, ctx, rule) -> {
                    String clear = model.getApplicationAttribute("android:usesCleartextTraffic");
                    if (!StringUtil.isTrue(clear)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:usesCleartextTraffic", clear, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.HIGH,
                            "Application allows cleartext traffic.",
                            "Unencrypted network traffic can be intercepted.",
                            "Disable cleartext or restrict it via networkSecurityConfig.",
                            refs(REF_NETWORK_CONFIG, REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.NETWORK.CLEARTEXT.NO_CONFIG", "Cleartext without networkSecurityConfig", "Network",
                (model, ctx, rule) -> {
                    String clear = model.getApplicationAttribute("android:usesCleartextTraffic");
                    String config = model.getApplicationAttribute("android:networkSecurityConfig");
                    if (!StringUtil.isTrue(clear) || !isEmpty(config)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:networkSecurityConfig", config, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                            "Cleartext traffic enabled without a network security config.",
                            "Cleartext traffic may be allowed for all domains.",
                            "Provide a networkSecurityConfig to scope cleartext allowances.",
                            refs(REF_NETWORK_CONFIG), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.NETWORK.CONFIG.DEBUG_OVERRIDES", "Debug network config shipped", "Network",
                (model, ctx, rule) -> {
                    String config = model.getApplicationAttribute("android:networkSecurityConfig");
                    if (isEmpty(config)) {
                        return Collections.emptyList();
                    }
                    String xmlName = extractXmlName(config);
                    if (xmlName == null) {
                        return Collections.emptyList();
                    }
                    String xml = ctx.getResourceResolver().loadXmlByName(xmlName);
                    if (xml == null || xml.isEmpty()) {
                        return Collections.emptyList();
                    }
                    String lower = xml.toLowerCase();
                    if (!(lower.contains("debug-overrides") || lower.contains("certificates src=\"user\"") || lower.contains("certificates src='user'"))) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:networkSecurityConfig", config, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.MEDIUM,
                            "Network security config includes debug overrides or user CA trust.",
                            "User-installed CAs can intercept TLS traffic in production.",
                            "Remove debug overrides for release builds.",
                            refs(REF_NETWORK_CONFIG), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));
    }

    private static void addDebugBackupRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.APP.DEBUGGABLE", "Debuggable build", "Debuggability",
                (model, ctx, rule) -> {
                    String debuggable = model.getApplicationAttribute("android:debuggable");
                    if (!StringUtil.isTrue(debuggable)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:debuggable", debuggable, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.CRITICAL, Confidence.HIGH,
                            "Application is marked debuggable.",
                            "Debuggable apps expose code and data to debuggers.",
                            "Disable android:debuggable for release builds.",
                            refs(REF_APPLICATION, REF_OWASP_MSTG), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.APP.BACKUP.SENSITIVE", "Backup enabled with sensitive permissions", "Backup",
                (model, ctx, rule) -> {
                    String allowBackup = model.getApplicationAttribute("android:allowBackup");
                    if (!StringUtil.isTrue(allowBackup)) {
                        return Collections.emptyList();
                    }
                    boolean sensitive = false;
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        if (PermissionCatalog.SENSITIVE_PERMISSIONS.contains(perm.getName())) {
                            sensitive = true;
                            break;
                        }
                    }
                    if (!sensitive) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:allowBackup", allowBackup, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.LOW,
                            "Backup is enabled while sensitive permissions are declared.",
                            "Sensitive data might be backed up without explicit exclusions.",
                            "Disable allowBackup or define backup rules.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.APP.BACKUP.NO_RULES", "Backup rules missing", "Backup",
                (model, ctx, rule) -> {
                    String allowBackup = model.getApplicationAttribute("android:allowBackup");
                    if (!StringUtil.isTrue(allowBackup)) {
                        return Collections.emptyList();
                    }
                    String fullBackup = model.getApplicationAttribute("android:fullBackupContent");
                    String extractionRules = model.getApplicationAttribute("android:dataExtractionRules");
                    if (!isEmpty(fullBackup) || !isEmpty(extractionRules)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:allowBackup", allowBackup, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                            "Backup is enabled without backup rules.",
                            "Default backup behavior may include unintended data.",
                            "Add fullBackupContent or dataExtractionRules or disable backups.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.APP.BACKUP.AGENT", "Custom backup agent", "Backup",
                (model, ctx, rule) -> {
                    String agent = model.getApplicationAttribute("android:backupAgent");
                    if (isEmpty(agent)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:backupAgent", agent, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.HIGH,
                            "Custom backupAgent is declared.",
                            "Backup agent code should be reviewed for data exposure.",
                            "Verify backup agent implementation and exclusions.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));
    }

    private static void addSdkRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.SDK.TARGET.LOW", "Target SDK is low", "SDK",
                (model, ctx, rule) -> {
                    UsesSdkInfo sdk = model.getUsesSdk();
                    if (sdk == null) {
                        return Collections.emptyList();
                    }
                    int target = parseInt(sdk.getTargetSdkVersion());
                    if (target <= 0 || target >= 30) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("uses-sdk", "uses-sdk",
                            sdk.getNode(), ctx.getSource(), "android:targetSdkVersion", sdk.getTargetSdkVersion(), "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "Target SDK version is below recommended levels.",
                            "Older target SDKs skip modern security hardening behaviors.",
                            "Raise targetSdkVersion to a supported API level.",
                            refs(REF_SDK), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.SDK.MIN.LOW", "Min SDK is low", "SDK",
                (model, ctx, rule) -> {
                    UsesSdkInfo sdk = model.getUsesSdk();
                    if (sdk == null) {
                        return Collections.emptyList();
                    }
                    int min = parseInt(sdk.getMinSdkVersion());
                    if (min <= 0 || min >= 21) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("uses-sdk", "uses-sdk",
                            sdk.getNode(), ctx.getSource(), "android:minSdkVersion", sdk.getMinSdkVersion(), "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "Minimum SDK is low.",
                            "Legacy OS versions may lack modern security protections.",
                            "Raise minSdkVersion if possible.",
                            refs(REF_SDK), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.STORAGE.LEGACY", "Legacy external storage enabled", "SDK",
                (model, ctx, rule) -> {
                    String legacy = model.getApplicationAttribute("android:requestLegacyExternalStorage");
                    if (!StringUtil.isTrue(legacy)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:requestLegacyExternalStorage", legacy, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.HIGH,
                            "Legacy external storage mode is enabled.",
                            "Legacy storage increases data exposure and bypasses scoped storage.",
                            "Migrate to scoped storage and remove requestLegacyExternalStorage.",
                            refs(REF_STORAGE), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.EXPORTED.MISSING_ATTR.ANY", "Missing android:exported for component", "Exported",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!RuleUtil.hasExplicitExported(component) && component.hasIntentFilter()) {
                            EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                    "android:exported", "", "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                    "Component has intent-filters but missing android:exported.",
                                    "Android 12+ requires explicit exported setting.",
                                    "Add android:exported explicitly.",
                                    refs(REF_EXPORTED_12), RuleSupport.evidenceList(evidence));
                            out.add(finding);
                        }
                    }
                    return out;
                }));
    }

    private static void addQueriesRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.QUERIES.BROAD", "Broad package visibility queries", "Queries",
                (model, ctx, rule) -> {
                    QueryInfo queries = model.getQueries();
                    if (queries == null) {
                        return Collections.emptyList();
                    }
                    boolean broad = queries.getPackages().size() > 10;
                    for (QueryIntentInfo intent : queries.getIntents()) {
                        if (intent.isBroad()) {
                            broad = true;
                            break;
                        }
                    }
                    if (!broad) {
                        return Collections.emptyList();
                    }
                    ManifestNode node = queries.getNode() == null ? model.getManifestNode() : queries.getNode();
                    EvidenceItem evidence = RuleSupport.evidenceForNode("queries", "queries", node,
                            ctx.getSource(), "queries", "broad", "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "Queries element grants broad package visibility.",
                            "Broad visibility can increase privacy exposure and review requirements.",
                            "Limit queries to specific packages or intents.",
                            refs(REF_QUERIES), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.QUERIES.ALL_PACKAGES", "QUERY_ALL_PACKAGES used", "Queries",
                (model, ctx, rule) -> {
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        if ("android.permission.QUERY_ALL_PACKAGES".equals(perm.getName())) {
                            EvidenceItem evidence = RuleSupport.evidenceForNode("uses-permission", perm.getName(),
                                    perm.getNode(), ctx.getSource(), "android:name", perm.getName(), "");
                            Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.HIGH,
                                    "QUERY_ALL_PACKAGES grants broad package visibility.",
                                    "Google Play restricts use and it increases privacy risk.",
                                    "Remove unless strictly required and justified.",
                                    refs(REF_QUERIES), RuleSupport.evidenceList(evidence));
                            return Collections.singletonList(finding);
                        }
                    }
                    return Collections.emptyList();
                }));

        rules.add(new SimpleRule("MANIFEST.QUERIES.EXCESSIVE", "Excessive queries with sensitive permissions", "Queries",
                (model, ctx, rule) -> {
                    QueryInfo queries = model.getQueries();
                    if (queries == null) {
                        return Collections.emptyList();
                    }
                    int count = queries.getPackages().size() + queries.getIntents().size() + queries.getProviders().size();
                    if (count < 20) {
                        return Collections.emptyList();
                    }
                    boolean sensitive = false;
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        if (PermissionCatalog.SENSITIVE_PERMISSIONS.contains(perm.getName())) {
                            sensitive = true;
                            break;
                        }
                    }
                    if (!sensitive) {
                        return Collections.emptyList();
                    }
                    ManifestNode node = queries.getNode() == null ? model.getManifestNode() : queries.getNode();
                    EvidenceItem evidence = RuleSupport.evidenceForNode("queries", "queries",
                            node, ctx.getSource(), "queries", "count=" + count, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.LOW,
                            "High number of queries combined with sensitive permissions.",
                            "Broad visibility combined with sensitive data can raise privacy concerns.",
                            "Reduce queries to only required packages or intents.",
                            refs(REF_QUERIES), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));
    }

    private static void addMiscRules(List<ManifestRule> rules) {
        rules.add(new SimpleRule("MANIFEST.MISSING", "Manifest not available", "Other",
                (model, ctx, rule) -> {
                    if (ctx.getSource() != null && ctx.getSource().getXml() != null
                            && !ctx.getSource().getXml().trim().isEmpty()) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("manifest", "manifest",
                            model.getManifestNode(), ctx.getSource(), "manifest", "missing", "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "AndroidManifest.xml could not be loaded from resources.",
                            "Manifest-based checks may be incomplete.",
                            "Ensure the APK/AAB contains a readable manifest resource.",
                            refs(REF_MANIFEST), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.SHARED_USER_ID", "sharedUserId used", "Other",
                (model, ctx, rule) -> {
                    String shared = model.getManifestAttribute("android:sharedUserId");
                    if (isEmpty(shared)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("manifest", "manifest",
                            model.getManifestNode(), ctx.getSource(), "android:sharedUserId", shared, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.HIGH,
                            "Manifest declares sharedUserId.",
                            "sharedUserId is deprecated and can weaken app isolation.",
                            "Remove sharedUserId unless strictly required.",
                            refs(REF_MANIFEST), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.ACTIVITY.TASK_AFFINITY.EXPORTED", "Suspicious taskAffinity on exported activity", "Other",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    String pkg = model.getPackageName();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        if (!RuleUtil.isExported(component)) {
                            continue;
                        }
                        String taskAffinity = component.getAttribute("android:taskAffinity");
                        if (isEmpty(taskAffinity) || taskAffinity.equals(pkg)) {
                            continue;
                        }
                        EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                "android:taskAffinity", taskAffinity, "");
                        Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                "Exported activity overrides taskAffinity.",
                                "Custom task affinities can enable task hijacking scenarios.",
                                "Use default taskAffinity or restrict export.",
                                refs(REF_ACTIVITY), RuleSupport.evidenceList(evidence));
                        out.add(finding);
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.COMPONENT.REMOTE_PROCESS.EXPORTED", "Exported component in remote process", "Other",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    String pkg = model.getPackageName();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!RuleUtil.isExported(component)) {
                            continue;
                        }
                        String process = component.getAttribute("android:process");
                        if (isEmpty(process)) {
                            continue;
                        }
                        boolean remote = process.startsWith(":") || (!pkg.isEmpty() && !pkg.equals(process));
                        if (!remote) {
                            continue;
                        }
                        EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                "android:process", process, "");
                        Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.MEDIUM,
                                "Exported component runs in a remote process.",
                                "Remote processes can increase IPC complexity and exposure.",
                                "Ensure exported remote components are permission-protected.",
                                refs(REF_MANIFEST), RuleSupport.evidenceList(evidence));
                        out.add(finding);
                    }
                    return out;
                }));

        rules.add(new SimpleRule("MANIFEST.APP.TESTONLY", "testOnly enabled", "Other",
                (model, ctx, rule) -> {
                    String testOnly = model.getApplicationAttribute("android:testOnly");
                    if (!StringUtil.isTrue(testOnly)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:testOnly", testOnly, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.HIGH, Confidence.HIGH,
                            "Application is marked testOnly.",
                            "Test-only builds should not be shipped to users.",
                            "Remove android:testOnly from release builds.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.APP.PROFILEABLE", "profileable enabled", "Other",
                (model, ctx, rule) -> {
                    if (!model.isProfileable()) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:profileable", "true", "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "Application is profileable.",
                            "Profiling can expose runtime behavior in production.",
                            "Disable profileable unless needed for performance analysis.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.APP.NON_SDK", "usesNonSdkApi enabled", "Other",
                (model, ctx, rule) -> {
                    String nonSdk = model.getApplicationAttribute("android:usesNonSdkApi");
                    if (!StringUtil.isTrue(nonSdk)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:usesNonSdkApi", nonSdk, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "Application opts into non-SDK APIs.",
                            "Hidden API usage can break and weaken security posture.",
                            "Avoid non-SDK APIs or gate usage.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.APP.EXTRACT_NATIVE_LIBS", "extractNativeLibs enabled", "Other",
                (model, ctx, rule) -> {
                    String extract = model.getApplicationAttribute("android:extractNativeLibs");
                    if (!StringUtil.isTrue(extract)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:extractNativeLibs", extract, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "Native libraries are extracted to the filesystem.",
                            "Extracted libraries are easier to tamper with or inspect.",
                            "Set android:extractNativeLibs=\"false\" where supported.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.APP.NATIVE_HEAP_TAGGING", "Native heap pointer tagging setting", "Other",
                (model, ctx, rule) -> {
                    String tagging = model.getApplicationAttribute("android:allowNativeHeapPointerTagging");
                    if (isEmpty(tagging)) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:allowNativeHeapPointerTagging", tagging, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.MEDIUM,
                            "Native heap pointer tagging configuration is explicitly set.",
                            "Pointer tagging can improve memory safety on supported devices.",
                            "Review whether this setting aligns with hardening goals.",
                            refs(REF_APPLICATION), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.NETWORK.CLEARTEXT_WITH_INTERNET", "Cleartext with INTERNET permission", "Network",
                (model, ctx, rule) -> {
                    String clear = model.getApplicationAttribute("android:usesCleartextTraffic");
                    if (!StringUtil.isTrue(clear)) {
                        return Collections.emptyList();
                    }
                    boolean hasInternet = false;
                    for (UsesPermissionInfo perm : model.getUsesPermissions()) {
                        if ("android.permission.INTERNET".equals(perm.getName())) {
                            hasInternet = true;
                            break;
                        }
                    }
                    if (!hasInternet) {
                        return Collections.emptyList();
                    }
                    EvidenceItem evidence = RuleSupport.evidenceForNode("application", "application",
                            model.getApplicationNode(), ctx.getSource(), "android:usesCleartextTraffic", clear, "");
                    Finding finding = RuleSupport.buildFinding(rule, Severity.MEDIUM, Confidence.HIGH,
                            "Cleartext traffic is enabled and INTERNET permission is declared.",
                            "Cleartext network requests may expose data in transit.",
                            "Disable cleartext traffic or scope it via networkSecurityConfig.",
                            refs(REF_NETWORK_CONFIG), RuleSupport.evidenceList(evidence));
                    return Collections.singletonList(finding);
                }));

        rules.add(new SimpleRule("MANIFEST.UI.HARDWARE_ACCEL.EXPORTED", "Hardware acceleration on exported activity", "Other",
                (model, ctx, rule) -> {
                    List<Finding> out = new ArrayList<>();
                    for (ComponentInfo component : model.getComponents()) {
                        if (!isActivity(component)) {
                            continue;
                        }
                        if (!RuleUtil.isExported(component)) {
                            continue;
                        }
                        String accel = component.getAttribute("android:hardwareAccelerated");
                        if (!StringUtil.isTrue(accel)) {
                            continue;
                        }
                        EvidenceItem evidence = RuleSupport.evidenceForComponent(component, ctx.getSource(),
                                "android:hardwareAccelerated", accel, "");
                        Finding finding = RuleSupport.buildFinding(rule, Severity.INFO, Confidence.LOW,
                                "Exported activity enables hardware acceleration.",
                                "Hardware acceleration can affect rendering behavior of sensitive screens.",
                                "Review if this is required for exported activities.",
                                refs(REF_ACTIVITY), RuleSupport.evidenceList(evidence));
                        out.add(finding);
                    }
                    return out;
                }));
    }

    private static boolean isActivity(ComponentInfo component) {
        return component.getType() == ComponentType.ACTIVITY || component.getType() == ComponentType.ACTIVITY_ALIAS;
    }

    private static boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static int parseInt(String value) {
        if (value == null || value.trim().isEmpty()) {
            return -1;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private static List<Reference> refs(Reference... references) {
        List<Reference> list = new ArrayList<>();
        if (references != null) {
            list.addAll(Arrays.asList(references));
        }
        return list;
    }

    private static String extractXmlName(String attrValue) {
        if (attrValue == null) {
            return null;
        }
        String trimmed = attrValue.trim();
        if (trimmed.startsWith("@xml/")) {
            return trimmed.substring("@xml/".length());
        }
        return null;
    }

    private static List<String> suggestPermission(String name) {
        List<String> suggestions = new ArrayList<>();
        if (name == null || name.isEmpty()) {
            return suggestions;
        }
        int best = Integer.MAX_VALUE;
        String bestMatch = null;
        for (String perm : PermissionCatalog.FRAMEWORK_PERMISSIONS) {
            int dist = Levenshtein.distance(name, perm);
            if (dist < best) {
                best = dist;
                bestMatch = perm;
            }
        }
        if (bestMatch != null && best <= 3) {
            suggestions.add(bestMatch);
        }
        return suggestions;
    }

    private static boolean isPrivilegedName(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase();
        return lower.contains("admin") || lower.contains("priv") || lower.contains("internal")
                || lower.contains("signature") || lower.contains("system") || lower.contains("root")
                || lower.contains("owner") || lower.contains("manage");
    }
}
