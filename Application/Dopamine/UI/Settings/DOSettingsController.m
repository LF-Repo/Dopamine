//
//  DOSettingsController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOSettingsController.h"
#import <objc/runtime.h>
#import <Photos/Photos.h>
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import "DOUIManager.h"
#import "DOPkgManagerPickerViewController.h"
#import "DOHeaderCell.h"
#import "DOEnvironmentManager.h"
#import "DOExploitManager.h"
#import "DOPSListItemsController.h"
#import "DOPSExploitListItemsController.h"
#import "DOThemeManager.h"
#import "DOSceneDelegate.h"
#import "DOPSJetsamListItemsController.h"
#import "DOButtonCell.h"

@interface DOSettingsController ()

@end

@interface DOAppHidePickerViewController : UITableViewController <UISearchBarDelegate, UISearchResultsUpdating>
@property (nonatomic, strong) NSMutableArray<NSMutableDictionary *> *allApps;
@property (nonatomic, strong) NSMutableArray<NSMutableDictionary *> *filteredApps;
@property (nonatomic, strong) UISearchBar *searchBar;
@property (nonatomic, strong) NSCache<NSString *, UIImage *> *iconCache;
- (UIImage *)iconForBundleID:(NSString *)bundleID;
@end

@implementation DOSettingsController

- (void)viewDidLoad
{
    _lastKnownTheme = [[DOThemeManager sharedInstance] enabledTheme].key;
    _lastKnownMaterial = [DOThemeManager enabledMaterialKey];
    [super viewDidLoad];
}

- (void)viewWillAppear:(BOOL)arg1
{
    [super viewWillAppear:arg1];
    if (_lastKnownMaterial != [DOThemeManager enabledMaterialKey])
    {
        // The button fill is applied when DOButtonCell is created, so the rows
        // have to be rebuilt for a material change to become visible.
        _lastKnownMaterial = [DOThemeManager enabledMaterialKey];
        [self reloadSpecifiers];
    }
    if (_lastKnownTheme != [[DOThemeManager sharedInstance] enabledTheme].key)
    {
        [DOSceneDelegate relaunch];
        NSString *icon = [[DOThemeManager sharedInstance] enabledTheme].icon;
        [[UIApplication sharedApplication] setAlternateIconName:icon completionHandler:^(NSError * _Nullable error) {
            if (error)
                NSLog(@"Error changing app icon: %@", error);
        }];

        if ([DOEnvironmentManager sharedManager].isJailbroken) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [[DOEnvironmentManager sharedManager] updateBootLogo];
            });
        }
    }
}

- (NSArray *)availableKernelExploitIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    for (DOExploit *exploit in _availableKernelExploits) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availableKernelExploitNames
{
    NSMutableArray *names = [NSMutableArray new];
    for (DOExploit *exploit in _availableKernelExploits) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)availablePACBypassIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    if (![DOEnvironmentManager sharedManager].isPACBypassRequired) {
        [identifiers addObject:@"none"];
    }
    for (DOExploit *exploit in _availablePACBypasses) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availablePACBypassNames
{
    NSMutableArray *names = [NSMutableArray new];
    if (![DOEnvironmentManager sharedManager].isPACBypassRequired) {
        [names addObject:DOLocalizedString(@"None")];
    }
    for (DOExploit *exploit in _availablePACBypasses) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)availablePPLBypassIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    for (DOExploit *exploit in _availablePPLBypasses) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availablePPLBypassNames
{
    NSMutableArray *names = [NSMutableArray new];
    for (DOExploit *exploit in _availablePPLBypasses) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)themeIdentifiers
{
    return [[DOThemeManager sharedInstance] getAvailableThemeKeys];
}

- (NSArray *)themeNames
{
    return [[DOThemeManager sharedInstance] getAvailableThemeNames];
}

- (NSArray *)materialIdentifiers
{
    return [DOThemeManager getAvailableMaterialKeys];
}

- (NSArray *)materialNames
{
    NSArray *names = [DOThemeManager getAvailableMaterialNames];
    NSMutableArray *localized = [NSMutableArray arrayWithCapacity:names.count];
    for (NSString *name in names) {
        NSString *key = [@"Material_" stringByAppendingString:name];
        NSString *value = DOLocalizedString(key);
        // DOLocalizedString returns the key itself when there is no translation.
        [localized addObject:[value isEqualToString:key] ? name : value];
    }
    return localized;
}

- (NSArray *)jetsamOptionNumbers
{
    return @[
    @2,
    @3,
    @4,
    @5,
    @6,
    @7,
    @8,
    ];
}

- (NSArray *)jetsamOptionTitles
{
    return @[
        @"1x",
        @"1.5x",
        @"2x",
        @"2.5x",
        [NSString stringWithFormat:@"3x (%@)", DOLocalizedString(@"Recommended")],
        @"3.5x",
        @"4x",
    ];
}

- (id)specifiers
{
    if(_specifiers == nil) {
        NSMutableArray *specifiers = [NSMutableArray new];
        DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
        DOExploitManager *exploitManager = [DOExploitManager sharedManager];

        NSNumber *buttonHeight = @(44);
        
        SEL defGetter = @selector(readPreferenceValue:);
        SEL defSetter = @selector(setPreferenceValue:specifier:);
        SEL expGetter = @selector(readExploitPreferenceValue:);
        
        NSSortDescriptor *prioritySortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"priority" ascending:NO];
        
        _availableKernelExploits = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_KERNEL] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
        if (envManager.isArm64e) {
            _availablePACBypasses = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_PAC] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
            _availablePPLBypasses = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_PPL] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
        }
        
        PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
        [headerSpecifier setProperty:@"DOHeaderCell" forKey:@"headerCellClass"];
        [headerSpecifier setProperty:[NSString stringWithFormat:@"Settings"] forKey:@"title"];
        [specifiers addObject:headerSpecifier];
        
        if (envManager.isSupported) {
            if (!envManager.isJailbroken) {
                PSSpecifier *exploitGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                exploitGroupSpecifier.name = DOLocalizedString(@"Section_Exploits");
                [specifiers addObject:exploitGroupSpecifier];
                
                PSSpecifier *kernelExploitSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Kernel Exploit") target:self set:defSetter get:expGetter detail:nil cell:PSLinkListCell edit:nil];
                [kernelExploitSpecifier setProperty:@YES forKey:@"enabled"];
                [kernelExploitSpecifier setProperty:exploitManager.preferredKernelExploit.identifier forKey:@"default"];
                kernelExploitSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                [kernelExploitSpecifier setProperty:@"availableKernelExploitIdentifiers" forKey:@"valuesDataSource"];
                [kernelExploitSpecifier setProperty:@"availableKernelExploitNames" forKey:@"titlesDataSource"];
                [kernelExploitSpecifier setProperty:@"selectedKernelExploit" forKey:@"key"];
                [kernelExploitSpecifier setProperty:(_availableKernelExploits.firstObject.identifier ?: @"none") forKey:@"recommendedExploitIdentifier"];
                [specifiers addObject:kernelExploitSpecifier];
                
                if (envManager.isArm64e) {
                    PSSpecifier *pacBypassSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"PAC Bypass") target:self set:defSetter get:expGetter detail:nil cell:PSLinkListCell edit:nil];
                    [pacBypassSpecifier setProperty:@YES forKey:@"enabled"];
                    DOExploit *preferredPACBypass = exploitManager.preferredPACBypass;
                    if (!preferredPACBypass) {
                        [pacBypassSpecifier setProperty:@"none" forKey:@"default"];
                    }
                    else {
                        [pacBypassSpecifier setProperty:preferredPACBypass.identifier forKey:@"default"];
                    }
                    pacBypassSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                    [pacBypassSpecifier setProperty:@"availablePACBypassIdentifiers" forKey:@"valuesDataSource"];
                    [pacBypassSpecifier setProperty:@"availablePACBypassNames" forKey:@"titlesDataSource"];
                    [pacBypassSpecifier setProperty:@"selectedPACBypass" forKey:@"key"];
                    [pacBypassSpecifier setProperty:([envManager isPACBypassRequired] ? _availablePACBypasses.firstObject.identifier : @"none") forKey:@"recommendedExploitIdentifier"];
                    [specifiers addObject:pacBypassSpecifier];
                    
                    NSString *pplBypassName = @"PPL Bypass";
                    if ([DOEnvironmentManager sharedManager].isSPTM) {
                        pplBypassName = @"SPTM Bypass";
                    }

                    PSSpecifier *pplBypassSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(pplBypassName) target:self set:defSetter get:expGetter detail:nil cell:PSLinkListCell edit:nil];
                    [pplBypassSpecifier setProperty:@YES forKey:@"enabled"];
                    [pplBypassSpecifier setProperty:exploitManager.preferredPPLBypass.identifier forKey:@"default"];
                    pplBypassSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                    [pplBypassSpecifier setProperty:@"availablePPLBypassIdentifiers" forKey:@"valuesDataSource"];
                    [pplBypassSpecifier setProperty:@"availablePPLBypassNames" forKey:@"titlesDataSource"];
                    [pplBypassSpecifier setProperty:@"selectedPPLBypass" forKey:@"key"];
                    [pplBypassSpecifier setProperty:(_availablePPLBypasses.firstObject.identifier ?: @"none") forKey:@"recommendedExploitIdentifier"];
                    [specifiers addObject:pplBypassSpecifier];
                }
            }
            
            PSSpecifier *settingsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
            settingsGroupSpecifier.name = DOLocalizedString(@"Section_Jailbreak_Settings");
            [specifiers addObject:settingsGroupSpecifier];
            
            PSSpecifier *tweakInjectionSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Tweak_Injection") target:self set:@selector(setTweakInjectionEnabled:specifier:) get:@selector(readTweakInjectionEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [tweakInjectionSpecifier setProperty:@YES forKey:@"enabled"];
            [tweakInjectionSpecifier setProperty:@"tweakInjectionEnabled" forKey:@"key"];
            [tweakInjectionSpecifier setProperty:@YES forKey:@"default"];
            [specifiers addObject:tweakInjectionSpecifier];

            PSSpecifier *disableCrashReporterSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Disable_Crash_Reporter") target:self set:@selector(setCrashReporterDisabled:specifier:) get:@selector(readCrashReporterDisabled:) detail:nil cell:PSSwitchCell edit:nil];
            [disableCrashReporterSpecifier setProperty:@YES forKey:@"enabled"];
            [disableCrashReporterSpecifier setProperty:@"crashReporterDisabled" forKey:@"key"];
            [disableCrashReporterSpecifier setProperty:@NO forKey:@"default"];
            [specifiers addObject:disableCrashReporterSpecifier];
            
            if (!envManager.isJailbroken) {
                PSSpecifier *verboseLogSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Verbose_Logs") target:self set:defSetter get:defGetter detail:nil cell:PSSwitchCell edit:nil];
                [verboseLogSpecifier setProperty:@YES forKey:@"enabled"];
                [verboseLogSpecifier setProperty:@"verboseLogsEnabled" forKey:@"key"];
                [verboseLogSpecifier setProperty:@NO forKey:@"default"];
                [specifiers addObject:verboseLogSpecifier];
            }
            
            PSSpecifier *idownloadSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_iDownload") target:self set:@selector(setIDownloadEnabled:specifier:) get:@selector(readIDownloadEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [idownloadSpecifier setProperty:@YES forKey:@"enabled"];
            [idownloadSpecifier setProperty:@"idownloadEnabled" forKey:@"key"];
            [idownloadSpecifier setProperty:@NO forKey:@"default"];
            [specifiers addObject:idownloadSpecifier];
            
            PSSpecifier *appJitSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Apps_JIT") target:self set:@selector(setAppJITEnabled:specifier:) get:@selector(readAppJITEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [appJitSpecifier setProperty:@YES forKey:@"enabled"];
            [appJitSpecifier setProperty:@"appJITEnabled" forKey:@"key"];
            [appJitSpecifier setProperty:@YES forKey:@"default"];
            [specifiers addObject:appJitSpecifier];
            
            PSSpecifier *jetsamSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Jetsam_Multiplier") target:self set:@selector(setJetsamMultiplier:specifier:) get:@selector(readJetsamMultiplier:) detail:nil cell:PSLinkListCell edit:nil];
            [jetsamSpecifier setProperty:@YES forKey:@"enabled"];
            [jetsamSpecifier setProperty:@"jetsamMultiplier" forKey:@"key"];
            [jetsamSpecifier setProperty:@6 forKey:@"default"];
            jetsamSpecifier.detailControllerClass = [DOPSJetsamListItemsController class];
            [jetsamSpecifier setProperty:@"jetsamOptionNumbers" forKey:@"valuesDataSource"];
            [jetsamSpecifier setProperty:@"jetsamOptionTitles" forKey:@"titlesDataSource"];
            [specifiers addObject:jetsamSpecifier];
            
            if (!envManager.isJailbroken && !envManager.isInstalledThroughTrollStore) {
                PSSpecifier *removeJailbreakSwitchSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Button_Remove_Jailbreak") target:self set:@selector(setRemoveJailbreakEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
                [removeJailbreakSwitchSpecifier setProperty:@YES forKey:@"enabled"];
                [removeJailbreakSwitchSpecifier setProperty:@"removeJailbreakEnabled" forKey:@"key"];
                [specifiers addObject:removeJailbreakSwitchSpecifier];
            }

            if (envManager.isBootstrapped) {
                // ===== Actions 分组 =====
                PSSpecifier *actionsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                actionsGroupSpecifier.name = DOLocalizedString(@"Section_Actions");
                [specifiers addObject:actionsGroupSpecifier];

                if (envManager.isJailbroken) {
                    PSSpecifier *refreshAppsSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [refreshAppsSpecifier setProperty:@"Button_Refresh_Jailbreak_Apps" forKey:@"title"];
                    [refreshAppsSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [refreshAppsSpecifier setProperty:buttonHeight forKey:@"height"];
                    [refreshAppsSpecifier setProperty:@"arrow.triangle.2.circlepath" forKey:@"image"];
                    [refreshAppsSpecifier setProperty:@"refreshJailbreakAppsPressed" forKey:@"action"];
                    [specifiers addObject:refreshAppsSpecifier];
                    
                    PSSpecifier *changeMobilePasswordSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [changeMobilePasswordSpecifier setProperty:@"Button_Change_Mobile_Password" forKey:@"title"];
                    [changeMobilePasswordSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [changeMobilePasswordSpecifier setProperty:buttonHeight forKey:@"height"];
                    [changeMobilePasswordSpecifier setProperty:@"key" forKey:@"image"];
                    [changeMobilePasswordSpecifier setProperty:@"changeMobilePasswordWithAuthenticationPressed" forKey:@"action"];
                    [specifiers addObject:changeMobilePasswordSpecifier];
                    
                    PSSpecifier *reinstallPackageManagersSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [reinstallPackageManagersSpecifier setProperty:@"Button_Reinstall_Package_Managers" forKey:@"title"];
                    [reinstallPackageManagersSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [reinstallPackageManagersSpecifier setProperty:buttonHeight forKey:@"height"];
                    if (@available(iOS 16.0, *))
                        [reinstallPackageManagersSpecifier setProperty:@"shippingbox.and.arrow.backward" forKey:@"image"];
                    else
                        [reinstallPackageManagersSpecifier setProperty:@"shippingbox" forKey:@"image"];
                    [reinstallPackageManagersSpecifier setProperty:@"reinstallPackageManagersPressed" forKey:@"action"];
                    [specifiers addObject:reinstallPackageManagersSpecifier];
                }

                BOOL hideJailbreakButtonShown = (envManager.isJailbroken || (envManager.isInstalledThroughTrollStore && !envManager.isJailbreakHidden));
                if (hideJailbreakButtonShown) {
                    PSSpecifier *hideUnhideJailbreakSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [hideUnhideJailbreakSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [hideUnhideJailbreakSpecifier setProperty:buttonHeight forKey:@"height"];
                    if (envManager.isJailbreakHidden) {
                        [hideUnhideJailbreakSpecifier setProperty:@"Button_Unhide_Jailbreak" forKey:@"title"];
                        [hideUnhideJailbreakSpecifier setProperty:@"eye" forKey:@"image"];
                    }
                    else {
                        [hideUnhideJailbreakSpecifier setProperty:@"Button_Hide_Jailbreak" forKey:@"title"];
                        [hideUnhideJailbreakSpecifier setProperty:@"eye.slash" forKey:@"image"];
                    }
                    [hideUnhideJailbreakSpecifier setProperty:@"hideUnhideJailbreakPressed" forKey:@"action"];
                    [specifiers addObject:hideUnhideJailbreakSpecifier];
                }

                PSSpecifier *rebootSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                [rebootSpecifier setProperty:@"Reboot Device" forKey:@"title"];
                [rebootSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [rebootSpecifier setProperty:buttonHeight forKey:@"height"];
                [rebootSpecifier setProperty:@"power" forKey:@"image"];
                [rebootSpecifier setProperty:@"rebootPressed" forKey:@"action"];
                [specifiers addObject:rebootSpecifier];

                if (!envManager.isJailbroken && envManager.isInstalledThroughTrollStore) {
                    PSSpecifier *removeJailbreakSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [removeJailbreakSpecifier setProperty:@"Button_Remove_Jailbreak" forKey:@"title"];
                    [removeJailbreakSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [removeJailbreakSpecifier setProperty:buttonHeight forKey:@"height"];
                    [removeJailbreakSpecifier setProperty:@"trash" forKey:@"image"];
                    [removeJailbreakSpecifier setProperty:@"removeJailbreakPressed" forKey:@"action"];
                    [specifiers addObject:removeJailbreakSpecifier];
                }
                
                if (hideJailbreakButtonShown) {
                    [actionsGroupSpecifier setProperty:DOLocalizedString(envManager.isJailbroken ? @"Hint_Hide_Jailbreak_Jailbroken" : @"Hint_Hide_Jailbreak") forKey:@"footerText"];
                }

                // ===== Hide Settings 分组 =====
                PSSpecifier *hideSettingsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                hideSettingsGroupSpecifier.name = DOLocalizedString(@"Section_Hide_Settings");
                [specifiers addObject:hideSettingsGroupSpecifier];

                PSSpecifier *injectionBlockSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                [injectionBlockSpecifier setProperty:@"Block App Injection" forKey:@"title"];
                [injectionBlockSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [injectionBlockSpecifier setProperty:buttonHeight forKey:@"height"];
                [injectionBlockSpecifier setProperty:@"shield.slash" forKey:@"image"];
                [injectionBlockSpecifier setProperty:@"injectionBlockPressed" forKey:@"action"];
                [specifiers addObject:injectionBlockSpecifier];

                PSSpecifier *appHideSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                [appHideSpecifier setProperty:@"Hide for App" forKey:@"title"];
                [appHideSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [appHideSpecifier setProperty:buttonHeight forKey:@"height"];
                [appHideSpecifier setProperty:@"eye.slash.circle" forKey:@"image"];
                [appHideSpecifier setProperty:@"appHidePressed" forKey:@"action"];
                [specifiers addObject:appHideSpecifier];

                PSSpecifier *mountGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                mountGroupSpecifier.name = DOLocalizedString(@"Section_Mount_Settings");
                [mountGroupSpecifier setProperty:DOLocalizedString(@"Mount_Settings_Footer") forKey:@"footerText"];
                [specifiers addObject:mountGroupSpecifier];

                PSSpecifier *mountSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                [mountSpecifier setProperty:@"Input_Mmount_Title" forKey:@"title"];
                [mountSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [mountSpecifier setProperty:buttonHeight forKey:@"height"];
                [mountSpecifier setProperty:@"folder.badge.plus" forKey:@"image"];
                [mountSpecifier setProperty:@"mountPressed" forKey:@"action"];
                [specifiers addObject:mountSpecifier];

                PSSpecifier *unmountSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                [unmountSpecifier setProperty:@"Input_Unmount_Title" forKey:@"title"];
                [unmountSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [unmountSpecifier setProperty:buttonHeight forKey:@"height"];
                [unmountSpecifier setProperty:@"folder.badge.gearshape" forKey:@"image"];
                [unmountSpecifier setProperty:@"unmountPressed" forKey:@"action"];
                [specifiers addObject:unmountSpecifier];
            }
        }
        
        PSSpecifier *themingGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
        themingGroupSpecifier.name = DOLocalizedString(@"Section_Customization");
        [specifiers addObject:themingGroupSpecifier];
        
        PSSpecifier *themeSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Theme") target:self set:defSetter get:defGetter detail:nil cell:PSLinkListCell edit:nil];
        themeSpecifier.detailControllerClass = [DOPSListItemsController class];
        [themeSpecifier setProperty:@YES forKey:@"enabled"];
        [themeSpecifier setProperty:@"theme" forKey:@"key"];
        [themeSpecifier setProperty:[[self themeIdentifiers] firstObject] forKey:@"default"];
        [themeSpecifier setProperty:@"themeIdentifiers" forKey:@"valuesDataSource"];
        [themeSpecifier setProperty:@"themeNames" forKey:@"titlesDataSource"];
        [specifiers addObject:themeSpecifier];

        PSSpecifier *materialSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Button_Material") target:self set:defSetter get:defGetter detail:nil cell:PSLinkListCell edit:nil];
        materialSpecifier.detailControllerClass = [DOPSListItemsController class];
        [materialSpecifier setProperty:@YES forKey:@"enabled"];
        [materialSpecifier setProperty:@"buttonMaterial" forKey:@"key"];
        [materialSpecifier setProperty:@"original" forKey:@"default"];
        [materialSpecifier setProperty:@"materialIdentifiers" forKey:@"valuesDataSource"];
        [materialSpecifier setProperty:@"materialNames" forKey:@"titlesDataSource"];
        [specifiers addObject:materialSpecifier];

        PSSpecifier *showUptimeSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Show_Uptime") target:self set:defSetter get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [showUptimeSpecifier setProperty:@YES forKey:@"enabled"];
        [showUptimeSpecifier setProperty:@"showUptime" forKey:@"key"];
        [showUptimeSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:showUptimeSpecifier];

        PSSpecifier *showVersionSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Show_Version") target:self set:defSetter get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [showVersionSpecifier setProperty:@YES forKey:@"enabled"];
        [showVersionSpecifier setProperty:@"showVersion" forKey:@"key"];
        [showVersionSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:showVersionSpecifier];

        PSSpecifier *bootlogoGropSpecifier = [PSSpecifier emptyGroupSpecifier];
        bootlogoGropSpecifier.name = DOLocalizedString(@"Section_Boot_Logo");
        [specifiers addObject:bootlogoGropSpecifier];

        PSSpecifier *bootlogoEnabledSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Enabled") target:self set:@selector(setBootlogoEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [bootlogoEnabledSpecifier setProperty:@YES forKey:@"enabled"];
        [bootlogoEnabledSpecifier setProperty:@"bootlogoEnabled" forKey:@"key"];
        [bootlogoEnabledSpecifier setProperty:@YES forKey:@"default"];
        bootlogoEnabledSpecifier.identifier = @"bootlogoEnabled";
        [specifiers addObject:bootlogoEnabledSpecifier];

        _customBootlogoEnabledSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Custom_Boot_Logo") target:self set:@selector(setCustomBootlogoEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [_customBootlogoEnabledSpecifier setProperty:@YES forKey:@"enabled"];
        [_customBootlogoEnabledSpecifier setProperty:@"customBootlogoEnabled" forKey:@"key"];
        [_customBootlogoEnabledSpecifier setProperty:@NO forKey:@"default"];
        _customBootlogoEnabledSpecifier.identifier = @"customBootlogoEnabled";

        _customBootlogoSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Select_Image") target:self set:defSetter get:defGetter detail:nil cell:PSButtonCell edit:nil];
        _customBootlogoSpecifier.buttonAction = @selector(selectCustomBootlogoPressed);
        [_customBootlogoSpecifier setProperty:@YES forKey:@"enabled"];
        [_customBootlogoSpecifier setProperty:@"customBootlogo" forKey:@"key"];
        _customBootlogoSpecifier.identifier = @"customBootlogo";

        if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"bootlogoEnabled" fallback:YES]) {
            [specifiers addObject:_customBootlogoEnabledSpecifier];

            if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"customBootlogoEnabled" fallback:NO]) {
                [specifiers addObject:_customBootlogoSpecifier];
            }
        }

        _specifiers = specifiers;
    }
    return _specifiers;
}

#pragma mark - Getters & Setters

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier
{
    NSString *key = [specifier propertyForKey:@"key"];
    [[DOPreferenceManager sharedManager] setPreferenceValue:value forKey:key];
}

- (id)readPreferenceValue:(PSSpecifier*)specifier
{
    NSString *key = [specifier propertyForKey:@"key"];
    id value = [[DOPreferenceManager sharedManager] preferenceValueForKey:key];
    if (!value) {
        return [specifier propertyForKey:@"default"];
    }
    return value;
}

- (id)readExploitPreferenceValue:(PSSpecifier *)specifier
{
    id value = [self readPreferenceValue:specifier];

    SEL dataSourceSel = nil;
    NSString *selString = [specifier propertyForKey:@"valuesDataSource"];
    if (selString) {
        dataSourceSel = NSSelectorFromString(selString);
    }

    if (dataSourceSel && [value isKindOfClass:[NSString class]]) {
        NSString *valueString = (NSString *)value;

        IMP imp = [specifier.target methodForSelector:dataSourceSel];
        if (imp) {
            NSArray *(*func)(id, SEL) = (void *)imp;
            NSArray *availableIdentifiers = func(specifier.target, dataSourceSel);
            if (![availableIdentifiers containsObject:valueString]) {
                return [specifier propertyForKey:@"default"];
            }
        }
    }

    return value;
}

- (id)readIDownloadEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @([DOEnvironmentManager sharedManager].isIDownloadEnabled);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setIDownloadEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        [[DOEnvironmentManager sharedManager] setIDownloadLoaded:((NSNumber *)value).boolValue needsUnsandbox:YES];
    }
}

- (id)readTweakInjectionEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @([DOEnvironmentManager sharedManager].isTweakInjectionEnabled);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setTweakInjectionEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        [[DOEnvironmentManager sharedManager] setTweakInjectionEnabled:((NSNumber *)value).boolValue];
        UIAlertController *userspaceRebootAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Title") message:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Body") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *rebootNowAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Reboot_Now") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [[DOEnvironmentManager sharedManager] rebootUserspace];
        }];
        UIAlertAction *rebootLaterAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Reboot_Later") style:UIAlertActionStyleCancel handler:nil];
        
        [userspaceRebootAlertController addAction:rebootNowAction];
        [userspaceRebootAlertController addAction:rebootLaterAction];
        [self presentViewController:userspaceRebootAlertController animated:YES completion:nil];
    }
}

- (id)readAppJITEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        bool v = jbclient_jbsettings_get_bool("markAppsAsDebugged");
        return @(v);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setAppJITEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_bool("markAppsAsDebugged", ((NSNumber *)value).boolValue);
    }
}

- (id)readJetsamMultiplier:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        double v = jbclient_jbsettings_get_double("jetsamMultiplier");
        return @((v < 1 || isnan(v)) ? 6 : ceil(v * 2));
    }
    return [self readPreferenceValue:specifier];
}

- (void)setJetsamMultiplier:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_double("jetsamMultiplier", ((NSNumber *)value).doubleValue / 2);
    }
}

- (id)readCrashReporterDisabled:(PSSpecifier *)specifier
{
    return @([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/.DopamineCrashReporterDisabled"]);
}

- (void)setCrashReporterDisabled:(id)value specifier:(PSSpecifier *)specifier
{
    BOOL disabled = ((NSNumber *)value).boolValue;
    if (disabled) {
        [[NSData data] writeToFile:@"/var/mobile/.DopamineCrashReporterDisabled" atomically:YES];
        jbclient_platform_set_crashreporter_enabled(false);
    } else {
        [[NSFileManager defaultManager] removeItemAtPath:@"/var/mobile/.DopamineCrashReporterDisabled" error:nil];
        jbclient_platform_set_crashreporter_enabled(true);
    }
}

- (void)setRemoveJailbreakEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    if (((NSNumber *)value).boolValue) {
        UIAlertController *confirmationAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Remove_Jailbreak_Title") message:DOLocalizedString(@"Alert_Remove_Jailbreak_Enabled_Body") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *uninstallAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Continue") style:UIAlertActionStyleDestructive handler:nil];
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [self setPreferenceValue:@NO specifier:specifier];
            [self reloadSpecifiers];
        }];
        [confirmationAlertController addAction:uninstallAction];
        [confirmationAlertController addAction:cancelAction];
        [self presentViewController:confirmationAlertController animated:YES completion:nil];
    }
}

- (void)setBootlogoEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    bool prevValueBool = ((NSNumber *)[self readPreferenceValue:specifier]).boolValue;
    [self setPreferenceValue:value specifier:specifier];
    bool valueBool = ((NSNumber *)value).boolValue;

    if (prevValueBool != valueBool) {
        NSMutableArray *affectedSpecifiers = [NSMutableArray new];
        [affectedSpecifiers addObject:_customBootlogoEnabledSpecifier];

        if (valueBool == ![self containsSpecifier:_customBootlogoSpecifier]) {
            [affectedSpecifiers addObject:_customBootlogoSpecifier];
        }

        if (valueBool) {
            [self insertContiguousSpecifiers:affectedSpecifiers afterSpecifier:specifier animated:YES];
        }
        else {
            [self removeContiguousSpecifiers:affectedSpecifiers animated:YES];
        }
    }

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }
}

- (void)setCustomBootlogoEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    bool prevValueBool = ((NSNumber *)[self readPreferenceValue:specifier]).boolValue;
    [self setPreferenceValue:value specifier:specifier];
    bool valueBool = ((NSNumber *)value).boolValue;

    if (prevValueBool != valueBool) {
        if (valueBool) {
            [self insertSpecifier:_customBootlogoSpecifier afterSpecifier:specifier animated:YES];
        }
        else {
            [self removeSpecifier:_customBootlogoSpecifier animated:YES];
        }
    }

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }
}

- (void)selectCustomBootlogoPressed
{
    PHAuthorizationStatus status = [PHPhotoLibrary authorizationStatus];
    if (status == PHAuthorizationStatusDenied || status == PHAuthorizationStatusRestricted) {
        return;
    } else if (status == PHAuthorizationStatusNotDetermined) {
        [PHPhotoLibrary requestAuthorization:^(PHAuthorizationStatus status) {
            if (status == PHAuthorizationStatusAuthorized) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self selectCustomBootlogoPressed];
                });
            }
        }];
        return;
    }

    UIImagePickerController *picker = [[UIImagePickerController alloc] init];
    picker.delegate = self;
    picker.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
    [self presentViewController:picker animated:YES completion:nil];
}

#pragma mark - Boot Logo Picker

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary<NSString *,id> *)info {
    UIImage *chosenImage = info[UIImagePickerControllerEditedImage];
    if (!chosenImage) {
        chosenImage = info[UIImagePickerControllerOriginalImage];
    }

    UIGraphicsBeginImageContextWithOptions(chosenImage.size, NO, 1.0);
    [chosenImage drawInRect:CGRectMake(0,0, chosenImage.size.width, chosenImage.size.height)];
    chosenImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();

    [UIImagePNGRepresentation(chosenImage) writeToFile:[DOUIManager sharedInstance].bootlogoPath atomically:YES];

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }

    [picker dismissViewControllerAnimated:YES completion:nil];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [picker dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - Button Actions

- (void)refreshJailbreakAppsPressed
{
    [[DOEnvironmentManager sharedManager] refreshJailbreakApps];
}

- (void)reinstallPackageManagersPressed
{
    [self.navigationController pushViewController:[[DOPkgManagerPickerViewController alloc] init] animated:YES];
}

- (void)changeMobilePasswordWithAuthenticationPressed
{
	LAContext *context = [[LAContext alloc] init];
	NSError *authError = nil;
	NSString *reason = DOLocalizedString(@"Password_Auth_Required");
	
	if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
		[context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
			localizedReason:reason
			reply:^(BOOL success, NSError * _Nullable error) {
			dispatch_async(dispatch_get_main_queue(), ^{
				if (success) {
					[self changeMobilePassword];
				}
			});
		}];
	}
	else {
		[self changeMobilePassword];
	}
}

- (void)changeMobilePassword
{
    UIAlertController *changeMobilePasswordAlert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Button_Change_Mobile_Password") message:DOLocalizedString(@"Alert_Change_Mobile_Password_Body") preferredStyle:UIAlertControllerStyleAlert];
    
    [changeMobilePasswordAlert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = DOLocalizedString(@"Password_Placeholder");
        textField.secureTextEntry = YES;
    }];
    
    [changeMobilePasswordAlert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = DOLocalizedString(@"Repeat_Password_Placeholder");
        textField.secureTextEntry = YES;
    }];
    
    UIAlertAction *changeButton = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Change") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action){
        NSString *password = changeMobilePasswordAlert.textFields[0].text;
        NSString *repeatPassword = changeMobilePasswordAlert.textFields[1].text;
        if (![password isEqualToString:repeatPassword]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self changeMobilePassword];
            });
        }
        else {
            [[DOEnvironmentManager sharedManager] changeMobilePassword:password];
        }
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil];
    [changeMobilePasswordAlert addAction:changeButton];
    [changeMobilePasswordAlert addAction:cancelAction];
    [self presentViewController:changeMobilePasswordAlert animated:YES completion:nil];
}

- (void)hideUnhideJailbreakPressed
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager setJailbreakHidden:!envManager.isJailbreakHidden];
    [self reloadSpecifiers];
}

- (void)removeJailbreakPressed
{
    UIAlertController *confirmationAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Remove_Jailbreak_Title") message:DOLocalizedString(@"Alert_Remove_Jailbreak_Pressed_Body") preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *uninstallAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Continue") style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [[DOEnvironmentManager sharedManager] deleteBootstrap];
        if ([DOEnvironmentManager sharedManager].isJailbroken) {
            [[DOEnvironmentManager sharedManager] reboot];
        }
        else {
            if (gSystemInfo.jailbreakInfo.rootPath) {
                free(gSystemInfo.jailbreakInfo.rootPath);
                gSystemInfo.jailbreakInfo.rootPath = NULL;
                [[DOEnvironmentManager sharedManager] locateJailbreakRoot];
            }
            [self reloadSpecifiers];
        }
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleDefault handler:nil];
    [confirmationAlertController addAction:uninstallAction];
    [confirmationAlertController addAction:cancelAction];
    [self presentViewController:confirmationAlertController animated:YES completion:nil];
}

- (NSString *)ensureAbsolutePath:(NSString *)path {
    NSString *trimmedPath = [path stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    
    if (![trimmedPath hasPrefix:@"/"]) 
        trimmedPath = [@"/" stringByAppendingString:trimmedPath];

    return [trimmedPath stringByStandardizingPath];
}

- (void)mountPressed
{
    UIAlertController *inputAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Input_Mmount_Title") message:DOLocalizedString(@"Mount_Input_Message") preferredStyle:UIAlertControllerStyleAlert];
    
    [inputAlertController addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = DOLocalizedString(@"Input_Mount_Title");
    }];
    
    UIAlertAction *mountAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Mount") style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        UITextField *inputTextField = inputAlertController.textFields.firstObject;
        NSString *trimmedInput = [inputTextField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (trimmedInput.length == 0) {
            UIAlertController *emptyAlert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Log_Error") message:DOLocalizedString(@"Error_Mount_Empty") preferredStyle:UIAlertControllerStyleAlert];
            [emptyAlert addAction:[UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:emptyAlert animated:YES completion:nil];
            return;
        }
        NSString *mountPath = [self ensureAbsolutePath:trimmedInput];
        
        BOOL isDirectory = NO;
        BOOL isExist = [[NSFileManager defaultManager] fileExistsAtPath:mountPath isDirectory:&isDirectory];
        if (!isExist || !isDirectory) {
            UIAlertController *errorAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Log_Error") message:DOLocalizedString(@"Error_Mount_Body") preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Mount") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                [self mountPressed];
            }];
            [errorAlertController addAction:okAction];
            [self presentViewController:errorAlertController animated:YES completion:nil];
            return;
        }

        if (mountPath.length > 1) {
            NSString *plistFilePath = JBROOT_PATH(@"/mnt/newFakePath.plist");
            NSMutableDictionary *plistDictionary = [NSMutableDictionary dictionaryWithContentsOfFile:plistFilePath];
            if (!plistDictionary) {
                plistDictionary = [NSMutableDictionary dictionary];
            }
            NSMutableArray *pathArray = plistDictionary[@"path"];
            if (!pathArray) {
                pathArray = [NSMutableArray array];
            }
            if (![pathArray containsObject:mountPath]) {
                [pathArray addObject:mountPath];
                [plistDictionary setObject:pathArray forKey:@"path"];
                [[DOEnvironmentManager sharedManager] mountDictionary:[plistDictionary copy] writeToFile:plistFilePath];
            } 

            [[DOEnvironmentManager sharedManager] fakeMount:mountPath unmount:NO shouldDeleteMntFiles:NO];
        }
    }];
    
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleDefault handler:nil];

    [inputAlertController addAction:mountAction];
    [inputAlertController addAction:cancelAction];
    
    [self presentViewController:inputAlertController animated:YES completion:nil];
}

- (void)unmountPressed
{
    NSString *plistPath = JBROOT_PATH(@"/mnt/newFakePath.plist");
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    NSMutableArray *paths = [plist[@"path"] mutableCopy];
    if (paths.count == 0) {
        UIAlertController *emptyAlert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Input_Unmount_Title") message:DOLocalizedString(@"Empty_Mount_List") preferredStyle:UIAlertControllerStyleAlert];
        [emptyAlert addAction:[UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:emptyAlert animated:YES completion:nil];
        return;
    }
    
    NSString *titleText = DOLocalizedString(@"Select_Mount_Title");
    NSMutableAttributedString *attrTitle = [[NSMutableAttributedString alloc] initWithString:titleText];
    [attrTitle addAttribute:NSFontAttributeName value:[UIFont boldSystemFontOfSize:24] range:NSMakeRange(0, titleText.length)];
    
    UIAlertController *listAlertController = [UIAlertController alertControllerWithTitle:@"" message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    
    [listAlertController setValue:attrTitle forKey:@"attributedTitle"];
    
    for (NSString *path in paths) {
        UIAlertAction *pathAction = [UIAlertAction actionWithTitle:path style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            NSString *targetMountPath = JBROOT_PATH([@"/mnt" stringByAppendingString:path]);
            
            NSMutableAttributedString *attrActionTitle = [[NSMutableAttributedString alloc] initWithString:path];
            [attrActionTitle addAttribute:NSFontAttributeName value:[UIFont boldSystemFontOfSize:12] range:NSMakeRange(0, path.length)];
    
            UIAlertController *actionAlertController = [UIAlertController alertControllerWithTitle:@"" message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    
            [actionAlertController setValue:attrActionTitle forKey:@"attributedTitle"];
    
            UIAlertAction *deletePathAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Delete_Path_Only") style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
                [paths removeObject:path];
                plist[@"path"] = paths;
                [[DOEnvironmentManager sharedManager] mountDictionary:plist writeToFile:plistPath];
            }];
            
            UIAlertAction *deleteAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Delete") style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
                [[DOEnvironmentManager sharedManager] fakeMount:path unmount:YES shouldDeleteMntFiles:YES];
                
                [paths removeObject:path];
                plist[@"path"] = paths;
                [[DOEnvironmentManager sharedManager] mountDictionary:plist writeToFile:plistPath];
            }];
            
            UIAlertAction *viewAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_View") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"filza://"]]) {
                    NSURL *filzaURL = [NSURL URLWithString:[@"filza://view" stringByAppendingString:targetMountPath]];
                    [[UIApplication sharedApplication] openURL:filzaURL options:@{} completionHandler:nil];
                }else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"fffff://"]]) {
                    NSURL *fffffURL = [NSURL URLWithString:[@"fffff://view" stringByAppendingString:targetMountPath]];
                    [[UIApplication sharedApplication] openURL:fffffURL options:@{} completionHandler:nil];
                }
            }];
            
            UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil];

            [actionAlertController addAction:deleteAction];
            [actionAlertController addAction:viewAction];
            [actionAlertController addAction:deletePathAction];
            [actionAlertController addAction:cancelAction];
            
            [self presentViewController:actionAlertController animated:YES completion:nil];
        }];
        
        [listAlertController addAction:pathAction];
    }
    
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil];
    
    [listAlertController addAction:cancelAction];
    
    [self presentViewController:listAlertController animated:YES completion:nil];
}

- (void)resetSettingsPressed
{
    [[DOUIManager sharedInstance] resetSettings];
    [self.navigationController popToRootViewControllerAnimated:YES];
    [self reloadSpecifiers];
}

- (void)injectionBlockPressed
{
    DOEnvironmentManager *env = [DOEnvironmentManager sharedManager];
    NSArray<NSString *> *current = [env allInjectionBlockedBundleIDs];
    NSString *currentStr = [current componentsJoinedByString:@", "];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Block App Injection")
                                                                   message:@"Enter bundle IDs to block injection from, separated by commas. Changes take effect after the target app is restarted."
                                                            preferredStyle:UIAlertControllerStyleAlert];

    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.text = currentStr;
        tf.placeholder = @"com.s1mplyc0de.P0stB0x, com.santander.app";
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    }];

    [alert addAction:[UIAlertAction actionWithTitle:@"Save" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *input = alert.textFields.firstObject.text ?: @"";
        NSArray *parts = [input componentsSeparatedByString:@","];
        NSMutableArray<NSString *> *newList = [NSMutableArray array];
        for (NSString *part in parts) {
            NSString *trimmed = [part stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (trimmed.length > 0) [newList addObject:trimmed];
        }

        for (NSString *bid in current) {
            [env setInjectionBlocked:NO forBundleID:bid];
        }
        for (NSString *bid in newList) {
            [env setInjectionBlocked:YES forBundleID:bid];
        }

        [self reloadSpecifiers];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];

    [self presentViewController:alert animated:YES completion:nil];
}

- (void)appHidePressed
{
    DOAppHidePickerViewController *picker = [[DOAppHidePickerViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    [self.navigationController pushViewController:picker animated:YES];
}

- (void)rebootPressed
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Reboot Device"
                                                                   message:@"Are you sure you want to reboot the device?"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Reboot" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [[DOEnvironmentManager sharedManager] reboot];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end

@implementation DOAppHidePickerViewController

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = DOLocalizedString(@"Hide for App");
    self.tableView.rowHeight = 64;
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.tableView.separatorInset = UIEdgeInsetsMake(0, 68, 0, 0);
    self.tableView.separatorColor = [[UIColor whiteColor] colorWithAlphaComponent:0.06];
    if (@available(iOS 15.0, *)) {
        self.tableView.sectionHeaderTopPadding = 12;
    }

    // Use the same page background as the other settings pages, but keep the table
    // itself clear: an opaque table background paints over the InsetGrouped corner
    // masking and the app cards lose their rounded outline.
    [DOPSListController setupViewControllerStyle:self];
    self.tableView.backgroundColor = [UIColor clearColor];

    self.allApps = [NSMutableArray array];
    self.filteredApps = [NSMutableArray array];
    self.iconCache = [[NSCache alloc] init];
    self.iconCache.countLimit = 200;

    [self loadInstalledApps];

    // A self-drawn search bar as the table header instead of a UISearchController
    // on navigationItem: this controller is pushed from a PSListController, which
    // does not always carry a navigation bar, and navigationItem.searchController
    // is silently ignored without one.
    UISearchBar *searchBar = [[UISearchBar alloc] init];
    searchBar.delegate = self;
    searchBar.placeholder = DOLocalizedString(@"App_Hide_Search_Placeholder");
    searchBar.autocapitalizationType = UITextAutocapitalizationTypeNone;
    searchBar.autocorrectionType = UITextAutocorrectionTypeNo;
    searchBar.searchBarStyle = UISearchBarStyleMinimal;
    if (@available(iOS 13.0, *)) {
        searchBar.searchTextField.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.12];
        searchBar.searchTextField.textColor = [UIColor whiteColor];
        searchBar.searchTextField.leftView.tintColor = [[UIColor whiteColor] colorWithAlphaComponent:0.5];
    }
    self.searchBar = searchBar;

    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.tableView.bounds.size.width, 60)];
    CGFloat screenWidth = CGRectGetWidth([UIScreen mainScreen].bounds);
    CGFloat searchWidth = MIN(screenWidth - 24, 400);
    searchBar.frame = CGRectMake((self.tableView.bounds.size.width - searchWidth) / 2, 6, searchWidth, 48);
    searchBar.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    [header addSubview:searchBar];
    self.tableView.tableHeaderView = header;

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                                          target:self
                                                                                          action:@selector(donePressed)];

    UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPress:)];
    [self.tableView addGestureRecognizer:longPress];
}

- (void)donePressed
{
    [self.navigationController popViewControllerAnimated:YES];
}

- (void)loadInstalledApps
{
    Class LSApplicationWorkspace_class = objc_getClass("LSApplicationWorkspace");
    if (!LSApplicationWorkspace_class) return;

    NSObject *workspace = [LSApplicationWorkspace_class performSelector:NSSelectorFromString(@"defaultWorkspace")];
    NSArray *allApps = [workspace performSelector:NSSelectorFromString(@"allApplications")];
    DOEnvironmentManager *env = [DOEnvironmentManager sharedManager];

    for (id app in allApps) {
        NSString *bundleID = [app valueForKey:@"applicationIdentifier"];
        NSString *name = [app valueForKey:@"localizedName"];
        if (!bundleID || !name) continue;
        if ([bundleID hasPrefix:@"com.apple."]) continue;

        BOOL hidden = [env isEnvironmentHiddenForBundleID:bundleID];
        BOOL noInject = [env isEnvironmentNoInjectForBundleID:bundleID];
        [self.allApps addObject:[@{
            @"bundleID": bundleID,
            @"name": name,
            @"hidden": @(hidden),
            @"noInject": @(noInject)
        } mutableCopy]];
    }

    [self.allApps sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];

    [self.filteredApps setArray:self.allApps];
    [self.tableView reloadData];
}

- (UIImage *)iconForBundleID:(NSString *)bundleID
{
    if (!bundleID) return nil;
    UIImage *cached = [self.iconCache objectForKey:bundleID];
    if (cached) return cached;

    UIImage *icon = nil;

    SEL iconSel = NSSelectorFromString(@"_applicationIconImageForBundleIdentifier:format:scale:");
    if ([UIImage respondsToSelector:iconSel]) {
        NSMethodSignature *sig = [UIImage methodSignatureForSelector:iconSel];
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.target = [UIImage class];
        inv.selector = iconSel;
        NSString *bid = bundleID;
        NSNumber *format = @(2);
        CGFloat scale = [UIScreen mainScreen].scale;
        [inv setArgument:&bid atIndex:2];
        [inv setArgument:&format atIndex:3];
        [inv setArgument:&scale atIndex:4];
        [inv invoke];
        __unsafe_unretained UIImage *result = nil;
        [inv getReturnValue:&result];
        icon = result;
    }

    if (!icon) {
        Class LSApplicationProxy = objc_getClass("LSApplicationProxy");
        if (LSApplicationProxy) {
            id proxy = [LSApplicationProxy performSelector:NSSelectorFromString(@"applicationProxyForIdentifier:") withObject:bundleID];
            if (proxy) {
                SEL dataSel = NSSelectorFromString(@"iconDataForVariant:");
                if ([proxy respondsToSelector:dataSel]) {
                    NSData *data = [proxy performSelector:dataSel withObject:@2];
                    if (data) icon = [UIImage imageWithData:data];
                }
            }
        }
    }

    if (icon) [self.iconCache setObject:icon forKey:bundleID];
    return icon;
}

- (UIImage *)roundedIcon:(UIImage *)icon size:(CGSize)size cornerRadius:(CGFloat)radius
{
    if (!icon) return nil;
    UIGraphicsImageRendererFormat *format = [UIGraphicsImageRendererFormat defaultFormat];
    format.scale = [UIScreen mainScreen].scale;
    format.opaque = NO;
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:size format:format];

    return [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        CGRect rect = CGRectMake(0, 0, size.width, size.height);
        UIBezierPath *path = [UIBezierPath bezierPathWithRoundedRect:rect cornerRadius:radius];
        [path addClip];
        [icon drawInRect:rect];
    }];
}

#pragma mark - Search

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    [self applySearchText:searchController.searchBar.text ?: @""];
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText
{
    [self applySearchText:searchText ?: @""];
}

- (void)searchBarCancelButtonClicked:(UISearchBar *)searchBar
{
    searchBar.text = @"";
    [self applySearchText:@""];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar
{
    [searchBar resignFirstResponder];
}

- (void)applySearchText:(NSString *)text
{
    NSString *query = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (query.length == 0) {
        [self.filteredApps setArray:self.allApps];
    } else {
        NSPredicate *predicate = [NSPredicate predicateWithFormat:@"name CONTAINS[cd] %@ OR bundleID CONTAINS[cd] %@", query, query];
        NSArray *filtered = [self.allApps filteredArrayUsingPredicate:predicate];
        [self.filteredApps setArray:filtered];
    }
    [self.tableView reloadData];
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    return DOLocalizedString(@"App_Hide_Header");
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    // When a search yields nothing, say so instead of showing a bare empty list.
    if (self.filteredApps.count == 0 && self.searchBar.text.length > 0) {
        return DOLocalizedString(@"App_Hide_Search_No_Results");
    }
    return DOLocalizedString(@"App_Hide_Footer");
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return self.filteredApps.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    static NSString *cellId = @"AppHideCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellId];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cellId];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.textLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
        cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    }

    NSDictionary *appInfo = self.filteredApps[indexPath.row];
    NSString *bundleID = appInfo[@"bundleID"];

    BOOL noInject = [appInfo[@"noInject"] boolValue];
    cell.textLabel.text = noInject ? [NSString stringWithFormat:@"%@ [NoInject]", appInfo[@"name"]] : appInfo[@"name"];
    cell.detailTextLabel.text = bundleID;

    UIImage *icon = [self iconForBundleID:bundleID];
    if (icon) {
        cell.imageView.image = [self roundedIcon:icon size:CGSizeMake(42, 42) cornerRadius:9];
    } else {
        cell.imageView.image = [UIImage systemImageNamed:@"app"];
    }

    UISwitch *toggle = [[UISwitch alloc] init];
    toggle.on = [appInfo[@"hidden"] boolValue];
    // Tag by index into the *unfiltered* list: after a search the row is a
    // filtered index, and toggleChanged: looks the app up in allApps.
    toggle.tag = [self.allApps indexOfObject:appInfo];
    [toggle addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;

    return cell;
}

- (void)toggleChanged:(UISwitch *)sender
{
    if (sender.tag < 0 || sender.tag >= (NSInteger)self.allApps.count) return;
    NSDictionary *appInfo = self.allApps[sender.tag];
    NSString *bundleID = appInfo[@"bundleID"];
    BOOL hidden = sender.on;

    [[DOEnvironmentManager sharedManager] setEnvironmentHidden:hidden forBundleID:bundleID];

    for (NSMutableDictionary *dict in self.allApps) {
        if ([dict[@"bundleID"] isEqualToString:bundleID]) {
            dict[@"hidden"] = @(hidden);
            if (!hidden) dict[@"noInject"] = @NO;
            break;
        }
    }

    UIImpactFeedbackGenerator *fb = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
    [fb impactOccurred];
}

// Long-press a (hidden) app to toggle "无注入" (RootHide-style no-injection) mode.
- (void)handleLongPress:(UILongPressGestureRecognizer *)gesture
{
    if (gesture.state != UIGestureRecognizerStateBegan) return;
    CGPoint p = [gesture locationInView:self.tableView];
    NSIndexPath *indexPath = [self.tableView indexPathForRowAtPoint:p];
    if (!indexPath) return;

    NSDictionary *appInfo = self.filteredApps[indexPath.row];
    if (![appInfo[@"hidden"] boolValue]) return; // only meaningful when already hidden
    NSString *bundleID = appInfo[@"bundleID"];

    BOOL noInject = ![appInfo[@"noInject"] boolValue];
    [[DOEnvironmentManager sharedManager] setEnvironmentNoInject:noInject forBundleID:bundleID];

    for (NSMutableDictionary *dict in self.allApps) {
        if ([dict[@"bundleID"] isEqualToString:bundleID]) {
            dict[@"noInject"] = @(noInject);
            break;
        }
    }
    [self.tableView reloadData];

    UIImpactFeedbackGenerator *fb = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
    [fb impactOccurred];
}

@end