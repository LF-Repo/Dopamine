//
//  DOPSAdditionalListItemsController.m
//  Dopamine
//
//  Created by 3.x-hide-dev.
//

#import "DOPSAdditionalListItemsController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOPSListItemsController.h"
#import <libjailbreak/jbclient_xpc.h>
#include <math.h>

@interface DOPSAdditionalListItemsController ()

@end

@implementation DOPSAdditionalListItemsController

- (void)viewDidLoad
{
    [super viewDidLoad];
    _table.tableHeaderView = [DOPSListItemsController makeHeader:DOLocalizedString(@"Additional") withTarget:self];
}

- (void)dismiss
{
    [self.navigationController popViewControllerAnimated:YES];
}

- (NSArray *)specifiers
{
    if (!_specifiers) {
        NSMutableArray *specifiers = [NSMutableArray new];

        PSSpecifier *spinlockFixSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Enhanced Spinlock Fix (iOS 15)") target:self set:@selector(setSpinlockFixEnhanced:specifier:) get:@selector(readSpinlockFixEnhanced:) detail:nil cell:PSSwitchCell edit:nil];
        [spinlockFixSpecifier setProperty:@YES forKey:@"enabled"];
        [spinlockFixSpecifier setProperty:@"spinlockFixEnhanced" forKey:@"key"];
        [spinlockFixSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:spinlockFixSpecifier];

        // Auto-close multiplier for NoInject hiding, presented the same way as the
        // Jetsam multiplier: a value list with 1x..4x and a footer explaining it.
        PSSpecifier *autoCloseSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"NoInject_Auto_Close") target:self set:@selector(setNoInjectAutoClose:specifier:) get:@selector(readNoInjectAutoClose:) detail:nil cell:PSLinkListCell edit:nil];
        autoCloseSpecifier.detailControllerClass = [DOPSListItemsController class];
        [autoCloseSpecifier setProperty:@YES forKey:@"enabled"];
        [autoCloseSpecifier setProperty:@"noInjectAutoClose" forKey:@"key"];
        [autoCloseSpecifier setProperty:@2 forKey:@"default"];
        [autoCloseSpecifier setProperty:@"noInjectAutoCloseNumbers" forKey:@"valuesDataSource"];
        [autoCloseSpecifier setProperty:@"noInjectAutoCloseTitles" forKey:@"titlesDataSource"];
        [specifiers addObject:autoCloseSpecifier];

        PSSpecifier *autoCloseFooterSpecifier = [PSSpecifier emptyGroupSpecifier];
        [autoCloseFooterSpecifier setProperty:DOLocalizedString(@"NoInject_Auto_Close_Description") forKey:@"footerText"];
        [specifiers addObject:autoCloseFooterSpecifier];

        PSSpecifier *disableCrashReporterSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Disable_Crash_Reporter") target:self set:@selector(setCrashReporterDisabled:specifier:) get:@selector(readCrashReporterDisabled:) detail:nil cell:PSSwitchCell edit:nil];
        [disableCrashReporterSpecifier setProperty:@YES forKey:@"enabled"];
        [disableCrashReporterSpecifier setProperty:@"crashReporterDisabled" forKey:@"key"];
        [disableCrashReporterSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:disableCrashReporterSpecifier];

        _specifiers = specifiers;
    }
    return _specifiers;
}

#pragma mark - Auto close multiplier

// The list stores an index (2..8); the jailbreak stores a multiplier (index/2).
// Reading back divides by two so the row shown matches what launchdhook uses.
- (id)readNoInjectAutoClose:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    double multiplier = 1.0;
    if (envManager.isJailbroken) {
        multiplier = jbclient_jbsettings_get_double("noInjectRestoreMultiplier");
    }
    if (multiplier <= 0) multiplier = 1.0;
    NSInteger index = (NSInteger)llround(multiplier * 2);
    if (index < 2) index = 2;
    if (index > 8) index = 8;
    return @(index);
}

- (void)setNoInjectAutoClose:(id)value specifier:(PSSpecifier *)specifier
{
    NSInteger index = ((NSNumber *)value).integerValue;
    if (index < 2) index = 2;
    if (index > 8) index = 8;

    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_double("noInjectRestoreMultiplier", (double)index / 2.0);
    }
}

// Same shape as the Jetsam multiplier list: the stored value is an index, and
// the multiplier is index/2. Default @2 == 1x, which is the previous 30s delay,
// so an untouched setting behaves exactly as before.
- (NSArray *)noInjectAutoCloseNumbers
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

- (NSArray *)noInjectAutoCloseTitles
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

#pragma mark - Spinlock fix

- (id)readSpinlockFixEnhanced:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @(jbclient_jbsettings_get_bool("spinlockFixEnhanced"));
    }
    return [self readPreferenceValue:specifier];
}

- (void)setSpinlockFixEnhanced:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_bool("spinlockFixEnhanced", ((NSNumber *)value).boolValue);
    }
}

#pragma mark - Crash reporter

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

@end