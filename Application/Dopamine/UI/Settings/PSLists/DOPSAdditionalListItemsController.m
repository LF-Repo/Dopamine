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

        // Everything on this page shares ONE section. A group specifier starts a
        // new section, so the extra empty group previously used to carry the footer
        // rendered as its own section and left the blank block seen under the rows.
        // Attaching the footer to the single leading group keeps the page tight.
        PSSpecifier *groupSpecifier = [PSSpecifier emptyGroupSpecifier];
        [groupSpecifier setProperty:DOLocalizedString(@"NoInject_Auto_Close_Description") forKey:@"footerText"];
        [specifiers addObject:groupSpecifier];

        PSSpecifier *spinlockFixSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Enhanced Spinlock Fix (iOS 15)") target:self set:@selector(setSpinlockFixEnhanced:specifier:) get:@selector(readSpinlockFixEnhanced:) detail:nil cell:PSSwitchCell edit:nil];
        [spinlockFixSpecifier setProperty:@YES forKey:@"enabled"];
        [spinlockFixSpecifier setProperty:@"spinlockFixEnhanced" forKey:@"key"];
        [spinlockFixSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:spinlockFixSpecifier];

        // Auto-close multiplier for NoInject hiding, presented the same way as the
        // Jetsam multiplier: a value list with 1x..4x plus Never.
        PSSpecifier *autoCloseSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"NoInject_Auto_Close") target:self set:@selector(setNoInjectAutoClose:specifier:) get:@selector(readNoInjectAutoClose:) detail:nil cell:PSLinkListCell edit:nil];
        autoCloseSpecifier.detailControllerClass = [DOPSListItemsController class];
        [autoCloseSpecifier setProperty:@YES forKey:@"enabled"];
        [autoCloseSpecifier setProperty:@"noInjectAutoClose" forKey:@"key"];
        [autoCloseSpecifier setProperty:@2 forKey:@"default"];
        [autoCloseSpecifier setProperty:@"noInjectAutoCloseNumbers" forKey:@"valuesDataSource"];
        [autoCloseSpecifier setProperty:@"noInjectAutoCloseTitles" forKey:@"titlesDataSource"];
        [specifiers addObject:autoCloseSpecifier];

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

// The list stores an index: -1 means "never", 2..8 means multiplier index/2.
// Reading back converts the stored multiplier into that index.
- (id)readNoInjectAutoClose:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    double multiplier = 1.0;
    if (envManager.isJailbroken) {
        multiplier = jbclient_jbsettings_get_double("noInjectRestoreMultiplier");
    }
    // A negative value is the "never" sentinel written by setNoInjectAutoClose:.
    if (multiplier < 0) return @(-1);
    if (multiplier == 0) multiplier = 1.0;
    NSInteger index = (NSInteger)llround(multiplier * 2);
    if (index < 2) index = 2;
    if (index > 8) index = 8;
    return @(index);
}

- (void)setNoInjectAutoClose:(id)value specifier:(PSSpecifier *)specifier
{
    NSInteger index = ((NSNumber *)value).integerValue;

    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (!envManager.isJailbroken) return;

    if (index < 0) {
        // "Never": a negative sentinel, because 0 is reserved for "unset" so a
        // device that never touched this setting keeps its 30s default.
        jbclient_platform_jbsettings_set_double("noInjectRestoreMultiplier", -1.0);
        return;
    }

    if (index < 2) index = 2;
    if (index > 8) index = 8;
    jbclient_platform_jbsettings_set_double("noInjectRestoreMultiplier", (double)index / 2.0);
}

// Same shape as the Jetsam multiplier list: the stored value is an index, and
// the multiplier is index/2. Default @2 == 1x, which is the previous 30s delay,
// so an untouched setting behaves exactly as before. -1 is "never".
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
    @-1,
    ];
}

- (NSArray *)noInjectAutoCloseTitles
{
    return @[
        [NSString stringWithFormat:@"1x (%@)", DOLocalizedString(@"Recommended")],
        @"1.5x",
        @"2x",
        @"2.5x",
        @"3x",
        @"3.5x",
        @"4x",
        DOLocalizedString(@"NoInject_Auto_Close_Never"),
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