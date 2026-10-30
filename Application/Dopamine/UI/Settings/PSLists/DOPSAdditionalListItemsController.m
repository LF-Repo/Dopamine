//
//  DOPSAdditionalListItemsController.m
//  Dopamine
//
//  Created by 3.x-hide-dev.
//

#import "DOPSAdditionalListItemsController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import <libjailbreak/jbclient_xpc.h>

@interface DOPSAdditionalListItemsController ()

@end

@implementation DOPSAdditionalListItemsController

// The specifier's own "key" (set on the parent specifier in DOSettingsController)
// would pathologically be overridden by the valuesDataSource mechanism of the
// PSListItemsController base class; read the keys straight from a fixed key instead.

- (NSArray *)specifiers
{
    if (!_specifiers) {
        _specifiers = [super specifiers];

        NSMutableArray *specifiers = [_specifiers mutableCopy];

        PSSpecifier *spinlockFixSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Spinlock_Fix_Enhanced") target:self set:@selector(setSpinlockFixEnhanced:specifier:) get:@selector(readSpinlockFixEnhanced:) detail:nil cell:PSSwitchCell edit:nil];
        [spinlockFixSpecifier setProperty:@YES forKey:@"enabled"];
        [spinlockFixSpecifier setProperty:@"spinlockFixEnhanced" forKey:@"key"];
        [spinlockFixSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:spinlockFixSpecifier];

        PSSpecifier *disableCrashReporterSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Disable_Crash_Reporter") target:self set:@selector(setCrashReporterDisabled:specifier:) get:@selector(readCrashReporterDisabled:) detail:nil cell:PSSwitchCell edit:nil];
        [disableCrashReporterSpecifier setProperty:@YES forKey:@"enabled"];
        [disableCrashReporterSpecifier setProperty:@"crashReporterDisabled" forKey:@"key"];
        [disableCrashReporterSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:disableCrashReporterSpecifier];

        _specifiers = specifiers;
    }
    return _specifiers;
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