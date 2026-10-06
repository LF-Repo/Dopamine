//
//  DOThemeManager.m
//  Dopamine
//
//  Created by tomt000 on 14/02/2024.
//

#import "DOThemeManager.h"
#import "DOPreferenceManager.h"

@implementation DOThemeManager

+ (instancetype)sharedInstance
{
    static DOThemeManager *sharedManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedManager = [[DOThemeManager alloc] init];
    });
    return sharedManager;
}

- (id)init
{
    self = [super init];
    if (self) {
        self.themes = [[NSMutableArray alloc] init];
        
        NSString *path = [[NSBundle mainBundle] pathForResource:@"Themes" ofType:@"plist"];
        NSArray *themes = [NSArray arrayWithContentsOfFile:path];

        for (NSDictionary *theme in themes) {
            DOTheme *newTheme = [[DOTheme alloc] initWithDictionary:theme];
            [((NSMutableArray *)self.themes) addObject:newTheme];
        }

    }
    return self;
}

- (NSArray*)getAvailableThemeKeys
{
    NSMutableArray *keys = [[NSMutableArray alloc] init];
    for (DOTheme *theme in _themes) {
        [keys addObject:theme.key];
    }
    return keys;
}

- (NSArray*)getAvailableThemeNames
{
    NSMutableArray *names = [[NSMutableArray alloc] init];
    for (DOTheme *theme in _themes) {
        [names addObject:theme.name];
    }
    return names;
}

- (DOTheme*)getThemeForKey:(NSString*)key
{
    for (DOTheme *theme in _themes) {
        if ([theme.key isEqualToString:key]) {
            return theme;
        }
    }
    return nil;
}

- (DOTheme*)enabledTheme
{
    id value = [[DOPreferenceManager sharedManager] preferenceValueForKey:@"theme"];
    if (!value)
        return self.themes.firstObject;
    return [self getThemeForKey:value] ?: self.themes.firstObject;
}


+ (UIColor*)menuColorWithAlpha:(float)alpha
{
    DOTheme *theme = [[DOThemeManager sharedInstance] enabledTheme];
    
    UIColor *color = theme.actionMenuColor;
    CGFloat red, green, blue, currentAlpha;
    [color getRed:&red green:&green blue:&blue alpha:&currentAlpha];
    return [UIColor colorWithRed:red green:green blue:blue alpha:currentAlpha * alpha];
}


#pragma mark - Button material

// The settings rows are drawn as buttons (DOButtonCell). The stock Dopamine look
// leaves them unfilled, so only the hairline border shows. "Custom" adds a subtle
// light fill, which makes the rounded corners read as an actual frosted button.
+ (NSString*)enabledMaterialKey
{
    id value = [[DOPreferenceManager sharedManager] preferenceValueForKey:@"buttonMaterial"];
    if ([value isKindOfClass:[NSString class]] && [value isEqualToString:@"custom"]) {
        return @"custom";
    }
    // Anything unset or unrecognised keeps the stock Dopamine look.
    return @"original";
}

+ (NSArray*)getAvailableMaterialKeys
{
    return @[ @"original", @"custom" ];
}

+ (NSArray*)getAvailableMaterialNames
{
    return @[ @"Original", @"Custom" ];
}

// Fill colour for the settings-row buttons. nil means "no fill", which is the
// stock Dopamine appearance.
+ (UIColor*)settingsButtonFillColor
{
    if ([[DOThemeManager enabledMaterialKey] isEqualToString:@"custom"]) {
        return [UIColor colorWithWhite:1 alpha:0.08];
    }
    return nil;
}

@end
