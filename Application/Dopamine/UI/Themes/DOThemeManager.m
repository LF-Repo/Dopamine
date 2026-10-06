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


#pragma mark - Background material

// The settings pages are drawn on a solid background (DOPSListController applies
// theme.windowColor to the view and keeps every cell transparent), so the
// "material" is just which colour sits behind them. Two choices only:
//   original - the stock Dopamine look (the theme's own windowColor)
//   custom   - a lighter, slightly translucent grey that reads as frosted glass
+ (NSString*)enabledMaterialKey
{
    id value = [[DOPreferenceManager sharedManager] preferenceValueForKey:@"backgroundMaterial"];
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

// Background colour for the settings pages, honouring the material choice.
+ (UIColor*)settingsBackgroundColor
{
    DOTheme *theme = [[DOThemeManager sharedInstance] enabledTheme];
    if ([[DOThemeManager enabledMaterialKey] isEqualToString:@"custom"]) {
        // Matches the frosted look of the stock Dopamine buttons: a neutral grey
        // with a little transparency so the wallpaper still shows through.
        return [UIColor colorWithWhite:0.5 alpha:0.72];
    }
    return theme.windowColor;
}

@end
