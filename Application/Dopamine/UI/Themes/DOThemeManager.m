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

// key -> (display name, UIBlurEffect.Style or nil for a plain vibrancy look).
// The first entry is the stock Dopamine look and the default.
+ (NSDictionary<NSString *, id> *)materialTable
{
    static NSDictionary *table = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        table = @{
            @"original":  @{ @"name": @"Original",     @"style": @(UIBlurEffectStyleSystemUltraThinMaterialDark) },
            @"light":     @{ @"name": @"Light",        @"style": @(UIBlurEffectStyleSystemUltraThinMaterialLight) },
            @"dark":      @{ @"name": @"Dark",         @"style": @(UIBlurEffectStyleSystemUltraThinMaterialDark) },
            @"thick":     @{ @"name": @"Thick",        @"style": @(UIBlurEffectStyleSystemThickMaterialDark) },
            @"regular":   @{ @"name": @"Regular",      @"style": @(UIBlurEffectStyleSystemMaterialDark) },
            @"chrome":    @{ @"name": @"Chrome",       @"style": @(UIBlurEffectStyleSystemChromeMaterialDark) },
            @"clear":     @{ @"name": @"Clear",        @"style": @(UIBlurEffectStyleSystemThinMaterialDark) },
        };
    });
    return table;
}

+ (NSArray*)getAvailableMaterialKeys
{
    // Keep a stable, human-friendly order rather than the dictionary's.
    return @[ @"original", @"regular", @"thick", @"clear", @"chrome", @"dark", @"light" ];
}

+ (NSArray*)getAvailableMaterialNames
{
    NSDictionary *table = [self materialTable];
    NSMutableArray *names = [NSMutableArray array];
    for (NSString *key in [self getAvailableMaterialKeys]) {
        [names addObject:table[key][@"name"] ?: key];
    }
    return names;
}

+ (NSString*)enabledMaterialKey
{
    id value = [[DOPreferenceManager sharedManager] preferenceValueForKey:@"backgroundMaterial"];
    NSArray *keys = [self getAvailableMaterialKeys];
    // Anything unset or unrecognised keeps the original look.
    if ([value isKindOfClass:[NSString class]] && [keys containsObject:value]) {
        return value;
    }
    return @"original";
}

+ (id)materialAppearanceForKey:(NSString*)key
{
    if (!key) return nil;

    NSDictionary *entry = [self materialTable][key];
    if (!entry) return nil;

    UIBlurEffect *effect = [UIBlurEffect effectWithStyle:[entry[@"style"] integerValue]];

    UINavigationBarAppearance *appearance = [[UINavigationBarAppearance alloc] init];
    [appearance configureWithTransparentBackground];
    appearance.backgroundEffect = effect;
    // Keep the material from looking washed out behind light content.
    appearance.backgroundColor = [UIColor colorWithWhite:0 alpha:0.12];
    return appearance;
}

@end
