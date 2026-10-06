//
//  DOThemeManager.h
//  Dopamine
//
//  Created by tomt000 on 14/02/2024.
//

#import <Foundation/Foundation.h>
#import "DOTheme.h"

NS_ASSUME_NONNULL_BEGIN

@interface DOThemeManager : NSObject

@property (nonatomic, retain) NSArray<DOTheme*> *themes;

+ (instancetype)sharedInstance;

+ (UIColor*)menuColorWithAlpha:(float)alpha;
- (NSArray*)getAvailableThemeKeys;
- (NSArray*)getAvailableThemeNames;
- (DOTheme*)getThemeForKey:(NSString*)key;
- (DOTheme*)enabledTheme;

// Background material for the settings pages. "Original" keeps the stock
// Dopamine look (the theme's windowColor), "Custom" uses a lighter translucent
// grey that reads as frosted glass. Default is Original.
+ (NSArray*)getAvailableMaterialKeys;
+ (NSArray*)getAvailableMaterialNames;
+ (NSString*)enabledMaterialKey;
+ (UIColor*)settingsBackgroundColor;

@end

NS_ASSUME_NONNULL_END
