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

// Material for the settings-row buttons. "Original" keeps the stock Dopamine
// look (no fill), "Custom" adds a subtle light fill that makes the rounded
// corners read as a frosted button. Default is Original.
+ (NSArray*)getAvailableMaterialKeys;
+ (NSArray*)getAvailableMaterialNames;
+ (NSString*)enabledMaterialKey;
+ (nullable UIColor*)settingsButtonFillColor;

@end

NS_ASSUME_NONNULL_END
