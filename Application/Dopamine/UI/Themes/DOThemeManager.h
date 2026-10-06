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

// Background material used by list-style pages. "Original" keeps the stock
// system material Dopamine ships with; the other keys let the user pick a
// different look without touching the theme (wallpaper) itself.
+ (NSArray*)getAvailableMaterialKeys;
+ (NSArray*)getAvailableMaterialNames;
+ (NSString*)enabledMaterialKey;

// Resolve a material key to a concrete appearance for the current trait
// collection. Returns nil for the original material, which means "leave the
// system material alone".
+ (nullable id)materialAppearanceForKey:(nullable NSString*)key;

@end

NS_ASSUME_NONNULL_END
