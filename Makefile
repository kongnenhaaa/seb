TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e
INSTALL_TARGET_PROCESSES := Zalo

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = clangg

clangg_FILES = Tweak.x
clangg_CFLAGS = -fobjc-arc -O3 -Wno-error -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function
clangg_FRAMEWORKS = UIKit Foundation WebKit Security

include $(THEOS_MAKE_PATH)/tweak.mk
